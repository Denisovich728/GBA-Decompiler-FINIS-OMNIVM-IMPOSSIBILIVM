"""Importador del desensamblado de StanHash/fomt y verificador contra nuestra ROM.

Lee refs/stanhash_fomt/asm/*.s (y src/*.cc), extrae por direccion: nombre, modo, instrucciones y
pool, y los compara contra el desensamblado capstone de 'fomt virgen.gba'.

Uso:
  python tools/match/stan_import.py --index            # construye logs/stan_index.json
  python tools/match/stan_import.py --verify           # compara con la ROM (mnemonicos+regs)
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAN = ROOT / "refs" / "stanhash_fomt"
OUT = ROOT / "logs" / "stan_index.json"
sys.path.insert(0, str(ROOT / "tools" / "match"))

START_RE = re.compile(r"^\s*(thumb_func_start|arm_func_start|non_word_aligned_thumb_func_start)\s+(\S+)")
LABEL_ADDR_RE = re.compile(r"^(\w+):\s*@\s*0x([0-9A-Fa-f]{8})")
INS_RE = re.compile(r"^\s+([a-z][a-z0-9.]*)\b(.*)$")
POOL_RE = re.compile(r"^\s*(?:[._]\w+:\s*)?\.(?:4byte|word|2byte|byte|hword)\b")


def parse_asm(path: Path):
    funcs, cur = [], None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("@", 1)[0].rstrip() if not LABEL_ADDR_RE.match(raw) else raw
        m = START_RE.match(raw)
        if m:
            cur = {"mode": "ARM" if m.group(1).startswith("arm") else "THUMB",
                   "name": m.group(2), "addr": None, "ins": [], "pool": [], "file": path.name}
            funcs.append(cur)
            continue
        if cur is None:
            continue
        la = LABEL_ADDR_RE.match(raw)
        if la and cur["addr"] is None:
            cur["addr"] = int(la.group(2), 16)
            continue
        if re.match(r"^\s*\.(?:align|balign)\b", raw):
            cur["ins"].append("@align")
            continue
        if POOL_RE.match(raw):
            cur["pool"].append(raw.strip())
            body = re.sub(r"^\s*(?:[._]\w+:\s*)?\.\w+\s*", "", raw.split("@", 1)[0])
            nvals = len([v for v in body.split(",") if v.strip()]) or 1
            if ".4byte" in raw or ".word" in raw:
                cur["ins"].append(f"@pool{4 * nvals}")
            elif ".2byte" in raw or ".hword" in raw:
                cur["ins"].append(f"@pool{2 * nvals}")
            else:
                cur["ins"].append(f"@blob{nvals}")
            continue
        if raw.strip().startswith(("_", ".L")) and raw.strip().endswith(":"):
            continue
        im = INS_RE.match(line)
        if im and not im.group(1).startswith("."):
            cur["ins"].append(f"{im.group(1)}{im.group(2)}".strip())
    return [f for f in funcs if f["addr"] is not None]


def build_index():
    funcs = []
    for p in sorted((STAN / "asm").glob("*.s")) + sorted((STAN / "src").glob("*.s")):
        funcs += parse_asm(p)
    named = sum(1 for f in funcs if not re.fullmatch(r"func_[0-9A-Fa-f]{8}", f["name"]))
    cc = {}
    for p in (STAN / "src").glob("*.cc"):
        for m in re.finditer(r"\bfunc_([0-9A-Fa-f]{8})\b", p.read_text(encoding="utf-8", errors="replace")):
            cc.setdefault(int(m.group(1), 16), p.name)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"asm": funcs, "cc_funcs": {f"{a:08X}": f for a, f in cc.items()}}, indent=1),
                   encoding="utf-8")
    byfile = collections.Counter(f["file"] for f in funcs)
    print(f"[+] funciones en asm: {len(funcs)} | con nombre semantico: {named} | en src/*.cc: {len(cc)}")
    print(f"[+] por modo: {dict(collections.Counter(f['mode'] for f in funcs))}")
    print(f"[+] por archivo: {dict(byfile.most_common(8))}")
    return funcs


_REG = re.compile(r"\b(sl|sb|fp|ip)\b")


def norm_stan(s: str) -> str:
    s = _REG.sub(lambda m: {"sl": "r10", "sb": "r9", "fp": "r11", "ip": "r12"}[m.group(1)], s)
    mn = s.split()[0]
    if mn == "bl" or (mn.startswith("b") and mn not in ("bx", "bic", "bics")):
        return mn.replace("b.n", "b") + " T"
    if mn == "ldr" and "[" not in s:
        return re.sub(r",.*", ", POOL", s)
    s = re.sub(r"#(0x[0-9a-fA-F]+|\d+)", lambda m: f"#{int(m.group(1), 0)}", s)
    return re.sub(r"\s+", " ", s)


def norm_cap(mn: str, op: str) -> str:
    s = _REG.sub(lambda m: {"sl": "r10", "sb": "r9", "fp": "r11", "ip": "r12"}[m.group(1)], f"{mn} {op}".strip())
    if mn == "bl" or (mn.startswith("b") and mn not in ("bx", "bic", "bics")):
        return mn + " T"
    if mn == "ldr" and "[pc" in op:
        return re.sub(r",.*", ", POOL", s)
    s = re.sub(r"#(0x[0-9a-fA-F]+|\d+)", lambda m: f"#{int(m.group(1), 0)}", s)
    return re.sub(r"\s+", " ", s)


def verify(funcs):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
    rom = (ROOT / "fomt virgen.gba").read_bytes()
    tmd, amd = Cs(CS_ARCH_ARM, CS_MODE_THUMB), Cs(CS_ARCH_ARM, CS_MODE_ARM)
    res = collections.Counter()
    bad = []
    byt = collections.Counter()
    for f in funcs:
        off = f["addr"] - 0x08000000
        if off < 0 or off >= len(rom):
            res["fuera"] += 1
            continue
        md = tmd if f["mode"] == "THUMB" else amd
        got, exp, pos, tail = [], [], off, True
        for s in f["ins"]:
            if s == "@align":
                if (f["addr"] + pos - off) % 4:
                    pos += 2
                continue
            if s.startswith("@pool") or s.startswith("@blob"):
                pos += int(s[5:])
                continue
            ci = next(md.disasm(rom[pos:pos + 4], f["addr"] + pos - off), None)
            if ci is None:
                got.append("??")
                pos += 2
            else:
                got.append(norm_cap(ci.mnemonic, ci.op_str))
                pos += ci.size
            exp.append(norm_stan(s))
        n = len(exp)
        if pos - off > len(rom) - off:
            res["fuera"] += 1
            continue
        if got == exp:
            res["match"] += 1
            byt["match"] += n * (2 if f["mode"] == "THUMB" else 4)
        else:
            k = sum(1 for a, b in zip(got, exp) if a != b) + abs(len(got) - len(exp))
            res["close" if k <= max(1, n // 10) else "distinto"] += 1
            if len(bad) < 5:
                d = next(((a, b) for a, b in zip(got, exp) if a != b), None)
                bad.append((f["name"], hex(f["addr"]), n, d))
    print(f"[+] verificacion ROM vs asm de Stan: {dict(res)}")
    print(f"[+] ejemplos de divergencia: {bad}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", action="store_true")
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    fs = build_index() if a.index or a.verify else []
    if a.verify:
        verify(fs)

