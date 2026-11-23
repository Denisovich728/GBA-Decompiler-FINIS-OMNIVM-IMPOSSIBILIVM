"""Normalizador de idiomas de ancho estrecho sobre seeds (Fase 1, determinista, sin IA).

Los seeds derivados de Ghidra expresan variables u8/u16 como 'u32 x; x = (x + 1) & 0xff;'
o 'param = param & 0xff;'. El codigo original usa tipos estrechos ('u8 x; x++', 'u8 param'),
que agbcc compila como lsls/lsrs #0x18 en el punto exacto. Este modulo reescribe esos patrones
y evalua el resultado contra la ROM.

Transformaciones (todas por variable, probadas individualmente y en conjunto):
  NARROW   'v = <expr> & 0xFF;'  ->  v pasa a u8  y se quita la mascara   (0xFFFF -> u16)
  PARAM    'p = p & 0xFF;' al inicio -> el parametro p pasa a u8/u16 y se elimina la linea
  LOOPCMP  tras narrowing, 'v + 1 & 0xFF' pierde la mascara (queda 'v + 1')

Uso:
  python tools/match/idiom_narrow.py --measure           # cuantos seeds se benefician (no escribe)
  python tools/match/idiom_narrow.py --measure --sample 200
  python tools/match/idiom_narrow.py --write             # guarda ganadores en <tree>/permute/idiom/
"""
import argparse
import itertools
import json
import os
import re
import sys
import time
import concurrent.futures
from pathlib import Path

if "FOMT_TREE" not in os.environ:
    os.environ["FOMT_TREE"] = "src_sweep"

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common  # noqa: E402
import lift  # noqa: E402
import rosetta_decompiler as RD  # noqa: E402

TYPES = r"(?:u32|s32|int|u16|s16|u8|s8|uint|ushort|byte)"
MASK_ASSIGN = re.compile(
    r"^(?P<ind>\s*)(?P<v>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+?)\s*&\s*(?P<m>0[xX][fF]{2}(?:[fF]{2})?)\s*;\s*$"
)
PAREN_MASK_ASSIGN = re.compile(
    r"^(?P<ind>\s*)(?P<v>[A-Za-z_]\w*)\s*=\s*\((?P<expr>.+)\)\s*&\s*(?P<m>0[xX][fF]{2}(?:[fF]{2})?)\s*;\s*$"
)


def width(m: str) -> str:
    return "u8" if len(m) == 4 else "u16"


def retype(code: str, var: str, new_t: str):
    """Cambia el tipo de la primera declaracion/parametro de 'var'. None si no lo encuentra."""
    pat = re.compile(rf"\b({TYPES})(\s+)({re.escape(var)})\b(?!\s*\[)")
    m = pat.search(code)
    if not m or m.group(1) == new_t:
        return None
    return code[:m.start(1)] + new_t + code[m.end(1):]


def candidates(code: str):
    """Genera (tag, codigo) para cada variable estrechable."""
    lines = code.splitlines()
    found = {}  # var -> (width, [line idx])
    for i, ln in enumerate(lines):
        m = PAREN_MASK_ASSIGN.match(ln) or MASK_ASSIGN.match(ln)
        if m:
            w = width(m.group("m"))
            d = found.setdefault(m.group("v"), [w, []])
            if d[0] == w:
                d[1].append(i)
    out = []
    for var, (w, idxs) in found.items():
        c = retype(code, var, w)
        if c is None:
            continue
        ls = c.splitlines()
        for i in idxs:
            m = PAREN_MASK_ASSIGN.match(ls[i]) or MASK_ASSIGN.match(ls[i])
            if not m:
                continue
            expr = m.group("expr").strip()
            if re.fullmatch(rf"{re.escape(var)}", expr):
                ls[i] = None  # 'p = p & 0xff;' -> eliminar
            else:
                ls[i] = f"{m.group('ind')}{var} = {expr};"
        ls = [l for l in ls if l is not None]
        out.append((f"narrow:{var}->{w}", "\n".join(ls) + "\n"))
    if len(out) > 1:
        c = code
        for var, (w, idxs) in found.items():
            c2 = retype(c, var, w)
            if c2 is None:
                continue
            c = c2
        ls = c.splitlines()
        for var, (w, idxs) in found.items():
            for i in idxs:
                m = PAREN_MASK_ASSIGN.match(ls[i]) or MASK_ASSIGN.match(ls[i]) if ls[i] else None
                if not m:
                    continue
                expr = m.group("expr").strip()
                ls[i] = None if expr == var else f"{m.group('ind')}{var} = {expr};"
        ls = [l for l in ls if l is not None]
        out.append(("narrow:ALL", "\n".join(ls) + "\n"))
    return out


def eval_one(e, manifest, state, rom):
    name = e["name"]
    st = state.get(name, {})
    presets = [st.get("preset") or "agbcc_O2"]
    for p in ("agbcc_O2", "agbcc_O1", "old_agbcc_O2"):
        if p not in presets:
            presets.append(p)
    target = common.rom_bytes(rom, e["addr"], e["size"])
    try:
        raw = RD.get_best_existing_code(e)
        if not raw:
            return name, None
        seed = lift.extract_c(raw, rom=rom, e=e)
        if not seed:
            return name, None
        ok, got, _ = lift.try_candidate(e, seed, manifest, presets[0])
        base = lift.score(e, target, got)[1] if ok and got else 0.0
        best = (base, None, None, False, None)
        for tag, code in candidates(seed):
            for p in presets:
                ok, g, _ = lift.try_candidate(e, code, manifest, p)
                if not ok or not g:
                    continue
                ex, sc = lift.score(e, target, g)
                if sc > best[0] or (ex and not best[3]):
                    best = (sc, tag, code, ex, p)
                if ex:
                    break
            if best[3]:
                break
        return name, {"base": base, "best": best[0], "tag": best[1], "code": best[2],
                      "exact": best[3], "preset": best[4], "size": e["size"]}
    except Exception as ex:  # noqa: BLE001
        return name, {"error": f"{type(ex).__name__}: {ex}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--measure", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    if not (a.measure or a.write):
        ap.error("usa --measure o --write")

    t0 = time.time()
    rom, manifest, state = common.load_rom(), common.load_manifest(), common.load_state()
    pend = [e for e in manifest if state.get(e["name"], {}).get("status") != "matched"]
    if a.sample:
        import random
        random.Random(7).shuffle(pend)
        pend = pend[:a.sample]
    res = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(eval_one, e, manifest, state, rom) for e in pend]
        for f in concurrent.futures.as_completed(futs):
            n, r = f.result()
            if r:
                res[n] = r

    tried = [r for r in res.values() if r.get("tag")]
    exact = {n: r for n, r in res.items() if r.get("exact")}
    improved = {n: r for n, r in res.items() if r.get("tag") and not r.get("exact") and r["best"] - r["base"] >= 0.02}
    print(f"[*] seeds evaluados: {len(res)} | con candidato narrow: {len(tried)}")
    print(f"[+] EXACTOS (diff 0): {len(exact)} funciones, {sum(r['size'] for r in exact.values())} bytes")
    print(f"[+] mejorados (>=+0.02): {len(improved)} funciones, {sum(r['size'] for r in improved.values())} bytes")
    for n, r in list(exact.items())[:8]:
        print(f"    exacto {n} {r['size']}B {r['tag']} ({r['preset']})")
    print(f"Tiempo: {time.time() - t0:.1f} s")

    if a.write:
        out = common.TREE_DIR / "permute" / "idiom"
        out.mkdir(parents=True, exist_ok=True)
        for n, r in {**exact, **improved}.items():
            (out / f"{n}.c").write_text(r["code"], encoding="utf-8")
        (out / "results.json").write_text(json.dumps(
            {n: {k: v for k, v in r.items() if k != "code"} for n, r in {**exact, **improved}.items()}, indent=2),
            encoding="utf-8")
        print(f"[+] guardado en {out}")


if __name__ == "__main__":
    main()

