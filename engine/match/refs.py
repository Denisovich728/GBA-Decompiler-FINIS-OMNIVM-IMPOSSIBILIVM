"""Contexto enriquecido para cada funcion: anotacion del literal pool (registros GBA, regiones de
memoria, funciones, tablas con su entropia), llamadas BL con nombres, y recuperacion de fragmentos
de codigo/simbolos de proyectos de referencia (FoMT Studio, decomp HM de PS1, etc.).

Directorios de referencia: lista en refs_dirs.txt (uno por linea) y/o variable FOMT_REFS
(separados por ';'). Se indexan .c .h .cs .cpp .txt .md .json .py .s
"""
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_OP_MEM
from capstone.arm import ARM_REG_PC

from common import *  # noqa

EXTS = {".c", ".h", ".cs", ".cpp", ".txt", ".md", ".json", ".py", ".s", ".asm"}
MAX_FILE = 3_000_000
HEX_RE = re.compile(r"0x[0-9A-Fa-f]{6,8}\b")

GBA_REGS = {
    0x04000000: "REG_DISPCNT", 0x04000004: "REG_DISPSTAT", 0x04000006: "REG_VCOUNT",
    0x04000008: "REG_BG0CNT", 0x0400000A: "REG_BG1CNT", 0x0400000C: "REG_BG2CNT", 0x0400000E: "REG_BG3CNT",
    0x04000010: "REG_BG0HOFS", 0x04000012: "REG_BG0VOFS", 0x04000014: "REG_BG1HOFS", 0x04000016: "REG_BG1VOFS",
    0x04000018: "REG_BG2HOFS", 0x0400001A: "REG_BG2VOFS", 0x0400001C: "REG_BG3HOFS", 0x0400001E: "REG_BG3VOFS",
    0x04000040: "REG_WIN0H", 0x04000044: "REG_WIN0V", 0x04000048: "REG_WININ", 0x0400004A: "REG_WINOUT",
    0x04000050: "REG_BLDCNT", 0x04000052: "REG_BLDALPHA", 0x04000054: "REG_BLDY",
    0x040000B0: "REG_DMA0SAD", 0x040000BC: "REG_DMA1SAD", 0x040000C8: "REG_DMA2SAD", 0x040000D4: "REG_DMA3SAD",
    0x040000D8: "REG_DMA3DAD", 0x040000DC: "REG_DMA3CNT",
    0x04000100: "REG_TM0CNT_L", 0x04000102: "REG_TM0CNT_H", 0x04000104: "REG_TM1CNT_L", 0x04000128: "REG_SIOCNT",
    0x04000130: "REG_KEYINPUT", 0x04000132: "REG_KEYCNT", 0x04000200: "REG_IE", 0x04000202: "REG_IF",
    0x04000204: "REG_WAITCNT", 0x04000208: "REG_IME", 0x04000300: "REG_POSTFLG",
    0x04000060: "REG_SOUND1CNT_L", 0x04000080: "REG_SOUNDCNT_L", 0x04000082: "REG_SOUNDCNT_H",
    0x04000084: "REG_SOUNDCNT_X", 0x040000A0: "REG_FIFO_A", 0x040000A4: "REG_FIFO_B",
}


def region(v):
    r = v >> 24
    return {0x00: "BIOS", 0x02: "EWRAM", 0x03: "IWRAM", 0x04: "IO", 0x05: "PALETTE", 0x06: "VRAM",
            0x07: "OAM", 0x08: "ROM", 0x09: "ROM", 0x0A: "ROM", 0x0B: "ROM", 0x0C: "ROM", 0x0D: "ROM",
            0x0E: "SRAM"}.get(r)


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(k / n * math.log2(k / n) for k in c.values())


def pool_and_calls(rom, e):
    """Devuelve (literales[(addr_pool, valor)], destinos_bl[int])."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if e["mode"] == "THUMB" else CS_MODE_ARM)
    md.detail = True
    code = rom_bytes(rom, e["addr"], e["size"])
    lits, calls = [], []
    for i in md.disasm(code, e["addr"]):
        if i.mnemonic == "bl" and i.op_str.startswith("#"):
            try:
                calls.append(int(i.op_str[1:], 16))
            except ValueError:
                pass
        if i.mnemonic.startswith("ldr") and i.operands:
            for op in i.operands:
                if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                    base = ((i.address + 4) & ~3) if e["mode"] == "THUMB" else i.address + 8
                    a = base + op.mem.disp
                    off = a - ROM_BASE
                    if 0 <= off <= len(rom) - 4:
                        lits.append((a, int.from_bytes(rom[off:off + 4], "little")))
    return lits, calls


class Refs:
    def __init__(self):
        self.chunks, self.post, self.syms = [], defaultdict(list), {}
        self.loaded = False

    def dirs(self):
        out = [d for d in os.environ.get("FOMT_REFS", "").split(";") if d.strip()]
        f = ROOT / "refs_dirs.txt"
        if f.exists():
            out += [l.strip().strip('"') for l in f.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
        return [Path(d) for d in out if Path(d).exists()]

    def load(self):
        if self.loaded:
            return self
        self.loaded = True
        cache = TREE_DIR / "refs_index.json"
        ds = self.dirs()
        sig = [str(d) for d in ds]
        if cache.exists():
            try:
                j = json.loads(cache.read_text(encoding="utf-8"))
                if j.get("sig") == sig:
                    self.chunks, self.syms = j["chunks"], {int(k): v for k, v in j["syms"].items()}
                    self._post()
                    print(f"[refs] indice cargado: {len(self.chunks)} fragmentos, {len(self.syms)} simbolos")
                    return self
            except Exception:
                pass
        n = 0
        for d in ds:
            for p in d.rglob("*"):
                if p.is_file() and p.suffix.lower() in EXTS and p.stat().st_size < MAX_FILE and ".git" not in p.parts:
                    try:
                        t = p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        continue
                    n += 1
                    self._ingest(p, t)
        print(f"[refs] {n} archivos indexados -> {len(self.chunks)} fragmentos, {len(self.syms)} simbolos")
        if ds:
            cache.write_text(json.dumps({"sig": sig, "chunks": self.chunks,
                                         "syms": {str(k): v for k, v in self.syms.items()}}), encoding="utf-8")
        self._post()
        return self

    def _ingest(self, p, t):
        # simbolos direccion<->nombre
        for m in re.finditer(r"\b([A-Za-z_]\w{3,})\s*[=:,]\s*\"?(0x[0-9A-Fa-f]{6,8})\b", t):
            self._sym(m.group(2), m.group(1))
        for m in re.finditer(r"(0x[0-9A-Fa-f]{6,8})\b\s*[=:,]?\s*\"?([A-Za-z_]\w{3,})\"?", t):
            self._sym(m.group(1), m.group(2))
        # fragmentos por funcion (C-like) o ventanas
        parts = re.split(r"\n(?=[A-Za-z_][\w \t\*]*\w\s*\([^;{]*\)\s*\{)", t) if p.suffix.lower() in (
            ".c", ".cs", ".cpp", ".h") else [t[i:i + 2500] for i in range(0, len(t), 2500)]
        for part in parts:
            consts = sorted({int(h, 16) for h in HEX_RE.findall(part)})
            if consts:
                self.chunks.append({"f": str(p), "t": part[:2500], "c": consts[:200]})

    def _sym(self, addr, name):
        a = int(addr, 16)
        if (0x02000000 <= a < 0x0A000000) and name not in ("0x", "None", "null"):
            self.syms.setdefault(a, name)

    def _post(self):
        self.post = defaultdict(list)
        for idx, c in enumerate(self.chunks):
            for v in c["c"]:
                if len(self.post[v]) < 60:
                    self.post[v].append(idx)

    def retrieve(self, consts, k=2):
        score = Counter()
        for v in consts:
            ids = self.post.get(v, [])
            for i in ids:
                score[i] += 1.0 / len(ids)
        return [(self.chunks[i], s) for i, s in score.most_common(k) if s >= 0.5]


_REFS = Refs()


def sym_name(addr, manifest_idx, refs):
    addr &= ~1
    if addr in refs.syms:
        return refs.syms[addr]
    if addr in manifest_idx:
        return manifest_idx[addr]["name"]
    return None


def describe_function(rom, e, manifest):
    """Texto de contexto para el prompt de la IA."""
    refs = _REFS.load()
    midx = {m["addr"]: m for m in manifest}
    lits, calls = pool_and_calls(rom, e)
    lines = []
    seen = set()
    for a, v in lits:
        if v in seen:
            continue
        seen.add(v)
        note = GBA_REGS.get(v) or None
        r = region(v)
        if note is None and r in ("ROM",):
            nm = sym_name(v, midx, refs)
            off = (v & 0x01FFFFFF)
            if nm:
                note = f"{nm} (ROM)"
            elif off < len(rom):
                ent = entropy(rom[off:off + 64])
                note = (f"dato/tabla en ROM (entropia {ent:.1f}: "
                        f"{'grafico/comprimido' if ent > 6.3 else 'tabla/codigo'})")
        elif note is None and r:
            nm = refs.syms.get(v)
            note = (nm + f" ({r})") if nm else r
        lines.append(f"  [pool 0x{a:08X}] 0x{v:08X}  {note or ''}")
    cl = []
    for t in sorted(set(calls)):
        cl.append(f"  bl 0x{t:08X} -> {sym_name(t, midx, refs) or 'func_%08X' % t}")
    txt = ""
    if lines:
        txt += "### Literales del pool (valores reales, usalos como constantes en el C)\n" + "\n".join(lines[:30]) + "\n\n"
    if cl:
        txt += "### Llamadas BL (nombres a usar)\n" + "\n".join(cl[:20]) + "\n\n"
    consts = [v for _, v in lits if v >= 0x1000]
    hits = refs.retrieve(consts, 2) if refs.chunks else []
    if hits:
        txt += "### Fragmentos de proyectos de referencia con constantes en comun (pueden ser de otra plataforma)\n"
        for c, s in hits:
            txt += f"--- {Path(c['f']).name} (afinidad {s:.1f}) ---\n{c['t'][:1200]}\n"
        txt += "\n"
    return txt
