"""Fase 1: divide fomt_virgen_all.c en un arbol de carpetas legible (un .c por funcion)
y genera manifest.json con direccion, modo (ARM/THUMB) y tamano de cada funcion.

Uso: python tools/match/split_tree.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa

BANK = 0x10000  # 64 KB por carpeta


def main():
    src = (DECOMP_DIR / "fomt_virgen_all.c").read_text(encoding="utf-8", errors="replace")
    syms = json.loads((DECOMP_DIR / "fomt_virgen_symbols.json").read_text(encoding="utf-8"))["functions"]
    rom_size = ROM_PATH.stat().st_size

    # direcciones de funciones conocidas ordenadas (para calcular tamano)
    addrs = sorted(int(a, 16) for a in syms)
    nxt = {a: (addrs[i + 1] if i + 1 < len(addrs) else ROM_BASE + rom_size) for i, a in enumerate(addrs)}

    heads = list(HEADER_RE.finditer(src))
    manifest = []
    for i, m in enumerate(heads):
        name, addr_s, mode, how = m.groups()
        addr = int(addr_s, 16)
        body = src[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(src)].strip("\r\n") + "\n"
        size = nxt.get(addr, addr) - addr
        bank = addr & ~(BANK - 1)
        rel = f"bank_{bank:08X}/{name}.c"
        out = TREE_DIR / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        hdr = (f"/* {name} @ 0x{addr:08X}  mode={mode}  size=0x{size:X}  origin={how} */\n"
               f"/* Pseudocodigo Ghidra crudo; reemplazar por C compilable (ver tools/match/lift.py). */\n")
        out.write_text(hdr + body, encoding="utf-8")
        manifest.append({"name": name, "addr": addr, "mode": mode, "size": size, "file": rel, "origin": how})

    manifest.sort(key=lambda e: e["addr"])
    MANIFEST.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"[+] {len(manifest)} funciones -> {TREE_DIR}")
    print(f"[+] carpetas (bancos de 64KB): {len({m['file'].split('/')[0] for m in manifest})}")


if __name__ == "__main__":
    main()
