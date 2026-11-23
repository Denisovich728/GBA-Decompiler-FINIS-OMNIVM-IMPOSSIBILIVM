"""Enfoque B: barrido directo de la ROM (independiente del manifest de Ghidra).

1. Escanea 'fomt virgen.gba' buscando prologos reales (Thumb: push {..,lr}; ARM: stmfd sp!,{..,lr}),
   valida que decodifiquen hasta un retorno y define los limites de cada funcion SOLO con los bytes.
2. Genera el arbol src_sweep/ (manifest + un .c por funcion). El pseudocodigo de Ghidra, si existe para
   esa misma direccion, se adjunta unicamente como comentario de REFERENCIA.
3. Lanza el bucle de IA (lift.py) sobre src_sweep en orden de direccion: qwen escribe C, se compila,
   se enlaza en la direccion exacta y se hace diff byte a byte contra la ROM, con reintentos.
   Todo se guarda en src_sweep/state.json (reanudable).

Uso:
  python tools/match/sweep.py                 # escanea (si hace falta) y procesa lotes
  python tools/match/sweep.py --scan-only
  python tools/match/sweep.py --limit 100 --max-size 512 --tries 4
  python tools/match/sweep.py --rescan
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

os.environ["FOMT_TREE"] = "src_sweep"
sys.path.insert(0, str(Path(__file__).parent))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB  # noqa
from common import *  # noqa

MAX_FUNC = 0x1000
ENT_MAX = 6.9
ADS_CONFIG = {
    "THUMB": {
        "cc": "agbcc.exe / tcc.exe",
        "cflags": ["-O2", "-mthumb-interwork", "-fhex-asm"],
        "dialect_hint": "GBA SDK C89 (agbcc.exe -O2 -mthumb-interwork + ADS 1.2 tcc.exe). C89 PURO: declara TODAS las variables al inicio del bloque. PROHIBIDO usar asm, __asm, push, pop, bl o mnemonicos ARM."
    },
    "ARM": {
        "cc": "armcc.exe",
        "cflags": ["-O2", "-Otime", "-cpu", "ARM7TDMI", "-apcs", "/interwork", "-c"],
        "dialect_hint": "ADS 1.2 ARM (armcc.exe). C89 PURO: declara TODAS las variables al inicio del bloque. PROHIBIDO usar asm, __asm o mnemonicos ARM."
    }
}

def entropy(b):
    import math
    from collections import Counter
    if not b:
        return 0.0
    n = len(b)
    return -sum(k / n * math.log2(k / n) for k in Counter(b).values())


def looks_like_code(rom, off, length=128):
    w = rom[off:off + length]
    if len(w) < 16:
        return False
    if entropy(w) > ENT_MAX:
        return False
    fill = sum(1 for x in w if x in (0x00, 0xFF)) / len(w)
    return fill < 0.6


def valid_run(md, rom, off, thumb, limit=MAX_FUNC):
    """Decodifica desde off; True si llega a un retorno real (incluyendo pop {r0..r3}; bx r0..r3 de agbcc)."""
    code = rom[off:off + limit]
    n = 0
    pos = 0
    step = 2 if thumb else 4
    while pos < len(code) and n < 1024:
        got = False
        for i in md.disasm(code[pos:pos + 4], ROM_BASE + off + pos, 1):
            got = True
            m, o = i.mnemonic, i.op_str
            pos += i.size
            n += 1
            if (m == "bx" and o in ("lr", "r0", "r1", "r2", "r3")) or (m in ("pop", "ldm", "ldmia", "ldmfd") and "pc" in o):
                return n >= 2
            if m == "bx" and thumb is False:
                return True
            break
        if not got:
            return False
        if pos % step:
            return False
    return False


def trim_thumb_func_size(md, rom, addr, max_size):
    """Determina el tamano exacto de una funcion Thumb (codigo + literal pool alineado a 4B) sin tragarse funciones hoja vecinas."""
    off = addr - ROM_BASE
    code = rom[off:off + max_size]
    ins_list = list(md.disasm(code, addr))
    if not ins_list:
        return max_size
    max_branch_target = addr
    max_pool_end = addr
    end_addr = addr + max_size
    for i in ins_list:
        m, op = i.mnemonic, i.op_str
        if m.startswith("b") and m not in ("bl", "bx") and op.startswith("#0x"):
            try:
                tgt = int(op[1:], 16)
                if addr < tgt < addr + max_size:
                    max_branch_target = max(max_branch_target, tgt)
            except ValueError:
                pass
        if m == "ldr" and "[pc" in op:
            base = (i.address + 4) & ~3
            m_imm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", op)
            disp = int(m_imm.group(1), 0) if m_imm else 0
            pool_word_end = base + disp + 4
            if pool_word_end <= addr + max_size:
                max_pool_end = max(max_pool_end, pool_word_end)
        is_ret = (m == "bx" and op in ("r0", "r1", "r2", "r3", "lr")) or (m == "pop" and "pc" in op)
        if is_ret and (i.address + i.size) > max_branch_target:
            raw_end = max(i.address + i.size, max_pool_end)
            # Alinear a 4 bytes si el par de bytes siguiente es padding (0x0000 o 0x46C0)
            if raw_end % 4 == 2 and (raw_end - ROM_BASE + 2) <= len(rom):
                pad = rom[raw_end - ROM_BASE:raw_end - ROM_BASE + 2]
                if pad in (b"\x00\x00", b"\xc0\x46", b"\xff\xff"):
                    raw_end += 2
            end_addr = raw_end
            break
    return max(4, min(max_size, end_addr - addr))


def scan(rom):
    thumb_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    arm_md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    # Limitar estrictamente al horizonte de codigo ejecutable (.text: 0x080000C0 .. 0x080E4000) para excluir 100% multimedia/rodata
    horizon_limit = min(len(rom), CODE_HORIZON_END - ROM_BASE)
    halfs = struct.unpack(f"<{horizon_limit // 2}H", rom[: (horizon_limit // 2) * 2])
    found = {}
    for idx, h in enumerate(halfs):
        off = idx * 2
        if off < (CODE_HORIZON_START - ROM_BASE):
            continue
        # Thumb: push {rlist, lr}  = 0xB5xx
        if (h & 0xFF00) == 0xB500 and looks_like_code(rom, off) and valid_run(thumb_md, rom, off, True):
            found[off] = "THUMB"
            continue
        # ARM: stmfd sp!, {..., lr} = 0xE92D4xxx (palabra alineada)
        if off % 4 == 0 and h & 0x4000 and idx + 1 < len(halfs) and halfs[idx + 1] == 0xE92D:
            if looks_like_code(rom, off) and valid_run(arm_md, rom, off, False):
                found[off] = "ARM"
    # Fusionar puntos de entrada verificados por FIO DECOMP dentro del horizonte .text
    src_tree_manifest = ROOT / "src_tree" / "manifest.json"
    if src_tree_manifest.exists():
        for m in json.loads(src_tree_manifest.read_text(encoding="utf-8")):
            addr = m["addr"]
            if 0x0800018C <= addr < CODE_HORIZON_END:
                off = addr - ROM_BASE
                if off not in found:
                    found[off] = m.get("mode", "THUMB")
    return found


def build_tree(rom):
    thumb_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    found = scan(rom)
    starts = sorted(found)
    ghidra = {m["addr"]: m for m in (json.loads(Path(ROOT / "src_tree" / "manifest.json").read_text())
                                     if (ROOT / "src_tree" / "manifest.json").exists() else [])}
    manifest = []
    for i, off in enumerate(starts):
        next_off = starts[i + 1] if i + 1 < len(starts) else min(len(rom), CODE_HORIZON_END - ROM_BASE)
        max_sz = min(next_off - off, MAX_FUNC)
        addr = ROM_BASE + off
        mode = found[off]
        size = trim_thumb_func_size(thumb_md, rom, addr, max_sz) if mode == "THUMB" else max_sz
        name = f"func_{addr:08X}"
        bank = addr & ~0xFFFF
        rel = f"bank_{bank:08X}/{name}.c"
        ref = "(sin referencia de Ghidra en esta direccion)\n"
        g = ghidra.get(addr)
        if g:
            gp = ROOT / "src_tree" / g["file"]
            if gp.exists():
                ref = gp.read_text(encoding="utf-8", errors="replace")
        mode = found[off]
        cfg = ADS_CONFIG[mode]
        out = TREE_DIR / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            f"/* {name} @ 0x{addr:08X} mode={mode} size=0x{size:X} (barrido ROM) */\n"
            f"/* COMPILADOR: {cfg['cc']} {' '.join(cfg['cflags'])} */\n"
            f"/* REGLAS IA: {cfg['dialect_hint']} */\n"
            f"/* REFERENCIA Ghidra (no confiable): */\n{ref}",
            encoding="utf-8"
        )
        manifest.append({
            "name": name,
            "addr": addr,
            "mode": mode,
            "cc": cfg["cc"],
            "cflags": cfg["cflags"],
            "dialect_hint": cfg["dialect_hint"],
            "size": size,
            "file": rel,
            "origin": "ROM_SWEEP"
        })
    MANIFEST.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    covered = sum(m["size"] for m in manifest)
    print(f"[+] Barrido: {len(manifest)} funciones detectadas, {covered / 1024:.0f} KB de codigo "
          f"({100 * covered / len(rom):.1f}% de la ROM); con referencia Ghidra: "
          f"{sum(1 for m in manifest if m['addr'] in ghidra)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--rescan", action="store_true")
    ap.add_argument("--phase", type=int, choices=[1, 2, 3], default=1)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--tries", type=int, default=30)
    ap.add_argument("--permute", type=int, default=800)
    ap.add_argument("--permute-quick", type=int, default=40)
    ap.add_argument("--approx", type=float, default=0.90)
    ap.add_argument("--min-size", type=int, default=8)
    ap.add_argument("--max-size", type=int, default=256)
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--max-score", type=float, default=1.0)
    ap.add_argument("--order", default="score")
    ap.add_argument("--retry-wip", action="store_true")
    ap.add_argument("--model", default=os.environ.get("FOMT_MODEL", "deepseek-coder-v2:latest"))
    a = ap.parse_args()

    TREE_DIR.mkdir(exist_ok=True)
    if a.rescan or not MANIFEST.exists():
        print("[*] Barriendo ROM (puede tardar un par de minutos)...")
        build_tree(load_rom())
    if a.scan_only:
        return
    cmd = [sys.executable, str(Path(__file__).parent / "lift.py"), "--phase", str(a.phase), "--order", a.order,
           "--limit", str(a.limit), "--tries", str(a.tries), "--min-size", str(a.min_size),
           "--max-size", str(a.max_size), "--model", a.model, "--permute", str(a.permute),
           "--permute-quick", str(a.permute_quick), "--approx", str(a.approx),
           "--min-score", str(a.min_score), "--max-score", str(a.max_score)]
    if a.retry_wip:
        cmd.append("--retry-wip")
        
    try:
        subprocess.run(cmd, env=os.environ.copy())
        subprocess.run([sys.executable, str(Path(__file__).parent / "build_rom.py")], env=os.environ.copy())
    except KeyboardInterrupt:
        print("\n[!] sweep.py: Secuencia abortada manualmente.")

if __name__ == "__main__":
    main()
