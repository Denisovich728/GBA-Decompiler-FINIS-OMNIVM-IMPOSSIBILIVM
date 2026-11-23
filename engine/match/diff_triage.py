"""Triage de funciones pendientes por clase de ASM-Diff (Fase 1).

Clases:
  - A: Solo difieren registros (mismo numero de instrucciones, mismos mnemónicos e inmediatos, solo r0..r7 difieren).
  - B: Mismos opcodes en distinto orden o ramas invertidas (multiset de opcodes identico).
  - C: Distinto tamaño o estructura incompatible.
  - D: pool_diff (instrucciones ensamblador 100% identicas, bytes distintos en literal pool o constantes).
"""
import collections
import concurrent.futures
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import lift
import rosetta_decompiler as RD
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

_THUMB_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
_ARM_MD = Cs(CS_ARCH_ARM, CS_MODE_ARM)

TRIAGE_FILE = ROOT / "logs" / "triage_classes.json"


def classify_diff(target_bytes: bytes, got_bytes: bytes, e: dict) -> tuple[str, str]:
    if not got_bytes:
        return "NO_BIN", "sin binario"
    if target_bytes == got_bytes:
        return "MATCH", "100% exacto"

    md = _THUMB_MD if e.get("mode") == "THUMB" else _ARM_MD
    t_ins = list(md.disasm(target_bytes, e["addr"]))
    g_ins = list(md.disasm(got_bytes, e["addr"]))

    if len(t_ins) != len(g_ins):
        return "C", f"distinto tamano (T={len(t_ins)} ins vs G={len(g_ins)} ins)"

    # Verificar si todas las instrucciones son identicas en texto
    t_strs = [f"{i.mnemonic} {i.op_str}".strip() for i in t_ins]
    g_strs = [f"{i.mnemonic} {i.op_str}".strip() for i in g_ins]

    if t_strs == g_strs:
        return "D", "pool_diff (instrucciones identicas, bytes de pool/constantes distintos)"

    # Normalizar registros r0..r7, sl, fp, ip, sp, lr, pc -> rX
    def norm_regs(s: str) -> str:
        return re.sub(r"\b(r\d+|sl|fp|ip|sp|lr|pc)\b", "rX", s)

    t_nreg = [norm_regs(s) for s in t_strs]
    g_nreg = [norm_regs(s) for s in g_strs]

    if t_nreg == g_nreg:
        return "A", "solo difieren registros (mismo flujo y constantes)"

    # Comprobar si los opcodes son los mismos en multiset (distinto orden o rama)
    t_ops = collections.Counter(i.mnemonic for i in t_ins)
    g_ops = collections.Counter(i.mnemonic for i in g_ins)

    if t_ops == g_ops:
        return "B", "mismos opcodes en distinto orden o ramas invertidas"

    # Si ademas comparten al menos el 80% de los opcodes
    overlap = sum((t_ops & g_ops).values()) / max(len(t_ins), 1)
    if overlap >= 0.85:
        return "B-partial", f"opcodes similares ({overlap*100:.1f}% coincidencia de operaciones)"

    return "C", f"estructura divergente ({overlap*100:.1f}% coincidencia de operaciones)"


def eval_one(e, manifest, state, rom):
    name = e["name"]
    st = state.get(name, {})
    preset = st.get("preset") or "agbcc_O2"
    target = common.rom_bytes(rom, e["addr"], e["size"])

    c_code = RD.get_best_existing_code(e)
    if not c_code:
        return name, "NO_SEED", "sin codigo c89 disponible", 0.0, e["size"]

    c_clean = lift.extract_c(c_code, rom=rom, e=e)
    if not c_clean:
        return name, "NO_SEED", "no se pudo extraer c89 limpio", 0.0, e["size"]

    ok, got, err = lift.try_candidate(e, c_clean, manifest, preset)
    if not ok or not got:
        return name, "COMPILE_ERROR", (err or "error desconocido").splitlines()[0][:60], 0.0, e["size"]

    ex, sc = lift.score(e, target, got)
    cls, hint = classify_diff(target, got, e)
    return name, cls, hint, sc, e["size"]


def main():
    t0 = time.time()
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    pending = [e for e in manifest if state.get(e["name"], {}).get("status") != "matched"]
    print(f"[*] Iniciando triage de {len(pending)} funciones pendientes con 12 hilos...")

    results = {}
    classes = collections.Counter()
    class_sizes = collections.defaultdict(list)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(eval_one, e, manifest, state, rom) for e in pending]
        done_cnt = 0
        for fut in concurrent.futures.as_completed(futs):
            done_cnt += 1
            if done_cnt % 250 == 0 or done_cnt == len(pending):
                print(f"  [+] Progreso: {done_cnt}/{len(pending)} funciones procesadas...")
            name, cls, hint, sc, sz = fut.result()
            results[name] = {"class": cls, "hint": hint, "score": round(sc, 4), "size": sz}
            classes[cls] += 1
            class_sizes[cls].append(sz)

    print("\n" + "=" * 70)
    print("RESUMEN DE TRIAGE POR CLASE DE DIFERENCIA ASM (Fase 1):")
    print("=" * 70)
    for cls, cnt in sorted(classes.items(), key=lambda x: -x[1]):
        pct = cnt * 100.0 / len(pending)
        avg_sz = sum(class_sizes[cls]) / max(len(class_sizes[cls]), 1)
        print(f"  Clase {cls:14s}: {cnt:5d} funciones ({pct:5.1f}%) | Tam promedio: {avg_sz:5.0f} bytes")
    print("=" * 70)
    print(f"Tiempo total: {time.time() - t0:.1f} s")

    TRIAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRIAGE_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Clasificacion guardada en: {TRIAGE_FILE}")


if __name__ == "__main__":
    main()

