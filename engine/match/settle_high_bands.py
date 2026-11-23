"""FOMT-MATCH-ENGINE :: Bucle de Asentamiento de Alta Paridad (>=80% y >=90%).

Estrategia Denisovich728:
1. Asienta de forma exhaustiva las funciones Approx (>=90%) y High WIP (80-90%) con el permutador
   multi-thread determinista a 8 workers (CPU pura).
2. Si una pasada empuja funciones de 80% hacia >=90% o logra matches 100%, re-itera sobre las nuevas
   candidatas de forma incremental hasta agotar todas las combinaciones posibles.
3. CERO LLM hasta que las 325 funciones de alta paridad esten completamente exprimidas y asentadas.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common

STOP_FLAG = common.TREE_DIR / "control" / "stop.flag"


def log(msg=""):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)


def stop_requested() -> bool:
    return STOP_FLAG.exists()


def get_high_band_counts():
    state = common.load_state()
    manifest = common.load_manifest()
    by = {e["name"]: e for e in manifest}
    ge90, ge80, matched = 0, 0, 0
    for name, st in state.items():
        if name not in by:
            continue
        status = st.get("status", "wip")
        sc = float(st.get("best", 0.0) or 0.0)
        if status == "matched" or sc >= 1.0:
            matched += 1
        elif sc >= 0.90:
            ge90 += 1
        elif sc >= 0.80:
            ge80 += 1
    return matched, ge90, ge80, len(manifest)


def run_band(min_score: float, max_score: float, label: str, workers: int = 8, seconds: int = 50, depth: int = 6, beam: int = 12):
    if stop_requested():
        return
    log(f"[*] EJECUTANDO {label} :: Rango [{int(min_score*100)}% - {int(max_score*100)}%] ({workers} workers concurrentes)...")
    cmd = [
        sys.executable,
        str(ROOT / "tools" / "match" / "fast_permuter_cli.py"),
        "--min-score", str(min_score),
        "--max-score", str(max_score),
        "--workers", str(workers),
        "--seconds", str(seconds),
        "--depth", str(depth),
        "--beam", str(beam),
        "--phase-label", label,
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    try:
        for line in iter(proc.stdout.readline, ""):
            text = line.strip()
            if text:
                log(f"  {text}")
            if stop_requested():
                proc.terminate()
                break
        proc.wait()
    except Exception as ex:
        log(f"[!] Error en ejecucion: {ex}")
    finally:
        common.sync_collection()


def main():
    workers = 8
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        workers = int(sys.argv[1])

    if STOP_FLAG.exists():
        STOP_FLAG.unlink()

    log("=" * 76)
    log(" FOMT-MATCH-ENGINE :: BUCLE DE ASENTAMIENTO DE ALTA PARIDAD (>=80% Y >=90%)")
    log("=" * 76)
    log(f" [*] CPU: Intel Core i7-13620H ({workers} Workers Paralelos)")
    log(" [*] Objetivo: Exprimir al 100% Zero-Diff las funciones maduras")
    log(f" [*] Detencion limpia: Crear '{STOP_FLAG}'")
    log("=" * 76)

    round_num = 1
    while not stop_requested():
        m_start, g90_start, g80_start, total = get_high_band_counts()
        pct = (m_start / total) * 100.0
        log(f"\n>>> RONDA DE ASENTAMIENTO #{round_num} <<<")
        log(f" [*] Estado inicial: {m_start} Matches ({pct:.2f}%) | {g90_start} en >=90% | {g80_start} en 80-89% (Total alta: {g90_start + g80_start})")

        # Paso 1: Asentar la banda Approxs (>=90%) con presupuesto agil para dar paso a la asistencia Qwen-Coder
        run_band(
            min_score=0.90, max_score=0.9999,
            label=f"ASENTAMIENTO // APPROX >=90% [R#{round_num}]",
            workers=workers, seconds=20, depth=4, beam=8
        )
        if stop_requested():
            break

        # Paso 2: Asentar la banda High WIP (80-89%) para empujar funciones a >=90% o 100%
        run_band(
            min_score=0.80, max_score=0.8999,
            label=f"ASENTAMIENTO // HIGH WIP 80-89% [R#{round_num}]",
            workers=workers, seconds=40, depth=5, beam=10
        )
        if stop_requested():
            break

        m_end, g90_end, g80_end, _ = get_high_band_counts()
        matches_ganados = m_end - m_start
        log(f"\n[*] FIN RONDA #{round_num}: +{matches_ganados} matches nuevos (Total: {m_end}/{total} - {(m_end/total)*100:.2f}%)")

        # Si no hubo matches nuevos ni candidatas nuevas que subieron, el lote esta asentado
        if matches_ganados == 0 and g90_end <= g90_start:
            log("[+] Asentamiento completado: Las bandas de alta paridad alcanzaron su maximo punto de convergencia.")
            break

        round_num += 1
        time.sleep(5)

    log("\n[+] Bucle de asentamiento finalizado con exito.")


if __name__ == "__main__":
    main()

