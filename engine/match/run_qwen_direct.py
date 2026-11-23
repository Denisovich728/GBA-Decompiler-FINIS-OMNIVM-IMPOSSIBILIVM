"""FOMT-MATCH-ENGINE :: Qwen 2.5 Coder 7B Directo a Bandas Altas (Zero-Diff Matcher).

Ejecutor desacoplado e independiente de la app principal:
- Pasa DIRECTAMENTE a Qwen 2.5 Coder 7B sobre las funciones mas cercanas a 100% (>=80% y >=90%).
- Cero barridos matematicos previos, cero colas de CPU masivas: ataca inmediatamente las Approxs.
- Secuencial y quirurgico: 1 funcion a la vez con feedback de compilador agbcc -O2 y micro-permutador.
- Transmite telemetria en tiempo real a la Techno Suite (status.json + engine.log).
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
os.environ.setdefault("FOMT_MODEL", "qwen2.5-coder:7b")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import lift

CTL_DIR = common.TREE_DIR / "control"
STATUS_FILE = CTL_DIR / "status.json"
ENGINE_LOG = CTL_DIR / "engine.log"
STOP_FLAG = CTL_DIR / "stop.flag"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(msg=""):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        with open(ENGINE_LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass


def write_hud_status(func_name: str, best_sc: float, last_sc: float, evals: int = 0, how: str = "", phase_label: str = "QWEN 2.5 CODER // ALTA PARIDAD"):
    try:
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        st = {
            "phase": phase_label,
            "func": func_name,
            "best_score": round(best_sc, 4),
            "last_score": round(last_sc, 4),
            "evals": evals,
            "how": how,
            "paused": False,
            "ts": time.time(),
        }
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(description="Qwen 2.5 Coder 7B directo a funciones de alta paridad")
    ap.add_argument("--model", default="qwen2.5-coder:7b", help="Modelo LLM de Ollama (default: qwen2.5-coder:7b)")
    ap.add_argument("--min-score", type=float, default=0.80, help="Puntaje minimo (default: 0.80)")
    ap.add_argument("--max-score", type=float, default=0.9999, help="Puntaje maximo (default: 0.9999)")
    ap.add_argument("--tries", type=int, default=2, help="Intentos de IA por funcion (default: 2, evita bucles)")
    ap.add_argument("--limit", type=int, default=50, help="Tope de funciones a procesar")
    ap.add_argument("--func", default=None, help="Funcion especifica a procesar (ej: func_080C3C18)")
    args = ap.parse_args()

    if STOP_FLAG.exists():
        try:
            STOP_FLAG.unlink()
        except OSError:
            pass

    log("=" * 76)
    log(" FOMT-MATCH-ENGINE :: QWEN 2.5 CODER 7B DIRECTO (BANDAS ALTAS A ZERO-DIFF)")
    log("=" * 76)
    log(f" [*] Modelo LLM: {args.model}")
    log(f" [*] Rango Objetivo: [{args.min_score*100:.1f}% - {args.max_score*100:.1f}%]")
    log(f" [*] Intentos por funcion: {args.tries}")
    log(f" [*] Modo: Secuencial Quirurgico (1 a la vez, agbcc + micro-permutador)")
    log("=" * 76)

    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    # Seleccionar candidatos ordenados de mayor a menor paridad
    if args.func:
        candidates = [e for e in manifest if e["name"] == args.func]
    else:
        candidates = []
        for e in manifest:
            name = e["name"]
            st = state.get(name, {})
            if st.get("status") == "matched":
                continue
            sc = float(st.get("best", 0.0) or 0.0)
            att = int(st.get("qwen_attempts", 0) or 0)
            if args.min_score <= sc <= args.max_score:
                candidates.append((att, -sc, e))
        candidates.sort(key=lambda x: (x[0], x[1]))
        candidates = [e for _, _, e in candidates]

    if args.limit > 0:
        candidates = candidates[:args.limit]

    total_cands = len(candidates)
    log(f"[*] Candidatos seleccionados para Qwen: {total_cands} funciones")
    if total_cands == 0:
        log("[!] No se encontraron funciones en el rango especificado.")
        return 0

    # Lift args simulados para procesar funcion a funcion
    lift_args = argparse.Namespace(
        phase=2,
        model=args.model,
        limit=1,
        func=None,
        tries=args.tries,
        permute=300,
        permute_quick=30,
        perm_threshold=0.60,
        approx=0.90,
        max_minutes=0,
        max_size=256,
        min_size=4,
        retry_wip=True,
        order="score",
        min_score=args.min_score,
        max_score=args.max_score,
    )

    matches_found = 0
    improved_count = 0

    try:
        for idx, e in enumerate(candidates, 1):
            if STOP_FLAG.exists():
                log("[!] Detencion solicitada (stop.flag detectado).")
                break

            name = e["name"]
            curr_st = state.get(name, {})
            b0 = float(curr_st.get("best", 0.0) or 0.0)

            log(f"\n---> [{idx}/{total_cands}] INVOCANDO QWEN PARA {name} (Paridad base: {b0*100:.1f}%, tamano: {e['size']}B)...")
            write_hud_status(name, b0, b0, phase_label=f"QWEN 2.5 CODER [{idx}/{total_cands}]")

            t0 = time.time()
            try:
                lift.process(e, rom, manifest, state, lift_args)
            except KeyboardInterrupt:
                log("\n[!] Proceso interrumpido por el usuario.")
                break
            except Exception as ex:
                log(f"  [!] Error procesando {name}: {ex}")

            dur = round(time.time() - t0, 1)
            # Releer estado actualizado
            new_st = state.get(name, {})
            new_best = float(new_st.get("best", 0.0) or 0.0)
            new_status = new_st.get("status", "wip")

            if new_status == "matched" or new_best >= 1.0:
                matches_found += 1
                log(f"  [+] [MATCH 100% ZERO-DIFF] {name} alcanzado en {dur}s!")
                write_hud_status(name, 1.0, 1.0, how="MATCH 100%", phase_label="MATCH 100% ZERO-DIFF!")
            elif new_best > b0 + 1e-6:
                improved_count += 1
                log(f"  [^] [MEJORA] {name} {b0*100:.1f}% -> {new_best*100:.1f}% en {dur}s (status: {new_status})")
                write_hud_status(name, new_best, new_best, how=f"Mejora {new_best*100:.1f}%")
            else:
                log(f"  [.] {name}: sin mejora tras intento de Qwen ({new_best*100:.1f}% en {dur}s)")
                write_hud_status(name, new_best, new_best, how="Sin mejora")

            # Registrar intento para avanzar monotónicamente en la cola sin repetir la misma funcion al reiniciar
            if name in state and state[name].get("status") != "matched":
                state[name]["qwen_attempts"] = int(state[name].get("qwen_attempts", 0) or 0) + 1
            # Checkpoint atomico
            common.save_state(state)
            common.sync_collection()

    finally:
        write_hud_status("", 0.0, 0.0, phase_label="STANDBY")
        try:
            subprocess.run(["ollama", "stop", args.model], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        except Exception:
            pass

    log("\n" + "=" * 76)
    log(f" SESION QWEN DIRECTO COMPLETADA")
    log(f" [+] Matches 100% Zero-Diff nuevos: {matches_found}")
    log(f" [^] Funciones mejoradas: {improved_count}")
    log("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())

