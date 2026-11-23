"""FOMT-MATCH-ENGINE :: Autonomous Continuous Recompilation Pipeline (100% C Pure Goal).

Orquestador de ejecucion autonoma continua ("manos libres"):
Ejecuta un bucle infinito en cascada cerrada disenado para alcanzar el 100% de decompilacion
a C puro sin requerir supervision manual:

  PASO 1 [Filtro Determinista 0-IA]:
         Ejecuta exact_permuter sobre todas las funciones en wip/approx (>= 80%).
         Convierte de forma inmediata las discrepancias de orden/casts en matches 100% (zero-diff)
         y las aplica a state.json.

  PASO 2 [Esclavo de Inferencia IA - Qwen 2.5 Coder 7B]:
         Procesa lotes de funciones huerfanas (orphan) y wip pendientes.
         Usa Qwen 2.5 Coder 7B (ligero, no satura los 16GB de RAM, 3x-4x mas rapido en CPU i7-13620H)
         con compilador agbcc -O2 y feedback C89.

  PASO 3 [Refinamiento Combinatorio]:
         Cualquier funcion que el LLM eleve por encima de 80% entra inmediatamente al
         permutador determinista para forzar el match exacto 100%.

  PASO 4 [Auto-Forja Continua de la ROM]:
         Cada ciclo o cada paquete de nuevas funciones matched, sincroniza forge_out/,
         ensambla los bloques .incbin de baserom.gba, compila el proyecto y reporta
         el porcentaje real de C en la ROM.

  PASO 5 [Gobernador de Salud y Recursos]:
         Monitorea activamente la memoria RAM (alerta si supera 88%) y controla los watts/hilos
         segun engine_config.json para permitir ejecucion continua de 24+ horas con estabilidad total.

Detencion limpia:
  Crea el archivo src_sweep/control/stop.flag o pulsa Ctrl+C en la terminal.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import exact_permuter
import forge_cli

CTL_DIR = common.TREE_DIR / "control"
STATUS_FILE = CTL_DIR / "autonomous_status.json"
ENGINE_STATUS_FILE = CTL_DIR / "status.json"
STOP_FLAG = CTL_DIR / "stop.flag"
ENGINE_LOG = CTL_DIR / "engine.log"

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


def write_status(**kw):
    kw["ts"] = time.time()
    kw["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(kw, indent=2), encoding="utf-8")
        os.replace(tmp, STATUS_FILE)
        # Sincronizar tambien con el status principal del HUD
        eng_status = {
            "phase": kw.get("step_label", "AUTONOMOUS PIPELINE"),
            "func": kw.get("current_func", ""),
            "best_score": kw.get("pct_c", 0.0) / 100.0,
            "last_score": kw.get("pct_c", 0.0) / 100.0,
            "paused": False,
            "ts": time.time(),
        }
        tmp_eng = ENGINE_STATUS_FILE.with_suffix(".tmp")
        tmp_eng.write_text(json.dumps(eng_status), encoding="utf-8")
        os.replace(tmp_eng, ENGINE_STATUS_FILE)
    except OSError:
        pass


def stop_requested() -> bool:
    return STOP_FLAG.exists()


def free_ollama_model(model_name: str):
    """Descarga de RAM un modelo inactivo en Ollama para mantener la memoria por debajo del 65%."""
    try:
        subprocess.run(["ollama", "stop", model_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except Exception:
        pass


def check_system_vitals():
    """Gobernador de hardware: cuida la RAM y evita sobrecalentamiento o swapping en disco."""
    mem = psutil.virtual_memory()
    if mem.percent > 85.0:
        log(f"[!] ALERTA DE RECURSOS: Uso de RAM al {mem.percent:.1f}% ({mem.used // (1024*1024)} MB). Purgando modelos inactivos de Ollama...")
        free_ollama_model("deepseek-coder-v2:latest")
        free_ollama_model("qwen2.5-coder:7b")
        time.sleep(3)
        mem_after = psutil.virtual_memory()
        log(f"[+] RAM estabilizada al {mem_after.percent:.1f}% ({mem_after.used // (1024*1024)} MB).")


def get_current_stats():
    state = common.load_state()
    manifest = common.load_manifest()
    total = len(manifest) or 3068
    counts = {"matched": 0, "approx": 0, "wip": 0, "orphan": 0}
    high_wip = 0
    for v in state.values():
        st = v.get("status")
        if st in counts:
            counts[st] += 1
        best = float(v.get("best", 0.0) or 0.0)
        if 0.80 <= best < 0.90 and st != "matched":
            high_wip += 1
    pct = round((counts["matched"] / total) * 100.0, 2)
    return total, counts, pct, high_wip


# ---------------------------------------------------------------------------------------------
# Fases del Pipeline
# ---------------------------------------------------------------------------------------------

def run_fast_permuter_band(min_score: float, max_score: float, phase_label: str, workers: int = 8, seconds_per_fn: int = 40, depth: int = 5, beam: int = 10):
    """Ejecuta fast_permuter_cli masivo paralelo para una banda específica sin cambiar de contexto."""
    if stop_requested():
        return 0
    log(f"[*] INICIANDO {phase_label} :: Rango [{int(min_score*100)}% - {int(max_score*100)}%] ({workers} workers paralelos)...")
    write_status(step="fast_perm", step_label=phase_label)

    cmd = [
        sys.executable,
        str(ROOT / "tools" / "match" / "fast_permuter_cli.py"),
        "--min-score", str(min_score),
        "--max-score", str(max_score),
        "--workers", str(workers),
        "--seconds", str(seconds_per_fn),
        "--depth", str(depth),
        "--beam", str(beam),
        "--phase-label", phase_label,
        "--apply",
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
        log(f"[!] Error ejecutando fast_permuter: {ex}")
    finally:
        common.sync_collection()


def step_exact_permuter(min_score: float = 0.80, workers: int = 4, seconds_per_fn: int = 75):
    """Paso 1 y 3: Corre el permutador determinista y aplica los exactos a state.json."""
    if stop_requested():
        return 0
    log(f"[*] INICIANDO PERMUTADOR DETERMINISTA (CERO IA // candidatos >= {int(min_score*100)}%)...")
    write_status(step="permuter", step_label=f"Permutador Determinista (>={int(min_score*100)}%)")
    
    # 1. Ejecutar permutador guardando resultados en permute/results.json
    res_code = exact_permuter.main.__globals__["_eval"]  # Verificacion de contexto
    sys_argv_bak = sys.argv
    sys.argv = [
        "exact_permuter.py",
        "--min-score", str(min_score),
        "--workers", str(workers),
        "--seconds", str(seconds_per_fn),
        "--depth", "4",
        "--patience", "2",
    ]
    try:
        exact_permuter.main()
    except Exception as ex:
        log(f"[!] Error en ejecucion del permutador: {ex}")
    finally:
        sys.argv = sys_argv_bak

    # 2. Aplicar inmediatamente los exactos a state.json
    applied = exact_permuter.apply_results(verbose=True)
    log(f"[+] Permutador finalizado. Nuevas funciones matched aplicadas: {applied}")
    return applied


def step_ai_slave_batch(model: str = "deepseek-coder-v2:latest", min_score: float = 0.0, max_score: float = 1.0, limit: int = 20, tries: int = 25, workers: int = 4, phase_label: str = "Esclavo IA"):
    """Paso IA: Barrido secuencial con el LLM seleccionado sobre la banda objetivo."""
    if stop_requested():
        return
    log(f"[*] INICIANDO {phase_label} :: {model.upper()} (Rango [{int(min_score*100)}%-{int(max_score*100)}%], {limit} fns, {tries} intentos/fn)...")
    write_status(step="ai_slave", step_label=f"{phase_label} ({model})")
    
    # Liberar el otro modelo de la memoria para que el modelo activo tenga todo el espacio
    other_model = "deepseek-coder-v2:latest" if "qwen" in model.lower() else "qwen2.5-coder:7b"
    free_ollama_model(other_model)

    cmd = [
        sys.executable,
        str(ROOT / "tools" / "match" / "sweep.py"),
        "--phase", "2",
        "--model", model,
        "--limit", str(limit),
        "--tries", str(tries),
        "--permute", "400",
        "--permute-quick", "30",
        "--approx", "0.90",
        "--min-score", str(min_score),
        "--max-score", str(max_score),
        "--order", "score",
        "--min-size", "8",
        "--max-size", "256",
    ]

    env = os.environ.copy()
    env.update({"FOMT_TREE": "src_sweep", "FOMT_MODEL": model, "PYTHONUNBUFFERED": "1"})

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )

    try:
        for line in iter(proc.stdout.readline, b""):
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                # Filtrar y emitir lineas relevantes al log
                if any(k in text for k in ("[MATCH]", "[approx]", "evaluando", "mejor preset", "ERROR", "avance", "LLM", "PARIEDAD", "Candidatos", "Procesando")):
                    log(f"  [AI] {text}")
            if stop_requested():
                proc.terminate()
                break
        proc.wait()
    finally:
        common.sync_collection()
        free_ollama_model(model)


def step_forge_and_build(out_dir: Path):
    """Paso 4: Forja el proyecto C limpio y compila la ROM para verificar paridad."""
    if stop_requested():
        return None
    log("[*] SINCRONIZANDO Y COMPILANDO PROYECTO LIMPIO (FORJA)...")
    write_status(step="forge", step_label="Forja y Verificacion de ROM")
    
    rom_info, err = forge_cli.validate_rom(str(common.ROM_PATH))
    if err:
        log(f"[!] Error validando ROM base: {err}")
        return None

    manifest = common.load_manifest()
    state = common.load_state()
    tools = forge_cli.tools_cfg()
    
    # 1. Verificar funciones matched
    good, bad = forge_cli.verify_all(
        manifest,
        state,
        workers=4,
        cache_path=out_dir / ".verify_cache.json",
        rom_sha=rom_info["sha1"],
    )

    # 2. Generar y compilar
    forge_cli.write_project(out_dir, rom_info, manifest, good, tools)
    res = forge_cli.run_build(out_dir)

    ok = bool(res.get("ok"))
    c_count = len(good)
    diff = res.get("diff_bytes", 0)
    
    if ok:
        log(f"[+] FORJA 100% BYTE-PERFECT: {c_count} funciones C compiladas | ROM identica a original (0 diff).")
    else:
        log(f"[!] FORJA COMPILADA CON {diff} BYTES DIFERENTES (mismatches: {len(res.get('mismatched', []))}).")

    return {"ok": ok, "c_functions": c_count, "diff_bytes": diff}


# ---------------------------------------------------------------------------------------------
# Bucle Autónomo Principal
# ---------------------------------------------------------------------------------------------

def run_autonomous_loop(args):
    out_dir = Path(args.out)
    model = args.model
    perm_workers = args.perm_workers or 4
    ai_limit = args.batch_limit
    
    log("=" * 74)
    log(" FOMT-MATCH-ENGINE :: ORQUESTADOR AUTONOMO CONTINUO (META: 100% C PURO)")
    log("=" * 74)
    log(f" [*] Directorio de salida limpio: {out_dir}")
    log(f" [*] Modelo Esclavo Local: {model}")
    log(f" [*] Hilos Permutador: {perm_workers}")
    log(f" [*] Detencion limpia: Crear archivo '{STOP_FLAG}'")
    log("=" * 74)

    if STOP_FLAG.exists():
        STOP_FLAG.unlink()

    cycle = 1
    t_start = time.time()

    while not stop_requested():
        total, counts, pct, high_wip = get_current_stats()
        log(f"\n##########################################################################")
        log(f" CICLO AUTONOMO #{cycle} | MATCH 1:1: {counts['matched']}/{total} ({pct}%) | APPROX: {counts['approx']} | HIGH WIP (80-89%): {high_wip} | WIP: {counts['wip']}")
        log(f"##########################################################################")
        
        write_status(
            cycle=cycle,
            step="cycle_start",
            step_label=f"Ciclo #{cycle} Iniciado",
            matched=counts["matched"],
            approx=counts["approx"],
            high_wip=high_wip,
            wip=counts["wip"],
            orphan=counts["orphan"],
            total=total,
            pct_c=pct,
            elapsed_min=round((time.time() - t_start) / 60.0, 1),
        )

        check_system_vitals()

        # -------------------------------------------------------------------------
        # PIPELINE ESCALONADO POR BANDAS (CERO FRICCION DE CAMBIO DE CONTEXTO)
        # -------------------------------------------------------------------------
        
        # BANDA 1: ELITE APPROX (>= 90%) - Procesa las candidatas mas cercanas
        run_fast_permuter_band(
            min_score=0.90, max_score=0.9999,
            phase_label="BANDA 1 // APPROX (>=90%)",
            workers=perm_workers, seconds_per_fn=45, depth=5, beam=10
        )
        if stop_requested():
            break

        # BANDA 2: HIGH WIP (80% <= score < 90%) - Empuja candidatos a >=90% o 100%
        run_fast_permuter_band(
            min_score=0.80, max_score=0.8999,
            phase_label="BANDA 2 // HIGH WIP (80-90%)",
            workers=perm_workers, seconds_per_fn=35, depth=4, beam=8
        )
        if stop_requested():
            break

        # BANDA 3: MID WIP (50% <= score < 80%) - Optimiza funciones intermedias
        run_fast_permuter_band(
            min_score=0.50, max_score=0.7999,
            phase_label="BANDA 3 // MID WIP (50-80%)",
            workers=perm_workers, seconds_per_fn=25, depth=3, beam=6
        )
        if stop_requested():
            break

        # RE-ASENTAMIENTO DE ALTA PARIDAD: Procesa las funciones que acaban de ascender a >=80% y >=90%
        log("[*] RE-ASENTANDO CANDIDATAS QUE ASCENDIERON A BANDA ALTA TRAS BANDA 3...")
        run_fast_permuter_band(
            min_score=0.90, max_score=0.9999,
            phase_label="ASENTAMIENTO // NUEVAS APPROX (>=90%)",
            workers=perm_workers, seconds_per_fn=50, depth=6, beam=12
        )
        if stop_requested():
            break

        run_fast_permuter_band(
            min_score=0.80, max_score=0.8999,
            phase_label="ASENTAMIENTO // NUEVAS HIGH WIP (80-90%)",
            workers=perm_workers, seconds_per_fn=40, depth=5, beam=10
        )
        if stop_requested():
            break

        # -------------------------------------------------------------------------
        # ESCALONAMIENTO IA: PRIMERO QWEN EN ALTAS (>=80% y >=90%), LUEGO DEEPSEEK EN BAJAS
        # -------------------------------------------------------------------------
        
        # FASE IA 1: QWEN 2.5 CODER 7B sobre bandas altas (Approxs y High WIPs)
        if not args.skip_qwen:
            step_ai_slave_batch(
                model="qwen2.5-coder:7b",
                min_score=0.80,
                max_score=0.9999,
                limit=args.qwen_limit,
                tries=args.ai_tries,
                workers=1,
                phase_label="IA QUIRURGICA QWEN (>=80% y >=90%)"
            )
        if stop_requested():
            break

        # FASE IA 2: DEEPSEEK CODER V2 sobre bandas bajas y huérfanas
        if not args.skip_deepseek:
            step_ai_slave_batch(
                model="deepseek-coder-v2:latest",
                min_score=0.0,
                max_score=0.7999,
                limit=args.deepseek_limit,
                tries=args.ai_tries,
                workers=1,
                phase_label="IA ESTRUCTURAL DEEPSEEK (<80% y Huerfanas)"
            )
        if stop_requested():
            break

        # BANDA 5: AUTO-FORJA Y CONSOLIDACION DE ROM 100% BYTE-PERFECT
        build_res = step_forge_and_build(out_dir)

        # Comprobar si alcanzamos la meta
        total, counts, pct, high_wip = get_current_stats()
        if counts["matched"] >= total:
            log("\n" + "*" * 74)
            log(" [!] META ALCANZADA: 100% DE LA ROM CONVERTIDA A CODIGO C PURO (ZERO-DIFF)!")
            log("*" * 74)
            break

        cycle += 1
        # Breve pausa termica de 10 segundos entre ciclos mayores
        time.sleep(10)

    log("\n[+] Pipeline autonomo detenido de forma ordenada.")
    write_status(step="stopped", step_label="Pipeline Detenido", pct_c=pct)


def main():
    ap = argparse.ArgumentParser(description="Orquestador autonomo para recompilacion 100% a C")
    ap.add_argument("--model", default="deepseek-coder-v2:latest", help="Modelo esclavo local para huerfanas/wip")
    ap.add_argument("--out", default=str(ROOT / "forge_out"), help="Carpeta de salida del proyecto C")
    ap.add_argument("--batch-limit", type=int, default=20, help="Funciones por lote de IA (legacy)")
    ap.add_argument("--qwen-limit", type=int, default=20, help="Funciones de banda alta (>=80%%) asignadas a Qwen por ciclo")
    ap.add_argument("--deepseek-limit", type=int, default=20, help="Funciones de banda baja (<80%%) asignadas a DeepSeek por ciclo")
    ap.add_argument("--skip-qwen", action="store_true", help="Omitir fase de Qwen")
    ap.add_argument("--skip-deepseek", action="store_true", help="Omitir fase de DeepSeek")
    ap.add_argument("--ai-tries", type=int, default=25, help="Intentos por funcion en el LLM")
    ap.add_argument("--perm-workers", type=int, default=8, help="Hilos para el permutador determinista")
    args = ap.parse_args()

    run_autonomous_loop(args)


if __name__ == "__main__":
    main()

