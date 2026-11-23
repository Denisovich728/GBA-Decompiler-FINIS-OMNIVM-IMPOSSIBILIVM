"""FOMT-MATCH-ENGINE :: Fast Multi-Function Parallel Permuter CLI.

Procesa MULTIPLES funciones simultaneamente en paralelo a traves de los nucleos de la CPU
(Intel Core i7-13620H: 16 hilos logicos).

A diferencia del permutador secuencial, este CLI distribuye N funciones completas en
N workers de procesos independientes. Si ejecutas con 8 o 12 workers, procesa 8 a 12 funciones
en paralelo por minuto, reduciendo el tiempo de computo al minimo absoluto posible.

Uso:
  python tools/match/fast_permuter_cli.py                      # automatico (8 workers, >=80%)
  python tools/match/fast_permuter_cli.py --workers 12 --min-score 0.75
  python tools/match/fast_permuter_cli.py --min-score 0.90   # solo las que estan a un paso
"""
import argparse
import collections
import json
import os
import random
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import exact_permuter as EP
import lift

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

STOP_FILE = common.TREE_DIR / "control" / "fast_perm_stop.flag"


def write_engine_status(func_name: str, phase_label: str, base_sc: float, best_sc: float, evals: int = 0, how: str = ""):
    """Actualiza status.json para que el HUD y la matriz ROM muestren la casilla y telemetría activa en tiempo real."""
    try:
        st_file = common.TREE_DIR / "control" / "status.json"
        st_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "phase": phase_label,
            "func": func_name,
            "best_score": round(float(best_sc), 4),
            "last_score": round(float(base_sc), 4),
            "evals": evals,
            "how": how,
            "ts": time.time(),
        }
        tmp = st_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, st_file)
    except Exception:
        pass


def log(msg=""):
    print(msg, flush=True)


# ---------------------------------------------------------------------------------------------
# Worker Unit: procesa UNA funcion completa de forma autonoma
# ---------------------------------------------------------------------------------------------
_LOCAL = {}


def _init_worker_env():
    try:
        import psutil
        if hasattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS"):
            psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass
    _LOCAL["rom"] = common.load_rom()
    _LOCAL["manifest"] = common.load_manifest()
    _LOCAL["by"] = {e["name"]: e for e in _LOCAL["manifest"]}


def _worker_process_function(task):
    """Ejecuta la busqueda combinatoria determinista sobre una funcion individual en su propio proceso."""
    name, b0, seconds_budget, depth_cfg, beam_cfg = task
    e = _LOCAL["by"].get(name)
    if not e:
        return {"name": name, "exact": False, "best": b0, "how": "not_found", "evals": 0, "secs": 0}

    code, src_path = EP.pick_source(e, {"best": b0})
    if not code:
        return {"name": name, "exact": False, "best": b0, "how": "no_source", "evals": 0, "secs": 0}

    target = common.rom_bytes(_LOCAL["rom"], e["addr"], e["size"])
    manifest = _LOCAL["manifest"]
    presets = EP.presets_for(e, {}, "agbcc")
    preset = presets[0]

    t0 = time.time()
    # Si seconds_budget es 0, no hay limite de tiempo (busqueda exhaustiva sin deadline)
    deadline = (t0 + seconds_budget) if seconds_budget > 0 else float("inf")
    rng = random.Random(name)
    evals = 0

    last_got = None

    def eval_cand(c, p):
        nonlocal evals, last_got
        evals += 1
        try:
            ok, got, _ = lift.try_candidate(e, c, manifest, p)
            if not ok:
                return 0.0, False
            last_got = got
            ex, sc = lift.score(e, target, got)
            return sc, bool(ex)
        except Exception:
            return 0.0, False

    # 1. Base
    sc_base, ex_base = eval_cand(code, preset)
    if ex_base:
        return {"name": name, "exact": True, "best": 1.0, "preset": preset, "how": "base", "code": code, "evals": evals, "secs": round(time.time() - t0, 1)}

    best_sc = max(b0, sc_base)
    best_code = code
    best_how = "base"

    # 2. Permutaciones completas de declaraciones locales
    perms = EP.decl_permutations(best_code, 5040)
    for tag_p, cand_p in perms:
        if time.time() > deadline:
            break
        sc, ex = eval_cand(cand_p, preset)
        if ex:
            return {"name": name, "exact": True, "best": 1.0, "preset": preset, "how": tag_p, "code": cand_p, "evals": evals, "secs": round(time.time() - t0, 1)}
        if sc > best_sc + 1e-9:
            best_sc, best_code, best_how = sc, cand_p, tag_p

    # 3. Beam search con vecindario de ediciones
    seen = {EP.norm(best_code)}
    frontier = [(best_sc, best_code)]
    is_approx = best_sc >= 0.90
    depth_limit = 3 if is_approx else depth_cfg
    beam_width = 8 if is_approx else beam_cfg
    patience_limit = 2
    sample_size = 120 if is_approx else 80

    stale = 0
    for d in range(depth_limit):
        if time.time() > deadline:
            break
        cand_list = []
        for _, cur_c in frontier:
            nb = [(tag, nc) for tag, nc in EP.neighbors(cur_c) if EP.norm(nc) not in seen]
            rng.shuffle(nb)
            for tag, nc in nb[:sample_size]:
                seen.add(EP.norm(nc))
                cand_list.append((tag, nc))

        if not cand_list:
            break

        improved = False
        scored_pool = []
        for tag, nc in cand_list:
            if time.time() > deadline:
                break
            sc, ex = eval_cand(nc, preset)
            if ex:
                return {"name": name, "exact": True, "best": 1.0, "preset": preset, "how": f"d{d+1}:{tag}", "code": nc, "evals": evals, "secs": round(time.time() - t0, 1)}
            scored_pool.append((sc, nc, tag))
            if sc > best_sc + 1e-9:
                best_sc, best_code, best_how = sc, nc, f"d{d+1}:{tag}"
                improved = True

        scored_pool.sort(key=lambda x: -x[0])
        keep = {EP.norm(c): (sc, c) for sc, c in frontier}
        for sc, nc, tag in scored_pool[:beam_width]:
            keep[EP.norm(nc)] = (sc, nc)
        frontier = sorted(keep.values(), key=lambda x: -x[0])[:beam_width]

        stale = 0 if improved else stale + 1
        if stale >= patience_limit:
            break

    # 4. Chequeo de otros presets sobre el mejor
    for alt_p in presets[1:]:
        if time.time() > deadline:
            break
        sc, ex = eval_cand(best_code, alt_p)
        if ex:
            return {"name": name, "exact": True, "best": 1.0, "preset": alt_p, "how": f"{best_how}+{alt_p}", "code": best_code, "evals": evals, "secs": round(time.time() - t0, 1)}
        if sc > best_sc + 1e-9:
            best_sc, preset, best_how = sc, alt_p, f"{best_how}+{alt_p}"

    secs = round(time.time() - t0, 1)
    # Considerar mejora únicamente si supera con significancia estadística (> 0.0005 o 0.05%)
    has_meaningful_improvement = (best_sc - b0) > 0.0005

    return {
        "name": name,
        "exact": False,
        "best": round(best_sc, 4),
        "preset": preset,
        "how": best_how,
        "code": best_code if has_meaningful_improvement else None,
        "evals": evals,
        "secs": secs,
    }


# ---------------------------------------------------------------------------------------------
# Orquestador del Pool de Procesos
# ---------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Permutador Multi-Thread Masivo por Funciones")
    ap.add_argument("--workers", type=int, default=8, help="Numero de funciones a procesar simultaneamente en paralelo")
    ap.add_argument("--min-score", type=float, default=0.75, help="Paridad minima de entrada (default: 0.75)")
    ap.add_argument("--max-score", type=float, default=0.9999)
    ap.add_argument("--seconds", type=int, default=120, help="Presupuesto maximo por funcion en segundos")
    ap.add_argument("--depth", type=int, default=5, help="Profundidad de beam search")
    ap.add_argument("--beam", type=int, default=10, help="Ancho del beam")
    ap.add_argument("--limit", type=int, default=0, help="Limite maximo de funciones a evaluar")
    ap.add_argument("--phase-label", type=str, default="FAST-PERM", help="Etiqueta de la fase en telemetria")
    ap.add_argument("--apply", action="store_true", default=True, help="Aplica inmediatamente los matches a state.json")
    args = ap.parse_args()

    workers = max(1, min(16, args.workers))
    state = common.load_state()
    manifest = common.load_manifest()
    by = {e["name"]: e for e in manifest}

    # Seleccionar cola de candidatos
    queue = []
    for name, st in state.items():
        if name not in by or st.get("status") not in ("wip", "approx"):
            continue
        sc = float(st.get("best", 0) or 0)
        if args.min_score <= sc <= args.max_score:
            queue.append((sc, name))

    # Ordenar de mayor a menor paridad (las mas cercanas primero)
    queue.sort(reverse=True)
    if args.limit > 0:
        queue = queue[:args.limit]

    total_tasks = len(queue)
    if total_tasks == 0:
        log(f"[*] No hay funciones pendientes en el rango de paridad {args.min_score*100:.0f}% - {args.max_score*100:.0f}%.")
        return 0

    log("=" * 76)
    log(" FOMT-MATCH-ENGINE :: FAST MULTI-FUNCTION PARALLEL PERMUTER")
    log("=" * 76)
    log(f" [*] Cola de Candidatos: {total_tasks} funciones (>= {int(args.min_score*100)}%)")
    log(f" [*] Hilos de CPU concurrentes: {workers} funciones en paralelo simultaneo")
    log(f" [*] Presupuesto: {args.seconds}s / funcion | Beam: {args.beam} | Profundidad: {args.depth}")
    log(f" [*] Para detener: Ctrl+C")
    log("=" * 76)

    t_start = time.time()
    exact_count = 0
    improved_count = 0
    done_count = 0

    perm_dir = common.TREE_DIR / "permute" / "code"
    perm_dir.mkdir(parents=True, exist_ok=True)

    tasks = [(name, sc, args.seconds, args.depth, args.beam) for sc, name in queue]

    try:
        with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker_env) as pool:
            futures = {pool.submit(_worker_process_function, t): t[0] for t in tasks}

            for fut in as_completed(futures):
                res = fut.result()
                name = res["name"]
                done_count += 1
                secs = res["secs"]
                evals = res["evals"]
                b_prev = [x[0] for x in queue if x[1] == name][0]

                # Notificar al HUD y a la matriz ROM la función y estado evaluado
                write_engine_status(
                    func_name=name,
                    phase_label=args.phase_label,
                    base_sc=b_prev,
                    best_sc=res["best"],
                    evals=evals,
                    how=res["how"],
                )

                if res["exact"]:
                    exact_count += 1
                    preset = res["preset"]
                    how = res["how"]
                    code = res["code"]
                    log(f"  [+] [MATCH 100%] {name} en {secs}s ({evals} evals) via {how} [{preset}]")

                    # Guardar archivo C verificado
                    (perm_dir / f"{name}.c").write_text(code, encoding="utf-8")
                    
                    # Aplicar siempre atómicamente a state.json
                    cur_state = common.load_state()
                    e = by[name]
                    rom = common.load_rom()
                    target = common.rom_bytes(rom, e["addr"], e["size"])
                    lift.save_matched(e, code, preset, manifest, cur_state, 0, f"fast-perm:{how}", target=target, rom=rom)

                elif res.get("code") is not None:
                    improved_count += 1
                    log(f"  [^] [MEJORADA]  {name} {b_prev*100:.1f}% -> {res['best']*100:.1f}% en {secs}s [{res['how']}]")
                    (perm_dir / f"{name}.c").write_text(res["code"], encoding="utf-8")
                    cur_state = common.load_state()
                    e = by[name]
                    path = common.TREE_DIR / e["file"]
                    lift._write_atomic(path.with_suffix(".wip.c"), res["code"])
                    cur_state[name] = {**cur_state.get(name, {}), "best": res["best"], "preset": res["preset"]}
                    if res["best"] >= 0.90:
                        cur_state[name]["status"] = "approx"
                    elif res["best"] >= 0.50:
                        cur_state[name]["status"] = "wip"
                    common.save_state(cur_state)
                else:
                    # No hubo mejora en este paso
                    if done_count % 5 == 0 or done_count == total_tasks:
                        log(f"  [.] [{done_count}/{total_tasks}] {name}: sin cambios ({res['best']*100:.1f}%)")

                # Telemetría de progreso en consola
                elapsed = time.time() - t_start
                rate = (done_count / elapsed) * 60.0 if elapsed > 0 else 0
                if done_count % 10 == 0 or done_count == total_tasks:
                    log(f"  >>> PROGRESO: {done_count}/{total_tasks} | EXACTAS: {exact_count} | MEJORADAS: {improved_count} | VELOCIDAD: {rate:.1f} fns/min")

    except KeyboardInterrupt:
        log("\n[!] Detencion solicitada por el usuario.")

    total_time = round(time.time() - t_start, 1)
    log("\n" + "=" * 76)
    log(f" FIN DE EJECUCION FAST-PERMUTER :: {done_count} procesadas en {total_time}s")
    log(f" [+] 100% MATCHES EXACTOS RESUELTOS: {exact_count}")
    log(f" [^] FUNCIONES MEJORADAS: {improved_count}")
    log("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())

