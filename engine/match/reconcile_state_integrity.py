"""Reconcilia y sanea la integridad de state.json en src_sweep y src_exp.

1. Verifica las 1.105 funciones 'matched':
   - Las que dan 100% Zero-Diff contra la ROM se ratifican con best=1.0.
   - Las 52 funciones discrepantes se corrigen a su estado real ('approx' o 'wip')
     con su paridad exacta calculada, eliminandolas de collection/matched/.
2. Reconcilia funciones 'wip' y 'approx':
   - Comprueba el codigo existente en disco (.wip.c, approx/<fn>.c, base .c).
   - Si el score real en disco supera al 'best' de state.json (el 57% detectado en Exp 2),
     actualiza state.json con el score superior y promueve a 'approx' si >= 0.85.
"""
import concurrent.futures
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.match import common, lift

def reconcile_tree(tree_name="src_sweep", max_workers=6):
    os.environ["FOMT_TREE"] = tree_name
    tree_dir = ROOT / tree_name
    state_file = tree_dir / "state.json"
    manifest_file = tree_dir / "manifest.json"

    print("=" * 80)
    print(f" RECONCILIACION Y SANEADO DE INTEGRIDAD: {tree_name.upper()}")
    print("=" * 80)

    rom = lift.load_rom()
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    manifest_map = {e["name"]: e for e in manifest}

    with open(state_file, "r", encoding="utf-8") as f:
        state = json.load(f)

    # 1. Auditoria de funciones 'matched'
    matched_to_audit = [(name, info, manifest_map[name]) for name, info in state.items() if info.get("status") == "matched" and name in manifest_map]
    print(f"[*] Auditando {len(matched_to_audit)} funciones con status 'matched'...")

    confirmed_matches = 0
    demoted_matches = 0
    demoted_details = []

    def audit_match(item):
        name, info, e = item
        preset = info.get("preset", "agbcc_O2")
        src_path = tree_dir / e["file"]
        if not src_path.exists():
            return name, False, 0.0, "Archivo faltante"
        try:
            code = lift.extract_c(src_path.read_text(encoding="utf-8", errors="ignore"), rom=rom, e=e)
            target = lift.rom_bytes(rom, e["addr"], e["size"])
            ok, got, log = lift.try_candidate(e, code, manifest, preset)
            if ok and got == target and len(got) == e["size"]:
                return name, True, 1.0, None
            _, sc = lift.score(e, target, got) if ok and got else (False, 0.0)
            return name, False, sc, f"Discrepante (score: {sc*100:.2f}%)"
        except Exception as exc:
            return name, False, 0.0, str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for name, ok, sc, err in pool.map(audit_match, matched_to_audit):
            if ok:
                confirmed_matches += 1
            else:
                demoted_matches += 1
                demoted_details.append((name, sc, err))
                new_st = "approx" if sc >= 0.85 else "wip"
                state[name]["status"] = new_st
                state[name]["best"] = round(sc, 4)
                # Quitar de collection/matched
                col_match = tree_dir / "collection" / "matched" / f"{name}.c"
                if col_match.exists():
                    try:
                        col_match.unlink()
                    except OSError:
                        pass

    print(f"  [+] Matches 100% Zero-Diff confirmados: {confirmed_matches}")
    print(f"  [-] Falsos matches saneados (devueltos a approx/wip): {demoted_matches}")

    # 2. Reconciliacion de progreso de disco en wip / approx
    progress_to_check = [
        (name, info, manifest_map[name])
        for name, info in state.items()
        if info.get("status") in ("wip", "approx") and name in manifest_map
    ]
    print(f"[*] Reconciliando {len(progress_to_check)} funciones 'wip' y 'approx' contra disco...")

    upgraded_from_disk = 0

    def check_disk_progress(item):
        name, info, e = item
        current_best = float(info.get("best", 0.0) or 0.0)
        preset = info.get("preset", "agbcc_O2")
        target = lift.rom_bytes(rom, e["addr"], e["size"])

        # Buscar mejor fuente en disco: approx, wip, o base
        best_sc_disk = -1.0
        best_code = None

        for p in (tree_dir / "approx" / f"{name}.c", (tree_dir / e["file"]).with_suffix(".wip.c"), tree_dir / e["file"]):
            if p.exists():
                try:
                    c = lift.extract_c(p.read_text(encoding="utf-8", errors="ignore"), rom=rom, e=e)
                    ok, got, _ = lift.try_candidate(e, c, manifest, preset)
                    if ok and got:
                        _, sc = lift.score(e, target, got)
                        if sc > best_sc_disk:
                            best_sc_disk = sc
                            best_code = c
                except Exception:
                    pass

        return name, current_best, best_sc_disk

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for name, cur_b, disk_b in pool.map(check_disk_progress, progress_to_check):
            if disk_b > cur_b + 0.005: # Mejora medible (>0.5%)
                upgraded_from_disk += 1
                state[name]["best"] = round(disk_b, 4)
                if disk_b >= 0.85 and state[name]["status"] == "wip":
                    state[name]["status"] = "approx"

    print(f"  [+] Funciones con progreso en disco actualizado en state.json: {upgraded_from_disk}")

    # Guardar state.json reconciliado
    common.save_state(state)
    print(f"[OK] {tree_name}/state.json saneado y sincronizado con exito.\n")

    return confirmed_matches, demoted_matches, upgraded_from_disk

if __name__ == "__main__":
    reconcile_tree("src_sweep", max_workers=6)
    reconcile_tree("src_exp", max_workers=6)

