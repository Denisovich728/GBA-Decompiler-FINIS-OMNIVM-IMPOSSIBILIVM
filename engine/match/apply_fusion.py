"""Aplica la fusion entre StanHash/fomt y src_sweep (manifest.json + state.json).

Acciones realizadas:
1. Agrega las 386 funciones faltantes descubiertas en Stan a manifest.json.
2. Genera los archivos .c stub en sus bancos correspondientes (bank_XXXXXXXX/func_XXXXXXXX.c).
3. Registra las nuevas funciones en state.json con estado 'orphan' y sus metadatos (module, class, semantic_name).
4. Enriquece las funciones existentes en state.json con sus metadatos de modulo, clase y nombre semantico provenientes de Stan.
5. Ordena manifest.json por direccion de memoria para garantizar la coherencia en enlace y barridos.

Uso:
  python tools/match/apply_fusion.py
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common

FUSION_DIR = common.TREE_DIR / "fusion"
ADDS_FILE = FUSION_DIR / "manifest_additions.json"
SEM_FILE = FUSION_DIR / "semantic_map.json"

DEFAULT_DIALECT_HINT = (
    "GBA SDK C89 (agbcc.exe -O2 -mthumb-interwork + ADS 1.2 tcc.exe). "
    "C89 PURO: declara TODAS las variables al inicio del bloque. "
    "PROHIBIDO usar asm, __asm, push, pop, bl o mnemonicos ARM."
)


def apply():
    if not ADDS_FILE.exists() or not SEM_FILE.exists():
        print("[!] Error: No se encontraron los archivos de fusion en src_sweep/fusion/")
        return False

    manifest = common.load_manifest()
    state = common.load_state()

    adds = json.loads(ADDS_FILE.read_text(encoding="utf-8"))
    sem_map = json.loads(SEM_FILE.read_text(encoding="utf-8"))

    existing_names = {e["name"] for e in manifest}
    existing_addrs = {e["addr"] for e in manifest}

    print(f"[*] Manifest actual: {len(manifest)} funciones")
    print(f"[*] State actual: {len(state)} entradas")
    print(f"[*] Nuevas funciones a incorporar: {len(adds)}")

    added_count = 0
    for item in adds:
        addr = item["addr"]
        name = item["name"]
        size = item.get("size") or 4
        mode = item.get("mode") or "THUMB"
        module = item.get("module") or "unknown"

        if name in existing_names or addr in existing_addrs:
            continue

        bank_addr = addr & ~0xFFFF
        bank_dir = common.TREE_DIR / f"bank_{bank_addr:08X}"
        bank_dir.mkdir(parents=True, exist_ok=True)

        rel_file = f"bank_{bank_addr:08X}/{name}.c"
        c_path = common.TREE_DIR / rel_file

        if not c_path.exists():
            c_content = (
                f"/* {name} @ 0x{addr:08X} mode={mode} size=0x{size:X} (importado de Stan: {module}) */\n"
                f"/* COMPILADOR: agbcc.exe / tcc.exe -O2 -mthumb-interwork -fhex-asm */\n"
                f"/* REGLAS IA: {DEFAULT_DIALECT_HINT} */\n"
                f"/* MODULO STAN: {module} */\n\n"
                f"// TODO: Reconstruir logica para coincidir 1:1 con la ROM\n"
            )
            c_path.write_text(c_content, encoding="utf-8")

        entry = {
            "name": name,
            "addr": addr,
            "mode": mode,
            "cc": "agbcc.exe / tcc.exe",
            "cflags": ["-O2", "-mthumb-interwork", "-fhex-asm"],
            "dialect_hint": DEFAULT_DIALECT_HINT,
            "size": size,
            "file": rel_file,
            "origin": "STAN_DISASM",
            "module": module,
        }
        manifest.append(entry)

        sem_info = sem_map.get(f"{addr:08X}", {})
        state[name] = {
            "status": "orphan",
            "best": 0.0,
            "preset": None,
            "phase": 1,
            "addr": addr,
            "size": size,
            "tries": 0,
            "module": module,
            "class": sem_info.get("class"),
            "semantic_name": sem_info.get("stan_name", ""),
        }
        added_count += 1

    # Enriquecer funciones ya existentes con metadata semántica de Stan
    enriched_count = 0
    for e in manifest:
        addr_hex = f"{e['addr']:08X}"
        if addr_hex in sem_map:
            s_info = sem_map[addr_hex]
            st = state.setdefault(e["name"], {})
            mod = s_info.get("module")
            cls = s_info.get("class")
            stan_nm = s_info.get("stan_name")

            changed = False
            if mod and "module" not in st:
                st["module"] = mod
                e["module"] = mod
                changed = True
            if cls and "class" not in st:
                st["class"] = cls
                changed = True
            if stan_nm and not stan_nm.startswith("func_") and not st.get("semantic_name"):
                st["semantic_name"] = stan_nm
                st["named"] = True
                changed = True

            if changed:
                enriched_count += 1

    # Ordenar manifest por dirección física
    manifest.sort(key=lambda x: x["addr"])

    # Guardar cambios
    common.MANIFEST.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    common.save_state(state)

    print(f"[+] Fusion aplicada exitosamente:")
    print(f"    - Funciones agregadas al manifest: {added_count}")
    print(f"    - Funciones existentes enriquecidas semanticamente: {enriched_count}")
    print(f"    - Nuevo total de funciones en manifest: {len(manifest)}")
    print(f"    - Total en state.json: {len(state)}")
    return True


if __name__ == "__main__":
    apply()

