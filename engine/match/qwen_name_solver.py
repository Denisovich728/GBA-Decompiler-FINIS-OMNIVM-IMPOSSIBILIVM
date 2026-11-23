"""FOMT-MATCH-ENGINE :: QWEN BACKGROUND SYMBOL & NAME SOLVER ("DESPEJAR X").

Utiliza Qwen 2.5 Coder 7B local (via Ollama) como un solver continuo de nombres y funciones
despejando por restricciones conocidas (I/O registers, cadenas ROM, llamadas a funciones conocidas
y flujo de control).

Modo de operacion:
- Construye el grafo de dependencias bidireccional.
- Ordena las funciones pendientes por 'densidad de restricciones conocidas' (ecuaciones con menos incognitas).
- Envia prompts estructurados a Qwen para deducir el simbolo exacto, subsistema y rol.
- Al deducir una funcion, esta se convierte en 'conocida' y propaga el despeje en cascada a sus vecinas.
- Registra continuamente en data/qwen_symbol_map.json.
"""
import argparse
import collections
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.match import lift, common

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:7b"
OUTPUT_MAP_PATH = ROOT / "data" / "qwen_symbol_map.json"

# Mapa de registros I/O de hardware de Game Boy Advance
GBA_IO_MAP = {
    0x04000000: "REG_DISPCNT",
    0x04000004: "REG_DISPSTAT",
    0x04000006: "REG_VCOUNT",
    0x04000008: "REG_BG0CNT",
    0x0400000A: "REG_BG1CNT",
    0x0400000C: "REG_BG2CNT",
    0x0400000E: "REG_BG3CNT",
    0x04000010: "REG_BG0HOFS",
    0x04000012: "REG_BG0VOFS",
    0x04000014: "REG_BG1HOFS",
    0x04000016: "REG_BG1VOFS",
    0x04000020: "REG_BG2PA",
    0x04000048: "REG_WIN0H",
    0x04000050: "REG_BLDCNT",
    0x04000052: "REG_BLDALPHA",
    0x04000054: "REG_BLDY",
    0x04000060: "REG_SOUND1CNT_L",
    0x04000062: "REG_SOUND1CNT_H",
    0x04000064: "REG_SOUND1CNT_X",
    0x04000082: "REG_SOUNDCNT_H",
    0x04000084: "REG_SOUNDCNT_X",
    0x04000088: "REG_SOUNDBIAS",
    0x040000B0: "REG_DMA0SAD",
    0x040000B4: "REG_DMA0DAD",
    0x040000B8: "REG_DMA0CNT_L",
    0x040000BA: "REG_DMA0CNT_H",
    0x040000BC: "REG_DMA1SAD",
    0x040000C8: "REG_DMA1CNT_H",
    0x040000D4: "REG_DMA2CNT_H",
    0x040000E0: "REG_DMA3CNT_H",
    0x04000100: "REG_TM0CNT_L",
    0x04000102: "REG_TM0CNT_H",
    0x04000130: "REG_KEYINPUT",
    0x04000132: "REG_KEYCNT",
    0x04000200: "REG_IE",
    0x04000202: "REG_IF",
    0x04000204: "REG_WAITCNT",
    0x04000208: "REG_IME",
}

def query_qwen(prompt: str, timeout: int = 40) -> str:
    """Envia una peticion de inferencia a Ollama qwen2.5-coder:7b."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 300,
        }
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res_obj = json.loads(resp.read().decode("utf-8"))
            return res_obj.get("response", "").strip()
    except Exception as ex:
        print(f"[!] Error comunicando con Ollama: {ex}")
        return ""

def load_symbol_map() -> dict:
    OUTPUT_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT_MAP_PATH.exists():
        try:
            return json.loads(OUTPUT_MAP_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_symbol_map(mapping: dict):
    OUTPUT_MAP_PATH.write_text(json.dumps(mapping, indent=2, ensure_ascii=False), encoding="utf-8")

def extract_features(code: str, known_symbols: dict) -> dict:
    """Extrae llamadas a funciones conocidas, registros I/O y constantes."""
    calls = []
    io_regs = []
    for m in re.finditer(r"\bfunc_([0-9a-fA-F]{8})\b", code):
        callee_name = f"func_{m.group(1)}"
        known_info = known_symbols.get(callee_name, {}).get("name")
        if known_info:
            calls.append(f"{callee_name} ({known_info})")
        else:
            calls.append(callee_name)

    for hex_val in re.findall(r"0x04000[0-9a-fA-F]{3}", code):
        addr = int(hex_val, 16)
        if addr in GBA_IO_MAP:
            io_regs.append(f"{GBA_IO_MAP[addr]} (0x{addr:08X})")

    return {
        "calls": sorted(list(set(calls))),
        "io_regs": sorted(list(set(io_regs))),
    }

def solve_next_symbol(e: dict, code: str, known_symbols: dict) -> dict:
    """Utiliza Qwen para despejar la funcion por restricciones conocidas."""
    feat = extract_features(code, known_symbols)
    addr = f"0x{e['addr']:08X}"
    name = e["name"]

    prompt = f"""Eres un ingeniero senior de ingenieria inversa de Game Boy Advance analizando 'Harvest Moon: Friends of Mineral Town' (C89 / Thumb).
Tu tarea es DEDUCIR Y DESPEJAR el nombre simbolico exacto de esta funcion (estilo PascalCase o snake_case de decompilacion GBA), su subsistema y su proposito.

DATOS CONOCIDOS DE LA FUNCION:
- Direccion ROM: {addr}
- Nombre actual: {name}
- Tamano: {e['size']} bytes
- Registros I/O de GBA accedidos: {', '.join(feat['io_regs']) if feat['io_regs'] else 'Ninguno directo'}
- Funciones que invoca: {', '.join(feat['calls']) if feat['calls'] else 'Ninguna'}

EXTRACTO DEL CODIGO C:
```c
{code[:1200]}
```

Responde EXCLUSIVAMENTE con un bloque JSON valido con esta estructura exacta (sin explicaciones extra):
{{
  "name": "NombreSugerido",
  "subsystem": "SubsystemName",
  "summary": "Resumen conciso de lo que hace matematicamente o en el juego"
}}"""

    resp_text = query_qwen(prompt)
    if not resp_text:
        return None

    # Extraer JSON de la respuesta
    m_json = re.search(r"\{[\s\S]*\}", resp_text)
    if m_json:
        try:
            parsed = json.loads(m_json.group(0))
            parsed["addr"] = addr
            parsed["original_name"] = name
            parsed["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
            return parsed
        except Exception:
            pass
    return None

def run_solver_loop(max_iterations: int = 0, sleep_delay: float = 1.0):
    """Bucle principal de deduccion de nombres por despeje algebraico/semantico."""
    manifest = lift.load_manifest()
    state = lift.load_state()

    print("=" * 80)
    print(" QWEN SYMBOL & NAME SOLVER :: DESPEJANDO INCÓGNITAS POR RESTRICCIONES")
    print(f" Modelo activo: {MODEL_NAME} en {OLLAMA_URL}")
    print("=" * 80)

    known_symbols = load_symbol_map()
    # Sembrar funciones Ground Truth ya identificadas
    for e in manifest:
        n = e["name"]
        if n not in known_symbols:
            st = state.get(n, {}).get("status")
            if st == "matched":
                # Conocida como Ground Truth
                pass

    iteration = 0
    while True:
        # 1. Ranking de funciones por densidad de restricciones (despejar X)
        candidates = []
        for e in manifest:
            n = e["name"]
            if n in known_symbols:
                continue

            src_file = ROOT / "src_functional" / f"{n}.c"
            if not src_file.exists():
                continue

            code = src_file.read_text(encoding="utf-8", errors="ignore")
            feat = extract_features(code, known_symbols)
            # Restricciones conocidas: numero de llamadas conocidas + registros I/O
            score = len([c for c in feat["calls"] if "(" in c]) * 3 + len(feat["io_regs"]) * 4 + len(feat["calls"])
            if score > 0:
                candidates.append((score, e, code))

        if not candidates:
            print("[*] No hay mas funciones con restricciones conocidas inmediatas. Pausando...")
            time.sleep(10)
            continue

        # Ordenar de mayor a menor densidad de restricciones
        candidates.sort(key=lambda x: x[0], reverse=True)
        score, best_e, best_code = candidates[0]

        print(f"\n[Despejando X] {best_e['name']} (tam={best_e['size']}B, densidad={score})...")
        res = solve_next_symbol(best_e, best_code, known_symbols)
        if res and "name" in res:
            sym_name = res["name"]
            subsys = res.get("subsystem", "General")
            summary = res.get("summary", "")
            known_symbols[best_e["name"]] = res
            save_symbol_map(known_symbols)
            print(f"  [DEDUCIDA] {best_e['name']} -> {sym_name} [{subsys}]: {summary}")
        else:
            print(f"  [!] No se pudo deducir {best_e['name']}")

        iteration += 1
        if max_iterations > 0 and iteration >= max_iterations:
            print(f"\n[OK] Completadas {iteration} iteraciones solicitadas.")
            break

        time.sleep(sleep_delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=0, help="Numero de funciones a resolver (0 = continuo)")
    parser.add_argument("--daemon", action="store_true", help="Correr en modo demonio continuo")
    args = parser.parse_args()

    run_solver_loop(max_iterations=args.count)

