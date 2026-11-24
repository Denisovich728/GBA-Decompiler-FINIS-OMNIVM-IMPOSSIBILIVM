"""Exportador Paralelo de Codigo C/C++ Legible y Renombrado para Port Nativo C#.

Construye `J:\\Laboratorio\\FIO-DECOMP-HMFOMT\\src_port_readable\\` completamente separado
de `src_zero_diff/` y `src_sweep/` (preservando intacto el 100% 0-Diff de GBA).

Para cada una de las 3,454 funciones:
  1. Selecciona la mejor fuente SIN __asm__ disponible:
     - readable_pure: C/C++ puro de src_sweep/ (0 __asm__)
     - readable_wip : semilla C pura de approx/ o .wip.c (normalizada con lift.normalize_c89)
     - pending_asm  : funciones que aun no tienen semilla C pura -> van a pending_asm_lift/
  2. Aplica renombrado real DENTRO del codigo fuente (definicion + llamadas func_08XXXXXX)
     usando src_sweep/symbol_map.json, y renombra param_1 -> self en metodos de clase/vtable.
  3. Agrupa las funciones legibles en modules/<Domain>.c y genera PORT_INDEX.md.
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import lift

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_OUT = Path(r"J:\Laboratorio\FIO-DECOMP-HMFOMT\src_port_readable")

CLASS_METHOD_DOMAINS = {
    "Farm", "Barn", "Coop", "Rucksack", "Farmer", "FarmHouse", "FieldPlot",
    "ShippingBin", "ToolChest", "Fridge", "Shelf", "RecordPlayer",
    "AEntity", "AScene", "AScriptEngine", "ScriptVM", "Cow", "Sheep",
    "Horse", "HarvestSprite", "HeldItem", "Item", "Livestock", "Dog",
}

WEAK_GROUP_RE = re.compile(r"^code_[0-9A-Fa-f]+")


def has_inline_asm(txt: str) -> bool:
    if not txt:
        return True
    if "__asm__" in txt or "asm volatile" in txt:
        return True
    if re.search(r"\basm\s*\(", txt) or re.search(r'\basm\s+"', txt):
        return True
    return False


def strip_prelude(code: str) -> str:
    if "#define NULL 0" in code:
        return code.split("#define NULL 0")[-1].strip()
    if "#define FALSE 0" in code:
        return code.split("#define FALSE 0")[-1].strip()
    return code.strip()


def sanitize_filename(dom: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", dom).strip("_")
    return s or "Misc"


def rename_identifiers_in_code(code: str, info: dict, name_lookup: dict) -> str:
    def _repl(m):
        orig = m.group(0)
        target = name_lookup.get(orig)
        return target if target else orig

    out = re.sub(r"\bfunc_[0-9A-F]{8}\b", _repl, code)

    dom = info.get("domain", "")
    meth = info.get("method", "")
    is_method = (
        dom in CLASS_METHOD_DOMAINS
        or meth in ("Ctor", "Dtor")
        or meth.startswith("vfunc_")
        or info.get("source") == "vtable_algebra"
    )
    if is_method and re.search(r"\bparam_1\b", out):
        out = re.sub(r"\bparam_1\b", "self", out)
    return out


def export_readable_port(out_dir: Path = DEFAULT_OUT):
    rom = common.load_rom()
    manifest = common.load_manifest()
    sym_path = common.TREE_DIR / "symbol_map.json"
    if not sym_path.exists():
        raise FileNotFoundError(f"No existe {sym_path}; ejecuta symbol_algebra_solver.py primero.")
    symbol_map = json.loads(sym_path.read_text(encoding="utf-8"))
    name_lookup = {k: v["clean_name"] for k, v in symbol_map.items()}

    out_dir.mkdir(parents=True, exist_ok=True)
    mods_dir = out_dir / "modules"
    pend_dir = out_dir / "pending_asm_lift"
    for d in (mods_dir, pend_dir):
        if d.exists():
            for old_f in d.glob("*.c"):
                old_f.unlink()
        d.mkdir(parents=True, exist_ok=True)

    readable_by_mod = collections.defaultdict(list)
    pending_by_bank = collections.defaultdict(list)
    counts = collections.Counter()

    # Contar frecuencias de dominio para decidir agrupar dominios pequenos (< 4 funcs)
    dom_freq = collections.Counter(symbol_map[e["name"]]["domain"] for e in manifest if e["name"] in symbol_map)

    for e in sorted(manifest, key=lambda x: x["addr"]):
        orig = e["name"]
        info = symbol_map.get(orig, {
            "addr": f"0x{e['addr']:08X}",
            "size": e["size"],
            "domain": "Misc",
            "method": orig,
            "clean_name": orig,
            "source": "unknown",
            "confidence": "HEURISTIC",
        })
        dom = info["domain"]
        c_path = common.TREE_DIR / e["file"]
        approx_p = common.TREE_DIR / "approx" / f"{orig}.c"
        wip_p = c_path.with_suffix(".wip.c")

        raw_main = c_path.read_text(encoding="utf-8", errors="replace") if c_path.exists() else ""
        chosen_origin = None
        chosen_code = None

        if raw_main and not has_inline_asm(raw_main):
            chosen_origin = "pure"
            chosen_code = strip_prelude(raw_main)
        else:
            for cand_p in (approx_p, wip_p):
                if cand_p.exists():
                    cand_txt = cand_p.read_text(encoding="utf-8", errors="replace")
                    if not has_inline_asm(cand_txt):
                        norm = lift.normalize_c89(cand_txt, rom=rom, e=e)
                        norm = strip_prelude(norm)
                        if norm and not has_inline_asm(norm) and orig in norm:
                            chosen_origin = "wip"
                            chosen_code = norm
                            break

        header_comment = (
            f"/* {info['addr']} ({e['size']}B) | {info['clean_name']} (orig: {orig}) | "
            f"origin: {chosen_origin or 'pending_asm'} | domain: {dom} | {info['confidence']} / {info['source']} */"
        )

        if chosen_code is not None:
            counts[f"readable_{chosen_origin}"] += 1
            renamed = rename_identifiers_in_code(chosen_code, info, name_lookup)
            # Decidir archivo destino de modulo
            if dom in CLASS_METHOD_DOMAINS or dom_freq[dom] >= 4:
                mod_name = sanitize_filename(dom)
            elif WEAK_GROUP_RE.match(dom):
                mod_name = sanitize_filename(dom)
            else:
                mod_name = "Misc_Subsystems"
            readable_by_mod[mod_name].append((header_comment, renamed))
        else:
            counts["pending_asm"] += 1
            mod_name = sanitize_filename(dom) if (dom_freq[dom] >= 8 or dom in CLASS_METHOD_DOMAINS) else f"bank_{e['addr'] & 0xFFFF0000:08X}"
            body = strip_prelude(raw_main) if raw_main else f"/* sin cuerpo */"
            pending_by_bank[mod_name].append((header_comment, body))

    prelude_header = (
        "#include <stdint.h>\n"
        "typedef uint8_t u8;\ntypedef uint16_t u16;\ntypedef uint32_t u32;\n"
        "typedef int8_t s8;\ntypedef int16_t s16;\ntypedef int32_t s32;\n"
        "#ifndef __cplusplus\n"
        "typedef u32 bool;\n#define true 1\n#define false 0\n"
        "#endif\n"
        "#ifndef NULL\n#define NULL 0\n#endif\n\n"
    )

    mod_stats = []
    for mod_name, entries in sorted(readable_by_mod.items(), key=lambda x: (-len(x[1]), x[0])):
        out_f = mods_dir / f"{mod_name}.c"
        chunks = [f"/* FIO-DECOMP-HMFOMT :: Port Readable Module: {mod_name} ({len(entries)} functions) */\n", prelude_header]
        for h_cmt, body in entries:
            chunks.append(f"{h_cmt}\n{body}\n\n")
        out_f.write_text("".join(chunks), encoding="utf-8")
        mod_stats.append((mod_name, len(entries)))

    pend_stats = []
    for mod_name, entries in sorted(pending_by_bank.items(), key=lambda x: (-len(x[1]), x[0])):
        out_f = pend_dir / f"{mod_name}_asm.c"
        chunks = [f"/* Pending CFG->C Lift: {mod_name} ({len(entries)} functions) */\n", prelude_header]
        for h_cmt, body in entries:
            chunks.append(f"{h_cmt}\n{body}\n\n")
        out_f.write_text("".join(chunks), encoding="utf-8")
        pend_stats.append((mod_name, len(entries)))

    total_readable = counts["readable_pure"] + counts["readable_wip"]
    total = total_readable + counts["pending_asm"]
    idx_lines = [
        "# Indice del Arbol Legible para Port C# (`src_port_readable/`)",
        "",
        "Carpeta paralela separada de `src_zero_diff/` para portar la logica a C# con nombres reales.",
        "",
        f"- **Funciones totales:** {total}",
        f"- **Listas en C/C++ legible (sin `__asm__`):** {total_readable} ({(total_readable/total)*100:.2f}%)",
        f"  - Ya purificadas a 0-Diff (`readable_pure`): {counts['readable_pure']}",
        f"  - Recuperadas desde `.wip.c` / `approx/` (`readable_wip`): {counts['readable_wip']}",
        f"- **Pendientes de levantamiento CFG (`pending_asm_lift/`):** {counts['pending_asm']} ({(counts['pending_asm']/total)*100:.2f}%)",
        "",
        "## Modulos Legibles Generados (`modules/`)",
        "",
        "| Archivo | Funciones |",
        "|---|---|",
    ]
    for mn, cnt in mod_stats:
        idx_lines.append(f"| `modules/{mn}.c` | {cnt} |")
    idx_lines.extend(["", "## Pendientes por Levantar (`pending_asm_lift/`)", "", "| Archivo | Funciones |", "|---|---|"])
    for mn, cnt in pend_stats:
        idx_lines.append(f"| `pending_asm_lift/{mn}_asm.c` | {cnt} |")
    idx_lines.append("")
    (out_dir / "PORT_INDEX.md").write_text("\n".join(idx_lines), encoding="utf-8")

    print("=" * 70)
    print(f"PORT READABLE EXPORTER :: {out_dir}")
    print("=" * 70)
    print(f"Listas en C/C++ legible: {total_readable}/{total} ({(total_readable/total)*100:.2f}%) "
          f"[pure={counts['readable_pure']}, wip={counts['readable_wip']}]")
    print(f"Pendientes en pending_asm_lift/: {counts['pending_asm']} ({(counts['pending_asm']/total)*100:.2f}%)")
    print(f"Modulos C/C++ escritos: {len(mod_stats)} | Archivos pending ASM: {len(pend_stats)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exporta arbol C/C++ legible con simbolos renombrados para port C#")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="Carpeta de salida paralela")
    args = ap.parse_args()
    export_readable_port(Path(args.out))
