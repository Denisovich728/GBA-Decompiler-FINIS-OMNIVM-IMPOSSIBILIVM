"""FOMT-MATCH-ENGINE :: BARRIDO QUIRURGICO DETERMINISTA (>=90% A ZERO-DIFF)

Aplica el conjunto de heurísticas y mutaciones exactas descubiertas por Hermes:
1. Reemplazo de máscaras AND por bitfield shifts: (X & 0x3F) -> ((u32)X << 26) >> 26
2. Corrección de anchos de tipo: *(u32 *) <-> *(u8 *), *(int *) <-> *(u16 *)
3. Encadenamiento de cero/uno en registros: *(u8 *) = zero = 0;, *(u8 *) = (one = 1);
4. Secuenciamiento de almacenamiento intermedio en stack: val = *p; *p = 0; stack = val;
5. Abstracción de sub-objetos: sub = (u32 *)(p + off); func(sub, sub[1]);
6. Desreferencia por array indexado vs aritmética de punteros
7. Micro-permutación de orden de asignaciones independientes
"""
import argparse
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import lift

TREE_DIR = common.TREE_DIR
STOP_FLAG = TREE_DIR / "control" / "stop.flag"


def log(msg=""):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{ts} {msg}", flush=True)


def get_candidate_code(name: str) -> str:
    search_dirs = [
        TREE_DIR / "permute" / "code" / f"{name}.c",
        TREE_DIR / "approx" / f"{name}.c",
        TREE_DIR / "collection" / "approx" / f"{name}.c",
        TREE_DIR / "collection" / "wip" / f"{name}.wip.c",
    ]
    for p in search_dirs:
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            if name in txt and "{" in txt:
                return txt
    return ""


def generate_surgical_mutations(code: str, func_name: str) -> list[str]:
    mutations = []

    # 1. Bitfield masks: & 0x3f, & 0x1f, & 0x7f, & 0x0f
    masks = [
        (r"\(\s*([^()]+)\s*&\s*0x3f\s*\)", 26),
        (r"\(\s*([^()]+)\s*&\s*0x1f\s*\)", 27),
        (r"\(\s*([^()]+)\s*&\s*0x7f\s*\)", 25),
        (r"\(\s*([^()]+)\s*&\s*0x0f\s*\)", 28),
        (r"([^()]+)\s*&\s*0x3f\b", 26),
        (r"([^()]+)\s*&\s*0x1f\b", 27),
        (r"([^()]+)\s*&\s*0x7f\b", 25),
        (r"([^()]+)\s*&\s*0x0f\b", 28),
    ]
    for pat, shift in masks:
        if re.search(pat, code):
            m_code = re.sub(pat, rf"(((u32)(\1) << {shift}) >> {shift})", code)
            if m_code != code:
                mutations.append(m_code)

    # 2. Store width conversions
    # *(u32 *)(X) = 0 -> *(u8 *)(X) = 0
    if "*(u32 *)" in code:
        mutations.append(code.replace("*(u32 *)", "*(u8 *)"))
        mutations.append(code.replace("*(u32 *)", "*(u16 *)"))
    if "*(int *)" in code:
        mutations.append(code.replace("*(int *)", "*(u8 *)"))
        mutations.append(code.replace("*(int *)", "*(u16 *)"))
    if "*(s32 *)" in code:
        mutations.append(code.replace("*(s32 *)", "*(u8 *)"))
        mutations.append(code.replace("*(s32 *)", "*(u16 *)"))
    if "*(u8 *)" in code:
        mutations.append(code.replace("*(u8 *)", "*(u32 *)"))
    if "*(s8 *)" in code:
        mutations.append(code.replace("*(s8 *)", "*(u32 *)"))
    if "*(u16 *)" in code:
        mutations.append(code.replace("*(u16 *)", "*(u32 *)"))

    # 3. Stack store sequencing
    # uStack_X = *param_2; *param_2 = 0; -> val = *param_2; *param_2 = 0; uStack_X = val;
    m_stack = re.search(r"(\w+)\s*=\s*\*(\w+);\s*\*\2\s*=\s*0;", code)
    if m_stack:
        var_stack, var_ptr = m_stack.group(1), m_stack.group(2)
        repl = f"val = *{var_ptr}; *{var_ptr} = 0; {var_stack} = val;"
        m_code = code.replace(m_stack.group(0), repl)
        if "u32 val;" not in m_code and "int val;" not in m_code:
            # inject declaration at top of function block
            idx = m_code.find("{")
            if idx != -1:
                m_code = m_code[:idx+1] + "\n  u32 val;\n" + m_code[idx+1:]
        mutations.append(m_code)

    # 4. Zero chaining on stores
    # *(u8 *)(param + off) = 0; -> *(u8 *)(param + off) = zero = 0;
    zero_stores = list(re.finditer(r"\*\(u8\s*\*\)\s*\(([^;]+)\)\s*=\s*0\s*;", code))
    if zero_stores:
        for zs in zero_stores:
            m_code = code[:zs.start()] + f"*(u8 *)({zs.group(1)}) = zero = 0;" + code[zs.end():]
            if "u32 zero;" not in m_code:
                idx = m_code.find("{")
                if idx != -1:
                    m_code = m_code[:idx+1] + "\n  u32 zero;\n" + m_code[idx+1:]
            mutations.append(m_code)

    # 5. One chaining on stores: *(u8 *)(param + off) = (one = 1);
    one_stores = list(re.finditer(r"\*\(u8\s*\*\)\s*\(([^;]+)\)\s*=\s*1\s*;", code))
    if one_stores:
        for os_m in one_stores:
            m_code = code[:os_m.start()] + f"*(u8 *)({os_m.group(1)}) = (one = 1);" + code[os_m.end():]
            if "int one;" not in m_code:
                idx = m_code.find("{")
                if idx != -1:
                    m_code = m_code[:idx+1] + "\n  int one;\n" + m_code[idx+1:]
            mutations.append(m_code)

    # 6. Return value forwarding
    # uVar1 = func_XXX(); uVar1 = *param; -> param[1] = func_XXX();
    m_fwd = re.search(r"(\w+)\s*=\s*(\w+\([^;]+\));\s*\1\s*=\s*\*(\w+);\s*(\w+)\[1\]\s*=\s*\1;", code)
    if m_fwd:
        v1, call_fn, p_src, p_dst = m_fwd.groups()
        repl = f"{p_dst}[1] = {call_fn};\n  val = *{p_src};\n  *{p_src} = 0;\n  {p_dst}[2] = val;"
        m_code = code.replace(m_fwd.group(0), repl)
        if "u32 val;" not in m_code:
            idx = m_code.find("{")
            if idx != -1:
                m_code = m_code[:idx+1] + "\n  u32 val;\n" + m_code[idx+1:]
        mutations.append(m_code)

    # 7. Sub-pointer extraction for repetitive calls (sub = (u32 *)(param + off))
    sub_matches = list(re.finditer(r"func_\w+\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*\*\(u32\s*\*\)\s*\(\s*\1\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*\);", code))
    if sub_matches:
        for sm in sub_matches:
            m_code = code
            idx = m_code.find("{")
            if idx != -1 and "u32 *sub;" not in m_code:
                m_code = m_code[:idx+1] + "\n  u32 *sub;\n" + m_code[idx+1:]
            # replace pattern
            m_code = m_code.replace(sm.group(0), f"sub = (u32 *)({sm.group(1)} + {sm.group(2)});\n  {sm.group(0).split('(')[0]}(sub, sub[1]);")
            mutations.append(m_code)

    return list(dict.fromkeys(mutations))


def sweep_surgical(min_score: float = 0.90, max_score: float = 0.9999, limit: int = 150):
    log("=" * 76)
    log(" FOMT-MATCH-ENGINE :: BARRIDO QUIRURGICO DETERMINISTA (HERMES)")
    log("=" * 76)
    log(f" [*] Rango Objetivo: [{min_score*100:.1f}% - {max_score*100:.1f}%]")
    log(f" [*] Presets: agbcc_O2 / agbcc_O1 / agbcc_O0")
    log("=" * 76)

    manifest = common.load_manifest()
    state = common.load_state()
    rom = common.load_rom()

    candidates = []
    for e in manifest:
        name = e["name"]
        st = state.get(name, {})
        if st.get("status") == "matched":
            continue
        sc = float(st.get("best", 0.0) or 0.0)
        if min_score <= sc <= max_score:
            candidates.append((sc, e))

    candidates.sort(key=lambda x: -x[0])
    candidates = [e for _, e in candidates][:limit]

    log(f"[*] Candidatos seleccionados para intervencion quirurgica: {len(candidates)} funciones")
    if not candidates:
        log("[!] No hay candidatos en el rango especificado.")
        return 0

    new_matches = 0
    improved = 0
    presets = ["agbcc_O2", "agbcc_O1", "agbcc_O0"]

    for idx, e in enumerate(candidates, 1):
        if STOP_FLAG.exists():
            log("[!] Detencion solicitada (stop.flag detectado).")
            break

        name = e["name"]
        curr_st = state.get(name, {})
        b0 = float(curr_st.get("best", 0.0) or 0.0)
        target = lift.rom_bytes(rom, e["addr"], e["size"])

        code = get_candidate_code(name)
        if not code:
            continue

        c_clean = lift.extract_c(code, rom=rom, e=e)
        base_sc, base_pr, got0, exact0, _ = lift.evaluate(e, c_clean, manifest, target, presets)
        if exact0:
            lift.save_matched(e, c_clean, base_pr, manifest, state, 0, "surgical-exact-pre", target=target, rom=rom, model="hermes-surgical", phase_num=2)
            new_matches += 1
            log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ya era exacto (preset {base_pr})!")
            continue

        mutations = generate_surgical_mutations(c_clean, name)
        best_sc = max(base_sc, b0)
        best_code = c_clean
        best_pr = base_pr
        matched = False

        for m_idx, m_code in enumerate(mutations):
            sc, pr, got, ex, _ = lift.evaluate(e, m_code, manifest, target, presets)
            if ex:
                lift.save_matched(e, m_code, pr, manifest, state, m_idx + 1, "hermes-surgical", target=target, rom=rom, model="hermes-surgical", phase_num=2)
                new_matches += 1
                matched = True
                log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ({b0*100:.1f}% -> 100.0%) con mutacion #{m_idx+1} (preset {pr})!")
                break
            if sc > best_sc + 1e-5:
                best_sc = sc
                best_code = m_code
                best_pr = pr

        if matched:
            common.save_state(state)
            common.sync_collection()
            continue

        if best_sc > b0 + 1e-5:
            improved += 1
            log(f"  [^] [MEJORA] {name}: {b0*100:.1f}% -> {best_sc*100:.1f}% (preset {best_pr})")
            state[name]["best"] = round(best_sc, 4)
            state[name]["preset"] = best_pr
            # Guardar en approx/
            approx_path = TREE_DIR / "approx" / f"{name}.c"
            approx_path.parent.mkdir(parents=True, exist_ok=True)
            approx_path.write_text(best_code, encoding="utf-8")
            common.save_state(state)
        else:
            if idx % 10 == 0 or b0 >= 0.95:
                log(f"  [.] [{idx}/{len(candidates)}] {name}: base {b0*100:.1f}%, probado con {len(mutations)} mutaciones (sin match)")

    log("\n" + "=" * 76)
    log(" BARRIDO QUIRURGICO DETERMINISTA COMPLETADO")
    log(f" [+] Matches 100% Zero-Diff nuevos: {new_matches}")
    log(f" [^] Funciones mejoradas: {improved}")
    total_matched = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "matched")
    log(f" [*] MARCADOR TOTAL CONSOLIDADO: {total_matched} / {len(manifest)} ({total_matched/len(manifest)*100:.2f}%)")
    log("=" * 76)
    return new_matches


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Barrido Quirúrgico Determinista Hermes")
    parser.add_argument("--min-score", type=float, default=0.90, help="Puntaje mínimo (default: 0.90)")
    parser.add_argument("--max-score", type=float, default=0.9999, help="Puntaje máximo (default: 0.9999)")
    parser.add_argument("--limit", type=int, default=150, help="Límite de funciones a procesar")
    args = parser.parse_args()

    sweep_surgical(min_score=args.min_score, max_score=args.max_score, limit=args.limit)

