"""FOMT-MATCH-ENGINE :: MOTOR DE CONTRASTE BINARIO ARM -> C89

Algoritmo de contraste contra el ensamblador original:
1. Desensambla el binario original de la ROM (Target) y el binario compilado por agbcc (Got) con Capstone THUMB.
2. Compara instrucción por instrucción para extraer el perfil exacto de discrepancias:
   - Discrepancias de tipo de acceso a memoria (str vs strb, ldr vs ldrb, ldrh, strh)
   - Inversión de orden en instrucciones adyacentes (A; B en Target vs B; A en Got)
   - Extracción de bitfields vs máscaras AND
   - Reutilización de registros con cero/uno encadenados
   - Aritmética de punteros vs struct / array indexing
3. Aplica mutaciones guiadas directamente por el diagnóstico de contraste.
4. Itera de forma continua / indefinida sobre las funciones de alta paridad (>=80% y >=90%)
   hasta alcanzar 100% Zero-Diff exacto.
"""
import argparse
import os
import re
import sys
import time
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
import lift

TREE_DIR = common.TREE_DIR
STOP_FLAG = TREE_DIR / "control" / "stop.flag"

MD_THUMB = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def log(msg=""):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{ts} {msg}", flush=True)


def stop_requested() -> bool:
    return STOP_FLAG.exists()


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


def disassemble(code_bytes: bytes, base_addr: int):
    return list(MD_THUMB.disasm(code_bytes, base_addr))


def analyze_contrast(target_bytes: bytes, got_bytes: bytes, base_addr: int):
    t_ins = disassemble(target_bytes, base_addr)
    g_ins = disassemble(got_bytes, base_addr)

    diffs = []
    max_len = max(len(t_ins), len(g_ins))
    min_len = min(len(t_ins), len(g_ins))

    has_strb_mismatch = False
    has_str_mismatch = False
    has_ldrb_mismatch = False
    has_ldr_mismatch = False
    has_bitfield_shift = False
    has_swapped_pair = False
    zero_reuse_target = False

    for i in range(min_len):
        t_m, t_op = t_ins[i].mnemonic, t_ins[i].op_str
        g_m, g_op = g_ins[i].mnemonic, g_ins[i].op_str

        if t_m != g_m or t_op != g_op:
            diffs.append((i, t_ins[i].address, f"{t_m} {t_op}", g_ins[i].address, f"{g_m} {g_op}"))

            # Deteccion de anchos de tipo
            if t_m == "strb" and g_m == "str":
                has_strb_mismatch = True
            elif t_m == "str" and g_m == "strb":
                has_str_mismatch = True
            elif t_m == "ldrb" and g_m == "ldr":
                has_ldrb_mismatch = True
            elif t_m == "ldr" and g_m == "ldrb":
                has_ldr_mismatch = True

            # Deteccion de bitfield shift
            if t_m == "lsls" and g_m in ("movs", "ands"):
                has_bitfield_shift = True

            # Deteccion de par invertido
            if i + 1 < min_len:
                t_next = f"{t_ins[i+1].mnemonic} {t_ins[i+1].op_str}"
                g_next = f"{g_ins[i+1].mnemonic} {g_ins[i+1].op_str}"
                if f"{t_m} {t_op}" == g_next and f"{g_m} {g_op}" == t_next:
                    has_swapped_pair = True

    # Comprobar si Target reutiliza registros para stores de cero
    target_zero_stores = sum(1 for ins in t_ins if ins.mnemonic in ("str", "strb", "strh") and any(r in ins.op_str for r in ["r0", "r1", "r2", "r3"]))
    if target_zero_stores >= 2:
        zero_reuse_target = True

    return {
        "len_target": len(t_ins),
        "len_got": len(g_ins),
        "diff_count": len(diffs),
        "diffs": diffs,
        "has_strb_mismatch": has_strb_mismatch,
        "has_str_mismatch": has_str_mismatch,
        "has_ldrb_mismatch": has_ldrb_mismatch,
        "has_ldr_mismatch": has_ldr_mismatch,
        "has_bitfield_shift": has_bitfield_shift,
        "has_swapped_pair": has_swapped_pair,
        "zero_reuse_target": zero_reuse_target,
    }


def generate_contrast_mutations(code: str, diag: dict) -> list[str]:
    mutations = []

    # 1. Mutaciones derivadas de bitfield shift
    if diag["has_bitfield_shift"] or "& 0x" in code:
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

    # 2. Mutaciones de ancho de tipo
    if diag["has_strb_mismatch"]:
        mutations.append(code.replace("*(u32 *)", "*(u8 *)"))
        mutations.append(code.replace("*(int *)", "*(u8 *)"))
        mutations.append(code.replace("*(s32 *)", "*(u8 *)"))
    if diag["has_str_mismatch"]:
        mutations.append(code.replace("*(u8 *)", "*(u32 *)"))
        mutations.append(code.replace("*(s8 *)", "*(u32 *)"))
    if diag["has_ldrb_mismatch"]:
        mutations.append(code.replace("*(u32 *)", "*(u8 *)"))
        mutations.append(code.replace("*(int *)", "*(u8 *)"))
    if diag["has_ldr_mismatch"]:
        mutations.append(code.replace("*(u8 *)", "*(u32 *)"))

    # 3. Encadenamiento de cero o uno en stores
    zero_stores = list(re.finditer(r"\*\(u8\s*\*\)\s*\(([^;]+)\)\s*=\s*0\s*;", code))
    if zero_stores:
        for zs in zero_stores:
            m_code = code[:zs.start()] + f"*(u8 *)({zs.group(1)}) = zero = 0;" + code[zs.end():]
            if "u32 zero;" not in m_code:
                idx = m_code.find("{")
                if idx != -1:
                    m_code = m_code[:idx+1] + "\n  u32 zero;\n" + m_code[idx+1:]
            mutations.append(m_code)

    one_stores = list(re.finditer(r"\*\(u8\s*\*\)\s*\(([^;]+)\)\s*=\s*1\s*;", code))
    if one_stores:
        for os_m in one_stores:
            m_code = code[:os_m.start()] + f"*(u8 *)({os_m.group(1)}) = (one = 1);" + code[os_m.end():]
            if "int one;" not in m_code:
                idx = m_code.find("{")
                if idx != -1:
                    m_code = m_code[:idx+1] + "\n  int one;\n" + m_code[idx+1:]
            mutations.append(m_code)

    # 4. Spilling intermedio en stack
    m_stack = re.search(r"(\w+)\s*=\s*\*(\w+);\s*\*\2\s*=\s*0;", code)
    if m_stack:
        var_stack, var_ptr = m_stack.group(1), m_stack.group(2)
        repl = f"val = *{var_ptr}; *{var_ptr} = 0; {var_stack} = val;"
        m_code = code.replace(m_stack.group(0), repl)
        if "u32 val;" not in m_code and "int val;" not in m_code:
            idx = m_code.find("{")
            if idx != -1:
                m_code = m_code[:idx+1] + "\n  u32 val;\n" + m_code[idx+1:]
        mutations.append(m_code)

    # 5. Punteros a sub-objetos en llamadas
    sub_matches = list(re.finditer(r"func_\w+\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*\*\(u32\s*\*\)\s*\(\s*\1\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*\);", code))
    if sub_matches:
        for sm in sub_matches:
            m_code = code
            idx = m_code.find("{")
            if idx != -1 and "u32 *sub;" not in m_code:
                m_code = m_code[:idx+1] + "\n  u32 *sub;\n" + m_code[idx+1:]
            m_code = m_code.replace(sm.group(0), f"sub = (u32 *)({sm.group(1)} + {sm.group(2)});\n  {sm.group(0).split('(')[0]}(sub, sub[1]);")
            mutations.append(m_code)

    # 6. Fallback general de anchos si diffs persisten
    mutations.append(code.replace("*(u32 *)", "*(u8 *)"))
    mutations.append(code.replace("*(u8 *)", "*(u32 *)"))
    mutations.append(code.replace("*(int *)", "*(u8 *)"))
    mutations.append(code.replace("*(u8 *)", "*(int *)"))

    return list(dict.fromkeys([m for m in mutations if m != code]))


def run_contrast_cycle(min_score: float = 0.85, max_score: float = 0.9999, cycle_num: int = 1):
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
    candidates = [e for _, e in candidates]

    log(f"\n---> CICLO DE CONTRASTE #{cycle_num} :: {len(candidates)} funciones en rango [{min_score*100:.1f}% - {max_score*100:.1f}%]")

    matches_in_cycle = 0
    improved_in_cycle = 0
    presets = ["agbcc_O2", "agbcc_O1", "agbcc_O0"]

    for idx, e in enumerate(candidates, 1):
        if stop_requested():
            log("[!] Detencion solicitada (stop.flag detectado).")
            return -1, -1

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
            lift.save_matched(e, c_clean, base_pr, manifest, state, 0, "contrast-exact-pre", target=target, rom=rom, model="contrast-engine", phase_num=2)
            matches_in_cycle += 1
            log(f"  [+] [MATCH 100% ZERO-DIFF] {name} verificado exacto (preset {base_pr})!")
            common.save_state(state)
            common.sync_collection()
            continue

        if got0 is None:
            continue

        diag = analyze_contrast(target, got0, e["addr"])
        mutations = generate_contrast_mutations(c_clean, diag)

        best_sc = max(base_sc, b0)
        best_code = c_clean
        best_pr = base_pr
        matched = False

        for m_idx, m_code in enumerate(mutations):
            sc, pr, got, ex, _ = lift.evaluate(e, m_code, manifest, target, presets)
            if ex:
                lift.save_matched(e, m_code, pr, manifest, state, m_idx + 1, "contrast-engine", target=target, rom=rom, model="contrast-engine", phase_num=2)
                matches_in_cycle += 1
                matched = True
                log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ({b0*100:.1f}% -> 100.0%) resuelto via contraste #{m_idx+1} (preset {pr})!")
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
            improved_in_cycle += 1
            log(f"  [^] [MEJORA] {name}: {b0*100:.1f}% -> {best_sc*100:.1f}% (preset {best_pr}, diffs: {diag['diff_count']})")
            state[name]["best"] = round(best_sc, 4)
            state[name]["preset"] = best_pr
            approx_path = TREE_DIR / "approx" / f"{name}.c"
            approx_path.parent.mkdir(parents=True, exist_ok=True)
            approx_path.write_text(best_code, encoding="utf-8")
            common.save_state(state)

    return matches_in_cycle, improved_in_cycle


def main():
    parser = argparse.ArgumentParser(description="Motor de Contraste Binario ARM contra C89 (Indefinido)")
    parser.add_argument("--min-score", type=float, default=0.85, help="Puntaje minimo (default: 0.85)")
    parser.add_argument("--max-score", type=float, default=0.9999, help="Puntaje maximo (default: 0.9999)")
    parser.add_argument("--max-cycles", type=int, default=0, help="Max ciclos (0 = indefinido hasta terminar)")
    args = parser.parse_args()

    if STOP_FLAG.exists():
        try:
            STOP_FLAG.unlink()
        except OSError:
            pass

    log("=" * 76)
    log(" FOMT-MATCH-ENGINE :: MOTOR DE CONTRASTE BINARIO ARM -> C89 INDEFINIDO")
    log("=" * 76)
    log(f" [*] Rango Objetivo: [{args.min_score*100:.1f}% - {args.max_score*100:.1f}%]")
    log(f" [*] Modo: Bucle Continuo Indefinido (Itera hasta 100% Zero-Diff)")
    log(" [*] Para detener: Ctrl+C")
    log("=" * 76)

    cycle = 1
    total_matches = 0
    total_improved = 0

    try:
        while True:
            if stop_requested():
                log("[!] Detencion solicitada (stop.flag detectado).")
                break

            m, imp = run_contrast_cycle(min_score=args.min_score, max_score=args.max_score, cycle_num=cycle)
            if m == -1:
                break

            total_matches += m
            total_improved += imp

            state = common.load_state()
            manifest = common.load_manifest()
            matched_count = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "matched")

            log(f"[*] Fin ciclo #{cycle} | Matches nuevos: {m} | Mejoras: {imp} | Total acumulado: {matched_count}/{len(manifest)} ({matched_count/len(manifest)*100:.2f}%)")

            if args.max_cycles > 0 and cycle >= args.max_cycles:
                log(f"[*] Limite de ciclos ({args.max_cycles}) alcanzado.")
                break

            # Si en un ciclo no hubo ni matches ni mejoras, baja ligeramente el piso para abrir mas candidatos o espera 5s
            if m == 0 and imp == 0:
                if args.min_score > 0.80:
                    args.min_score = round(args.min_score - 0.02, 2)
                    log(f"[*] Sin cambios en ciclo #{cycle} -> ampliando rango hacia {args.min_score*100:.1f}%...")
                else:
                    log("[*] Banda completamente exprimida. Pausando 10s antes del siguiente ciclo...")
                    time.sleep(10)

            cycle += 1
            time.sleep(1)

    except KeyboardInterrupt:
        log("\n[!] Proceso detenido por el usuario.")

    log("\n" + "=" * 76)
    log(" SESION DE CONTRASTE BINARIO COMPLETADA")
    log(f" [+] Matches 100% Zero-Diff nuevos consolidados: {total_matches}")
    log(f" [^] Funciones mejoradas: {total_improved}")
    log("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())

