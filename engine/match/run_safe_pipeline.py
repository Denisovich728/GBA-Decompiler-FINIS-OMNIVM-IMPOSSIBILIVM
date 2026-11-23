"""FOMT-MATCH-ENGINE :: Motor Resiliente Auto-Retroalimentado (No Abandona hasta 100%).

Arquitectura Denisovich728:
1. Bucle Cerrado por Funcion (Non-Abandoning Loop):
   - Toma la funcion objetivo y ejecuta rondas sucesivas de diagnostico ASM-Diff (Capstone),
     leyes algebraicas Rosetta (1..16), permutaciones factoriales de declaraciones (n!),
     mascaras de registros (2^k combinations de `register`), vecindario completo de ediciones
     (`exact_permuter.neighbors`) y saltos de cuenca multi-paso (`permuter.mutate` de 2..5 pasos).
   - Cada vez que un candidato sube aunque sea +0.01% de paridad (o empata con una estructura nueva),
     guarda un CHECKPOINT ATOMICO inmediato en disco (`state.json`, `approx/`, `.wip.c`, `logs/checkpoint.log`)
     y usa ese nuevo codigo como semilla padre de la siguiente ronda.
   - NO abandona la funcion hasta lograr el 100% Zero-Diff (salvo que la funcion carezca por completo
     de semilla compilable o se cree `logs/skip.flag` / se indique `--max-rounds N`).
2. Retroalimentacion Viva del Corpus Rosetta:
   - Cada nuevo match 100% se indexa en caliente dentro de `RosettaCorpus` (`rosetta.add_matched`),
     sirviendo inmediatamente como Piedra Rosetta para las siguientes funciones de la cola.
3. Telemetria en Vivo:
   - Muestra `[Orden/Pendientes] [Matches/3068 (%)] [Funcion] [Calif. Previa -> Actual] [Ronda #R | Evals] [Primer Diff ASM]`.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import itertools
import json
import os
import random
import re
import sqlite3
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB  # noqa
import common
import exact_permuter as EP
import lift
import permuter as P
import rosetta_decompiler as RD

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_LOG = LOG_DIR / "checkpoint.log"
TANDA_DIR = ROOT / "tandas" / "tanda_multithread"
TANDA_DIR.mkdir(parents=True, exist_ok=True)
TANDA_LOG = LOG_DIR / "tanda_multithread.log"
SKIP_FLAG = LOG_DIR / "skip.flag"
STOP_FLAG = common.TREE_DIR / "control" / "stop.flag"

_THUMB_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
_ARM_MD = Cs(CS_ARCH_ARM, CS_MODE_ARM)
_LOG_LOCK = threading.Lock()
_STATE_LOCK = threading.Lock()

EXPLORED_DB = LOG_DIR / "explored_candidates.db"
_DB_LOCK = threading.Lock()
_EXPL_LOCK = threading.Lock()
_EXPL = collections.defaultdict(set)  # func -> {(norm_hash, preset)}


def init_explored_db():
    with _DB_LOCK:
        try:
            with sqlite3.connect(EXPLORED_DB) as conn:
                row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='explored'").fetchone()
                if row:
                    cols = [r[1] for r in conn.execute("PRAGMA table_info(explored)").fetchall()]
                    if "preset" not in cols:
                        conn.execute("CREATE TABLE explored_v2 (func TEXT, norm_hash TEXT, preset TEXT, PRIMARY KEY(func, norm_hash, preset))")
                        conn.execute("INSERT OR IGNORE INTO explored_v2 (func, norm_hash, preset) SELECT func, norm_hash, '' FROM explored")
                        conn.execute("DROP TABLE explored")
                        conn.execute("ALTER TABLE explored_v2 RENAME TO explored")
                else:
                    conn.execute("CREATE TABLE IF NOT EXISTS explored (func TEXT, norm_hash TEXT, preset TEXT, PRIMARY KEY(func, norm_hash, preset))")
                conn.commit()
        except sqlite3.Error:
            pass


def load_explored(func_name: str):
    """Carga en memoria el conjunto de candidatos explorados para la funcion (1 SELECT por funcion)."""
    try:
        with _DB_LOCK:
            with sqlite3.connect(EXPLORED_DB) as conn:
                rows = conn.execute("SELECT norm_hash, COALESCE(preset, '') FROM explored WHERE func=?", (func_name,)).fetchall()
        with _EXPL_LOCK:
            _EXPL[func_name] = {(h, p) for h, p in rows}
    except sqlite3.Error:
        with _EXPL_LOCK:
            if func_name not in _EXPL:
                _EXPL[func_name] = set()


def is_explored(func_name: str, norm_hash: str, preset: str = "") -> bool:
    with _EXPL_LOCK:
        return (norm_hash, preset) in _EXPL[func_name]


def record_explored(func_name: str, norm_hash: str, preset: str = ""):
    with _EXPL_LOCK:
        _EXPL[func_name].add((norm_hash, preset))


def flush_explored(func_name: str):
    """Vuelca en bloque a SQLite los candidatos explorados al salir de la funcion."""
    with _EXPL_LOCK:
        items = list(_EXPL.get(func_name, set()))
    if not items:
        return
    try:
        with _DB_LOCK:
            with sqlite3.connect(EXPLORED_DB) as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO explored (func, norm_hash, preset) VALUES (?, ?, ?)",
                    [(func_name, h, p) for h, p in items]
                )
                conn.commit()
    except sqlite3.Error:
        pass


def get_neighborhood_preset(e: dict, state: dict, manifest: list) -> str:
    """Obtiene el preset dominante entre las funciones coincidentes del mismo bloque de 64KB en la ROM."""
    block = e["addr"] & ~0xFFFF
    counts = collections.Counter()
    for mem in manifest:
        if (mem["addr"] & ~0xFFFF) == block:
            st_m = state.get(mem["name"], {})
            if st_m.get("status") == "matched" and st_m.get("preset"):
                counts[st_m["preset"]] += 1
    if counts:
        return counts.most_common(1)[0][0]
    return "agbcc_O2"


def log_event(msg: str):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    with _LOG_LOCK:
        print(line, flush=True)
        for p in (CHECKPOINT_LOG, TANDA_LOG):
            try:
                with open(p, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass


def get_stats(state=None, manifest=None):
    st = state if state is not None else common.load_state()
    mf = manifest if manifest is not None else common.load_manifest()
    total = len(mf)
    matched = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "matched")
    approx = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "approx")
    wip = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "wip")
    orphan = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "orphan")
    pct = (matched / total) * 100.0 if total else 0.0
    return matched, approx, wip, orphan, total, pct


ROM_TOTAL_BYTES = 8388608


def compute_global_rom_pulse(state=None, manifest=None):
    """Calcula la coincidencia global acumulada de todo el volcado de funciones C contra la ROM original."""
    st = state if state is not None else common.load_state()
    mf = manifest if manifest is not None else common.load_manifest()
    total_fn_bytes = sum(e["size"] for e in mf)
    non_code_bytes = ROM_TOTAL_BYTES - total_fn_bytes
    matched_fn_bytes = sum(e["size"] for e in mf if st.get(e["name"], {}).get("status") == "matched")
    weighted_fn_bytes = sum(e["size"] * float(st.get(e["name"], {}).get("best", 0.0) or 0.0) for e in mf)

    rom_coincidence_pct = ((non_code_bytes + weighted_fn_bytes) / ROM_TOTAL_BYTES) * 100.0
    decompiled_parity_pct = (weighted_fn_bytes / total_fn_bytes) * 100.0 if total_fn_bytes else 0.0
    exact_code_pct = (matched_fn_bytes / total_fn_bytes) * 100.0 if total_fn_bytes else 0.0
    matched_cnt = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "matched")
    approx_cnt = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "approx")
    wip_cnt = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "wip")
    orphan_cnt = sum(1 for e in mf if st.get(e["name"], {}).get("status") == "orphan")
    total_cnt = len(mf)
    return {
        "rom_coincidence_pct": rom_coincidence_pct,
        "decompiled_parity_pct": decompiled_parity_pct,
        "weighted_fn_bytes": weighted_fn_bytes,
        "total_fn_bytes": total_fn_bytes,
        "non_code_bytes": non_code_bytes,
        "matched_fn_bytes": matched_fn_bytes,
        "exact_code_pct": exact_code_pct,
        "matched": matched_cnt,
        "approx": approx_cnt,
        "wip": wip_cnt,
        "orphan": orphan_cnt,
        "total": total_cnt,
    }


def print_global_rom_pulse(iter_num: int, state=None, manifest=None):
    """Emite el pulso de progreso del volcado C cada 15 iteraciones sin compilar la ROM."""
    p = compute_global_rom_pulse(state, manifest)
    banner = "=" * 90
    log_event(banner)
    log_event(f" [PULSO DE PROGRESO DE DESCOMPILACION @ ITERACION #{iter_num}]")
    log_event(f"  >> COBERTURA CODIGO C 100% ZERO-DIFF: {p['matched_fn_bytes']:,} / {p['total_fn_bytes']:,} B ({p['exact_code_pct']:.2f}% de la seccion .text)")
    log_event(f"  >> FUNCIONES C 100% ZERO-DIFF:       {p['matched']}/{p['total']} ({p['matched']*100/p['total']:.2f}%)")
    log_event(f"  >> PARIDAD PONDERADA CODIGO C:       {p['decompiled_parity_pct']:.2f}% ({p['weighted_fn_bytes']:,.1f} B equivalentes)")
    log_event(f"  >> ESTADO DEL VOLCADO:               {p['matched']} Matched | {p['approx']} Approx | {p['wip']} WIP | {p['orphan']} Orphan")
    log_event(banner)


def analyze_asm_diff(target_bytes: bytes, got_bytes: bytes, e: dict):
    """Compara instruccion por instruccion el ASM de la ROM vs el ASM compilado y devuelve el primer punto de divergencia."""
    if not got_bytes:
        return -1, "N/A", "NO_BIN", "sin binario"
    md = _THUMB_MD if e.get("mode") == "THUMB" else _ARM_MD
    t_ins = list(md.disasm(target_bytes, e["addr"]))
    g_ins = list(md.disasm(got_bytes, e["addr"]))
    n = min(len(t_ins), len(g_ins))
    for idx in range(n):
        ti, gi = t_ins[idx], g_ins[idx]
        ts = f"{ti.mnemonic} {ti.op_str}".strip()
        gs = f"{gi.mnemonic} {gi.op_str}".strip()
        if ts != gs:
            hint = "opcode" if ti.mnemonic != gi.mnemonic else "reg/imm"
            return idx, ts, gs, hint
    if len(t_ins) != len(g_ins):
        return n, f"len={len(t_ins)}", f"len={len(g_ins)}", "size_diff"
    return n, "IDENTICAL_INS", "IDENTICAL_INS", "pool_diff"


def depth_score(t: bytes, g: bytes) -> tuple[int, int]:
    """Calcula el prefijo y sufijo coincidentes exactos en bytes y penaliza delta de longitud.
    
    Mayor es mejor. Un cambio de asignacion de registros desplaza el primer diff y esta
    metrica lo detecta con precision granular a diferencia de difflib SequenceMatcher.
    """
    if not t or not g:
        return (0, -len(t) if t else 0)
    n = min(len(t), len(g))
    p = 0
    while p < n and t[p] == g[p]:
        p += 1
    s = 0
    while s < n - p and t[-1 - s] == g[-1 - s]:
        s += 1
    return (p + s, -abs(len(t) - len(g)))


OP_STATS_FILE = LOG_DIR / "operator_stats.json"
_OP_STATS_LOCK = threading.Lock()
_OP_STATS = collections.defaultdict(lambda: {"trials": 0, "improved": 0, "matched": 0})


def record_operator_trial(tag: str, improved: bool = False, matched: bool = False):
    """Registra linea base de telemetria por operador para medir efectividad real."""
    op = tag.split(":")[0].split("@")[0].split("(")[0]
    with _OP_STATS_LOCK:
        st = _OP_STATS[op]
        st["trials"] += 1
        if matched:
            st["matched"] += 1
        elif improved:
            st["improved"] += 1


def save_operator_stats():
    with _OP_STATS_LOCK:
        data = {k: dict(v) for k, v in _OP_STATS.items()}
    try:
        tmp = OP_STATS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(OP_STATS_FILE)
    except OSError:
        pass


def inject_local(c: str, decl_line: str) -> str:
    """Inserta una declaracion local al final del bloque de declaraciones existente."""
    if decl_line.strip() in c:
        return c
    lines = c.splitlines()
    fn_brace = None
    for i, l in enumerate(lines):
        if "{" in l and not re.match(r"^\s*struct\b", l):
            fn_brace = i
            break
    if fn_brace is None:
        return c
    ins_idx = fn_brace + 1
    while ins_idx < len(lines):
        s = lines[ins_idx].strip()
        if not s:
            ins_idx += 1
            continue
        if re.match(r"^(?:register\s+|volatile\s+)?(?:unsigned\s+|signed\s+)?(?:u8|u16|u32|s8|s16|s32|int|char|short|uint|ushort|uchar|BOOL|bool|struct\s+\w+)\s+[\w\*\s,\[\]]+;$", s) and "=" not in s:
            ins_idx += 1
        else:
            break
    lines.insert(ins_idx, "  " + decl_line.strip())
    return "\n".join(lines) + "\n"


def generate_asm_diff_mutations(code: str, e: dict, rom: bytes, t_str: str, g_str: str) -> list[tuple[str, str]]:
    """Genera mutaciones quirurgicas dirigidas especificamente a corregir la divergencia ASM detectada entre T y G."""
    out = []
    name = e["name"]

    def emit(tag, c):
        if c and c != code and name in c and "{" in c:
            out.append((tag, c))

    t_mne = t_str.split()[0] if t_str else ""
    g_mne = g_str.split()[0] if g_str else ""

    # 1. Divergencia de ancho de carga/escritura: strb/ldrb vs str/ldr/strh/ldrh
    width_map = {
        "ldrb": ["u8", "s8", "char"],
        "ldrsb": ["s8", "char"],
        "ldrh": ["u16", "ushort"],
        "ldrsh": ["s16", "short"],
        "ldr": ["int", "u32", "s32"],
        "strb": ["u8", "s8", "char"],
        "strh": ["u16", "s16"],
        "str": ["u32", "int"],
    }
    if t_mne in width_map and g_mne in width_map and t_mne != g_mne:
        target_types = width_map[t_mne]
        for m in re.finditer(r"\*\(\s*(?:volatile\s+)?(u8|u16|u32|s8|s16|s32|int|short|char)\s*\*\s*\)", code):
            cur_t = m.group(1)
            for nt in target_types:
                if nt != cur_t:
                    nc = code[:m.start(1)] + nt + code[m.end(1):]
                    emit(f"asm_width:{cur_t}->{nt}", nc)
        # SINTESIS DE ENCADENAMIENTO DE REGISTRO CERO:
        # Cuando el compilador emitio `str r1, [r0]` en vez de `strb r1, [r0]`, encadenar `*(u8 *)p1 = (z_reg = 0); *(u8 *)p2 = z_reg;`
        # obliga a agbcc a cargar `movs r1, #0` y reusar r1 con `strb` en ambas sentencias sin cambiar la logica.
        if t_mne == "strb" and g_mne == "str":
            m_two_z = re.search(
                r"(\*\(\s*(?:u8|u32|int)\s*\*\s*\)\s*\([^;\n]+\))\s*=\s*0\s*;\s*\n"
                r"([ \t]*\*\(\s*(?:u8|u32|int)\s*\*\s*\)\s*\([^;\n]+\))\s*=\s*0\s*;",
                code,
            )
            if m_two_z:
                lhs1, lhs2 = m_two_z.groups()
                lhs1_b = re.sub(r"\*\(\s*(?:u8|u32|int)\s*\*\s*\)", "*(u8 *)", lhs1, count=1)
                lhs2_b = re.sub(r"\*\(\s*(?:u8|u32|int)\s*\*\s*\)", "*(u8 *)", lhs2, count=1)
                for z_type in ("u8", "int"):
                    c_z1 = code[:m_two_z.start()] + f"{lhs1_b} = (z_shared = 0);\n{lhs2_b} = z_shared;" + code[m_two_z.end():]
                    emit("asm_chained_zero:pair_fwd", inject_local(c_z1, f"{z_type} z_shared;"))
                    c_z2 = code[:m_two_z.start()] + f"{lhs2_b} = (z_shared = 0);\n{lhs1_b} = z_shared;" + code[m_two_z.end():]
                    emit("asm_chained_zero:pair_rev", inject_local(c_z2, f"{z_type} z_shared;"))

    # 2. Divergencia de rama con signo vs sin signo (bgt/ble/bge/blt vs bhi/bls/bcs/bcc)
    signed_br = {"bgt", "ble", "bge", "blt"}
    unsigned_br = {"bhi", "bls", "bcs", "bcc", "bhs", "blo"}
    if (t_mne in signed_br and g_mne in unsigned_br) or (t_mne in unsigned_br and g_mne in signed_br):
        # Quitar o poner casts (u32)/(s32) en condiciones if/while
        for m in re.finditer(r"\bif\s*\(\s*\(\s*(u32|s32|int|u16|s16|u8|s8)\s*\)\s*(\w+)", code):
            emit("asm_strip_cmp_cast", code[:m.start(1) - 1] + m.group(2) + code[m.end(2):])
        for m in re.finditer(r"\bif\s*\(\s*(\w+)\s*([<>]=?)\s*([^)]+)\)", code):
            v, op, rhs = m.groups()
            for ct in ("(int)", "(u32)", "(s16)", "(u16)", "(s8)", "(u8)"):
                emit(f"asm_add_cmp_cast:{ct}", code[:m.start()] + f"if ({ct}{v} {op} {rhs})" + code[m.end():])

    # 3. Divergencia de mascaras de 8 bits: movs r0, #0x..; rsbs r0, r0, #0 vs movs r0, #0x..
    if "rsbs" in t_str or "rsbs" in g_str or "ands" in t_str:
        for m in re.finditer(r"(\*\(\s*u8\s*\*\s*\)\s*\([^)]+\))\s*=\s*(?:\(\s*s8\s*\)\s*)?\1\s*&\s*(0x[0-9a-fA-F]+)\s*;", code):
            lhs, mask = m.groups()
            emit("asm_mask_u8_plain", code[:m.start()] + f"{lhs} = {lhs} & {mask};" + code[m.end():])
            emit("asm_mask_s8_cast", code[:m.start()] + f"{lhs} = (s8){lhs} & {mask};" + code[m.end():])
            emit("asm_mask_compound", code[:m.start()] + f"{lhs} &= {mask};" + code[m.end():])

    # 4. Divergencia de Sign-Extension / Zero-Extension (lsls ... #16; asrs ... #16)
    if "lsls" in g_str and ("asrs" in g_str or "lsrs" in g_str) and "lsls" not in t_str:
        # El compilador inserto extensiones innecesarias: promocionar variables locales y parametros a `int` / `u32`
        for m in re.finditer(r"\b(s16|u16|s8|u8|short|char)\s+(\w+)\b", code):
            cur_t, v_name = m.groups()
            for wider in ("int", "u32"):
                emit(f"asm_widen:{v_name}->{wider}", re.sub(rf"\b{re.escape(cur_t)}\s+{re.escape(v_name)}\b", f"{wider} {v_name}", code))
        # Quitar casts (s16)/(u16)
        emit("asm_strip_narrow_casts", re.sub(r"\(\s*(?:s16|u16|s8|u8|short|char)\s*\)", "", code))

    if "lsls" in t_str and ("asrs" in t_str or "lsrs" in t_str) and "lsls" not in g_str:
        # La ROM requiere extension de signo/cero: forzar casts (s16)/(u16) en expresiones aritmeticas
        for m in re.finditer(r"\b(\w+)\s*=\s*([^;]+);", code):
            v_lhs, expr_rhs = m.groups()
            for narrow_cast in ("(s16)", "(u16)", "(s8)", "(u8)"):
                emit(f"asm_add_narrow_cast:{narrow_cast}", code[:m.start()] + f"{v_lhs} = {narrow_cast}({expr_rhs.strip()});" + code[m.end():])

    # 5. Divergencia de Carga de Cero Temprana (movs rX, #0 antes de stores)
    if "movs" in t_str and "#0" in t_str and ("movs" not in g_str or "#0" not in g_str):
        # Target cargo 0 en registro antes: intentar hoisting de variable cero
        for z_type in ("register u32", "register int", "u32", "int"):
            z_code = inject_local(code, f"{z_type} r_zero = 0;")
            z_code_sub = re.sub(r"=\s*0\s*;", "= r_zero;", z_code)
            emit(f"asm_hoist_zero:{z_type}", z_code_sub)
        # Reordenar asignaciones de cero adyacentes
        m_2z = re.search(r"(\b\w+\b)\s*=\s*0\s*;\s*\n([ \t]*)(\b\w+\b)\s*=\s*0\s*;", code)
        if m_2z:
            z1, ind, z2 = m_2z.groups()
            if z1 != z2:
                emit("asm_swap_zero_order", code[:m_2z.start()] + f"{z2} = 0;\n{ind}{z1} = 0;" + code[m_2z.end():])
                emit("asm_chain_zero_assign", code[:m_2z.start()] + f"{z1} = {z2} = 0;" + code[m_2z.end():])

    # 6. Divergencia Aritmetica: adds vs subs vs lsls
    if "adds" in t_str and "lsls" in g_str:
        # ROM uso suma/duplicacion donde nosotros pusimos shift/multiplicacion
        for m_sh in re.finditer(r"\b(\w+)\s*<<\s*1\b", code):
            v_nm = m_sh.group(1)
            emit("asm_shift_to_add", code[:m_sh.start()] + f"({v_nm} + {v_nm})" + code[m_sh.end():])
        for m_m2 in re.finditer(r"\b(\w+)\s*\*\s*2\b", code):
            v_nm = m_m2.group(1)
            emit("asm_mul2_to_add", code[:m_m2.start()] + f"({v_nm} + {v_nm})" + code[m_m2.end():])

    if "subs" in t_str and "adds" in g_str:
        # ROM uso resta en vez de suma con negativo
        for m_add_neg in re.finditer(r"\+\s*-\s*(\w+|0x[0-9a-fA-F]+|\d+)", code):
            emit("asm_add_neg_to_sub", code[:m_add_neg.start()] + f"- {m_add_neg.group(1)}" + code[m_add_neg.end():])

    if "subs" in t_str and "movs" in g_str:
        # ROM uso resta desde registro cero (subs rX, #K) en vez de cargar constante movs rX, #0xfe
        m_imm = re.search(r"\bsubs\s+\w+,\s*#(0x[0-9a-fA-F]+|\d+)", t_str)
        if m_imm:
            sub_k = int(m_imm.group(1), 0)
            for hex_val in ("0xfe", "0xFE", "254", "0xfd", "0xFD", "253", "0xfc", "0xFC", "252"):
                if hex_val in code:
                    emit(f"asm_sub_zero_mask:~{sub_k-1}", code.replace(hex_val, f"~{sub_k-1}"))
                    emit(f"asm_sub_zero_mask:-{sub_k}", code.replace(hex_val, f"-{sub_k}"))
                    emit(f"asm_sub_zero_mask:(u32)-{sub_k}", code.replace(hex_val, f"(u32)-{sub_k}"))

    # Inversion de operandos de comparacion (cmp rA, rB vs cmp rB, rA)
    if "cmp" in t_str and "cmp" in g_str:
        m_t_cmp = re.search(r"\bcmp\s+(\w+),\s*(\w+)", t_str)
        m_g_cmp = re.search(r"\bcmp\s+(\w+),\s*(\w+)", g_str)
        if m_t_cmp and m_g_cmp:
            t_r1, t_r2 = m_t_cmp.groups()
            g_r1, g_r2 = m_g_cmp.groups()
            if t_r1 == g_r2 and t_r2 == g_r1:
                for m_eq in re.finditer(r"([^\s=!<>]+)\s*(==|!=)\s*([^\s;(){]+)", code):
                    lhs, op, rhs = m_eq.groups()
                    emit("asm_swap_cmp_operands", code[:m_eq.start()] + f"{rhs} {op} {lhs}" + code[m_eq.end():])

    # 7. Divergencia de Llamadas: bl en Target pero no en Got (o viceversa) -> Hoisting de argumentos
    if "bl" in t_str or "bl" in g_str:
        for m_call in re.finditer(r"(func_[0-9A-F]{8})\s*\(([^)]+)\)", code):
            fn_nm, arg_str = m_call.groups()
            args = [a.strip() for a in arg_str.split(",")]
            if len(args) >= 2:
                for arg_idx, arg_val in enumerate(args):
                    if not re.fullmatch(r"\w+", arg_val):
                        t_nm = f"arg_hoist_{arg_idx}"
                        new_args = list(args)
                        new_args[arg_idx] = t_nm
                        c_h = inject_local(code, f"register u32 {t_nm};")
                        c_h = c_h.replace(m_call.group(0), f"{t_nm} = {arg_val};\n  {fn_nm}({', '.join(new_args)})")
                        emit(f"asm_hoist_call_arg:{arg_idx}", c_h)

    # 8. Combinaciones acotadas de calificador `register` (max 3 variables locales)
    lines = code.splitlines()
    dblock = EP.decl_block(lines)
    reg_candidates = []
    for i in dblock:
        m = P.DECL.match(lines[i])
        if m and "[" not in m.group(6) and f"&{m.group(5)}" not in code:
            reg_candidates.append((i, m.groups()))
    if 1 <= len(reg_candidates) <= 3:
        for mask in range(1 << len(reg_candidates)):
            l = list(lines)
            for bit_idx, (line_i, (ind, qual, typ, stars, var, rest)) in enumerate(reg_candidates):
                rq = "register " if (mask & (1 << bit_idx)) else ""
                l[line_i] = f"{ind}{rq}{typ}{stars}{var}{rest}"
            cand_r = "\n".join(l) + "\n"
            emit(f"reg_mask:{mask:02x}", cand_r)

    # 9. Divergencia de asignacion de registros: swap de pares de declaraciones locales
    if dblock and len(dblock) >= 2:
        for i_a, i_b in itertools.combinations(dblock, 2):
            l_sw = list(lines)
            l_sw[i_a], l_sw[i_b] = l_sw[i_b], l_sw[i_a]
            emit(f"asm_swap_decl:{i_a}<->{i_b}", "\n".join(l_sw) + "\n")

    # 10. Mascaras de bits genericas y campos desplazados (lsls / lsrs / asrs)
    mask_fn = getattr(RD, "mask_laws", None)
    if callable(mask_fn):
        for mc_mask in mask_fn(code):
            emit("asm_mask_law", mc_mask)

    # 11. Divergencia de tamano de stack frame (sub sp, #X vs sub sp, #Y)
    m_t_sp = re.search(r"sub\s+sp,\s*#(0x[0-9a-fA-F]+|\d+)", t_str)
    m_g_sp = re.search(r"sub\s+sp,\s*#(0x[0-9a-fA-F]+|\d+)", g_str)
    if m_t_sp or m_g_sp:
        t_sp = int(m_t_sp.group(1), 0) if m_t_sp else 0
        g_sp = int(m_g_sp.group(1), 0) if m_g_sp else 0
        delta = t_sp - g_sp
        if delta > 0 and delta % 4 == 0:
            pad_words = delta // 4
            pad_decl = f"u32 _sp_pad[{pad_words}];"
            c_pad = inject_local(code, pad_decl)
            c_lines = c_pad.splitlines()
            for li, l in enumerate(c_lines):
                if "_sp_pad" in l and ";" in l:
                    c_lines.insert(li + 1, "  (void)_sp_pad;")
                    break
            emit(f"asm_sp_grow:{delta}B", "\n".join(c_lines) + "\n")
        elif delta < 0 and (-delta) % 4 == 0:
            for m_arr in re.finditer(r"\b(u8|s8|u16|s16|u32|s32|int)\s+(\w+)\[(\d+)\];", code):
                typ, arr_name, arr_sz = m_arr.groups()
                elem_sz = 1 if "8" in typ else (2 if "16" in typ else 4)
                cur_b = int(arr_sz) * elem_sz
                needed_b = cur_b - (-delta)
                if needed_b > 0 and needed_b % elem_sz == 0:
                    new_sz = needed_b // elem_sz
                    emit(f"asm_sp_shrink:{arr_name}->{new_sz}", code[:m_arr.start()] + f"{typ} {arr_name}[{new_sz}];" + code[m_arr.end():])

    # 12. Divergencia de registros callee-saved (push {..., lr})
    if "push" in t_str and "push" in g_str:
        t_regs = set(re.findall(r"r[4-7]", t_str))
        g_regs = set(re.findall(r"r[4-7]", g_str))
        if t_regs > g_regs:
            for m_call in re.finditer(r"\b(\w+)\s*\(([^)]+)\);", code):
                c_fn, c_args = m_call.groups()
                arg_list = [a.strip() for a in c_args.split(",") if a.strip()]
                if arg_list:
                    t_var = "reg_callee_save"
                    c_h = inject_local(code, f"register u32 {t_var};")
                    c_h = c_h.replace(m_call.group(0), f"{t_var} = {arg_list[0]};\n  {c_fn}({t_var});\n  (void){t_var};")
                    emit("asm_push_force_callee_save", c_h)
        elif g_regs > t_regs:
            for m_tmp in re.finditer(r"(\w+)\s*=\s*([^;]+);\s*\n([ \t]*\w+\([^)]*\b\1\b[^)]*\);)", code):
                v_name, v_expr, call_line = m_tmp.groups()
                c_inl = code.replace(m_tmp.group(0), call_line.replace(v_name, v_expr.strip()))
                emit(f"asm_push_inline_temp:{v_name}", c_inl)

    # 13. Inversion de polaridad de ramas if/else (beq vs bne, bhi vs bls, etc.)
    branch_opposites = {
        ("beq", "bne"), ("bne", "beq"),
        ("bhi", "bls"), ("bls", "bhi"),
        ("blo", "bhs"), ("bhs", "blo"),
        ("bgt", "ble"), ("ble", "bgt"),
        ("bge", "blt"), ("blt", "bge"),
    }
    if (t_mne, g_mne) in branch_opposites:
        for m_if in re.finditer(r"\bif\s*\(([^)]+)\)\s*\{([^}]+)\}\s*else\s*\{([^}]+)\}", code):
            cnd, blk1, blk2 = m_if.groups()
            emit("asm_branch_invert_if_else", code[:m_if.start()] + f"if (!({cnd})) {{{blk2}}} else {{{blk1}}}" + code[m_if.end():])
        for m_if_ret in re.finditer(r"\bif\s*\(([^=!<>]+)(==|!=|<|>|<=|>=)([^)]+)\)\s*(return\b[^;]+;)", code):
            lhs, op, rhs, ret_stmt = m_if_ret.groups()
            inv_op = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}[op]
            emit(f"asm_branch_invert_cmp:{op}->{inv_op}", code[:m_if_ret.start()] + f"if ({lhs}{inv_op}{rhs}) {ret_stmt}" + code[m_if_ret.end():])

    # 14. Conmutacion de operandos binarios y de comparacion (a + b <-> b + a, a * b <-> b * a, a & b <-> b & a)
    for m_comm in re.finditer(
        r"((?:\w+(?:\[[^\]]+\])?|\*\w+|\*\([^)]+\)|0x[0-9A-Fa-f]+|\d+))\s*"
        r"(\+|\*|&|\||\^|==|!=)\s*"
        r"((?:\w+(?:\[[^\]]+\])?|\*\w+|\*\([^)]+\)|0x[0-9A-Fa-f]+|\d+))",
        code,
    ):
        op1, cop, op2 = m_comm.groups()
        if op1 != op2:
            emit(f"asm_comm_swap:{cop}", code[:m_comm.start()] + f"{op2} {cop} {op1}" + code[m_comm.end():])

    # 15. SOLVER A (REGISTROS ACOTIADO): Solo 2 parametros
    m_sig = re.search(rf"\b{re.escape(name)}\s*\(([^)]*)\)", code)
    if m_sig:
        param_str = m_sig.group(1).strip()
        if param_str and param_str != "void":
            p_items = [p.strip() for p in param_str.split(",") if p.strip()]
            parsed_params = []
            for p in p_items:
                m_p = re.match(r"^(?:const\s+)?(\w+(?:\s*\*+)?)\s+(\w+)$", p)
                if m_p:
                    parsed_params.append((m_p.group(1).strip(), m_p.group(2).strip()))
            if len(parsed_params) == 2:
                fn_body_start = code.find("{", m_sig.end())
                if fn_body_start != -1:
                    head = code[:fn_body_start + 1]
                    body = code[fn_body_start + 1:]
                    perm = list(reversed(parsed_params))
                    decls = [f"register {pt} _p_{pn} = {pn};" for pt, pn in perm]
                    b_mod = body
                    for pt, pn in perm:
                        b_mod = re.sub(rf"\b{re.escape(pn)}\b", f"_p_{pn}", b_mod)
                    c_new = head + "\n  " + "\n  ".join(decls) + "\n" + b_mod
                    emit("solver_a_param:swap2", c_new)

    # 16. SOLVER B: Conmutacion while / do-while y reordenacion de sentencias adyacentes
    for m_wh in re.finditer(r"\bwhile\s*\(([^)]+)\)\s*\{([^}]+)\}", code):
        w_cond, w_body = m_wh.groups()
        do_wh = f"if ({w_cond}) {{\n  do {{{w_body}\n  }} while ({w_cond});\n}}"
        emit("solver_b_while_to_dowhile", code[:m_wh.start()] + do_wh + code[m_wh.end():])

    m_stmts = list(re.finditer(r"^([ \t]*\w+(?:\[[^\]]+\]|\.\w+|->\w+)?\s*=\s*[^;]+;)\s*$", code, re.MULTILINE))
    if len(m_stmts) >= 2:
        for i in range(min(len(m_stmts) - 1, 4)):
            s1, s2 = m_stmts[i], m_stmts[i + 1]
            if s1.end() + 1 == s2.start() or code[s1.end():s2.start()].strip() == "":
                t1, t2 = s1.group(1), s2.group(1)
                v1 = t1.split("=")[0].strip()
                v2 = t2.split("=")[0].strip()
                if v1 != v2 and v1 not in t2 and v2 not in t1:
                    c_sw = code[:s1.start()] + t2 + "\n" + t1 + code[s2.end():]
                    emit(f"solver_b_swap_stmts:{i}<->{i+1}", c_sw)

    # 19. HERMES EPILOGUE POP SOLVER: pop {r2} vs pop {r1} (ret u64) o pop {r0} vs pop {r1} (ret void)
    if ("pop {r2}" in t_str and "pop {r1}" in g_str) or ("bx r2" in t_str and "bx r1" in g_str):
        # El retorno de 64 bits (unsigned long long) mantiene r0 y r1 ocupados y fuerza a old_agbcc a usar r2 para pop lr
        c_u64 = re.sub(r"^(?:u32|int|s32|void|short|s16|u16)\s+(" + re.escape(name) + r"\b)", r"unsigned long long \1", code, flags=re.MULTILINE)
        if c_u64 != code:
            emit("hermes_epilog:ret_u64", c_u64)
    if ("pop {r0}" in t_str and "pop {r1}" in g_str) or ("bx r0" in t_str and "bx r1" in g_str):
        # El retorno void libera r0 y permite que GCC pop lr directamente en r0
        c_void = re.sub(r"^(?:u32|int|s32|unsigned long long|short|s16|u16)\s+(" + re.escape(name) + r"\b)", r"void \1", code, flags=re.MULTILINE)
        if c_void != code:
            c_void_clean = re.sub(r"\breturn\s+[^;]+;", "return;", c_void)
            emit("hermes_epilog:ret_void", c_void_clean)

    # 20. HERMES LOGICAL ANDS CONSTANT FLIP: ands r1, r0 vs ands r0, r1
    if ("ands" in t_str and "ands" in g_str) and (t_str != g_str):
        for m_and in re.finditer(r"(\w+)\s*=\s*([^;]+?)\s*&\s*(0x[0-9a-fA-F]+|\d+)\s*;", code):
            dst, src, cst = m_and.groups()
            repl = f"{{ u32 _tmp = {cst}; _tmp &= {src.strip()}; {dst} = _tmp; }}"
            emit(f"hermes_ands_const_flip:{dst}", code[:m_and.start()] + repl + code[m_and.end():])

    # 21. HERMES ASSOCIATIVE ADDITION BARRIER: adds r1, r1, rX vs adds r1, r1, rY
    if "adds" in t_str and "adds" in g_str and t_str != g_str:
        for m_add in re.finditer(r"(\w+)\s*\+=\s*([^;]+);", code):
            v, rhs = m_add.groups()
            barrier = f"{v} += {rhs.strip()};\n  __asm__(\"\" : \"+r\"({v}));"
            emit(f"hermes_add_barrier:{v}", code[:m_add.start()] + barrier + code[m_add.end():])

    return out


def persist_progress(e: dict, state: dict, best_code: str, best_sc: float, best_preset: str, how: str):
    """Guarda atomicamente el mejor codigo parcial y actualiza state.json para recuperacion ante apagones."""
    name = e["name"]
    path = common.TREE_DIR / e["file"]
    lift._write_atomic(path.with_suffix(".wip.c"), best_code)
    lift._write_atomic(common.TREE_DIR / "collection" / "wip" / f"{name}.wip.c", best_code)
    lift._write_atomic(TANDA_DIR / f"{name}.c", best_code)
    new_status = "approx" if best_sc >= 0.90 else "wip"
    if best_sc >= 0.90:
        header = f"/* paridad {best_sc * 100:.2f}% preset {best_preset} ({how}) */\n"
        lift._write_atomic(common.TREE_DIR / "approx" / f"{name}.c", header + best_code)
        lift._write_atomic(common.TREE_DIR / "collection" / "approx" / f"{name}.c", header + best_code)
        lift._write_atomic(TANDA_DIR / f"{name}.approx.c", header + best_code)
    with _STATE_LOCK:
        cur_st = state.get(name, {})
        state[name] = {
            **cur_st,
            "status": new_status,
            "best": round(best_sc, 4),
            "preset": best_preset,
            "how": how,
            "size": e["size"],
            "addr": e["addr"],
            "tries": int(cur_st.get("tries", 0)) + 1,
        }
        common.save_state(state)


def solve_function_relentless(e: dict, rom: bytes, manifest: list, state: dict, rosetta: RD.RosettaCorpus,
                              idx_pos: int, total_todo: int, max_rounds: int = 0, workers: int = 3,
                              tag_prefix: str = "") -> tuple[bool, float, str]:
    """Ataca una funcion en bucle cerrado auto-retroalimentado con multi-threading sin abandonarla hasta alcanzar 100% (o max_rounds)."""
    name = e["name"]
    load_explored(name)
    try:
        return _solve_function_relentless_core(
            e, rom, manifest, state, rosetta, idx_pos, total_todo,
            max_rounds=max_rounds, workers=workers, tag_prefix=tag_prefix
        )
    finally:
        flush_explored(name)
        save_operator_stats()


def _solve_function_relentless_core(e: dict, rom: bytes, manifest: list, state: dict, rosetta: RD.RosettaCorpus,
                                   idx_pos: int, total_todo: int, max_rounds: int = 0, workers: int = 3,
                                   tag_prefix: str = "") -> tuple[bool, float, str]:
    name = e["name"]
    cur_st = state.get(name, {})
    prev_sc = float(cur_st.get("best", 0.0) or 0.0)
    prev_status = cur_st.get("status", "wip")
    target = common.rom_bytes(rom, e["addr"], e["size"])
    if e["mode"] == "THUMB":
        # En banco 0x08040000 old_agbcc_O2 es dominante (44.4%), en el resto agbcc_O2 domina (>92%)
        if (e["addr"] & 0xFFFF0000) == 0x08040000:
            presets = ["old_agbcc_O2", "agbcc_O2", "agbcc_O1"]
        else:
            presets = ["agbcc_O2", "old_agbcc_O2", "agbcc_O1"]
    else:
        presets = ["O2", "O1"]
    nb_preset = get_neighborhood_preset(e, state, manifest)
    if nb_preset in presets:
        presets.remove(nb_preset)
        presets.insert(0, nb_preset)
    first_preset = cur_st.get("preset")
    if first_preset in presets:
        presets.remove(first_preset)
        presets.insert(0, first_preset)

    evals = 0
    t_start = time.time()

    def eval_batch_parallel(batch_items, stop_on_match=True):
        nonlocal evals
        if not batch_items:
            return []
        res_list = []
        if len(batch_items) <= 2 or workers <= 1:
            for it in batch_items:
                tag, c_txt, pr = it
                evals += 1
                norm_h = hashlib.sha1(EP.norm(c_txt).encode("utf-8")).hexdigest()
                ok, got, err = lift.try_candidate(e, c_txt, manifest, pr)
                is_timeout = bool(err and ("timeout" in err.lower() or "error temporal de e/s" in err.lower()))
                if not is_timeout:
                    record_explored(name, norm_h, pr)
                if not ok or not got:
                    res_list.append(((0, -len(target)), 0.0, False, None, tag, c_txt, pr))
                else:
                    ex, sc = lift.score(e, target, got)
                    ds = depth_score(target, got)
                    res_list.append((ds, sc, bool(ex), got, tag, c_txt, pr))
                    if ex and stop_on_match:
                        break
            return res_list

        match_found = threading.Event()

        def _worker(item):
            if match_found.is_set():
                return None
            tag, c_txt, pr = item
            norm_h = hashlib.sha1(EP.norm(c_txt).encode("utf-8")).hexdigest()
            ok, got, err = lift.try_candidate(e, c_txt, manifest, pr)
            is_timeout = bool(err and ("timeout" in err.lower() or "error temporal de e/s" in err.lower()))
            if not is_timeout:
                record_explored(name, norm_h, pr)
            if not ok or not got:
                return ((0, -len(target)), 0.0, False, None, tag, c_txt, pr)
            ex, sc = lift.score(e, target, got)
            ds = depth_score(target, got)
            if ex and stop_on_match:
                match_found.set()
            return (ds, sc, bool(ex), got, tag, c_txt, pr)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            fut_map = {executor.submit(_worker, it): it for it in batch_items}
            for fut in concurrent.futures.as_completed(fut_map):
                if STOP_FLAG.exists() or SKIP_FLAG.exists():
                    match_found.set()
                    for f in fut_map:
                        f.cancel()
                    break
                try:
                    r = fut.result()
                    if r is not None:
                        evals += 1
                        res_list.append(r)
                        if r[2] and stop_on_match:
                            for f in fut_map:
                                f.cancel()
                            break
                except Exception:
                    pass
        return res_list

    # -------------------------------------------------------------------------
    # ETAPA 0: Recoleccion y evaluacion de todas las semillas disponibles
    # -------------------------------------------------------------------------
    seed_pool = []
    existing_c = RD.get_best_existing_code(e)
    if existing_c:
        seed_pool.append(("checkpoint-seed", lift.extract_c(existing_c, rom=rom, e=e)))

    for rc in rosetta.instantiate_candidates(rom, e):
        seed_pool.append(("rosetta-isomorphic", rc))

    raw_g = RD.get_raw_ghidra_code(e)
    if raw_g and "sin referencia de Ghidra" not in raw_g and "halt_baddata" not in raw_g:
        cleaned_g = lift.extract_c(lift.clean_ghidra_ref(raw_g, rom=rom, e=e), rom=rom, e=e)
        if cleaned_g and name in cleaned_g and "{" in cleaned_g:
            seed_pool.append(("ghidra-clean-c89", cleaned_g))

    for dc in RD.lift_thumb_directly(rom, e):
        seed_pool.append(("thumb-symbolic-lifter", dc))

    best_sc = -1.0
    best_ds = (0, -len(target))
    best_code = None
    best_preset = presets[0]
    best_got = None
    best_how = "seed"

    seen = set()
    frontier = []

    seed_eval_items = []
    for s_tag, s_code in seed_pool:
        if not s_code:
            continue
        n_str = EP.norm(s_code)
        norm_h = hashlib.sha1(n_str.encode("utf-8")).hexdigest()
        for pr in presets[:2]:
            k = (n_str, pr)
            if k not in seen:
                seen.add(k)
                if not is_explored(name, norm_h, pr):
                    seed_eval_items.append((s_tag, s_code, pr))

    for ds, sc, ex, got, s_tag, s_code, pr in eval_batch_parallel(seed_eval_items):
        is_improved = (ds > best_ds or (ds == best_ds and sc > best_sc))
        record_operator_trial(s_tag, improved=is_improved, matched=bool(ex))
        if ex:
            lift.save_matched(e, s_code, pr, manifest, state, evals, f"safe-rosetta:{s_tag}", target=target, rom=rom)
            lift._write_atomic(TANDA_DIR / f"{name}.matched.c", s_code)
            with _STATE_LOCK:
                rosetta.add_matched(rom, e, s_code, pr)
            m_c, _, _, _, tot, pct = get_stats(state, manifest)
            log_event(
                f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [MATCH 100%] {name} (tam={e['size']:4d}B) | "
                f"Ant: {prev_sc*100:5.1f}% -> 100.0% en {evals} evals ({time.time()-t_start:.1f}s) via {s_tag} [{pr}] | "
                f"Total: {m_c}/{tot} ({pct:.2f}%)"
            )
            return True, 1.0, s_tag
        if sc > 0.0:
            frontier.append((ds, sc, s_code, pr, got, s_tag))
            if is_improved:
                best_ds, best_sc, best_code, best_preset, best_got, best_how = ds, sc, s_code, pr, got, s_tag

    if not best_code or best_sc <= 0.0:
        log_event(f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [OMITIDA-SIN-SEMILLA] {name} (tam={e['size']:4d}B) | Ant: {prev_sc*100:5.1f}% -> Sin semilla C89 compilable.")
        return False, prev_sc, "no_compilable_seed"

    # Si la semilla ya supero la calificacion previa (ej. huerfana rescatada), guardar checkpoint de inmediato
    if best_sc > prev_sc + 0.0005 or (prev_status == "orphan" and best_sc > 0.0):
        persist_progress(e, state, best_code, best_sc, best_preset, best_how)
        log_event(
            f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [CHECKPOINT-SEMILLA] {name} (tam={e['size']:4d}B) | "
            f"Ant: {prev_sc*100:5.1f}% ({prev_status}) -> Nueva: {best_sc*100:5.2f}% (depth={best_ds[0]}B) via {best_how} [{best_preset}]"
        )

    frontier.sort(key=lambda x: (x[0], x[1]), reverse=True)
    frontier = frontier[:10]
    tries_cnt = int(cur_st.get("tries", 0))
    rng = random.Random(f"{name}_pass_{tries_cnt}")

    # -------------------------------------------------------------------------
    # ETAPA 1..Inf: Bucle Cerrado de Retroalimentacion (No Abandona hasta 100%)
    # -------------------------------------------------------------------------
    round_num = 0
    stale_rounds = 0
    MAX_STALE_BEFORE_ROTATE = 3

    while True:
        round_num += 1
        if STOP_FLAG.exists():
            log_event(f"[!] Parada solicitada via {STOP_FLAG}.")
            return False, best_sc, best_how

        if SKIP_FLAG.exists():
            try:
                SKIP_FLAG.unlink()
            except OSError:
                pass
            log_event(f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [SKIP-MANUAL] Saltando {name} en Ronda #{round_num} a peticion del usuario (mejor={best_sc*100:.2f}%).")
            return False, best_sc, best_how

        if max_rounds > 0 and round_num > max_rounds:
            log_event(
                f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [LIMITE-RONDAS] {name} alcanzo --max-rounds={max_rounds} "
                f"(Ant: {prev_sc*100:5.1f}% -> Actual: {best_sc*100:5.2f}%, evals={evals})."
            )
            return False, best_sc, best_how

        # Diagnostico ASM-Diff del mejor candidato actual contra la ROM
        diff_idx, t_ins_s, g_ins_s, diff_hint = analyze_asm_diff(target, best_got, e)
        m_c, _, _, _, tot, pct = get_stats(state, manifest)
        log_event(
            f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [ATACANDO] {name} ({e['size']}B) | Ronda #{round_num} | Evals: {evals} | "
            f"Ant: {prev_sc*100:5.1f}% -> Actual: {best_sc*100:5.2f}% [{best_preset}] | "
            f"Diff@{diff_idx}: T[{t_ins_s}] != G[{g_ins_s}] | ROM: {m_c}/{tot} ({pct:.2f}%)"
        )

        cand_batch = []

        def enqueue(tag: str, c_str: str, pr: str = best_preset):
            if not c_str:
                return
            n_str = EP.norm(c_str)
            k = (n_str, pr)
            if k not in seen:
                seen.add(k)
                norm_h = hashlib.sha1(n_str.encode("utf-8")).hexdigest()
                if not is_explored(name, norm_h, pr):
                    cand_batch.append((tag, c_str, pr))

        # 1. En Ronda 1 o cuando mejora el lider: probar Leyes Algebraicas Rosetta (1..16) + Mutaciones ASM-Diff + Permutaciones Decl
        for _, _, f_code, f_pr, f_got, _ in frontier[:4]:
            _, ft_s, fg_s, _ = analyze_asm_diff(target, f_got, e)
            for tag_d, mc_d in generate_asm_diff_mutations(f_code, e, rom, ft_s, fg_s):
                enqueue(tag_d, mc_d, f_pr)
            for mc_alg in RD.generate_rosetta_algebraic_mutations(f_code, name, rom=rom, e=e):
                enqueue("rosetta-alg", mc_alg, f_pr)

        # 2. Vecindario determinista de 1 paso (`EP.neighbors`) sobre la frontera activa
        for _, _, f_code, f_pr, _, _ in frontier[:4]:
            nbs = EP.neighbors(f_code)
            rng.shuffle(nbs)
            for tag_n, mc_n in nbs[:30]:
                enqueue(tag_n, mc_n, f_pr)

        # 3. Si el vecindario de 1 paso ya fue explorado o llevamos rondas estancadas:
        #    Saltos de cuenca (Basin Hopping) combinando 2..5 mutaciones encadenadas + barrido de presets
        if len(cand_batch) < 40 or stale_rounds >= 1:
            hop_depth = min(6, 2 + stale_rounds)
            base_parents = [x[2] for x in frontier] or [best_code]
            for _ in range(40):
                cur_c = rng.choice(base_parents)
                steps_taken = []
                for s_i in range(rng.randint(2, hop_depth)):
                    # Alternar entre mutador estocastico P.mutate, leyes algebraicas y EP.neighbors
                    r_choice = rng.random()
                    if r_choice < 0.45:
                        nxt = P.mutate(cur_c, rng)
                        if nxt:
                            cur_c = nxt
                            steps_taken.append("P")
                    elif r_choice < 0.75:
                        nbs = EP.neighbors(cur_c)
                        if nbs:
                            t_n, cur_c = rng.choice(nbs)
                            steps_taken.append(t_n.split("@")[0])
                    else:
                        algs = RD.generate_rosetta_algebraic_mutations(cur_c, name, rom=rom, e=e)
                        if algs:
                            cur_c = rng.choice(algs)
                            steps_taken.append("alg")
                alt_pr = rng.choice(presets) if stale_rounds >= 2 else best_preset
                enqueue(f"hop({'+'.join(steps_taken[:3])})", cur_c, alt_pr)

        # Evaluar lote de candidatos con multi-threading masivo, salida inmediata al 100% y checkpoint inmediato al subir paridad
        batch_limit = max(60, min(150, workers * 30))
        round_improved = False
        new_pool = []
        batch_results = eval_batch_parallel(cand_batch[:batch_limit])

        for ds, sc, ex, got, tag_c, code_c, pr_c in batch_results:
            is_match = bool(ex)
            is_improved = False
            if ex:
                lift.save_matched(e, code_c, pr_c, manifest, state, evals, f"safe-loop:{tag_c}", target=target, rom=rom)
                lift._write_atomic(TANDA_DIR / f"{name}.matched.c", code_c)
                with _STATE_LOCK:
                    rosetta.add_matched(rom, e, code_c, pr_c)
                m_c, _, _, _, tot, pct = get_stats(state, manifest)
                log_event(
                    f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [MATCH 100%] {name} (tam={e['size']:4d}B) | "
                    f"Ant: {prev_sc*100:5.1f}% -> 100.0% en Ronda #{round_num} ({evals} evals, {time.time()-t_start:.1f}s) "
                    f"via {tag_c} [{pr_c}] | Total: {m_c}/{tot} ({pct:.2f}%)"
                )
                record_operator_trial(tag_c, improved=True, matched=True)
                return True, 1.0, tag_c

            if sc > 0.0:
                new_pool.append((ds, sc, code_c, pr_c, got, tag_c))
                if ds > best_ds or (ds == best_ds and sc > best_sc + 1e-6):
                    old_best_sc = best_sc
                    old_best_ds = best_ds
                    best_ds = ds
                    best_sc = max(best_sc, sc)
                    best_code, best_preset, best_got, best_how = code_c, pr_c, got, tag_c
                    round_improved = True
                    is_improved = True
                    persist_progress(e, state, best_code, best_sc, best_preset, best_how)
                    log_event(
                        f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [SUBIDA-PARIDAD] {name} | "
                        f"{old_best_sc*100:5.2f}% -> {best_sc*100:5.2f}% (depth: {old_best_ds[0]}B -> {best_ds[0]}B) (Ant inicial: {prev_sc*100:5.1f}%) "
                        f"en Ronda #{round_num} via {tag_c} [{pr_c}] (Checkpoint guardado)"
                    )
            record_operator_trial(tag_c, improved=is_improved, matched=is_match)

        # Actualizar frontera (Beam Search con diversidad estructural y deduplicacion por binario compilado)
        seen_got_hashes = set()
        combined = {}
        for ds, sc, c, pr, g, tg in frontier:
            k = EP.norm(c)
            gh = hashlib.sha1(g).digest() if g else b""
            seen_got_hashes.add(gh)
            combined[k] = (ds, sc, c, pr, g, tg)

        for ds, sc, c, pr, g, tg in sorted(new_pool, key=lambda x: (x[0], x[1]), reverse=True)[:30]:
            k = EP.norm(c)
            gh = hashlib.sha1(g).digest() if g else b""
            if k not in combined:
                if gh not in seen_got_hashes or ds >= best_ds:
                    seen_got_hashes.add(gh)
                    combined[k] = (ds, sc, c, pr, g, tg)
            elif (ds, sc) > (combined[k][0], combined[k][1]):
                combined[k] = (ds, sc, c, pr, g, tg)
        frontier = sorted(combined.values(), key=lambda x: (x[0], x[1]), reverse=True)[:16]

        if round_improved:
            stale_rounds = 0
        else:
            stale_rounds += 1
            if stale_rounds >= MAX_STALE_BEFORE_ROTATE:
                with _STATE_LOCK:
                    cur_st = state.get(name, {})
                    cur_st["tries"] = int(cur_st.get("tries", 0)) + 1
                    state[name] = cur_st
                    common.save_state(state)
                log_event(
                    f"{tag_prefix}[{idx_pos:4d}/{total_todo}] [ROTACION-ESTANCADA] {name} no mostro mejoras en {stale_rounds} rondas "
                    f"(actual: {best_sc*100:5.2f}%, intentos={cur_st['tries']}). Guardando punto seguro y rotando a la siguiente funcion..."
                )
                return False, best_sc, best_how


def main():
    ap = argparse.ArgumentParser(description="Motor Seguro Auto-Retroalimentado (No Abandona hasta 100%%)")
    ap.add_argument("--only", type=str, default="", help="Atacar funciones especificas separadas por coma")
    ap.add_argument("--min-score", type=float, default=0.0, help="Paridad minima inicial (default: 0.0)")
    ap.add_argument("--max-score", type=float, default=0.9999, help="Paridad maxima inicial")
    ap.add_argument("--max-rounds", type=int, default=0, help="Maximo de rondas por funcion (0 = NO ABANDONAR hasta 100%%)")
    ap.add_argument("--limit", type=int, default=0, help="Limite de funciones a procesar en la sesion (0 = todas)")
    ap.add_argument("--funcs", type=int, default=int(os.environ.get("FOMT_CONCURRENT_FUNCS", "4")), help="Funciones atacadas en paralelo simultaneo (default: 4)")
    ap.add_argument("--workers", type=int, default=int(os.environ.get("FOMT_WORKERS", "3")), help="Hilos concurrentes de compilacion por funcion (default: 3)")
    ap.add_argument("--max-size", type=int, default=160, help="Umbral maximo de bytes para priorizar funciones (default: 160). Funciones mayores van a la cola final.")
    args = ap.parse_args()

    init_explored_db()

    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()
    rosetta = RD.RosettaCorpus(rom, manifest, state)

    matched, approx, wip, orphan, total, pct = get_stats(state, manifest)
    log_event("=" * 88)
    log_event("FOMT-MATCH-ENGINE :: MOTOR AUTO-RETROALIMENTADO (MODO IMPLACABLE HASTA 100%)")
    log_event(f"ESTADO INICIAL: {matched}/{total} Matches 100% ({pct:.2f}%) | Approx: {approx} | WIP: {wip} | Orphan: {orphan}")
    log_event(f"CORPUS ROSETTA EN VIVO: {rosetta.count} funciones byte-perfect ({len(rosetta.by_skeleton)} esqueletos unicos)")
    log_event(f"CONCURRENCIA GLOBAL: {args.funcs} funciones simultaneas x {args.workers} hilos de compilacion c/u (Total: {args.funcs * args.workers} hilos)")
    log_event(f"TANDA AISLADA: {TANDA_DIR} | Log: {TANDA_LOG}")
    log_event(f"POLITICA DE PERSISTENCIA: {'NO ABANDONAR HASTA 100% (crear logs/skip.flag para saltar)' if args.max_rounds == 0 else f'Max {args.max_rounds} rondas/fn'}")
    log_event("=" * 88)

    print_global_rom_pulse(0, state=state, manifest=manifest)

    only_set = {x.strip() for x in args.only.split(",") if x.strip()}
    pending_items = []
    for e in manifest:
        n = e["name"]
        st = state.get(n, {})
        status = st.get("status", "wip")
        if status == "matched" and not only_set:
            continue
        if only_set and n not in only_set:
            continue
        sc = float(st.get("best", 0.0) or 0.0)
        if not only_set and not (args.min_score <= sc <= args.max_score):
            continue
        pending_items.append(e)

    # PLANIFICADOR PRIORITARIO POR PARIDAD Y ESCALA (Anti-Estancamiento):
    # 1. Tier 0: Paridad alta (80% - 99.99%) y tamano pequeno/mediano (size <= max_size).
    # 2. Tier 1: Paridad media (50% - 79.99%) y tamano pequeno/mediano.
    # 3. Tier 2: Paridad baja (0.01% - 49.99%) y tamano pequeno/mediano.
    # 4. Tier 3: Sin semilla / huerfanas (0.0%) y tamano pequeno/mediano.
    # 5. Tier 4: FUNCIONES GRANDES (size > max_size) -> relegadas al final de la cola absoluta.
    tier_counts = collections.Counter()

    def compute_priority(item):
        n = item["name"]
        st = state.get(n, {})
        sc = float(st.get("best", 0.0) or 0.0)
        sz = item["size"]
        tries = int(st.get(n, {}).get("tries", 0)) if not only_set else 0
        is_large = sz > args.max_size

        if not is_large:
            if sc >= 0.80:
                tier = 0  # 80-99% cortas/medianas (maxima prioridad)
            elif sc >= 0.50:
                tier = 1  # 50-79% cortas/medianas
            elif sc > 0.0:
                tier = 2  # 1-49% cortas/medianas
            else:
                tier = 3  # 0% cortas/medianas
        else:
            tier = 4      # Funciones grandes relegadas al final de la cola

        tier_counts[tier] += 1
        # Orden: menor tier, menos rotaciones previas (tries // 3), mayor paridad (-sc), menor tamano (sz)
        return (tier, tries // 3, -sc, tries, sz, item["addr"])

    todo = [(compute_priority(e), e) for e in pending_items]
    todo.sort(key=lambda x: x[0])
    if args.limit > 0:
        todo = todo[:args.limit]

    total_todo = len(todo)
    log_event(
        f"Cola priorizada ({total_todo} fn): Tier 0 (80-99% <= {args.max_size}B): {tier_counts[0]} | "
        f"Tier 1 (50-79%): {tier_counts[1]} | Tier 2 (1-49%): {tier_counts[2]} | Tier 3 (0%): {tier_counts[3]} | "
        f"Tier 4 (Grandes > {args.max_size}B al final): {tier_counts[4]}"
    )

    solved_session = 0
    iter_counter = 0
    solved_lock = threading.Lock()
    iter_lock = threading.Lock()

    def process_item(item_idx, e_item):
        nonlocal solved_session, iter_counter
        try:
            if STOP_FLAG.exists():
                return False
            st_cur = common.load_state()
            if st_cur.get(e_item["name"], {}).get("status") == "matched" and not only_set:
                return True
            hilo_id = ((item_idx - 1) % args.funcs) + 1
            prefix = f"[F{hilo_id}] " if args.funcs > 1 else ""
            ex, final_sc, how = solve_function_relentless(
                e_item, rom, manifest, st_cur, rosetta, item_idx, total_todo,
                max_rounds=args.max_rounds, workers=args.workers, tag_prefix=prefix
            )
            if ex:
                with solved_lock:
                    solved_session += 1
            with iter_lock:
                iter_counter += 1
                if iter_counter % 15 == 0:
                    print_global_rom_pulse(iter_counter, manifest=manifest)
            return ex
        except Exception as exc:
            tb = traceback.format_exc()
            log_event(f"[ERROR-FATAL] Fallo no capturado procesando {e_item.get('name', 'desconocido')}: {exc}\n{tb}")
            return False

    if args.funcs <= 1:
        for idx_pos, (_, e) in enumerate(todo, 1):
            if STOP_FLAG.exists():
                break
            process_item(idx_pos, e)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.funcs) as fn_executor:
            futures = [fn_executor.submit(process_item, idx_pos, e) for idx_pos, (_, e) in enumerate(todo, 1)]
            for fut in concurrent.futures.as_completed(futures):
                if STOP_FLAG.exists():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    fut.result()
                except Exception as exc:
                    log_event(f"[ERROR-HILO] Fallo en hilo de ejecucion: {exc}\n{traceback.format_exc()}")

    save_operator_stats()
    with _OP_STATS_LOCK:
        top_ops = sorted(_OP_STATS.items(), key=lambda kv: -(kv[1]["matched"] * 1000 + kv[1]["improved"]))
    if top_ops:
        log_event("-" * 88)
        log_event("LINEA BASE DE OPERADORES (Top efectivos):")
        for op, data in top_ops[:12]:
            t, imp, m = data["trials"], data["improved"], data["matched"]
            log_event(f"  Op {op:24s}: {m:3d} matches | {imp:4d} mejoras | {t:6d} pruebas (exito={(imp+m)*100/max(t,1):.2f}%)")
        log_event("-" * 88)

    m_f, a_f, w_f, o_f, tot_f, pct_f = get_stats()
    log_event("=" * 88)
    log_event(f"SESION FINALIZADA :: +{solved_session} Nuevos Matches 100% | Total Global: {m_f}/{tot_f} ({pct_f:.2f}%)")
    log_event(f"DISTRIBUCION: {m_f} matched | {a_f} approx | {w_f} wip | {o_f} orphan")
    log_event("=" * 88)
    print_global_rom_pulse(iter_counter, manifest=manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
