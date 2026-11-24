"""Motor Autonomo 100% CPU para Transpilacion a Pure C/C++ (Zero __asm__, Zero Tokens).

Opera exclusivamente en CPU local sobre todas las funciones de src_sweep/ que aun
contienen __asm__ / asm( / asm volatile, manteniendo en todo momento la regla de oro:
ningun archivo en src_sweep/ se reemplaza a menos que:
  1) El codigo candidato este 100% libre de ensamblador inline.
  2) Al compilarlo (agbcp_O2 / agbcc_O2 / etc.) y enlazarlo produzca 0-Diff exacto
     byte a byte contra 'fomt virgen.gba'.

Etapas (ejecutables individualmente o encadenadas con --stages):
  1. clean   : Limpiador de algebraic-lifter y barreras vacias / register asm("rX").
  2. rosetta : Motor Rosetta Dual (C89 + C++98) sobre el corpus de funciones 100% puras,
               con retroalimentacion en vivo al lograr nuevos matches puros.
  3. synth   : Sintetizadores parametricos C/C++ (destructores polimorficos, FixedVec,
               AutoPtr, switch dispatchers, bitfields, wrappers y pure_cpp_transpiler).
  4. beam    : Beam Search + Permutador Dual (agbcp_O2 + agbcc_O2) sobre semillas .wip.c
               y approx/ usando temporales en SSD local (%TEMP%) y cache SQLite.

Uso tipico:
  python tools/match/pure_cpu_forge.py --stages clean,rosetta,synth --workers 12
  python tools/match/pure_cpu_forge.py --stages beam --max-size 128 --workers 12 --seconds 15
  python tools/match/pure_cpu_forge.py --stages all --workers 12 --max-size 256 --verify-rom
"""
import argparse
import collections
import concurrent.futures
import difflib
import hashlib
import itertools
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FOMT_TREE", "src_sweep")
sys.path.insert(0, str(ROOT / "tools" / "match"))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB  # noqa
import algebraic_lifter as al
import common
import exact_permuter as EP
import fsm_lifter as fl
import lift
import pure_cpp_transpiler as pct
import rosetta_decompiler as RD

try:
    import psutil
except ImportError:
    psutil = None

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MD_THUMB = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
TEMP_ROOT = Path(tempfile.gettempdir()) / "fomt_cpu_forge"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
EXPLORED_DB = LOG_DIR / "pure_forge_explored.db"
STOP_FLAG = common.TREE_DIR / "control" / "stop.flag"

DEFAULT_PRESETS = ("agbcp_O2", "agbcc_O2", "agbcp_O1", "agbcc_O1", "old_agbcc_O2", "agbcc_Os")

_FILE_LOCK = threading.RLock()
_DB_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()


def log(msg: str = ""):
    ts = time.strftime("[%H:%M:%S]")
    with _LOG_LOCK:
        print(f"{ts} {msg}", flush=True)


def set_cpu_thermal_policy(workers: int):
    """Fija prioridad BELOW_NORMAL en Windows para evitar estrangulamiento termico sostenido."""
    if psutil is None or os.name != "nt":
        return
    try:
        p = psutil.Process(os.getpid())
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        n_cpus = os.cpu_count() or 8
        mask_n = max(1, min(n_cpus, int(workers)))
        if mask_n < n_cpus:
            p.cpu_affinity(list(range(mask_n)))
    except Exception:
        pass


def has_inline_asm(txt: str) -> bool:
    if not txt:
        return True
    if "__asm__" in txt or "asm volatile" in txt:
        return True
    if re.search(r"\basm\s*\(", txt):
        return True
    if re.search(r'\basm\s+"', txt):
        return True
    return False


def strip_prelude(code: str) -> str:
    if "#define NULL 0" in code:
        tail = code.split("#define NULL 0")[-1].strip()
        return tail + "\n"
    if "#define FALSE 0" in code:
        tail = code.split("#define FALSE 0")[-1].strip()
        return tail + "\n"
    return code.strip() + "\n"


def norm_code_hash(code: str, preset: str = "") -> str:
    norm = re.sub(r"\s+", " ", code).strip()
    return hashlib.sha1(f"{preset}:{norm}".encode("utf-8", errors="ignore")).hexdigest()[:24]


def init_db():
    with _DB_LOCK:
        try:
            with sqlite3.connect(EXPLORED_DB, timeout=15) as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS explored ("
                    "func TEXT, h TEXT, PRIMARY KEY(func, h))"
                )
                conn.commit()
        except sqlite3.Error:
            pass


def db_load_func(func_name: str) -> set:
    with _DB_LOCK:
        try:
            with sqlite3.connect(EXPLORED_DB, timeout=15) as conn:
                rows = conn.execute("SELECT h FROM explored WHERE func=?", (func_name,)).fetchall()
            return {r[0] for r in rows}
        except sqlite3.Error:
            return set()


def db_save_func(func_name: str, hashes: list):
    if not hashes:
        return
    with _DB_LOCK:
        try:
            with sqlite3.connect(EXPLORED_DB, timeout=15) as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO explored (func, h) VALUES (?, ?)",
                    [(func_name, h) for h in hashes],
                )
                conn.commit()
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------------------
# Evaluador rapido en SSD local (%TEMP%) con enlace rapido y scoring ASM-Diff
# ---------------------------------------------------------------------------

def _is_padding_only(rem: bytes) -> bool:
    if not rem:
        return True
    return len(rem.replace(b"\x00", b"").replace(b"\xc0\x46", b"").replace(b"\xff", b"")) == 0


def _score_asm_bytes(got: bytes, target: bytes, addr: int) -> float:
    if got == target:
        return 1.0
    if not got or not target:
        return 0.0
    ins_g = [f"{i.mnemonic} {i.op_str}" for i in MD_THUMB.disasm(got, addr)]
    ins_t = [f"{i.mnemonic} {i.op_str}" for i in MD_THUMB.disasm(target, addr)]
    op_sim = difflib.SequenceMatcher(None, ins_g, ins_t).ratio() if (ins_g and ins_t) else 0.0
    byte_sim = difflib.SequenceMatcher(None, got, target).ratio()
    len_pen = min(len(got), len(target)) / max(len(got), len(target))
    sc = (0.65 * op_sim + 0.35 * byte_sim) * (0.75 + 0.25 * len_pen)
    return min(0.9999, sc)


def eval_candidate_fast(
    e: dict,
    code: str,
    rom: bytes,
    presets: tuple = DEFAULT_PRESETS,
    compute_score: bool = False,
):
    """Compila y evalua code (0 __asm__ obligatorio) usando SSD %TEMP%/fomt_cpu_forge."""
    if has_inline_asm(code):
        return False, None, 0.0
    name = e["name"]
    target = common.rom_bytes(rom, e["addr"], e["size"])
    body = strip_prelude(code) if "typedef unsigned char u8;" in code else code
    full_code = al.PRELUDE + "\n" + body

    stem = f"f_{os.getpid()}_{threading.get_ident()}_{name}"
    wdir = TEMP_ROOT / f"w_{threading.get_ident() % 32}"
    wdir.mkdir(parents=True, exist_ok=True)
    tmp_c = wdir / f"{stem}.c"
    tmp_o = wdir / f"{stem}.o"
    tmp_bin = wdir / f"{stem}.bin"
    tmp_ld = wdir / f"{stem}.ld"
    tmp_elf = wdir / f"{stem}.elf"

    best_score = 0.0
    best_preset = None
    objcopy_bin = common.find_tool("objcopy")
    ld_bin = common.find_tool("ld")

    try:
        tmp_c.write_text(full_code, encoding="utf-8")
        need_ld = any(
            k in body
            for k in (
                "func_", "g_", "C_", "D_", "delete", "new", "/", "%",
                "memcpy", "memset", "memmove", "memcmp", "strcpy", "strlen", "strcat", "malloc", "free", "rand",
            )
        )
        sym_defs = None
        for preset in presets:
            for pf in (tmp_o, tmp_bin, tmp_elf):
                try:
                    if pf.exists():
                        pf.unlink()
                except OSError:
                    pass
            r = common.cc_compile(tmp_c, tmp_o, "THUMB", preset, c_code=full_code, exclude_name=name)
            if r.returncode != 0 or not tmp_o.exists():
                continue
            subprocess.run(
                [objcopy_bin, "-O", "binary", "-j", ".text", str(tmp_o), str(tmp_bin)],
                capture_output=True,
                timeout=10,
            )
            if not tmp_bin.exists():
                continue
            got = tmp_bin.read_bytes()
            exact = False
            if got == target or (len(got) <= len(target) and got == target[:len(got)] and _is_padding_only(target[len(got):])):
                exact = True
            if not exact and need_ld:
                if sym_defs is None:
                    calls = re.findall(r"func_([0-9A-Fa-f]{8})", body)
                    gsyms = re.findall(r"g_([0-9A-Fa-f]{8})", body)
                    vtsyms = re.findall(r"\bC_([0-9A-Fa-f]{8})\b", body)
                    dtsyms = re.findall(r"\bD_([0-9A-Fa-f]{8})\b", body)
                    sd = [f"func_{c} = 0x{int(c, 16) & ~1:08X};" for c in set(calls) if f"func_{c}" != name]
                    sd += [f"g_{g} = 0x{int(g, 16):08X};" for g in set(gsyms)]
                    sd += [f"__vt_10C_{v} = 0x{int(v, 16):08X};" for v in set(vtsyms)]
                    sd += [f"_._10D_{d} = 0x{int(d, 16) & ~1:08X};" for d in set(dtsyms) if f"func_{d}" != name]
                    sd += [
                        "__builtin_delete = 0x08000608;",
                        "__builtin_new = 0x080005D4;",
                        "__divsi3 = 0x080D0EC8;",
                        "__modsi3 = 0x080D0ED0;",
                        "__udivsi3 = 0x080D0EDA;",
                        "__umodsi3 = 0x080D0F4E;",
                        "malloc = 0x080D01F8;",
                        "free = 0x080D0260;",
                        "rand = 0x080D11E4;",
                        "memcmp = 0x080D3948;",
                        "memcpy = 0x080D3994;",
                        "memmove = 0x080D39F8;",
                        "memset = 0x080D3A84;",
                        "strcat = 0x080D3ADC;",
                        "strcpy = 0x080D3B28;",
                        "strlen = 0x080D3B78;",
                    ]
                    sym_defs = "\n".join(sd)
                    ld_txt = f"SECTIONS {{\n  . = 0x{e['addr']:08X};\n  .text : {{ *(.text) }}\n}}\n{sym_defs}\n"
                    tmp_ld.write_text(ld_txt, encoding="utf-8")
                lr = subprocess.run(
                    [ld_bin, "-T", str(tmp_ld), "-o", str(tmp_elf), str(tmp_o)],
                    capture_output=True,
                    timeout=10,
                )
                if lr.returncode == 0 and tmp_elf.exists():
                    subprocess.run(
                        [objcopy_bin, "-O", "binary", str(tmp_elf), str(tmp_bin)],
                        capture_output=True,
                        timeout=10,
                    )
                    if tmp_bin.exists():
                        got = tmp_bin.read_bytes()
                        if got == target or (len(got) <= len(target) and got == target[:len(got)] and _is_padding_only(target[len(got):])):
                            exact = True
            if exact:
                return True, preset, 1.0
            if compute_score:
                sc = _score_asm_bytes(got, target, e["addr"])
                if sc > best_score:
                    best_score = sc
                    best_preset = preset
    finally:
        for pf in (tmp_c, tmp_o, tmp_bin, tmp_ld, tmp_elf):
            try:
                if pf.exists():
                    pf.unlink()
            except OSError:
                pass
    return False, best_preset, best_score


def commit_pure_match(e: dict, code: str, preset: str, how: str, state: dict):
    """Persiste un match 100% Pure C/C++ verificado en src_sweep y state.json."""
    if has_inline_asm(code):
        raise ValueError(f"Intento de escribir ASM inline en commit_pure_match para {e['name']}")
    body = strip_prelude(code) if "typedef unsigned char u8;" in code else code
    full_code = al.PRELUDE + "\n" + body.strip() + "\n"
    with _FILE_LOCK:
        c_file = common.TREE_DIR / e["file"]
        c_file.write_text(full_code, encoding="utf-8")
        st = state.setdefault(e["name"], {})
        st["status"] = "matched"
        st["preset"] = preset
        st["best"] = 1.0
        st["how"] = how
        st["size"] = e["size"]
        common.save_state(state)


def get_asm_pending(manifest: list) -> list:
    pending = []
    for e in manifest:
        p = common.TREE_DIR / e["file"]
        txt = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        if has_inline_asm(txt):
            pending.append(e)
    return pending


# ---------------------------------------------------------------------------
# Etapa 1: Limpiador de algebraic-lifter y barreras vacias
# ---------------------------------------------------------------------------

def _gen_clean_variants(e: dict) -> list:
    p = common.TREE_DIR / e["file"]
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="replace")
    if ".macro bx reg" in raw:
        return []
    body = strip_prelude(raw)
    cands = []

    # Variante 1: eliminar barreras vacias + quitar asm("rX") de declaraciones register
    v1 = re.sub(r'(__asm__|asm)\s*(volatile)?\s*\(\s*""\s*:[^;]*\);?', "", body)
    v1 = re.sub(r'\bregister\s+(.+?)\s+(?:__asm__|asm)\s*\(\s*"r\d+"\s*\)\s*;', r"register \1;", v1)
    v1 = re.sub(r'asm\s*\(\s*"ldr\s+%0,\s*=\s*(0x[0-9A-Fa-f]+|\d+)"\s*:\s*"=r"\s*\(\s*(\w+)\s*\)\s*\)\s*;', r"\2 = \1;", v1)
    if not has_inline_asm(v1):
        cands.append(v1)

    # Variante 2: quitar tambien 'register'
    v2 = re.sub(r"\bregister\s+", "", v1)
    if not has_inline_asm(v2) and v2 != v1:
        cands.append(v2)

    # Variante 3: usar const para literales ldr si la funcion es pequena
    v3 = re.sub(r"(\bu32\s+\w+)\s*;\s*\n(\s*)(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;", r"const \1 = \4;", v2)
    if not has_inline_asm(v3) and v3 not in cands:
        cands.append(v3)

    return cands


def stage_clean_algebraic(rom: bytes, manifest: list, state: dict, workers: int) -> int:
    pending = get_asm_pending(manifest)
    targets = [(e, _gen_clean_variants(e)) for e in pending]
    targets = [(e, cs) for e, cs in targets if cs]
    log(f"[Stage 1/clean] {len(targets)} funciones ASM candidatas a limpieza directa ({workers} workers)...")
    if not targets:
        return 0

    def _work(item):
        e, cands = item
        for code in cands:
            ok, preset, _ = eval_candidate_fast(e, code, rom, presets=DEFAULT_PRESETS)
            if ok:
                return e, code, preset
        return e, None, None

    wins = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_work, it) for it in targets]
        for fut in concurrent.futures.as_completed(futs):
            if STOP_FLAG.exists():
                break
            e, code, preset = fut.result()
            if code:
                commit_pure_match(e, code, preset, "pure-cpu-clean", state)
                wins += 1
                log(f"  [CLEAN 0-DIFF] {e['name']} ({e['size']}B) -> {preset}")
    log(f"[Stage 1/clean] Completado: {wins} funciones purificadas.")
    return wins


# ---------------------------------------------------------------------------
# Etapa 2: Rosetta Dual (C89 + C++98) sobre corpus 100% puro con feedback
# ---------------------------------------------------------------------------

def _build_pure_rosetta_index(rom: bytes, manifest: list, state: dict):
    by_skel = collections.defaultdict(list)
    total = 0
    for e in manifest:
        p = common.TREE_DIR / e["file"]
        if not p.exists():
            continue
        raw = p.read_text(encoding="utf-8", errors="replace")
        if has_inline_asm(raw):
            continue
        feat = RD.extract_thumb_features(rom, e)
        if not feat or not feat["skeleton"]:
            continue
        body = strip_prelude(raw)
        preset = state.get(e["name"], {}).get("preset", "agbcc_O2")
        by_skel[feat["skeleton"]].append({
            "name": e["name"],
            "code": body,
            "literals": feat["literals"],
            "calls": feat["calls"],
            "preset": preset,
        })
        total += 1
    return by_skel, total


def _instantiate_dual(tpl: dict, feat: dict, target_name: str) -> str:
    cand = tpl["code"]
    cand = re.sub(rf"\b{re.escape(tpl['name'])}\b", target_name, cand)
    if len(tpl["calls"]) == len(feat["calls"]):
        for idx, old_fn in enumerate(tpl["calls"]):
            cand = re.sub(rf"\b{re.escape(old_fn)}\b", f"__R_CALL_{idx}__", cand, count=1)
        for idx, new_fn in enumerate(feat["calls"]):
            cand = cand.replace(f"__R_CALL_{idx}__", new_fn)
    if len(tpl["literals"]) == len(feat["literals"]):
        old_vts = []
        new_vts = []
        for idx, (ov, nv) in enumerate(zip(tpl["literals"], feat["literals"])):
            if ov == nv:
                continue
            cand = cand.replace(f"g_{ov:08X}", f"__R_G_{idx}__")
            cand = cand.replace(f"C_{ov:08X}", f"__R_C_{idx}__")
            for pat in (f"0x{ov:08X}", f"0x{ov:08x}", f"0x{ov:X}", f"0x{ov:x}"):
                cand = re.sub(rf"\b{re.escape(pat)}\b", f"__R_L_{idx}__", cand)
            old_vts.append((idx, ov, nv))
        for idx, ov, nv in old_vts:
            cand = cand.replace(f"__R_G_{idx}__", f"g_{nv:08X}")
            cand = cand.replace(f"__R_C_{idx}__", f"C_{nv:08X}")
            cand = cand.replace(f"__R_L_{idx}__", f"0x{nv:08X}")
    return cand


def stage_rosetta_dual(rom: bytes, manifest: list, state: dict, workers: int) -> int:
    by_skel, total_pure = _build_pure_rosetta_index(rom, manifest, state)
    log(f"[Stage 2/rosetta] Indice Rosetta Dual construido con {total_pure} funciones puras ({len(by_skel)} esqueletos unicos)...")
    total_wins = 0
    rnd = 1
    while not STOP_FLAG.exists():
        pending = get_asm_pending(manifest)
        work_items = []
        for e in pending:
            feat = RD.extract_thumb_features(rom, e)
            if not feat:
                continue
            tpls = by_skel.get(feat["skeleton"])
            if not tpls:
                continue
            cands = []
            for tpl in tpls[:4]:
                c = _instantiate_dual(tpl, feat, e["name"])
                if not has_inline_asm(c) and c not in cands:
                    cands.append((c, tpl["preset"]))
            if cands:
                work_items.append((e, feat, cands))

        if not work_items:
            break
        log(f"  [Rosetta R#{rnd}] {len(work_items)} funciones pendientes tienen esqueleto identico en el corpus...")

        def _work(item):
            e, feat, cands = item
            for code, donor_preset in cands:
                ordered = tuple(dict.fromkeys([donor_preset] + list(DEFAULT_PRESETS)))
                ok, preset, _ = eval_candidate_fast(e, code, rom, presets=ordered)
                if ok:
                    return e, feat, code, preset
            return e, feat, None, None

        round_wins = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_work, it) for it in work_items]
            for fut in concurrent.futures.as_completed(futs):
                if STOP_FLAG.exists():
                    break
                e, feat, code, preset = fut.result()
                if code:
                    commit_pure_match(e, code, preset, "pure-cpu-rosetta", state)
                    by_skel[feat["skeleton"]].append({
                        "name": e["name"],
                        "code": strip_prelude(code),
                        "literals": feat["literals"],
                        "calls": feat["calls"],
                        "preset": preset,
                    })
                    round_wins += 1
                    total_wins += 1
                    log(f"  [ROSETTA 0-DIFF] {e['name']} ({e['size']}B) -> {preset}")
        if round_wins == 0:
            break
        rnd += 1
    log(f"[Stage 2/rosetta] Completado: {total_wins} funciones purificadas.")
    return total_wins


# ---------------------------------------------------------------------------
# Etapa 3: Sintetizadores Parametricos C++ / C89
# ---------------------------------------------------------------------------

def _gen_parametric_candidates(e: dict, rom: bytes) -> list:
    cands = list(pct.generate_pure_candidates(e, rom))
    name = e["name"]
    addr = e["addr"]
    size = e["size"]
    insns = al.get_clean_insns(rom, addr, size)
    fsm = fl.parse_function_fsm(rom, addr, size)
    calls = [f"func_{ins.operands[0].imm:08X}" for pc, ins in sorted(fsm["insns_at"].items()) if ins.mnemonic == "bl"]
    vts = [f"{v:08X}" for k, v in sorted(fsm["pool_words"].items()) if 0x080E5000 <= v < 0x080EA000]

    # Sintetizador parametrico A: Simple deleting destructor de 1 clase (vtable + func_08000608)
    if 36 <= size <= 72 and len(calls) == 1 and calls[0] == "func_08000608" and len(vts) == 1:
        vt = vts[0]
        for off in (0, 4, 8, 12, 16, 20):
            pad = f"u8 pad[0x{off:x}];\n    " if off > 0 else ""
            cands.append(f"""struct C_{vt} {{
    {pad}virtual ~C_{vt}() {{}}
}};
extern "C" void {name}() __attribute__((alias("_._10C_{vt}")));
""")

    # Sintetizador parametrico B: Switch dispatcher pequeno (cmp r1, #k; beq ...) que escribe en [r2, #off]
    if 28 <= size <= 64 and not calls and insns:
        ops_str = [f"{i.mnemonic} {i.op_str}" for i in insns]
        cases = []
        for idx, s in enumerate(ops_str):
            m = re.match(r"cmp r1, #(0x[0-9a-fA-F]+|\d+)", s)
            if m:
                cases.append(int(m.group(1), 0))
        if len(cases) >= 2 and any("ldr" in s and "[pc" in s for s in ops_str):
            pools = [v for _, v in sorted(fsm["pool_words"].items())]
            # Detectar offset de vtable store str r0, [r2, #off]
            st_off = None
            for s in ops_str:
                m_st = re.match(r"str r0, \[r2(?:, #(0x[0-9a-fA-F]+|\d+))?\]", s)
                if m_st and any("pc" in x for x in ops_str):
                    st_off = int(m_st.group(1), 0) if m_st.group(1) else 0
            if st_off is not None and len(pools) == 1:
                # Variante tipo func_080940C0
                b_st = [re.match(r"strb r0, \[r2, #(0x[0-9a-fA-F]+|\d+)\]", s) for s in ops_str]
                b_off = next((int(m.group(1), 0) for m in b_st if m), None)
                if b_off is not None:
                    cands.append(f"""struct S {{ u8 pad[0x{max(st_off+4, b_off+1):x}]; }};
extern "C" void {name}(u8 *s, int x) {{
    switch (x) {{
    case {cases[0]}:
        s[0x{b_off:x}] = 1;
        break;
    case {cases[1]}:
        s[0x{b_off:x}] = 0;
        break;
    default:
        return;
    }}
    *(u32 *)(s + 0x{st_off:x}) = 0x{pools[0]:08X};
}}
""")

    # Limpiar duplicados y solo puros
    uniq = []
    seen = set()
    for c in cands:
        if has_inline_asm(c):
            continue
        h = norm_code_hash(c)
        if h not in seen:
            seen.add(h)
            uniq.append(c)
    return uniq


def stage_parametric_synth(rom: bytes, manifest: list, state: dict, workers: int) -> int:
    pending = get_asm_pending(manifest)
    items = [(e, _gen_parametric_candidates(e, rom)) for e in pending]
    items = [(e, cs) for e, cs in items if cs]
    log(f"[Stage 3/synth] Probando {len(items)} funciones con candidatos parametricos ({workers} workers)...")
    if not items:
        return 0

    def _work(item):
        e, cands = item
        for code in cands:
            ok, preset, _ = eval_candidate_fast(e, code, rom, presets=DEFAULT_PRESETS)
            if ok:
                return e, code, preset
        return e, None, None

    wins = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_work, it) for it in items]
        for fut in concurrent.futures.as_completed(futs):
            if STOP_FLAG.exists():
                break
            e, code, preset = fut.result()
            if code:
                commit_pure_match(e, code, preset, "pure-cpu-synth", state)
                wins += 1
                log(f"  [SYNTH 0-DIFF] {e['name']} ({e['size']}B) -> {preset}")
    log(f"[Stage 3/synth] Completado: {wins} funciones purificadas.")
    return wins


# ---------------------------------------------------------------------------
# Etapa 4: Beam Search + Permutador Dual sobre semillas .wip.c / approx/
# ---------------------------------------------------------------------------

def _load_pure_seed(e: dict, rom: bytes):
    approx_p = common.TREE_DIR / "approx" / f"{e['name']}.c"
    wip_p = (common.TREE_DIR / e["file"]).with_suffix(".wip.c")
    raw = None
    for p in (approx_p, wip_p):
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            if not has_inline_asm(txt):
                raw = txt
                break
    if not raw:
        return None
    norm = lift.normalize_c89(raw, rom=rom, e=e)
    norm = strip_prelude(norm)
    if has_inline_asm(norm) or e["name"] not in norm:
        return None
    return norm


def _extra_cpp_variants(code: str) -> list:
    """Genera variantes idiomaticas C++98 / C89 ligeras para el Beam Search."""
    out = []
    # Retorno bool <-> u32 <-> int <-> void
    m_ret = re.match(r"^(\s*)(void|u32|u16|u8|s32|s16|s8|int|bool)\b(.*)$", code, re.M)
    if m_ret:
        ind, rt, rest = m_ret.groups()
        alts = ["u32", "int", "bool", "s32", "u16", "u8"] if rt != "void" else ["u32", "int"]
        for nrt in alts:
            if nrt != rt:
                nc = code[:m_ret.start()] + f"{ind}{nrt}{rest}" + code[m_ret.end():]
                out.append(("ret->" + nrt, nc))
    # Quitar/poner cast (u8)/(u16)/(s16) en returns
    if "return (" in code:
        nc = re.sub(r"return\s*\((?:u8|u16|u32|s8|s16|s32|int)\)\s*", "return ", code)
        if nc != code:
            out.append(("un_ret_cast", nc))
    # Compactar != 0 / == 0 en if
    for m in list(re.finditer(r"if\s*\(([^()]+?)\s*!=\s*0\)", code))[:4]:
        nc = code[:m.start()] + f"if ({m.group(1)})" + code[m.end():]
        out.append(("drop_ne0", nc))
    for m in list(re.finditer(r"if\s*\(([^()]+?)\s*==\s*0\)", code))[:4]:
        nc = code[:m.start()] + f"if (!({m.group(1)}))" + code[m.end():]
        out.append(("eq0_to_not", nc))
    # Quitar llaves redundantes de if de una linea o invertir bloques if/else
    return out


def _solve_beam_one(e: dict, rom: bytes, max_seconds: float, beam_w: int = 5, max_depth: int = 3):
    seed = _load_pure_seed(e, rom)
    if not seed:
        return e, None, None, 0.0, 0

    name = e["name"]
    t0 = time.time()
    seen = db_load_func(name)
    new_hashes = []
    evals = 0

    def try_eval(code: str, presets: tuple):
        nonlocal evals
        h = norm_code_hash(code, "+".join(presets))
        if h in seen:
            return False, None, 0.0
        seen.add(h)
        new_hashes.append(h)
        evals += 1
        return eval_candidate_fast(e, code, rom, presets=presets, compute_score=True)

    # Evaluar semilla en todos los presets principales para detectar cual compila mejor
    ok, best_preset, best_sc = try_eval(seed, DEFAULT_PRESETS)
    if ok:
        db_save_func(name, new_hashes)
        return e, seed, best_preset, 1.0, evals
    if not best_preset:
        best_preset = "agbcp_O2"

    focus_presets = tuple(dict.fromkeys([best_preset, "agbcp_O2", "agbcc_O2"]))
    beam = [(best_sc, seed)]
    best_code = seed

    # Fase A: permutaciones de declaraciones locales (n! hasta 24)
    for tag, cand in EP.decl_permutations(seed, cap=24):
        if time.time() - t0 > max_seconds or STOP_FLAG.exists():
            break
        ok, pr, sc = try_eval(cand, focus_presets)
        if ok:
            db_save_func(name, new_hashes)
            return e, cand, pr, 1.0, evals
        if sc > best_sc:
            best_sc, best_code = sc, cand
            beam.append((sc, cand))

    beam.sort(key=lambda x: x[0], reverse=True)
    beam = beam[:beam_w]

    # Fase B: Beam Search combinando exact_permuter.neighbors + variantes C++98
    for depth in range(max_depth):
        if time.time() - t0 > max_seconds or STOP_FLAG.exists():
            break
        next_pool = []
        for _, base_code in beam:
            if time.time() - t0 > max_seconds or STOP_FLAG.exists():
                break
            cands = EP.neighbors(base_code) + _extra_cpp_variants(base_code)
            # Limitar explosión combinatoria en funciones medianas manteniendo variedad
            for tag, cand in cands[:60]:
                if time.time() - t0 > max_seconds or STOP_FLAG.exists():
                    break
                if has_inline_asm(cand):
                    continue
                ok, pr, sc = try_eval(cand, focus_presets)
                if ok:
                    db_save_func(name, new_hashes)
                    return e, cand, pr, 1.0, evals
                if sc > best_sc:
                    best_sc, best_code = sc, cand
                if sc >= best_sc - 0.04:
                    next_pool.append((sc, cand))
        if not next_pool:
            break
        next_pool.sort(key=lambda x: x[0], reverse=True)
        # Mantener mejores distintos
        dedup_beam = []
        b_hashes = set()
        for sc, c in next_pool:
            ch = norm_code_hash(c)
            if ch not in b_hashes:
                b_hashes.add(ch)
                dedup_beam.append((sc, c))
            if len(dedup_beam) >= beam_w:
                break
        if not dedup_beam:
            break
        beam = dedup_beam

    db_save_func(name, new_hashes)
    return e, best_code, None, best_sc, evals


def stage_beam_wip(
    rom: bytes,
    manifest: list,
    state: dict,
    workers: int,
    max_size: int = 256,
    seconds: float = 15.0,
    limit: int = 0,
) -> int:
    pending = get_asm_pending(manifest)
    queue = []
    for e in pending:
        if max_size > 0 and e["size"] > max_size:
            continue
        if _load_pure_seed(e, rom):
            queue.append(e)
    queue.sort(key=lambda x: (x["size"], x["addr"]))
    if limit > 0:
        queue = queue[:limit]

    log(f"[Stage 4/beam] {len(queue)} funciones con semilla C pura (size <= {max_size or 'INF'}B, {seconds}s/func, {workers} workers)...")
    if not queue:
        return 0

    wins = 0
    done = 0
    total_evals = 0
    approx_dir = common.TREE_DIR / "approx"
    approx_dir.mkdir(parents=True, exist_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_solve_beam_one, e, rom, seconds): e for e in queue}
        for fut in concurrent.futures.as_completed(futs):
            e, code, preset, sc, ev = fut.result()
            done += 1
            total_evals += ev
            if preset:
                commit_pure_match(e, code, preset, "pure-cpu-beam", state)
                wins += 1
                log(f"  [BEAM 0-DIFF] ({done}/{len(queue)}) {e['name']} ({e['size']}B) -> {preset} ({ev} evals)")
            else:
                if code and sc >= 0.85:
                    with _FILE_LOCK:
                        ap_file = approx_dir / f"{e['name']}.c"
                        ap_file.write_text(al.PRELUDE + "\n" + code.strip() + "\n", encoding="utf-8")
                if done % 25 == 0 or sc >= 0.90:
                    log(f"  [beam {done}/{len(queue)}] {e['name']} ({e['size']}B) best={sc*100:.2f}% ({ev} evals)")
            if STOP_FLAG.exists():
                break

    log(f"[Stage 4/beam] Completado: {wins}/{done} funciones purificadas ({total_evals} evaluaciones totales).")
    return wins


def main():
    ap = argparse.ArgumentParser(description="FOMT-MATCH-ENGINE :: Motor Autonomo 100% CPU hacia Pure C/C++")
    ap.add_argument("--stages", default="all", help="Etapas a ejecutar: all o lista separada por comas (clean,rosetta,synth,beam)")
    ap.add_argument("--workers", type=int, default=min(12, os.cpu_count() or 8), help="Workers concurrentes en CPU")
    ap.add_argument("--max-size", type=int, default=256, help="Tamano maximo en bytes para Stage 4 beam (0 = sin limite)")
    ap.add_argument("--seconds", type=float, default=15.0, help="Presupuesto maximo en segundos por funcion en beam")
    ap.add_argument("--limit", type=int, default=0, help="Limite de funciones en Stage 4 beam (0 = todas)")
    ap.add_argument("--verify-rom", action="store_true", help="Ejecuta build_rom.py al concluir")
    args = ap.parse_args()

    if STOP_FLAG.exists():
        STOP_FLAG.unlink()

    set_cpu_thermal_policy(args.workers)
    init_db()

    stages = ["clean", "rosetta", "synth", "beam"] if args.stages == "all" else [s.strip() for s in args.stages.split(",") if s.strip()]
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    initial_pending = len(get_asm_pending(manifest))
    total_funcs = len(manifest)
    log("=" * 72)
    log(f"PURE CPU FORGE :: Inicio | Puras: {total_funcs - initial_pending}/{total_funcs} | ASM restantes: {initial_pending}")
    log(f"Stages: {stages} | Workers: {args.workers} | Temp SSD: {TEMP_ROOT}")
    log("=" * 72)

    t0 = time.time()
    wins_total = 0

    if "clean" in stages and not STOP_FLAG.exists():
        wins_total += stage_clean_algebraic(rom, manifest, state, args.workers)
    if "rosetta" in stages and not STOP_FLAG.exists():
        wins_total += stage_rosetta_dual(rom, manifest, state, args.workers)
    if "synth" in stages and not STOP_FLAG.exists():
        wins_total += stage_parametric_synth(rom, manifest, state, args.workers)
    if "beam" in stages and not STOP_FLAG.exists():
        wins_total += stage_beam_wip(rom, manifest, state, args.workers, max_size=args.max_size, seconds=args.seconds, limit=args.limit)

    final_pending = len(get_asm_pending(manifest))
    pure_now = total_funcs - final_pending
    log("=" * 72)
    log(f"PURE CPU FORGE :: Fin en {time.time() - t0:.1f}s | Purificadas hoy: +{wins_total}")
    log(f"Puras totales: {pure_now}/{total_funcs} ({(pure_now/total_funcs)*100:.2f}%) | ASM restantes: {final_pending}")
    log("=" * 72)

    if args.verify_rom:
        log("[*] Verificando ROM completa via build_rom.py...")
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "match" / "build_rom.py")], cwd=str(ROOT))
        return r.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
