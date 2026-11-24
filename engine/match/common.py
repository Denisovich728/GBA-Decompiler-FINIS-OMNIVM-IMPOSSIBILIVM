"""Utilidades compartidas del pipeline de matching FoMT (ROM <-> C)."""
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROM_PATH = ROOT / "fomt virgen.gba"
ROM_BASE = 0x08000000
DECOMP_DIR = ROOT / "DECOMPS MADRE" / "fomt_virgen"
def _default_tree_name():
    if "FOMT_TREE" in os.environ:
        return os.environ["FOMT_TREE"]
    sweep_m = ROOT / "src_sweep" / "manifest.json"
    tree_m = ROOT / "src_tree" / "manifest.json"
    if sweep_m.exists():
        return "src_sweep"
    if tree_m.exists():
        return "src_tree"
    return "src_sweep"


TREE_NAME = _default_tree_name()
TREE_DIR = ROOT / TREE_NAME
BUILD_DIR = ROOT / ("build_match" if TREE_NAME == "src_tree" else "build_" + TREE_NAME)
MANIFEST = TREE_DIR / "manifest.json"
STATE = TREE_DIR / "state.json"

HEADER_RE = re.compile(r"^// --- (\S+) @ ([0-9a-fA-F]+) \[(\w+)/([\w]+)\] ---\s*$", re.M)

# Presets de compilacion que el driver prueba (el compilador original es desconocido).
CFLAG_PRESETS = {
    "O1": ["-O1"],
    "O2": ["-O2"],
    "Os": ["-Os"],
    "O0": ["-O0"],
}
COMMON_CFLAGS = [
    "-mcpu=arm7tdmi", "-mthumb-interwork", "-ffreestanding", "-fno-builtin",
    "-fno-toplevel-reorder", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-fno-stack-protector", "-fno-ident", "-fno-pic", "-nostdlib", "-w",
    "-I" + str(ROOT / "include"),
]

# Horizonte real de codigo ejecutable (.text) en fomt virgen.gba (0x080000C0 .. 0x080E4000).
# A partir de 0x080E4000 comienzan vtables, .rodata, textos, graficos y audio M4A.
CODE_HORIZON_START = 0x080000C0
CODE_HORIZON_END = 0x080E4000

# ---- Backend Principal GBA SDK: agbcc / agbcp (C++ cc1plus) / old_agbcc (GCC 2.95.2 original de FoMT) + ADS 1.2 ----
AGBCC_DIR = ROOT / "UTILITYS" / "agbcc"
AGBCC_EXE = AGBCC_DIR / "bin" / "agbcc.exe"
AGBCP_EXE = AGBCC_DIR / "bin" / "agbcp.exe"
OLD_AGBCC_EXE = AGBCC_DIR / "bin" / "old_agbcc.exe"

ADS_DIR = ROOT / "UTILITYS" / "ADSv1_2"
ADS_TCC = ADS_DIR / "Bin" / "tcc.exe"
ADS_ARMCC = ADS_DIR / "Bin" / "armcc.exe"
ADS_ARMLINK = ADS_DIR / "Bin" / "armlink.exe"
ADS_FROMELF = ADS_DIR / "Bin" / "fromelf.exe"
USE_ADS = True

AGBCC_PRESETS = {
    "agbcc_O2": (AGBCC_EXE, ["-O2", "-mthumb-interwork", "-fhex-asm"]),
    "agbcp_O2": (AGBCP_EXE, ["-quiet", "-fno-exceptions", "-fno-rtti", "-fvtable-thunks", "-O2", "-mthumb-interwork", "-fhex-asm"]),
    "old_agbcc_O2": (OLD_AGBCC_EXE, ["-O2", "-mthumb-interwork", "-fhex-asm"]),
    "agbcc_O1": (AGBCC_EXE, ["-O1", "-mthumb-interwork", "-fhex-asm"]),
    "agbcp_O1": (AGBCP_EXE, ["-quiet", "-fno-exceptions", "-fno-rtti", "-fvtable-thunks", "-O1", "-mthumb-interwork", "-fhex-asm"]),
    "agbcc_Os": (AGBCC_EXE, ["-Os", "-mthumb-interwork", "-fhex-asm"]),
    "agbcp_Os": (AGBCP_EXE, ["-quiet", "-fno-exceptions", "-fno-rtti", "-fvtable-thunks", "-Os", "-mthumb-interwork", "-fhex-asm"]),
    "old_agbcc_Os": (OLD_AGBCC_EXE, ["-Os", "-mthumb-interwork", "-fhex-asm"]),
    "agbcc_O0": (AGBCC_EXE, ["-O0", "-mthumb-interwork", "-fhex-asm"]),
}

ADS_PRESETS = {
    "O2": ["-O2"],
    "O2s": ["-O2", "-Ospace"],
    "O2t": ["-O2", "-Otime"],
    "O2_nocse": ["-O2", "-Otime", "-Ono_cse"],
    "O2s_nocse": ["-O2", "-Ospace", "-Ono_cse"],
    "O1": ["-O1"],
    "O1_nocse": ["-O1", "-Ono_cse"],
    "O2_nosched": ["-O2", "-Ono_cse", "-Ono_schedule"],
    "O0": ["-O0"],
}
CFLAG_PRESETS = {**AGBCC_PRESETS}
ALL_CFLAG_PRESETS = {**AGBCC_PRESETS, **ADS_PRESETS}
CONFIG_FILE = TREE_DIR / "engine_config.json"

DEFAULT_ENGINE_CONFIG = {
    "watts": 45,
    "threads": 8,
    "cooldown": 1.5,
    "batch_cooldown": 12,
    "duty_cycle": 85,
    "priority": "below_normal",
    "model": "deepseek-coder-v2:latest",
    "num_ctx": 6144,
    "temp_base": 0.08,
    "temp_max": 0.25,
    "tries": 25,
    "permute": 800,
    "permute_quick": 80,
    "approx": 0.90,
    "limit": 25,
}


def estimate_power(threads: int, cooldown: float, duty_cycle: int = 85, priority: str = "below_normal") -> dict:
    """Calculadora electrica calibrada para Intel Core i7-13620H (10C/16T: 6P+4E, Base 45W, PL2 115W) + 16GB RAM."""
    p_system_base = 14.0  # Placa base, NVMe, DDR5 16GB (~3.5W), ventiladores y pantalla minima
    t = max(1, min(16, int(threads)))
    # Primeros 8 hilos en Windows con BELOW_NORMAL evitan Turbo Boost agresivo (~2.9W/hilo); 9..16 escalan en PL2 (~4.6W/hilo)
    if t <= 8:
        cpu_peak = t * 2.95
    else:
        cpu_peak = (8 * 2.95) + ((t - 8) * 4.65)
    if priority == "idle":
        cpu_peak *= 0.78
    elif priority == "normal":
        cpu_peak *= 1.18
    # Factor de ciclo de trabajo efectivo considerando el cooldown entre inferencias (t_inf promedio ~5.5s)
    t_inf = 5.5
    cooldown_factor = t_inf / (t_inf + max(0.0, float(cooldown)))
    duty_factor = (max(20, min(100, int(duty_cycle))) / 100.0) * cooldown_factor
    cpu_avg = cpu_peak * duty_factor
    total_avg = round(p_system_base + cpu_avg, 1)
    total_peak = round(p_system_base + cpu_peak, 1)
    vrm_amp = round(cpu_peak / 1.15, 1)  # Corriente estimada en Vcore (~1.15V)
    risk = "BAJO (Seguro)" if total_peak <= 60 else ("MODERADO" if total_peak <= 82 else "ALTO (Riesgo Apagon)")
    return {
        "total_avg_w": total_avg,
        "total_peak_w": total_peak,
        "cpu_avg_w": round(cpu_avg, 1),
        "cpu_peak_w": round(cpu_peak, 1),
        "system_base_w": p_system_base,
        "vrm_amps": vrm_amp,
        "duty_effective_pct": round(duty_factor * 100.0, 1),
        "risk": risk,
    }


def auto_tune_for_watts(target_watts: float) -> dict:
    """Ajusta automaticamente threads, cooldown, duty_cycle y prioridad para no superar target_watts."""
    w = max(22.0, min(115.0, float(target_watts)))
    best_cfg = {"watts": int(w), "threads": 2, "cooldown": 4.0, "duty_cycle": 50, "priority": "idle"}
    # Buscamos la combinacion de mayor rendimiento cuyo pico no exceda el objetivo (o promedio si es muy bajo)
    for prio in ("below_normal", "idle", "normal"):
        for th in range(16, 0, -1):
            for cd in (0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0):
                for dc in (100, 90, 85, 75, 65, 50):
                    est = estimate_power(th, cd, dc, prio)
                    if est["total_peak_w"] <= w and est["total_avg_w"] <= w * 0.92:
                        return {
                            "watts": int(w),
                            "threads": th,
                            "cooldown": cd,
                            "duty_cycle": dc,
                            "priority": prio,
                            "batch_cooldown": max(6, int(cd * 8)),
                        }
    return best_cfg


def load_engine_config() -> dict:
    cfg = dict(DEFAULT_ENGINE_CONFIG)
    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg.update(loaded)
        except Exception:
            pass
    if int(cfg.get("num_ctx", 6144)) < 6144:
        cfg["num_ctx"] = 6144
    return cfg


def save_engine_config(cfg: dict) -> dict:
    TREE_DIR.mkdir(parents=True, exist_ok=True)
    merged = load_engine_config()
    merged.update(cfg)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CONFIG_FILE)
    return merged


def reset_all_progress() -> dict:
    """Reinicia el progreso desde 0 (limpia state.json, .wip.c, approx/ y collection/) restaurando respaldos .ghidra.txt."""
    restored = 0
    removed_wip = 0
    if TREE_DIR.exists():
        for gfile in TREE_DIR.rglob("*.ghidra.txt"):
            cfile = gfile.with_suffix("")  # quita .txt -> deja .ghidra, espera: path.with_suffix(".ghidra.txt")
            # En save_matched se hizo: path.with_suffix(".ghidra.txt") sobre func_XXXX.c -> func_XXXX.ghidra.txt
            orig_c = gfile.parent / (gfile.name[:-len(".ghidra.txt")] + ".c")
            try:
                shutil.copyfile(gfile, orig_c)
                gfile.unlink()
                restored += 1
            except OSError:
                pass
        for wfile in TREE_DIR.rglob("*.wip.c"):
            try:
                wfile.unlink()
                removed_wip += 1
            except OSError:
                pass
    for folder in (TREE_DIR / "approx", TREE_DIR / "collection"):
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)
    for st_file in (STATE, STATE.with_suffix(".bak"), STATE.with_suffix(".tmp")):
        if st_file.exists():
            try:
                st_file.unlink()
            except OSError:
                pass
    save_state({})
    return {"restored_c": restored, "removed_wip": removed_wip}


_ADS_VERIFIED_INFO = None


def verify_ads_compilers() -> dict:
    """Verifica la existencia e integridad de agbcc/old_agbcc (SDK Nintendo GBA) y ADS 1.2 (con cache)."""
    global _ADS_VERIFIED_INFO
    if _ADS_VERIFIED_INFO is not None:
        return _ADS_VERIFIED_INFO
    for name, path in (("tcc.exe", ADS_TCC), ("armcc.exe", ADS_ARMCC), ("armlink.exe", ADS_ARMLINK), ("fromelf.exe", ADS_FROMELF)):
        if not path.exists():
            raise RuntimeError(f"Herramienta ADS 1.2 no encontrada ({name}): {path}")
    _ADS_VERIFIED_INFO = {
        "agbcc": str(AGBCC_EXE) if AGBCC_EXE.exists() else None,
        "old_agbcc": str(OLD_AGBCC_EXE) if OLD_AGBCC_EXE.exists() else None,
        "tcc": str(ADS_TCC),
        "armcc": str(ADS_ARMCC),
        "armlink": str(ADS_ARMLINK),
        "fromelf": str(ADS_FROMELF),
        "ok": True,
    }
    return _ADS_VERIFIED_INFO


_GNU_TOOLS_CACHE = {}


def find_tool(name):
    """Localiza arm-none-eabi-<name> en PATH o en rutas de instalacion tipicas (con cache en memoria)."""
    if name in _GNU_TOOLS_CACHE:
        return _GNU_TOOLS_CACHE[name]
    exe = f"arm-none-eabi-{name}"
    p = shutil.which(exe)
    if p:
        _GNU_TOOLS_CACHE[name] = p
        return p
    roots = [os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", ""),
             str(Path.home() / "AppData/Local/Programs"), "C:/"]
    for r in roots:
        if not r:
            continue
        for pat in (f"Arm*/**/bin/{exe}.exe", f"Arm GNU Toolchain*/bin/{exe}.exe",
                    f"GNU Arm Embedded Toolchain*/*/bin/{exe}.exe",
                    f"gcc-arm-none-eabi*/bin/{exe}.exe", f"devkitPro/devkitARM/bin/{exe}.exe"):
            for hit in Path(r).glob(pat):
                _GNU_TOOLS_CACHE[name] = str(hit)
                return str(hit)
    raise RuntimeError(f"No se encontro {exe}. Instala Arm GNU Toolchain y reabre la terminal.")


def ads_env():
    env = os.environ.copy()
    env["ARMROOT"] = str(ADS_DIR)
    env["ARMLIB"] = str(ADS_DIR / "Lib")
    env["ARMINC"] = str(ADS_DIR / "Include")
    env["LM_LICENSE_FILE"] = str(ADS_DIR / "licenses" / "license.dat")
    return env


def _try_fast_preprocess(raw_src: str, is_cpp: bool):
    """Preprocesado ligero en Python cuando el fuente no usa #include ni macros complejas."""
    if re.search(r"#\s*include\b", raw_src):
        return None
    if re.search(r"\b(?:CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|BOOL)\b", raw_src):
        return None
    no_comments = re.sub(r"/\*.*?\*/", "", raw_src, flags=re.S)
    no_comments = re.sub(r"//.*", "", no_comments)
    out_lines = []
    skip_depth = 0
    for ln in no_comments.splitlines():
        st = ln.strip()
        if st.startswith("#"):
            if re.match(r"#\s*ifndef\s+__cplusplus\s*$", st):
                if is_cpp:
                    skip_depth += 1
                continue
            if re.match(r"#\s*endif\b", st):
                if skip_depth > 0:
                    skip_depth -= 1
                continue
            if skip_depth > 0:
                continue
            if re.match(r"#\s*define\s+(?:true|false|TRUE|FALSE|NULL)\b", st):
                continue
            return None
        if skip_depth > 0:
            continue
        out_lines.append(ln)
    if skip_depth != 0:
        return None
    txt = "\n".join(out_lines)
    txt = re.sub(r"\bNULL\b", "0", txt)
    if not is_cpp:
        txt = re.sub(r"\btrue\b", "1", txt)
        txt = re.sub(r"\bfalse\b", "0", txt)
    txt = re.sub(r"\bTRUE\b", "1", txt)
    txt = re.sub(r"\bFALSE\b", "0", txt)
    if is_cpp:
        txt = txt.replace("typedef u32 bool;", "")
        if 'extern "C"' not in txt:
            txt = 'extern "C" {\n' + txt + '\n}\n'
        else:
            txt = txt + "\n"
    else:
        txt = txt + "\n"
    return txt


def cc_compile(src, obj, mode, preset, c_code="", exclude_name=None):
    """Compila src -> obj (ELF ARM) con agbcc/old_agbcc (SDK Nintendo GBA) o ARM ADS 1.2."""
    verify_ads_compilers()
    if preset in AGBCC_PRESETS and mode == "THUMB":
        cc1_exe, flags = AGBCC_PRESETS[preset]
        if not cc1_exe.exists():
            return subprocess.CompletedProcess(args=[str(cc1_exe)], returncode=1, stdout="", stderr="agbcc.exe no encontrado")
        as_bin = find_tool("as")
        i_file = obj.with_suffix(".i")
        s_file = obj.with_suffix(".s")
        try:
            is_cpp = preset.startswith("agbcp")
            raw_src = c_code or src.read_text(encoding="utf-8", errors="replace")
            fast_i = _try_fast_preprocess(raw_src, is_cpp)
            if fast_i is not None:
                i_file.write_text(fast_i, encoding="utf-8")
            else:
                cpp_bin = find_tool("cpp")
                cpp_cmd = [cpp_bin, "-nostdinc", "-undef", "-I" + str(AGBCC_DIR / "include"), "-I" + str(ROOT / "include")]
                if is_cpp:
                    libcpp_inc = ROOT / "refs" / "stanhash_fomt" / "tools" / "libagbc++"
                    if libcpp_inc.exists():
                        cpp_cmd.append("-I" + str(libcpp_inc))
                    stan_inc = ROOT / "refs" / "stanhash_fomt" / "include"
                    if stan_inc.exists():
                        cpp_cmd.append("-I" + str(stan_inc))
                    cpp_cmd.extend(["-D__cplusplus", "-fno-exceptions"])
                cpp_cmd.extend([src.as_posix(), "-o", i_file.as_posix()])
                r_cpp = subprocess.run(
                    cpp_cmd,
                    capture_output=True, text=True, timeout=15,
                )
                if r_cpp.returncode != 0:
                    return r_cpp
                if is_cpp and i_file.exists():
                    i_txt = i_file.read_text(encoding="utf-8", errors="replace")
                    i_txt = i_txt.replace("typedef u32 bool;", "")
                    i_lines = [l for l in i_txt.splitlines() if not l.strip().startswith("#")]
                    if 'extern "C"' not in i_txt:
                        i_file.write_text('extern "C" {\n' + "\n".join(i_lines) + '\n}\n', encoding="utf-8")
                    else:
                        i_file.write_text("\n".join(i_lines) + "\n", encoding="utf-8")
            r_cc1 = subprocess.run(
                [str(cc1_exe)] + list(flags) + [i_file.name, "-o", s_file.name],
                cwd=str(i_file.parent),
                capture_output=True, text=True, timeout=15,
            )
            if r_cc1.returncode != 0 or not s_file.exists():
                return r_cc1
            src_txt = raw_src
            used_funcs = sorted(set(re.findall(r"\bfunc_[0-9A-F]{8}\b", src_txt)) - ({exclude_name} if exclude_name else set()))
            used_globs = sorted(set(re.findall(r"\bg_[0-9A-Fa-f]{8}\b", src_txt)))
            thumb_decls = "\n".join(f"\t.thumb_func\n\t.equ {fn}, 0x{int(fn[5:], 16) & ~1:08X}" for fn in used_funcs)
            glob_decls = "\n".join(f"\t.equ {gn}, 0x{int(gn[2:], 16):08X}" for gn in used_globs)
            call_via_regs = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "ip", "sp", "lr"]
            call_via_decls = "\n".join(f"\t.thumb_func\n\t.equ _call_via_{rg}, 0x{0x080D390C + idx * 4:08X}" for idx, rg in enumerate(call_via_regs))
            s_raw = s_file.read_text(encoding="utf-8", errors="replace")
            if is_cpp and ".gnu.linkonce." in s_raw:
                alias_lines = [l for l in s_raw.splitlines() if exclude_name and exclude_name in l]
                s_raw = re.split(r"\n\s*\.section\s+\.gnu\.linkonce\.", s_raw)[0]
                for al_line in alias_lines:
                    if al_line not in s_raw:
                        s_raw += "\n" + al_line
            if ".macro bx reg" in s_raw:
                s_raw = s_raw.replace("\t.align\t2, 0", "\t.align\t1, 0", 1)
                trail_align = "\n"
            else:
                trail_align = "\n\t.align 2, 0\n"
            used_vts = sorted(set(re.findall(r"\bC_([0-9A-Fa-f]{8})\b", src_txt)))
            vt_decls = "\n".join(f"\t.equ __vt_10C_{v}, 0x{int(v, 16):08X}" for v in used_vts)
            used_dtors = sorted(set(re.findall(r"\bD_([0-9A-Fa-f]{8})\b", src_txt)))
            dtor_decls = "\n".join(f"\t.thumb_func\n\t.equ _._10D_{d}, 0x{int(d, 16) & ~1:08X}" for d in used_dtors if f"func_{d}" != exclude_name)
            rt_syms = [
                ("__builtin_delete", 0x08000608),
                ("__builtin_new", 0x080005D4),
                ("__divsi3", 0x080D0EC8),
                ("__modsi3", 0x080D0ED0),
                ("__udivsi3", 0x080D0EDA),
                ("__umodsi3", 0x080D0F4E),
                ("malloc", 0x080D01F8),
                ("free", 0x080D0260),
                ("rand", 0x080D11E4),
                ("memcmp", 0x080D3948),
                ("memcpy", 0x080D3994),
                ("memmove", 0x080D39F8),
                ("memset", 0x080D3A84),
                ("strcat", 0x080D3ADC),
                ("strcpy", 0x080D3B28),
                ("strlen", 0x080D3B78),
            ]
            rt_decls = "\n".join(f"\t.thumb_func\n\t.equ {sn}, 0x{sa:08X}" for sn, sa in rt_syms if sn != exclude_name)
            s_txt = (
                s_raw
                + trail_align
                + call_via_decls
                + "\n" + rt_decls
                + ("\n" + vt_decls if vt_decls else "")
                + ("\n" + dtor_decls if dtor_decls else "")
                + ("\n" + thumb_decls if thumb_decls else "")
                + ("\n" + glob_decls if glob_decls else "")
                + "\n"
            )
            s_file.write_text(s_txt, encoding="utf-8")
            r_as = subprocess.run(
                [as_bin, "-mcpu=arm7tdmi", "-mthumb-interwork", str(s_file), "-o", str(obj)],
                capture_output=True, text=True, timeout=15,
            )
            return r_as
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args=[str(cc1_exe)], returncode=124, stdout="", stderr="Timeout compilando con agbcc")
        finally:
            for tmp_f in (i_file, s_file):
                try:
                    if tmp_f.exists():
                        tmp_f.unlink()
                except OSError:
                    pass

    ads_flags = ADS_PRESETS.get(preset, ADS_PRESETS["O2"])
    exe = ADS_TCC if mode == "THUMB" else ADS_ARMCC
    cmd = [
        str(exe),
        "-c",
        "-cpu", "ARM7TDMI",
        "-apcs", "/noswst/interwork",
        "-I" + str(ROOT / "include"),
        "-W",
    ] + ads_flags + [str(src), "-o", str(obj)]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, env=ads_env(), timeout=15)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=cmd, returncode=124, stdout="", stderr="Timeout compilando con ADS")


def run(cmd, **kw):
    kw.setdefault("timeout", 90)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def load_rom():
    return ROM_PATH.read_bytes()


def rom_bytes(rom, addr, size):
    off = addr - ROM_BASE
    return rom[off:off + size]


def load_manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def load_state():
    for p in (STATE, STATE.with_suffix(".bak")):
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                print(f"[!] {p.name} corrupto, probando backup")
    return {}


def save_state(state):
    """Guardado atomico concurrente con fusion monotona (nunca degrada matches ni mejores scores de otros procesos)."""
    if state:
        disk = load_state()
        for k, d_val in disk.items():
            if k not in state:
                state[k] = d_val
                continue
            s_val = state[k]
            d_st = d_val.get("status")
            s_st = s_val.get("status")
            if d_st == "matched" and s_st != "matched":
                state[k] = d_val
            elif s_st != "matched" and float(d_val.get("best", 0.0) or 0.0) > float(s_val.get("best", 0.0) or 0.0) + 1e-6:
                merged = dict(d_val)
                merged["tries"] = max(int(d_val.get("tries", 0) or 0), int(s_val.get("tries", 0) or 0))
                state[k] = merged
            elif s_st == d_st:
                s_val["tries"] = max(int(d_val.get("tries", 0) or 0), int(s_val.get("tries", 0) or 0))
_COMMON_STATE_LOCK = threading.RLock()


def save_state(state):
    """Guarda state.json de forma atomica y robusta ante concurrencia en Windows."""
    with _COMMON_STATE_LOCK:
        # Reconciliar con state.json en disco para no perder matches de otros workers/procesos
        if STATE.exists():
            try:
                disk = load_state()
            except Exception:
                disk = {}
            for k, d_val in disk.items():
                if k not in state:
                    state[k] = d_val
                    continue
                s_val = state[k]
                d_st = d_val.get("status")
                s_st = s_val.get("status")
                if d_st == "matched" and s_st != "matched":
                    state[k] = d_val
                elif s_st != "matched" and float(d_val.get("best", 0.0) or 0.0) > float(s_val.get("best", 0.0) or 0.0) + 1e-6:
                    merged = dict(d_val)
                    merged["tries"] = max(int(d_val.get("tries", 0) or 0), int(s_val.get("tries", 0) or 0))
                    state[k] = merged
                elif s_st == d_st:
                    s_val["tries"] = max(int(d_val.get("tries", 0) or 0), int(s_val.get("tries", 0) or 0))

        tmp = STATE.with_suffix(f".{os.getpid()}_{threading.get_ident()}_{time.time_ns()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=1)
                f.flush()
                os.fsync(f.fileno())

            # Bucle de reintento tolerante a Windows para evitar bloqueos transitorios por AV / indexer
            for attempt in range(15):
                try:
                    if STATE.exists():
                        try:
                            shutil.copyfile(STATE, STATE.with_suffix(".bak"))
                        except OSError:
                            pass
                    os.replace(tmp, STATE)
                    break
                except (PermissionError, OSError):
                    if attempt == 14:
                        raise
                    time.sleep(0.04 * (attempt + 1))
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

        sync_collection(state)


def sync_collection(state=None):
    """Mantiene sincronizada la coleccion de funciones y telemetria en TREE_DIR / 'collection'."""
    try:
        if state is None:
            state = load_state()
        col_dir = TREE_DIR / "collection"
        for sub in ("matched", "approx", "wip"):
            (col_dir / sub).mkdir(parents=True, exist_ok=True)
        counts = {"matched": 0, "approx": 0, "wip": 0, "regressed": 0}
        manifest_map = {}
        if MANIFEST.exists():
            try:
                manifest_map = {e["name"]: e for e in load_manifest()}
            except Exception:
                pass
        for name, info in state.items():
            st = info.get("status", "wip")
            counts[st] = counts.get(st, 0) + 1
            e = manifest_map.get(name)
            if not e:
                continue
            src_path = TREE_DIR / e["file"]
            if st == "matched" and src_path.exists():
                dst = col_dir / "matched" / f"{name}.c"
                if not dst.exists():
                    try:
                        shutil.copyfile(src_path, dst)
                    except OSError:
                        pass
            elif st == "approx":
                ap_src = TREE_DIR / "approx" / f"{name}.c"
                dst = col_dir / "approx" / f"{name}.c"
                if ap_src.exists() and not dst.exists():
                    try:
                        shutil.copyfile(ap_src, dst)
                    except OSError:
                        pass
            elif st == "wip":
                wip_src = src_path.with_suffix(".wip.c")
                dst = col_dir / "wip" / f"{name}.wip.c"
                if wip_src.exists() and not dst.exists():
                    try:
                        shutil.copyfile(wip_src, dst)
                    except OSError:
                        pass
        summary = {
            "total_manifest": len(manifest_map),
            "total_tracked": len(state),
            "counts": counts,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        sum_tmp = col_dir / f"summary.{os.getpid()}_{threading.get_ident()}_{time.time_ns()}.tmp"
        try:
            with open(sum_tmp, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            for attempt in range(10):
                try:
                    os.replace(sum_tmp, col_dir / "summary.json")
                    break
                except (PermissionError, OSError):
                    if attempt == 9:
                        break
                    time.sleep(0.04 * (attempt + 1))
        finally:
            if sum_tmp.exists():
                try:
                    sum_tmp.unlink()
                except OSError:
                    pass
    except OSError:
        pass

