"""FOMT-MATCH-ENGINE :: Supervision & Telemetry Console.

Provides real-time binary matching visualization, hardware power telemetry,
and interactive configuration management.
"""
import ctypes
import json
import msvcrt
import os
import re
import shutil
import sys
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).parent))
import common

ROOT_DIR = common.ROOT
TREE_DIR = common.TREE_DIR
MANIFEST_FILE = common.MANIFEST
STATE_FILE = common.STATE
CTL_DIR = TREE_DIR / "control"
CMD_FILE = CTL_DIR / "commands.txt"
STATUS_FILE = CTL_DIR / "status.json"
LOG_FILE = CTL_DIR / "engine.log"
STOP_FLAG = CTL_DIR / "stop.flag"

RST = "\033[0m"
BOLD = "\033[1m"
FG_GREEN = "\033[38;5;46m"
FG_CYAN = "\033[38;5;51m"
FG_YELLOW = "\033[38;5;226m"
FG_ORANGE = "\033[38;5;208m"
FG_RED = "\033[38;5;196m"
FG_GRAY = "\033[38;5;242m"
FG_WHITE = "\033[38;5;255m"

ANSI_RE = re.compile(r"\033\[[0-9;]*[a-zA-Z]")


def vlen(s: str) -> int:
    """Returns the visible character length of a string (ignoring ANSI escape codes)."""
    return len(ANSI_RE.sub("", s))


def box_row(content: str, width: int = 108, border: str = "│") -> str:
    """Formats a single row inside a box of exact visible width `width` between borders."""
    vis = vlen(content)
    if vis > width - 2:
        # Truncate plain text safely if needed
        plain = ANSI_RE.sub("", content)[: width - 2]
        return f"  {border} {plain.ljust(width - 2)} {border}"
    pad = " " * (width - 2 - vis)
    return f"  {border} {content}{pad} {border}"


def enable_vt_mode():
    """Enables UTF-8 and ANSI VT100 escape sequences on Windows Console."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            h_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(h_out, ctypes.byref(mode))
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
        except Exception:
            pass
    # Buffer alterno (sin scrollback), cursor oculto; el tamano real de la ventana se respeta (sin forzar 'mode con')
    sys.stdout.write("\033[?1049h\033[?25l\033[2J\033[H")
    sys.stdout.flush()


def load_json_safe(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        bak = path.with_suffix(".bak")
        if bak.exists():
            try:
                return json.loads(bak.read_text(encoding="utf-8"))
            except Exception:
                pass
        return default


def apply_live_power_limits(cfg: dict) -> int:
    """Applies CPU thread affinity and process priority to active engine and LLM processes."""
    threads = max(1, min(16, int(cfg.get("threads", 8))))
    prio_str = cfg.get("priority", "below_normal")
    prio_map = {
        "idle": getattr(psutil, "IDLE_PRIORITY_CLASS", 0x00000040),
        "below_normal": getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", 0x00004000),
        "normal": getattr(psutil, "NORMAL_PRIORITY_CLASS", 0x00000020),
    }
    target_prio = prio_map.get(prio_str, prio_map["below_normal"])
    mask = list(range(min(threads, os.cpu_count() or 8)))
    touched = 0
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            pname = (proc.info.get("name") or "").lower()
            if "ollama" in pname or "llama" in pname or "python" in pname:
                try:
                    proc.cpu_affinity(mask)
                    if os.name == "nt" and proc.pid != os.getpid():
                        proc.nice(target_prio)
                    touched += 1
                except Exception:
                    pass
    except Exception:
        pass
    return touched


def build_progress_bar(pct: float, width: int = 32, color: str = FG_GREEN) -> str:
    filled = int(round((pct / 100.0) * width))
    filled = max(0, min(width, filled))
    return f"{color}{'█' * filled}{FG_GRAY}{'░' * (width - filled)}{RST}"


def render_grid(manifest, state, active_func: str, cols: int = 95, rows: int = 16, width: int = 108):
    """Renders the ROM function matching matrix."""
    total_cells = cols * rows
    n_funcs = len(manifest)
    grid_lines = []

    hdr = f"─[ ROM FUNCTION MATCHING MATRIX ({n_funcs} Functions | {cols}x{rows} Grid) ]"
    grid_lines.append(f"  ┌{hdr}{'─' * max(0, width - len(hdr))}┐")

    for r in range(rows):
        row_chars = []
        for c in range(cols):
            cell_idx = r * cols + c
            if n_funcs == 0:
                row_chars.append(f"{FG_GRAY}·{RST}")
                continue
            f_start = (cell_idx * n_funcs) // total_cells
            f_end = max(f_start + 1, ((cell_idx + 1) * n_funcs) // total_cells)
            bucket = manifest[f_start:f_end]

            has_active = any(f["name"] == active_func for f in bucket)
            statuses = [state.get(f["name"], {}).get("status", "pending") for f in bucket]

            if has_active:
                row_chars.append(f"{BOLD}{FG_CYAN}◈{RST}")
            elif "matched" in statuses:
                row_chars.append(f"{FG_GREEN}█{RST}")
            elif "approx" in statuses:
                row_chars.append(f"{FG_YELLOW}▓{RST}")
            elif "wip" in statuses:
                row_chars.append(f"{FG_ORANGE}▒{RST}")
            elif "regressed" in statuses or "orphan" in statuses:
                row_chars.append(f"{FG_RED}×{RST}")
            else:
                row_chars.append(f"{FG_GRAY}·{RST}")

        addr_hint = manifest[min(n_funcs - 1, (r * cols * n_funcs) // total_cells)]["addr"] if n_funcs else 0x08000000
        grid_lines.append(f"  │ {FG_GRAY}{addr_hint:08X}{RST} │ {''.join(row_chars)} │")

    grid_lines.append(f"  └──────────┴─{'─' * cols}─┘")
    return grid_lines


def render_cfg_view(cfg: dict, cfg_logs: list, width: int = 108):
    """Renders the configuration and power management panel."""
    pwr = common.estimate_power(
        cfg.get("threads", 8),
        cfg.get("cooldown", 1.5),
        cfg.get("duty_cycle", 85),
        cfg.get("priority", "below_normal"),
    )
    tcc_ok = common.ADS_TCC.exists()
    armcc_ok = common.ADS_ARMCC.exists()

    lines = []
    hdr = "─[ SYSTEM CONFIGURATION & POWER MANAGEMENT (FOMT-CFG) ]"
    lines.append(f"  ┌{hdr}{'─' * max(0, width - len(hdr))}┐")
    lines.append(f"  ├──────────────────────┬──────────────────────────────┬──────────────────────────────────────────────────────┤")
    lines.append(f"  │ {BOLD}PARAMETER{RST}            │ {BOLD}ACTIVE VALUE{RST}                 │ {BOLD}COMMAND SYNTAX{RST}                                       │")
    lines.append(f"  ├──────────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────┤")

    rows = [
        ("WATTS (TDP Limit)", f"{cfg.get('watts', 45)} W (Peak: {pwr['total_peak_w']} W)", "set watts <25..115>"),
        ("THREADS (CPU Cores)", f"{cfg.get('threads', 8)} / 16 Logical Threads", "set threads <1..16>"),
        ("COOLDOWN (Thermal)", f"{cfg.get('cooldown', 1.5):.1f} s / inference", "set cooldown <0.0..15.0>"),
        ("DUTY CYCLE", f"{cfg.get('duty_cycle', 85)} % (Eff: {pwr['duty_effective_pct']}%)", "set duty <30..100>"),
        ("PROCESS PRIORITY", f"{cfg.get('priority', 'below_normal').upper()}", "set priority <idle|below_normal|normal>"),
        ("LLM MODEL", f"{cfg.get('model', 'deepseek-coder-v2:latest')[:26]}", "set model <model_tag>"),
        ("CONTEXT WINDOW", f"{cfg.get('num_ctx', 4096)} tokens", "set ctx <2048|4096|8192>"),
        ("TEMPERATURE RANGE", f"{cfg.get('temp_base', 0.10):.2f} - {cfg.get('temp_max', 0.45):.2f}", "set temp <0.05..0.80>"),
        ("SEARCH BUDGET", f"{cfg.get('tries', 25)} tries / {cfg.get('permute', 500)} perm", "set tries <N>  |  set permute <N>"),
        ("ADS 1.2 TOOLCHAIN", f"tcc={'OK' if tcc_ok else 'ERR'} | armcc={'OK' if armcc_ok else 'ERR'}", "verify ads"),
    ]
    for k, v, d in rows:
        lines.append(f"  │ {FG_WHITE}{k.ljust(20)}{RST} │ {FG_GREEN}{v.ljust(28)}{RST} │ {FG_GRAY}{d.ljust(52)}{RST} │")

    lines.append(f"  ├──────────────────────┴──────────────────────────────┴──────────────────────────────────────────────────────┤")
    w_bar = build_progress_bar(min(100.0, (pwr["total_peak_w"] / 115.0) * 100.0), 24, FG_CYAN if pwr["total_peak_w"] <= 65 else FG_YELLOW)
    calc_line = (
        f"POWER TELEMETRY : [{w_bar}] Avg: {BOLD}{FG_GREEN}{pwr['total_avg_w']} W{RST} | "
        f"Peak: {BOLD}{FG_YELLOW}{pwr['total_peak_w']} W{RST} (CPU: {pwr['cpu_peak_w']} W + Base: {pwr['system_base_w']} W | ~{pwr['vrm_amps']} A)"
    )
    lines.append(box_row(calc_line, width))
    lines.append(f"  ├{'─' * width}┤")
    for lg in cfg_logs[-4:]:
        lines.append(box_row(f"{FG_GRAY}>{RST} {lg[:width - 6]}", width))
    for _ in range(max(0, 4 - len(cfg_logs[-4:]))):
        lines.append(box_row("", width))
    lines.append(f"  └{'─' * width}┘")
    return lines


def render_help_view(width: int = 108):
    """Renders the built-in command reference screen."""
    lines = []
    hdr = "─[ COMMAND REFERENCE & SYSTEM DOCUMENTATION ]"
    lines.append(f"  ┌{hdr}{'─' * max(0, width - len(hdr))}┐")
    help_entries = [
        (f"{BOLD}{FG_CYAN}NAVIGATION & VIEWS{RST}", ""),
        ("  grid", "Switch to the ROM Function Matching Matrix view."),
        ("  cfg", "Open the System Configuration & Power Management utility (FOMT-CFG)."),
        ("  help", "Display this command reference screen."),
        ("  exit / quit", "Close the supervision console (engine continues unless stopped)."),
        ("", ""),
        (f"{BOLD}{FG_CYAN}ENGINE RUNTIME CONTROL{RST}", ""),
        ("  start [1|2|3]", "Arranca el pipeline (F1 CPU, F2 DeepSeek huerfanas, F3 nombrado). Con N inicia desde esa fase."),
        ("  pause / resume", "Pause or resume the matching engine after the current inference."),
        ("  skip [func_XXXX]", "Abort the current function (or queue a specific function to skip)."),
        ("  retry", "Restart LLM attempts on the active function from scratch."),
        ("  more <N>", "Grant <N> additional LLM attempts to the active function."),
        ("  permute <N>", "Run <N> additional hill-climbing permuter iterations on the best candidate."),
        ("  accept", "Manually promote the current best candidate to approx/ collection."),
        ("  resync", "Synchronize state.json and candidate files into src_sweep/collection/."),
        ("  reset all", "Wipe all progress (state.json, .wip.c, collection/) and start from 0."),
        ("  stop", "Gracefully stop the engine after saving the current checkpoint."),
    ]
    for cmd_name, desc in help_entries:
        if not desc:
            lines.append(box_row(cmd_name, width))
        else:
            lines.append(box_row(f"{FG_WHITE}{cmd_name.ljust(22)}{RST} {FG_GRAY}{desc}{RST}", width))
    lines.append(f"  └{'─' * width}┘")
    return lines


def handle_cfg_command(cmd_raw: str, cfg: dict, cfg_logs: list, state: dict) -> tuple[str | None, str]:
    """Processes configuration commands. Returns (new_ui_mode_or_None, status_message)."""
    parts = cmd_raw.strip().split()
    if not parts:
        return None, ""
    verb = parts[0].lower()
    args = parts[1:]

    if re.match(r"^\d+(\.\d+)?w$", verb):
        w_val = float(verb[:-1])
        args = ["watts", str(w_val)]
        verb = "set"

    if verb in ("back", "grid", "exit", "quit", "q"):
        return "GRID", "View switched to ROM Matching Matrix."

    if verb in ("help", "?"):
        cfg_logs.append("Syntax: set <watts|threads|cooldown|duty|priority|ctx|temp|tries|permute|model> <value>")
        cfg_logs.append("Tools : calc <threads> <cooldown> [duty] | list [power|all] | preset <eco|half|65w|max>")
        cfg_logs.append("System: verify ads | reset all | back")
        return None, "Configuration command syntax listed."

    if verb == "list":
        sub = args[0].lower() if args else "all"
        pwr = common.estimate_power(cfg["threads"], cfg["cooldown"], cfg["duty_cycle"], cfg["priority"])
        if sub == "power":
            cfg_logs.append(
                f"Power Telemetry: Avg={pwr['total_avg_w']}W | Peak={pwr['total_peak_w']}W | CPU={pwr['cpu_peak_w']}W | "
                f"VRM=~{pwr['vrm_amps']}A | Profile={pwr['risk']}"
            )
        else:
            cfg_logs.append(
                f"Active Config: Watts={cfg['watts']}W, Threads={cfg['threads']}, Cooldown={cfg['cooldown']}s, "
                f"Ctx={cfg['num_ctx']}, Temp={cfg['temp_base']}-{cfg['temp_max']}"
            )
        return None, "Telemetry summary updated."

    if verb == "calc":
        try:
            th = int(args[0]) if len(args) >= 1 else cfg.get("threads", 8)
            cd = float(args[1]) if len(args) >= 2 else cfg.get("cooldown", 1.5)
            dc = int(args[2]) if len(args) >= 3 else cfg.get("duty_cycle", 85)
            est = common.estimate_power(th, cd, dc, cfg.get("priority", "below_normal"))
            cfg_logs.append(
                f"Estimator ({th}T, {cd}s cd, {dc}% duty) -> Avg: {est['total_avg_w']} W | "
                f"Peak: {est['total_peak_w']} W (~{est['vrm_amps']} A VRM) [{est['risk']}]"
            )
            return None, f"Estimated Power: {est['total_avg_w']} W avg / {est['total_peak_w']} W peak."
        except ValueError:
            cfg_logs.append("Usage: calc <threads> <cooldown_sec> [duty_pct]")
            return None, "Invalid parameters for calc."

    if verb == "preset" and args:
        p = args[0].lower()
        presets_map = {"eco": 32, "half": 45, "50%": 45, "65w": 65, "max": 95}
        if p not in presets_map:
            cfg_logs.append("Available presets: eco (32W), half (45W), 65w (65W), max (95W)")
            return None, "Unknown preset."
        target_w = presets_map[p]
        tuned = common.auto_tune_for_watts(target_w)
        cfg.update(tuned)
        common.save_engine_config(cfg)
        n_proc = apply_live_power_limits(cfg)
        est = common.estimate_power(cfg["threads"], cfg["cooldown"], cfg["duty_cycle"], cfg["priority"])
        cfg_logs.append(
            f"Preset '{p.upper()}' ({target_w}W) applied -> {cfg['threads']}T, {cfg['cooldown']}s cooldown, "
            f"priority={cfg['priority']} (Peak: {est['total_peak_w']}W across {n_proc} processes)."
        )
        return None, f"Power preset {p.upper()} ({target_w} W) active."

    if verb == "verify":
        try:
            info = common.verify_ads_compilers()
            cfg_logs.append(f"ADS 1.2 THUMB Compiler : {info['tcc']} [VERIFIED]")
            cfg_logs.append(f"ADS 1.2 ARM Compiler   : {info['armcc']} [VERIFIED]")
            return None, "ARM ADS 1.2 compilers verified."
        except Exception as ex:
            cfg_logs.append(f"ADS 1.2 Verification Error: {ex}")
            return None, str(ex)

    if verb in ("reset", "clean"):
        if len(args) >= 1 and args[0].lower() in ("all", "0", "zero", "confirm"):
            res = common.reset_all_progress()
            state.clear()
            with open(CMD_FILE, "a", encoding="utf-8") as f:
                f.write("reset\n")
                f.flush()
            cfg_logs.append(
                f"State reset complete: {res['removed_wip']} WIP files cleared, "
                f"{res['restored_c']} source files restored."
            )
            return None, "All progress reset to zero."
        else:
            cfg_logs.append("Confirmation required: type 'reset all' to wipe all progress.")
            return None, "Type 'reset all' to confirm."

    if verb == "set" and len(args) >= 2:
        key, val = args[0].lower(), args[1]
        try:
            if key in ("watts", "power", "w"):
                w_num = float(val.rstrip("wW"))
                tuned = common.auto_tune_for_watts(w_num)
                cfg.update(tuned)
                common.save_engine_config(cfg)
                n_proc = apply_live_power_limits(cfg)
                est = common.estimate_power(cfg["threads"], cfg["cooldown"], cfg["duty_cycle"], cfg["priority"])
                cfg_logs.append(
                    f"Target {int(w_num)}W applied: {cfg['threads']}/16T | Cooldown {cfg['cooldown']}s | "
                    f"Duty {cfg['duty_cycle']}% | Prio {cfg['priority']} -> Avg {est['total_avg_w']}W / Peak {est['total_peak_w']}W ({n_proc} procs)"
                )
                return None, f"Power limit auto-tuned to {int(w_num)} W."
            elif key in ("threads", "hilos", "cpu"):
                cfg["threads"] = max(1, min(16, int(val)))
            elif key == "cooldown":
                cfg["cooldown"] = max(0.0, min(15.0, float(val)))
            elif key in ("duty", "duty_cycle"):
                cfg["duty_cycle"] = max(25, min(100, int(val)))
            elif key in ("priority", "prio"):
                if val.lower() in ("idle", "below_normal", "normal"):
                    cfg["priority"] = val.lower()
                else:
                    cfg_logs.append("Valid priorities: idle | below_normal | normal")
                    return None, "Invalid priority class."
            elif key in ("ctx", "num_ctx"):
                cfg["num_ctx"] = max(1024, min(16384, int(val)))
            elif key in ("temp", "temperature"):
                t_v = max(0.0, min(1.0, float(val)))
                cfg["temp_base"] = round(t_v, 2)
                cfg["temp_max"] = round(min(0.85, t_v + 0.30), 2)
            elif key == "tries":
                cfg["tries"] = max(1, min(200, int(val)))
            elif key == "permute":
                cfg["permute"] = max(0, min(5000, int(val)))
            elif key == "model":
                cfg["model"] = val
            else:
                cfg_logs.append(f"Unknown parameter '{key}'. Type 'help' for valid parameters.")
                return None, f"Unknown parameter: {key}"

            est = common.estimate_power(cfg["threads"], cfg["cooldown"], cfg["duty_cycle"], cfg["priority"])
            cfg["watts"] = int(round(est["total_peak_w"]))
            common.save_engine_config(cfg)
            apply_live_power_limits(cfg)
            cfg_logs.append(
                f"Updated {key.upper()} -> Estimated Power: {est['total_avg_w']} W avg / {est['total_peak_w']} W peak."
            )
            return None, f"Configuration parameter '{key}' updated."
        except ValueError:
            cfg_logs.append(f"Invalid numeric value for '{key}': {val}")
            return None, "Invalid numeric value."

    cfg_logs.append(f"Unrecognized command '{cmd_raw}'. Type 'help' or 'back'.")
    return None, "Unrecognized command. Type 'help'."


def tail_log(max_lines: int = 12, max_chars: int = 400) -> list:
    """Devuelve las ultimas lineas de engine.log (salida en vivo del motor) sin codigos ANSI ni caracteres de control."""
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 24000))
            raw = f.read()
    except OSError:
        return []
    txt = ANSI_RE.sub("", raw.decode("utf-8", "replace")).replace("\r\n", "\n").replace("\r", "")
    lines = []
    for ln in txt.split("\n"):
        ln = "".join(ch for ch in ln.replace("\t", "    ") if ch.isprintable()).rstrip()
        if ln.strip():
            lines.append(ln[:max_chars])
    return lines[-max_lines:]


def main():
    CTL_DIR.mkdir(parents=True, exist_ok=True)
    if not CMD_FILE.exists():
        CMD_FILE.write_text("", encoding="utf-8")

    cfg = common.load_engine_config()
    common.save_engine_config(cfg)
    apply_live_power_limits(cfg)

    enable_vt_mode()
    manifest = load_json_safe(MANIFEST_FILE, [])
    input_buf = ""
    ui_mode = "GRID"  # "GRID", "CFG", "HELP"
    cfg_logs = [
        "FOMT-CFG Power & Parameter Manager ready.",
        "Type 'set watts <W>', 'calc <threads> <cooldown>', 'verify ads', 'reset all', or 'back'.",
    ]
    last_cmd_msg = "STANDBY: el motor NO arranca solo. Escribe 'start' + Enter (o 'start 2' / 'start 3' para elegir fase)."
    last_data_reload = 0.0
    last_hw_tick = 0.0
    last_lines = []
    cpu_u = 0.0
    ram_used_gb = 0.0
    ram_total_gb = 0.0
    state = {}
    status = {}
    log_tail = []

    psutil.cpu_percent(interval=None)

    try:
        while True:
            now = time.time()
            if now - last_data_reload >= 0.45:
                if not manifest and MANIFEST_FILE.exists():
                    manifest = load_json_safe(MANIFEST_FILE, [])
                state = load_json_safe(STATE_FILE, {})
                status = load_json_safe(STATUS_FILE, {"phase": "STANDBY"})
                cfg = common.load_engine_config()
                log_tail = tail_log(12, 400)
                last_data_reload = now

            while msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    cmd = input_buf.strip()
                    input_buf = ""
                    if not cmd:
                        continue

                    low = cmd.lower()
                    if ui_mode == "CFG":
                        new_mode, msg = handle_cfg_command(cmd, cfg, cfg_logs, state)
                        if msg:
                            last_cmd_msg = msg
                        if new_mode:
                            ui_mode = new_mode
                            last_lines = []
                        continue

                    if ui_mode == "HELP":
                        if low in ("back", "grid", "q", "exit"):
                            ui_mode = "GRID"
                            last_lines = []
                            last_cmd_msg = "View switched to ROM Matching Matrix."
                            continue
                        elif low == "cfg":
                            ui_mode = "CFG"
                            last_lines = []
                            last_cmd_msg = "FOMT-CFG active. Type 'help' or 'back'."
                            continue

                    if low in ("exit", "quit"):
                        sys.stdout.write("\033[?25h\033[0m\n")
                        return
                    elif low in ("help", "?"):
                        ui_mode = "HELP"
                        last_lines = []
                        last_cmd_msg = "Command reference displayed. Type 'grid' or 'cfg' to switch views."
                    elif low == "grid":
                        ui_mode = "GRID"
                        last_lines = []
                        last_cmd_msg = "View switched to ROM Matching Matrix."
                    elif low in ("cfg", "config", "power", "setup"):
                        ui_mode = "CFG"
                        last_lines = []
                        last_cmd_msg = "FOMT-CFG active. Type 'help' for parameters or 'back' to return."
                    elif low in ("reset 0", "reset all", "clean all"):
                        res = common.reset_all_progress()
                        state.clear()
                        with open(CMD_FILE, "a", encoding="utf-8") as f:
                            f.write("reset\n")
                            f.flush()
                        last_cmd_msg = f"State reset to zero ({res['removed_wip']} WIP files removed)."
                    elif re.match(r"^\d+(\.\d+)?w$", low) or low.startswith("set watts"):
                        _, msg = handle_cfg_command(low, cfg, cfg_logs, state)
                        last_cmd_msg = msg
                    elif low == "resync":
                        common.sync_collection(state)
                        last_cmd_msg = "Collection synchronized in src_sweep/collection/."
                    else:
                        with open(CMD_FILE, "a", encoding="utf-8") as f:
                            f.write(cmd + "\n")
                            f.flush()
                        if low.split()[0] == "stop":
                            try:
                                STOP_FLAG.write_text("stop", encoding="utf-8")
                            except OSError:
                                pass
                        last_cmd_msg = f"Dispatched command: '{cmd}' ({time.strftime('%H:%M:%S')})"
                elif ch == "\x08":
                    input_buf = input_buf[:-1]
                elif ch == "\x03":
                    raise KeyboardInterrupt
                elif ch.isprintable():
                    input_buf += ch

            n_total = len(manifest) or 1
            n_matched = sum(1 for v in state.values() if v.get("status") == "matched")
            n_approx = sum(1 for v in state.values() if v.get("status") == "approx")
            n_wip = sum(1 for v in state.values() if v.get("status") == "wip")
            n_orph = sum(1 for v in state.values() if v.get("status") == "orphan")
            n_pend = max(0, len(manifest) - (n_matched + n_approx + n_wip + n_orph))
            pct_match = (n_matched / n_total) * 100.0
            pct_explored = ((n_matched + n_approx + n_wip + n_orph) / n_total) * 100.0

            # Telemetria de hardware con refresco lento (1 Hz) y valores redondeados: evita parpadeo constante de la barra superior
            if now - last_hw_tick >= 1.0:
                cpu_u = float(round(psutil.cpu_percent(interval=None)))
                ram = psutil.virtual_memory()
                ram_used_gb = round(ram.used / (1024 ** 3), 1)
                ram_total_gb = round(ram.total / (1024 ** 3), 1)
                last_hw_tick = now
            pwr = common.estimate_power(
                cfg.get("threads", 8),
                cfg.get("cooldown", 1.5),
                cfg.get("duty_cycle", 85),
                cfg.get("priority", "below_normal"),
            )

            active_fn = status.get("func", "")
            phase_txt = status.get("phase", "STANDBY")
            paused_flag = status.get("paused", False)
            best_sc = status.get("best_score", 0.0) * 100.0
            last_sc = status.get("last_score", 0.0) * 100.0
            threads_cap = cfg.get("threads", 8)

            term = shutil.get_terminal_size((120, 40))
            W = max(60, min(108, term.columns - 6))
            grid_cols = max(20, W - 13)
            log_n = 8 if term.lines >= 40 else 6 if term.lines >= 32 else 4 if term.lines >= 26 else 3
            grid_rows = max(3, min(16, term.lines - 18 - log_n))
            out = []
            out.append(f"  ╔{'═' * W}╗")
            title = "FOMT-MATCH-ENGINE :: 1:1 BINARY MATCHING SUITE (agbcc + ARM ADS 1.2)"
            out.append(box_row(f"{BOLD}{FG_WHITE}{title.center(W - 2)}{RST}", W, "║"))
            hw_line = (
                f"CPU: i7-13620H [{threads_cap}/16T | {cpu_u:3.0f}%] | "
                f"PWR: {pwr['total_avg_w']}W avg / {pwr['total_peak_w']}W pk (Cap: {cfg.get('watts', 45)}W) | "
                f"RAM: {ram_used_gb:4.1f}/{ram_total_gb:4.1f} GB | ADS 1.2: OK"
            )
            out.append(box_row(f"{FG_CYAN}{hw_line}{RST}", W, "║"))
            out.append(f"  ╠{'═' * W}╣")

            pbar = build_progress_bar(pct_match, 34)
            stats_line = (
                f"1:1 MATCH PROGRESS : [{pbar}] {BOLD}{FG_GREEN}{n_matched:4d}{RST}/{len(manifest)} ({pct_match:5.2f}%) "
                f"| Analyzed: {pct_explored:5.2f}%"
            )
            out.append(box_row(stats_line, W, "║"))

            legend = (
                f"STATUS: [{FG_GREEN}█{RST}] Matched ({n_matched})  "
                f"[{FG_YELLOW}▓{RST}] Approx ({n_approx})  "
                f"[{FG_ORANGE}▒{RST}] WIP ({n_wip})  "
                f"[{FG_RED}×{RST}] Orphan ({n_orph})  "
                f"[{FG_CYAN}◈{RST}] Active  "
                f"[{FG_GRAY}·{RST}] Pending ({n_pend})  "
                f"| View: [{BOLD}{FG_CYAN}{ui_mode}{RST}]"
            )
            out.append(box_row(legend, W, "║"))
            out.append(f"  ╚{'═' * W}╝")

            if ui_mode == "GRID":
                out.extend(render_grid(manifest, state, active_fn, cols=grid_cols, rows=grid_rows, width=W))
            elif ui_mode == "CFG":
                out.extend(render_cfg_view(cfg, cfg_logs, width=W))
            else:
                out.extend(render_help_view(width=W))

            hdr_tel = "─[ ENGINE TELEMETRY & STATUS ]"
            out.append(f"  ┌{hdr_tel}{'─' * max(0, W - len(hdr_tel))}┐")
            st_badge = f"{FG_YELLOW}[PAUSED]{RST}" if paused_flag else f"{FG_GREEN}[ACTIVE]{RST}"
            if "STANDBY" in str(phase_txt).upper():
                st_badge = f"{FG_CYAN}[STANDBY]{RST}"
            l1 = f"Engine : {st_badge} {phase_txt[:max(10, W - 52)].ljust(max(10, W - 52))} | Best: {best_sc:5.1f}% (Last: {last_sc:5.1f}%)"
            out.append(box_row(l1, W))
            l2 = f"Event  : {last_cmd_msg[:W - 12]}"
            out.append(box_row(l2, W))
            l3 = f"{FG_GRAY}Cmds: start [1|2|3] | help | cfg | grid | pause | resume | skip | retry | more N | permute N | stop{RST}"
            out.append(box_row(l3, W))
            out.append(f"  └{'─' * W}┘")

            # Panel ENGINE LOG: salida en vivo del motor (lift/sweep/build) unificada en esta misma ventana
            hdr_log = "─[ ENGINE LOG (en vivo) ]"
            out.append(f"  ┌{hdr_log}{'─' * max(0, W - len(hdr_log))}┐")
            shown = log_tail[-log_n:]
            for ln in shown:
                out.append(box_row(f"{FG_GRAY}{ln[:W - 4]}{RST}", W))
            for _ in range(log_n - len(shown)):
                out.append(box_row("", W))
            out.append(f"  └{'─' * W}┘")

            prompt_label = "FOMT-CFG>" if ui_mode == "CFG" else "FOMT-CLI>"
            out.append(f"  {BOLD}{FG_CYAN}{prompt_label}{RST} {input_buf}█")

            # Recortar al alto real de la ventana para evitar desplazamiento (scroll) en pantallas chicas
            max_lines = max(10, term.lines - 1)
            if len(out) > max_lines:
                out = out[: max_lines - 1] + [out[-1]]

            # Actualizacion por diferencias: solo se reescriben las lineas que cambiaron (cero parpadeo, incluso en pantallas chicas)
            if len(out) != len(last_lines):
                buf = "\033[H" + "\n".join(f"{ln}\033[K" for ln in out) + "\033[J"
                last_lines = list(out)
            else:
                parts = []
                for row_idx, ln in enumerate(out):
                    if ln != last_lines[row_idx]:
                        parts.append(f"\033[{row_idx + 1};1H{ln}\033[K")
                buf = "".join(parts)
                last_lines = list(out)
            if buf:
                sys.stdout.write(buf)
                sys.stdout.flush()
            time.sleep(0.08)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h\033[0m\033[?1049l\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
