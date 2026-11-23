"""FORGE CLI: agente que reordena la maranya de src_sweep y produce un proyecto compilable sin errores.

Pide la ROM original (banco de datos) y hace lo siguiente:

  1. Valida la ROM (tamanyo, codigo de juego A4NE, SHA-1).
  2. Recupera el C de cada funcion 'matched' desde todas las fuentes del arbol (.c, collection/,
     permute/code/) y lo RE-VERIFICA compilando y comparando byte a byte contra la ROM.
  3. Genera un proyecto ordenado y autonomo:  src/<banco>/<func>.c, asm/<banco>.s (.incbin de la ROM
     para datos, graficos, audio y funciones aun no resueltas), ld/layout.ld, build.py, build.bat.
  4. Compila el proyecto, compara contra la ROM y degrada a .incbin cualquier funcion que no
     reproduzca la ROM, hasta obtener un build limpio (0 bytes de diferencia).
  5. Opcional (--agent o comando 'agent'): un agente LLM intenta reparar las funciones que fallaron.

Es de SOLO LECTURA sobre el arbol de trabajo (src_sweep): puede ejecutarse con el motor activo.

Uso:
  python tools/match/forge_cli.py                       # shell interactiva  FORGE>
  python tools/match/forge_cli.py forge --rom "J:/.../fomt virgen.gba" --out forge_out
  python tools/match/forge_cli.py scan
  python tools/match/forge_cli.py agent --agent-tries 3
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

if "FOMT_TREE" not in os.environ:
    os.environ["FOMT_TREE"] = "src_sweep"

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_OUT = ROOT / "forge_out"
STATUS_FILE = TREE_DIR / "control" / "forge_status.json"
GAME_CODE = b"A4NE"
EXPECTED_SIZE = 8 * 1024 * 1024
PRELUDE_END = "#define NULL ((void *)0)\n"
EXTERN_RE = re.compile(r"\A(?:extern u32 func_[0-9A-Fa-f]{8}\(\);\s*\n)+")

BUILD_PY = r'''#!/usr/bin/env python3
"""Build autonomo del proyecto FOMT ordenado por forge_cli.py.

Compila las funciones C verificadas (agbcc), ensambla los bloques .incbin de baserom.gba y enlaza
segun ld/layout.ld. Compara el resultado con baserom.gba y deja build/result.json.
"""
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

R = Path(__file__).resolve().parent
T = json.loads((R / "tools.json").read_text(encoding="utf-8"))
F = json.loads((R / "functions.json").read_text(encoding="utf-8"))
OBJ = R / "build" / "o"
OBJ.mkdir(parents=True, exist_ok=True)


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(R))


def compile_c(fn):
    src, obj = R / fn["file"], OBJ / (fn["name"] + ".o")
    i_f, s_f = obj.with_suffix(".i"), obj.with_suffix(".s")
    r = sh([T["cpp"], "-nostdinc", "-undef", "-I", T["agbcc_include"], str(src), "-o", str(i_f)])
    if r.returncode:
        return fn["name"], r.stderr
    r = sh([fn.get("cc", T["agbcc"])] + fn["cflags"] + [str(i_f), "-o", str(s_f)])
    if r.returncode or not s_f.exists():
        return fn["name"], r.stderr + r.stdout
    import re
    used = sorted(set(re.findall(r"\bfunc_[0-9A-F]{8}\b", src.read_text(encoding="utf-8", errors="replace"))) - {fn["name"]})
    decls = "\n".join("\t.thumb_func\n\t.equ %s, 0x%08X" % (u, int(u[5:], 16) & ~1) for u in used)
    s_f.write_text(s_f.read_text(encoding="utf-8", errors="replace") + "\n\t.align 2, 0\n" + decls + "\n", encoding="utf-8")
    r = sh([T["as"], "-mcpu=arm7tdmi", "-mthumb-interwork", str(s_f), "-o", str(obj)])
    for t in (i_f, s_f):
        t.unlink(missing_ok=True)
    return fn["name"], (r.stderr if r.returncode else "")


def main():
    errors = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for name, err in ex.map(compile_c, F["functions"]):
            if err:
                errors[name] = err[:600]
    asm_objs = []
    for s in sorted((R / "asm").glob("*.s")):
        o = OBJ / ("asm_" + s.stem + ".o")
        r = sh([T["as"], "-mcpu=arm7tdmi", "-I", ".", str(s), "-o", str(o)])
        if r.returncode:
            errors[s.name] = r.stderr[:600]
        asm_objs.append(str(o))
    result = {"compile_errors": errors, "mismatched": [], "diff_bytes": None, "ok": False}
    if errors:
        (R / "build" / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
        print("[!] errores de compilacion: %d" % len(errors))
        for k, v in list(errors.items())[:10]:
            print("   ", k, v.splitlines()[0] if v else "")
        return 2
    objs = ["build/o/%s.o" % f["name"] for f in F["functions"]] + [Path(a).relative_to(R).as_posix() for a in asm_objs]
    (R / "build" / "objs.rsp").write_text("\n".join(objs) + "\n", encoding="utf-8")
    elf, out = R / "build" / "fomt.elf", R / "build" / "fomt.gba"
    r = sh([T["ld"], "-T", "ld/layout.ld", "-o", "build/fomt.elf", "@build/objs.rsp"])
    if r.returncode:
        print(r.stderr[:3000])
        result["link_error"] = r.stderr[:3000]
        (R / "build" / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
        return 3
    r = sh([T["objcopy"], "-O", "binary", str(elf), str(out)])
    built, rom = out.read_bytes(), (R / "baserom.gba").read_bytes()
    n = min(len(built), len(rom))
    diff = sum(1 for a, b in zip(built[:n], rom[:n]) if a != b) + abs(len(built) - len(rom))
    for f in F["functions"]:
        o = f["addr"] - 0x08000000
        if built[o:o + f["emitted"]] != rom[o:o + f["emitted"]]:
            result["mismatched"].append(f["name"])
    result.update({"diff_bytes": diff, "built_size": len(built), "rom_size": len(rom), "ok": diff == 0,
                   "c_functions": len(F["functions"])})
    (R / "build" / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print("[+] funciones C: %d | tamanyo %d/%d | bytes distintos: %d | mismatches: %d"
          % (len(F["functions"]), len(built), len(rom), diff, len(result["mismatched"])))
    if diff == 0:
        print("[+] BUILD LIMPIO: ROM identica byte a byte a baserom.gba")
    return 0 if diff == 0 else 4


if __name__ == "__main__":
    sys.exit(main())
'''


def _prelude():
    import lift
    return lift.PRELUDE


def log(msg=""):
    print(msg, flush=True)


def write_status(**kw):
    kw["ts"] = time.time()
    try:
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(kw), encoding="utf-8")
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------
# ROM = banco de datos
# ---------------------------------------------------------------------------------------------
def validate_rom(path):
    p = Path(path.strip().strip('"'))
    if not p.is_file():
        return None, f"No existe: {p}"
    data = p.read_bytes()
    info = {"path": str(p), "size": len(data), "sha1": hashlib.sha1(data).hexdigest(),
            "game_code": data[0xAC:0xB0].decode("ascii", "replace") if len(data) > 0xB0 else "?",
            "title": data[0xA0:0xAC].decode("ascii", "replace").strip("\x00 ") if len(data) > 0xB0 else "?"}
    warn = []
    if data[0xAC:0xB0] != GAME_CODE:
        warn.append(f"codigo de juego {info['game_code']} != A4NE")
    if len(data) != EXPECTED_SIZE:
        warn.append(f"tamanyo {len(data)} != {EXPECTED_SIZE}")
    info["warnings"] = warn
    return info, None


def ask_rom(cli_value=None, assume_yes=False):
    default = str(ROM_PATH)
    val = cli_value
    if not val:
        if assume_yes or not sys.stdin.isatty():
            val = default
        else:
            val = input(f"[FORGE] Ruta de la ROM ORIGINAL (banco de datos) [{default}]: ").strip() or default
    info, err = validate_rom(val)
    while err:
        log(f"[!] {err}")
        if assume_yes or not sys.stdin.isatty():
            raise SystemExit(2)
        info, err = validate_rom(input("[FORGE] Ruta valida de la ROM: "))
    for w in info["warnings"]:
        log(f"[!] AVISO ROM: {w}")
    log(f"[+] ROM: {info['path']}  {info['size']} B  {info['game_code']}  sha1={info['sha1']}")
    return info


# ---------------------------------------------------------------------------------------------
# Inventario y recuperacion de fuentes
# ---------------------------------------------------------------------------------------------
def scan():
    manifest, state = load_manifest(), load_state()
    cnt = {}
    for v in state.values():
        cnt[v.get("status", "?")] = cnt.get(v.get("status", "?"), 0) + 1
    by = {e["name"]: e for e in manifest}
    matched = [n for n, v in state.items() if v.get("status") == "matched" and n in by]
    srcs = {"tree": 0, "collection": 0, "permute": 0, "none": 0}
    for n in matched:
        kind = classify_source(by[n])
        srcs[kind] += 1
    pend_perm = 0
    rf = TREE_DIR / "permute" / "results.json"
    if rf.exists():
        try:
            pend_perm = sum(1 for r in json.loads(rf.read_text(encoding="utf-8")).values()
                            if r.get("exact") and not r.get("applied"))
        except Exception:
            pass
    log(f"[scan] manifest={len(manifest)} funciones | estados: {cnt}")
    log(f"[scan] matched con C recuperable: tree={srcs['tree']} collection={srcs['collection']} "
        f"permute={srcs['permute']} sin_fuente={srcs['none']}")
    log(f"[scan] exactos del permutador pendientes de aplicar a state.json: {pend_perm}")
    return {"counts": cnt, "sources": srcs, "pending_permute": pend_perm}


def source_candidates(e):
    n = e["name"]
    return [("tree", TREE_DIR / e["file"]),
            ("collection", TREE_DIR / "collection" / "matched" / f"{n}.c"),
            ("permute", TREE_DIR / "permute" / "code" / f"{n}.c")]


def extract_body(txt):
    """Devuelve el cuerpo C sin PRELUDE ni externs auto-generados, o None si es Ghidra crudo."""
    if PRELUDE_END in txt:
        txt = txt.split(PRELUDE_END, 1)[1]
    elif "Pseudocodigo Ghidra crudo" in txt or "undefined4" in txt:
        return None
    txt = EXTERN_RE.sub("", txt.lstrip("\n"))
    return txt if "{" in txt and "}" in txt else None


def classify_source(e):
    for kind, p in source_candidates(e):
        if p.exists() and extract_body(p.read_text(encoding="utf-8", errors="replace")):
            return kind
    return "none"


def recover_bodies(e):
    out = []
    for kind, p in source_candidates(e):
        if p.exists():
            b = extract_body(p.read_text(encoding="utf-8", errors="replace"))
            if b and b not in [x[1] for x in out]:
                out.append((kind, b))
    return out


# ---------------------------------------------------------------------------------------------
# Verificacion paralela
# ---------------------------------------------------------------------------------------------
_W = {}


def _init():
    try:
        import psutil
        psutil.Process().nice(getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", 0x4000))
    except Exception:
        pass
    import lift  # noqa
    _W["lift"], _W["rom"], _W["manifest"] = lift, load_rom(), load_manifest()
    _W["by"] = {e["name"]: e for e in _W["manifest"]}


def _verify(job):
    """job = (name, [(kind, body)...], [presets]) -> (name, kind, body, preset, emitted_len, error)."""
    name, bodies, presets = job
    lift, e = _W["lift"], _W["by"][name]
    target = rom_bytes(_W["rom"], e["addr"], e["size"])
    last = "sin fuente C recuperable"
    for kind, body in bodies:
        for p in presets:
            try:
                ok, got, err = lift.try_candidate(e, body, _W["manifest"], p)
            except Exception as ex:  # noqa
                ok, got, err = False, None, str(ex)
            if not ok:
                last = err
                continue
            if lift.score(e, target, got)[0]:
                return name, kind, body, p, len(got), ""
            last = f"no coincide con la ROM (preset {p})"
    return name, None, None, None, 0, str(last)[:400]


def verify_all(manifest, state, workers, extra=None, cache_path=None, rom_sha=""):
    by = {e["name"]: e for e in manifest}
    cache = {}
    if cache_path and Path(cache_path).exists():
        try:
            c = json.loads(Path(cache_path).read_text(encoding="utf-8"))
            if c.get("rom_sha") == rom_sha:
                cache = c.get("ok", {})
        except Exception:
            pass
    jobs, good, bad, cached = [], {}, {}, 0
    for n, st in state.items():
        if st.get("status") != "matched" or n not in by:
            continue
        e = by[n]
        bodies = recover_bodies(e)
        if extra and n in extra:
            bodies = [("agent", extra[n])] + bodies
        if e["mode"] != "THUMB":
            continue
        hit = cache.get(n)
        if hit:
            for kind, b in bodies:
                if hashlib.sha1(b.encode("utf-8")).hexdigest() == hit["h"]:
                    good[n] = {"kind": kind, "body": b, "preset": hit["preset"], "emitted": hit["emitted"]}
                    cached += 1
                    break
            if n in good:
                continue
        presets = [st.get("preset")] if st.get("preset") in AGBCC_PRESETS else []
        presets += [p for p in AGBCC_PRESETS if p not in presets]
        jobs.append((n, bodies, presets))
    total = len(jobs)
    log(f"[forge] verificando {total} funciones matched contra la ROM ({workers} workers; {cached} en cache)...")
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=workers, initializer=_init) as pool:
        for i, (name, kind, body, preset, emitted, err) in enumerate(pool.map(_verify, jobs, chunksize=4), 1):
            if kind:
                good[name] = {"kind": kind, "body": body, "preset": preset, "emitted": emitted}
            else:
                bad[name] = err
            if i % 50 == 0 or i == total:
                log(f"  [{i}/{total}] verificadas ok={len(good)} fallidas={len(bad)} ({time.time() - t0:.0f}s)")
                write_status(phase="verify", done=i, total=total, ok=len(good), failed=len(bad))
    if cache_path:
        try:
            Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
            Path(cache_path).write_text(json.dumps({"rom_sha": rom_sha, "ok": {
                n: {"h": hashlib.sha1(g["body"].encode("utf-8")).hexdigest(), "preset": g["preset"], "emitted": g["emitted"]}
                for n, g in good.items()}}), encoding="utf-8")
        except OSError:
            pass
    for n, st in state.items():
        if st.get("status") == "matched" and n in by and by[n]["mode"] != "THUMB":
            bad[n] = "modo ARM (ADS) no soportado por el build autonomo: se conserva como .incbin"
    return good, bad


# ---------------------------------------------------------------------------------------------
# Generacion del proyecto
# ---------------------------------------------------------------------------------------------
def build_segments(manifest, c_info, rom_len):
    """Segmentos [(kind, start, end, name)] ordenados. kind: 'c' | 'bin'."""
    segs, cursor = [], ROM_BASE
    for e in sorted(manifest, key=lambda x: x["addr"]):
        start, end = e["addr"], e["addr"] + e["size"]
        if end <= cursor:
            continue
        start = max(start, cursor) if start < cursor else start
        if start > cursor:
            segs.append(["bin", cursor, start, None])
        info = c_info.get(e["name"])
        if info and start == e["addr"]:
            em = min(info["emitted"], end - start)
            segs.append(["c", start, start + em, e["name"]])
            if start + em < end:
                segs.append(["bin", start + em, end, None])
        else:
            segs.append(["bin", start, end, None])
        cursor = end
    if cursor < ROM_BASE + rom_len:
        segs.append(["bin", cursor, ROM_BASE + rom_len, None])
    merged = []
    for s in segs:
        if merged and s[0] == "bin" and merged[-1][0] == "bin" and merged[-1][2] == s[1]:
            merged[-1][2] = s[2]
        else:
            merged.append(s)
    return merged


def write_project(out, rom_info, manifest, good, tools):
    out = Path(out)
    by = {e["name"]: e for e in manifest}
    for sub in ("src", "asm", "ld", "build"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    # banco de datos
    dst = out / "baserom.gba"
    if not dst.exists() or hashlib.sha1(dst.read_bytes()).hexdigest() != rom_info["sha1"]:
        shutil.copyfile(rom_info["path"], dst)
    (out / "rom.json").write_text(json.dumps({k: rom_info[k] for k in ("size", "sha1", "game_code", "title")}, indent=1),
                                  encoding="utf-8")
    (out / "tools.json").write_text(json.dumps(tools, indent=1), encoding="utf-8")
    (out / "src" / "fomt_types.h").write_text(
        "#ifndef FOMT_TYPES_H\n#define FOMT_TYPES_H\n" + _prelude() + "#endif\n", encoding="utf-8")

    keep, funcs = set(), []
    for name in sorted(good, key=lambda n: by[n]["addr"]):
        e, g = by[name], good[name]
        bank = Path(e["file"]).parent.name or "bank"
        rel = f"src/{bank}/{name}.c"
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        used = sorted(set(re.findall(r"\bfunc_[0-9A-F]{8}\b", g["body"])))
        externs = "".join(f"extern u32 {u}();\n" for u in used if not re.search(rf"\b{u}\s*\([^)]*\)\s*\{{", g["body"]))
        header = (f"/* {name} @ 0x{e['addr']:08X} THUMB {e['size']} B | agbcc preset {g['preset']} | "
                  f"verificado 1:1 contra la ROM */\n#include \"../fomt_types.h\"\n")
        p.write_text(header + externs + g["body"].rstrip() + "\n", encoding="utf-8")
        keep.add(p.resolve())
        funcs.append({"name": name, "addr": e["addr"], "size": e["size"], "emitted": g["emitted"], "file": rel,
                      "preset": g["preset"], "cc": str(AGBCC_PRESETS[g["preset"]][0]),
                      "cflags": list(AGBCC_PRESETS[g["preset"]][1])})
    for old in (out / "src").rglob("*.c"):
        if old.resolve() not in keep:
            old.unlink()
    (out / "functions.json").write_text(json.dumps({"functions": funcs}, indent=1), encoding="utf-8")

    segs = build_segments(manifest, good, rom_info["size"])
    for old in (out / "asm").glob("*.s"):
        old.unlink()
    banks = {}
    layout = ["SECTIONS {"]
    for kind, s, e_, name in segs:
        a = f"{s:08X}"
        if kind == "c":
            layout.append(f"  . = 0x{a}; .t_{a} : {{ *{name}.o(.text*) }}")
            continue
        cur = s
        while cur < e_:
            nxt = min(e_, (cur // 0x10000 + 1) * 0x10000)
            banks.setdefault(cur // 0x10000 * 0x10000, []).append((cur, nxt))
            ca = f"{cur:08X}"
            layout.append(f"  . = 0x{ca}; .t_{ca} : {{ *(.seg_{ca}) }}")
            cur = nxt
    layout.append("  /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.data*) *(.bss*) *(.rodata*) }")
    layout.append("}")
    (out / "ld" / "layout.ld").write_text("\n".join(layout) + "\n", encoding="utf-8")
    sorted_m = sorted(manifest, key=lambda x: x["addr"])
    for base, parts in sorted(banks.items()):
        lines = [f"@ Banco 0x{base:08X}: datos y funciones sin resolver tomados de baserom.gba (banco de datos)\n"]
        for s, e_ in parts:
            names = [m["name"] for m in sorted_m if s <= m["addr"] < e_ and m["name"] not in good]
            lines.append(f"@ 0x{s:08X}-0x{e_:08X} ({e_ - s} B)" +
                         (f" | {len(names)} funciones pendientes: {names[0]} .. {names[-1]}" if names else " | datos"))
            lines.append(f'.section .seg_{s:08X},"ax"\n.incbin "baserom.gba", 0x{s - ROM_BASE:X}, 0x{e_ - s:X}\n')
        (out / "asm" / f"bank_{base:08X}.s").write_text("\n".join(lines), encoding="utf-8")
    (out / "build.py").write_text(BUILD_PY, encoding="utf-8")
    (out / "build.bat").write_text("@echo off\r\ncd /d \"%~dp0\"\r\npython build.py %*\r\n", encoding="utf-8")
    return funcs, segs


def tools_cfg():
    return {"agbcc": str(AGBCC_EXE), "agbcc_include": str(AGBCC_DIR / "include"),
            "cpp": find_tool("cpp"), "as": find_tool("as"), "ld": find_tool("ld"), "objcopy": find_tool("objcopy")}


def run_build(out):
    r = subprocess.run([sys.executable, str(Path(out) / "build.py")], capture_output=True, text=True)
    for ln in (r.stdout + r.stderr).strip().splitlines()[-12:]:
        log("  " + ln)
    try:
        return json.loads((Path(out) / "build" / "result.json").read_text(encoding="utf-8"))
    except Exception:
        return {"ok": False, "compile_errors": {"build": r.stderr[:400]}, "mismatched": []}


# ---------------------------------------------------------------------------------------------
# Agente LLM (reparacion de funciones matched que ya no reproducen la ROM)
# ---------------------------------------------------------------------------------------------
def agent_repair(bad, manifest, tries, workers):
    import ai_gateway
    import lift
    cfg = load_engine_config()
    provider, model = cfg.get("ai_provider", "ollama"), cfg.get("ai_model") or cfg.get("model")
    by = {e["name"]: e for e in manifest}
    rom = load_rom()
    fixed = {}
    log(f"[agent] proveedor={provider} modelo={model} funciones a reparar={len(bad)} intentos={tries}")
    for name, err in list(bad.items()):
        e = by.get(name)
        if not e or e["mode"] != "THUMB":
            continue
        srcs = recover_bodies(e)
        code = srcs[0][1] if srcs else ""
        target = rom_bytes(rom, e["addr"], e["size"])
        feedback = err
        for t in range(1, tries + 1):
            msgs = [{"role": "system", "content": lift.SYSTEM},
                    {"role": "user", "content": f"Funcion {name} ({e['size']} B, THUMB, agbcc -O2). Codigo actual:\n```c\n{code}\n```\n"
                                                f"Problema: {feedback}\nDevuelve la funcion corregida."}]
            try:
                reply = ai_gateway.call_unified_llm(msgs, provider, model, temperature=0.1 + 0.05 * t,
                                                    max_tokens=900, num_ctx=int(cfg.get("num_ctx", 6144)),
                                                    threads=int(cfg.get("threads", 8)))
            except Exception as ex:  # noqa
                log(f"[agent] LLM no disponible ({ex}); se omite el agente")
                return fixed
            cand = lift.extract_c(reply, rom, e)
            if not cand:
                feedback = "la respuesta no contenia una funcion C valida"
                continue
            for p in AGBCC_PRESETS:
                ok, got, cerr = lift.try_candidate(e, cand, manifest, p)
                if ok and lift.score(e, target, got)[0]:
                    fixed[name] = cand
                    log(f"[agent] REPARADA {name} (intento {t}, {p})")
                    break
                feedback = cerr if not ok else lift.feedback(e, target, got)
            if name in fixed:
                break
            code = cand
    return fixed


# ---------------------------------------------------------------------------------------------
def pipeline(args, rom_info=None):
    t0 = time.time()
    rom_info = rom_info or ask_rom(args.rom, args.yes)
    manifest, state = load_manifest(), load_state()
    try:
        import psutil
        busy = any(re.search(r"(lift|sweep)\.py", " ".join(p.info.get("cmdline") or []))
                   for p in psutil.process_iter(["cmdline"]))
    except Exception:
        busy = False
    workers = args.workers or (3 if busy else max(2, min(8, (os.cpu_count() or 8) - 2)))
    if busy:
        log("[!] El motor lift/sweep esta activo: forge es de solo lectura sobre el arbol, usando pocos workers.")
    write_status(phase="start", running=True)
    tools = tools_cfg()
    good, bad = verify_all(manifest, state, workers, cache_path=Path(args.out) / ".verify_cache.json",
                           rom_sha=rom_info["sha1"])
    extra = {}
    for rnd in range(1, 4):
        funcs, segs = write_project(args.out, rom_info, manifest, good, tools)
        log(f"[forge] ronda {rnd}: proyecto escrito en {args.out} ({len(funcs)} funciones C, "
            f"{sum(1 for s in segs if s[0] == 'bin')} bloques .incbin)")
        write_status(phase="build", round=rnd, c_functions=len(funcs))
        res = run_build(args.out)
        demote = set(res.get("mismatched", [])) | {n for n in res.get("compile_errors", {}) if n in good}
        if res.get("ok") or not demote:
            break
        log(f"[forge] degradando {len(demote)} funciones a .incbin: {sorted(demote)[:6]}")
        for n in demote:
            bad[n] = res.get("compile_errors", {}).get(n) or "difiere tras el enlace final"
            good.pop(n, None)
    if (args.agent or getattr(args, "cmd", "") == "agent") and bad:
        fixed = agent_repair(bad, manifest, args.agent_tries, workers)
        if fixed:
            g2, b2 = verify_all(manifest, state, workers, extra=fixed,
                                cache_path=Path(args.out) / ".verify_cache.json", rom_sha=rom_info["sha1"])
            good = {n: g2[n] for n in g2 if n not in bad or n in fixed}
            funcs, segs = write_project(args.out, rom_info, manifest, good, tools)
            res = run_build(args.out)
    ok = bool(res.get("ok"))
    report = {"rom": {k: rom_info[k] for k in ("path", "sha1", "size")}, "c_functions": len(good),
              "demoted_or_failed": bad, "build_ok": ok, "diff_bytes": res.get("diff_bytes"),
              "seconds": round(time.time() - t0, 1)}
    (Path(args.out) / "forge_report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    write_status(phase="done", running=False, build_ok=ok, c_functions=len(good), failed=len(bad),
                 diff_bytes=res.get("diff_bytes"), out=str(args.out))
    log(f"[forge] RESULTADO: build_ok={ok} | funciones C={len(good)} | pendientes/fallidas={len(bad)} | "
        f"{report['seconds']}s | reporte: {Path(args.out) / 'forge_report.json'}")
    return report


def shell(args):
    rom_info = None
    log("FOMT FORGE :: agente de reordenado y compilacion (escribe 'help')")
    while True:
        try:
            line = input("FORGE> ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        cmd = cmd.lower()
        if cmd in ("quit", "exit", "q"):
            return 0
        elif cmd == "help":
            log("  rom [ruta]   fija y valida la ROM original (banco de datos)\n"
                "  scan         inventario del arbol y salud de las fuentes\n"
                "  out <dir>    carpeta de salida (actual: %s)\n"
                "  forge        reordena, verifica, genera el proyecto y lo compila\n"
                "  agent [N]    como forge + agente LLM reparando fallos (N intentos)\n"
                "  build        recompila la carpeta de salida\n  quit" % args.out)
        elif cmd == "rom":
            rom_info = ask_rom(rest or None)
        elif cmd == "scan":
            scan()
        elif cmd == "out" and rest:
            args.out = Path(rest.strip('"'))
        elif cmd in ("forge", "agent"):
            if cmd == "agent":
                args.agent = True
                args.agent_tries = int(rest) if rest.strip().isdigit() else args.agent_tries
            rom_info = rom_info or ask_rom(None)
            pipeline(args, rom_info)
            args.agent = False
        elif cmd == "build":
            run_build(args.out)
        else:
            log("comando desconocido; usa 'help'")


def main():
    ap = argparse.ArgumentParser(description="FORGE: reordena el arbol y genera un proyecto compilable")
    ap.add_argument("cmd", nargs="?", default="shell", choices=["shell", "scan", "forge", "agent", "build"])
    ap.add_argument("--rom", default=None)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--agent", action="store_true")
    ap.add_argument("--agent-tries", type=int, default=3)
    ap.add_argument("--yes", action="store_true", help="no preguntar: usar la ROM por defecto")
    args = ap.parse_args()
    args.out = Path(args.out)
    if args.cmd == "shell":
        return shell(args)
    if args.cmd == "scan":
        scan()
        return 0
    if args.cmd == "build":
        return 0 if run_build(args.out).get("ok") else 2
    rep = pipeline(args)
    return 0 if rep["build_ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
