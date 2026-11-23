"""Triage v2 con CAUSA de diferencia y valor en bytes (Fase 1).

Mejora sobre diff_triage.py:
  - Normaliza el relleno final (0x0000 / 0x46C0 / 0xFFFF) del objetivo antes de comparar, para
    no clasificar como 'tamano distinto' lo que solo es alineacion.
  - Separa la literal pool del cuerpo de instrucciones (posicion del ultimo ldr pc-relativo).
  - Reporta una causa concreta por funcion y los bytes recuperables por causa.

Causas (en orden de prioridad):
  PAD          cuerpo + pool identicos salvo relleno final (arreglable por alineacion/enlace)
  POOL         mismas instrucciones, cambia el contenido/orden de la literal pool
  REGS         mismo flujo; solo difieren registros
  ORDER        mismo multiset de opcodes, distinto orden
  PROLOGUE     difiere el prologo (push/mov inicial) pero no el resto
  EPILOGUE     difiere el epilogo (pop/bx/tail-call) pero no el resto
  TAILCALL     el objetivo termina en bl + pop{r1}/bx r1 (tail-call) y el candidato no
  SHORT / LONG el candidato emite menos / mas instrucciones (delta en 'delta')
  NO_SEED / COMPILE_ERROR

Uso:
  python tools/match/triage_causes.py                  # todas las pendientes
  python tools/match/triage_causes.py --sample 80      # muestra rapida
  python tools/match/triage_causes.py --workers 8
Salida: logs/triage_causes.json y resumen por causa (funciones y bytes).
"""
import argparse
import collections
import concurrent.futures
import json
import os
import re
import sys
import time
from pathlib import Path

if "FOMT_TREE" not in os.environ:
    os.environ["FOMT_TREE"] = "src_sweep"

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common  # noqa: E402
import lift  # noqa: E402
import rosetta_decompiler as RD  # noqa: E402
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB  # noqa: E402

OUT_FILE = ROOT / "logs" / "triage_causes.json"
_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
_REG = re.compile(r"\b(r\d+|sl|fp|ip|sp|lr|pc)\b")


def strip_padding(b: bytes) -> bytes:
    """Quita relleno final de 2 en 2 bytes (0x0000, 0x46C0, 0xFFFF)."""
    while len(b) >= 2 and b[-2:] in (b"\x00\x00", b"\xc0\x46", b"\xff\xff"):
        b = b[:-2]
    return b


def split_pool(b: bytes, addr: int):
    """Devuelve (codigo, pool). La pool empieza tras la ultima instruccion de retorno/rama final
    y se infiere por el mayor destino de ldr pc-relativo."""
    ins = list(_MD.disasm(b, addr))
    pool_end = 0
    for i in ins:
        if i.mnemonic == "ldr" and "[pc" in i.op_str:
            m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", i.op_str)
            disp = int(m.group(1), 0) if m else 0
            pool_end = max(pool_end, ((i.address + 4) & ~3) + disp + 4 - addr)
    if pool_end <= 0 or pool_end > len(b):
        return b, b""
    # el inicio de la pool: primer literal referenciado
    starts = []
    for i in ins:
        if i.mnemonic == "ldr" and "[pc" in i.op_str:
            m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", i.op_str)
            disp = int(m.group(1), 0) if m else 0
            starts.append(((i.address + 4) & ~3) + disp - addr)
    pstart = min(starts) if starts else len(b)
    pstart = min(pstart, len(b))
    return b[:pstart], b[pstart:]


def texts(b, addr):
    return [f"{i.mnemonic} {i.op_str}".strip() for i in _MD.disasm(b, addr)]


def classify(target: bytes, got: bytes, e: dict):
    addr = e["addr"]
    tt, gg = strip_padding(target), strip_padding(got)
    if tt == gg:
        return "PAD", "identico salvo relleno final", 0
    t_code, t_pool = split_pool(tt, addr)
    g_code, g_pool = split_pool(gg, addr)
    t_ins, g_ins = texts(t_code, addr), texts(g_code, addr)
    delta = len(g_ins) - len(t_ins)

    if t_ins == g_ins:
        return "POOL", f"cuerpo identico; pool T={len(t_pool)}B vs G={len(g_pool)}B", 0

    nreg = lambda L: [_REG.sub("rX", x) for x in L]
    if len(t_ins) == len(g_ins):
        if nreg(t_ins) == nreg(g_ins):
            return "REGS", "solo difieren registros", 0
        if collections.Counter(x.split()[0] for x in t_ins) == collections.Counter(x.split()[0] for x in g_ins):
            return "ORDER", "mismos opcodes, distinto orden o ramas", 0

    # divergencia localizada en prologo / epilogo
    n = min(len(t_ins), len(g_ins))
    first = next((k for k in range(n) if t_ins[k] != g_ins[k]), n)
    last = next((k for k in range(n) if t_ins[-1 - k] != g_ins[-1 - k]), n)
    tail_t = " ".join(t_ins[-3:])
    if "pop {r1}" in tail_t and "bx r1" in tail_t and "bl " in " ".join(t_ins[-4:]):
        got_tail = " ".join(g_ins[-3:])
        if not ("pop {r1}" in got_tail and "bx r1" in got_tail):
            return "TAILCALL", "objetivo usa bl+pop{r1}+bx r1 y el candidato no", delta
    if first <= 2 and last >= max(0, n - 2) and first < n:
        pass
    if first < 3 and last >= n - 1 and len(t_ins) > 6:
        return "PROLOGUE", f"difiere el prologo (primer desvio en ins {first})", delta
    if last < 3 and first >= n - 3 and len(t_ins) > 6:
        return "EPILOGUE", f"difiere el epilogo (ultimas {last} ins coinciden)", delta
    return ("SHORT" if delta < 0 else "LONG"), f"candidato emite {delta:+d} ins (primer desvio ins {first}/{len(t_ins)})", delta


def eval_one(e, manifest, state, rom):
    name = e["name"]
    st = state.get(name, {})
    preset = st.get("preset") or "agbcc_O2"
    target = common.rom_bytes(rom, e["addr"], e["size"])
    try:
        c_code = RD.get_best_existing_code(e)
        if not c_code:
            return name, "NO_SEED", "sin codigo c89 disponible", e["size"], 0
        c_clean = lift.extract_c(c_code, rom=rom, e=e)
        if not c_clean:
            return name, "NO_SEED", "no se pudo extraer c89 limpio", e["size"], 0
        ok, got, err = lift.try_candidate(e, c_clean, manifest, preset)
    except Exception as ex:  # noqa: BLE001
        return name, "COMPILE_ERROR", f"excepcion {type(ex).__name__}", e["size"], 0
    if not ok or not got:
        return name, "COMPILE_ERROR", (err or "error desconocido").splitlines()[0][:80], e["size"], 0
    cause, hint, delta = classify(target, got, e)
    return name, cause, hint, e["size"], delta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="procesar solo N funciones (muestra)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only-class", default="", help="solo funciones cuya clase v1 sea esta (ej. C)")
    a = ap.parse_args()

    t0 = time.time()
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()
    pending = [e for e in manifest if state.get(e["name"], {}).get("status") != "matched"]
    if a.only_class:
        v1 = json.loads((ROOT / "logs" / "triage_classes.json").read_text(encoding="utf-8"))
        pending = [e for e in pending if v1.get(e["name"], {}).get("class") == a.only_class]
    if a.sample:
        import random
        random.Random(7).shuffle(pending)
        pending = pending[: a.sample]
    print(f"[*] Triage v2 de {len(pending)} funciones, {a.workers} hilos")

    res, cnt, byt = {}, collections.Counter(), collections.Counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(eval_one, e, manifest, state, rom) for e in pending]
        for k, f in enumerate(concurrent.futures.as_completed(futs), 1):
            name, cause, hint, sz, delta = f.result()
            res[name] = {"cause": cause, "hint": hint, "size": sz, "delta": delta}
            cnt[cause] += 1
            byt[cause] += sz
            if k % 200 == 0:
                print(f"  [+] {k}/{len(pending)}")

    print("\n" + "=" * 66)
    print(f"{'causa':14s} {'funcs':>6s} {'bytes':>9s}  {'med.B':>6s}")
    for c, n in sorted(cnt.items(), key=lambda x: -byt[x[0]]):
        print(f"{c:14s} {n:6d} {byt[c]:9d}  {byt[c] // n:6d}")
    print("=" * 66)
    print(f"Tiempo: {time.time() - t0:.1f} s")
    if not a.sample:
        OUT_FILE.write_text(json.dumps(res, indent=2), encoding="utf-8")
        print(f"Guardado: {OUT_FILE}")
    else:
        for c in cnt:
            ex_ = [(n, v["hint"]) for n, v in res.items() if v["cause"] == c][:2]
            print(c, ex_)


if __name__ == "__main__":
    main()

