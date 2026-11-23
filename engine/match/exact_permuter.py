"""Permutador exacto (Fase 2.5): busca el punto de reorden exacto SIN usar IA.

Toma las funciones wip/approx cuya paridad ya es alta (por defecto >= 80%) y las somete a una
busqueda sistematica y determinista sobre el codigo C candidato existente, en lugar del
hill-climbing aleatorio de permuter.py:

  Etapa 0  Re-evaluacion base sobre los presets del compilador.
  Etapa A  Todas las permutaciones del bloque de declaraciones locales (n! hasta --max-decl-n).
           agbcc/GCC 2.95 asigna r4-r7 y offsets de pila por orden de declaracion: es el
           "punto de reorden" mas frecuente.
  Etapa B  Beam search con vecindario COMPLETO (no muestreado) de ediciones de un paso:
           swap de declaraciones, register on/off, tipos de variable y de puntero, swap de
           sentencias adyacentes, conmutacion de operandos, inversion de comparaciones,
           formas de incremento, casts, tipo de retorno, hundimiento de cero, asignacion en
           condicional y separacion de init.
  Etapa C  Barrido de los demas presets sobre los mejores candidatos.

La verdad de terreno es siempre la ROM original: un candidato solo es "exacto" si el binario
compilado coincide byte a byte con la funcion en 'fomt virgen.gba'.

Seguridad con el motor: si lift.py / sweep.py estan en ejecucion NO se escribe state.json; los
resultados quedan en <tree>/permute/ y se aplican con --apply-only cuando el motor este detenido.

Uso:
  python tools/match/exact_permuter.py                      # todas las wip/approx >= 80%
  python tools/match/exact_permuter.py --only func_0800042C --dry-run
  python tools/match/exact_permuter.py --apply-only         # vuelca resultados pendientes a state.json
"""
import argparse
import itertools
import json
import os
import random
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

if "FOMT_TREE" not in os.environ:
    _tree = "src_sweep"
    for _i, _a in enumerate(sys.argv):
        if _a == "--tree" and _i + 1 < len(sys.argv):
            _tree = sys.argv[_i + 1]
    os.environ["FOMT_TREE"] = _tree

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa
import permuter as P  # noqa

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PERM_DIR = TREE_DIR / "permute"
RESULTS_FILE = PERM_DIR / "results.json"
STATUS_FILE = TREE_DIR / "control" / "permute_status.json"
STOP_FILE = TREE_DIR / "control" / "permute_stop.flag"

SCALARS = ["u32", "s32", "int", "u16", "s16", "u8", "s8"]
POINTEES = ["u8", "u16", "u32", "s8", "s16", "s32"]
RET_TYPES = ["void", "u32", "u16", "u8", "s32", "s16", "s8", "int"]
CAST_OPTS = ["(u32)", "(u16)", "(u8)", "(s16)", "(s8)", "(s32)"]
INC_RE = re.compile(r"\b(\w+)\s*(\+\+|--|\+= 1|-= 1|= \1 \+ 1|= \1 - 1)\s*;")
PCAST_RE = re.compile(r"\(\s*(?:volatile\s+)?(u8|u16|u32|s8|s16|s32|int|char|short)\s*\*\s*\)")
PCAST_ALT = ["u8", "u16", "u32", "s8", "s16", "s32", "int", "char", "short"]
DEREF_RE = re.compile(r"\*\(\s*(?:volatile\s+)?\w+\s*\*\s*\)\s*(0x[0-9A-Fa-f]+)")
CALL_RE = re.compile(r"^(\s*)(?:(\w+)\s*=\s*)?(func_[0-9A-Fa-f]{8})\s*\((.*)\)\s*;\s*$")
RET_RE = re.compile(r"^(\s*)(void|u32|u16|u8|s32|s16|s8|int|BOOL)(\s+func_[0-9A-Fa-f]{8}\s*\(.*)$")
COMM_EXPR = re.compile(
    r"((?:\w+(?:\[[^\]]+\])?|\*\w+|\*\([^)]+\)|0x[0-9A-Fa-f]+|\d+))\s*"
    r"(\+|\*|&|\||\^|==|!=)\s*"
    r"((?:\w+(?:\[[^\]]+\])?|\*\w+|\*\([^)]+\)|0x[0-9A-Fa-f]+|\d+))"
)


def log(msg):
    print(msg, flush=True)


def norm(code):
    return re.sub(r"\s+", " ", code).strip()


# ---------------------------------------------------------------------------------------------
# Vecindario completo de ediciones de un paso
# ---------------------------------------------------------------------------------------------
def decl_block(lines):
    s = next((i for i, l in enumerate(lines) if "{" in l), None)
    if s is None:
        return []
    idx = []
    for i in range(s + 1, len(lines)):
        if P.DECL.match(lines[i]):
            idx.append(i)
        elif not lines[i].strip():
            continue
        else:
            break
    return idx


def decl_permutations(code, cap):
    """Todas las permutaciones del bloque de declaraciones (excepto la identidad) si n! <= cap."""
    lines = code.splitlines()
    idx = decl_block(lines)
    n = len(idx)
    if n < 2:
        return []
    fact = 1
    for k in range(2, n + 1):
        fact *= k
    if fact > cap:
        return []
    texts = [lines[i] for i in idx]
    out = []
    for perm in itertools.permutations(range(n)):
        if list(perm) == list(range(n)):
            continue
        l = list(lines)
        for pos, src in zip(idx, perm):
            l[pos] = texts[src]
        out.append((f"decl_perm{perm}", "\n".join(l) + "\n"))
    return out


def neighbors(code):
    lines = code.splitlines()
    out = []

    def emit(tag, ls):
        out.append((tag, "\n".join(ls) + "\n"))

    n = len(lines)
    dblock = decl_block(lines)
    for a, b in itertools.combinations(dblock, 2):
        l = list(lines)
        l[a], l[b] = l[b], l[a]
        emit(f"swap_decl {a}<->{b}", l)

    for i in range(n):
        m = P.DECL.match(lines[i])
        if not m:
            continue
        ind, qual, typ, stars, var, rest = m.groups()
        qual = qual or ""
        is_arr = "[" in rest
        is_ptr = "*" in stars
        if not is_arr and f"&{var}" not in code:
            if "register" in qual:
                nq = ""
            elif not qual:
                nq = "register "
            else:
                nq = None
            if nq is not None:
                l = list(lines)
                l[i] = f"{ind}{nq}{typ}{stars}{var}{rest}"
                emit(f"register@{i}", l)
        if not is_arr:
            holds_32bit_addr = bool(re.search(rf"\b{re.escape(var)}\s*=\s*(?:\([^)]+\))?\s*0x0[2345678][0-9A-Fa-f]{{6}}\b", code))
            scalar_opts = ["u32", "s32", "int"] if holds_32bit_addr else SCALARS
            for t in (POINTEES if is_ptr else scalar_opts):
                if t != typ:
                    l = list(lines)
                    l[i] = f"{ind}{qual}{t}{stars}{var}{rest}"
                    emit(f"type@{i}->{t}", l)
            if "=" in rest and not is_ptr:
                init = rest.split("=", 1)[1].rstrip().rstrip(";").strip()
                l = list(lines)
                l[i] = f"{ind}{qual}{typ}{stars}{var};"
                last = max(j for j, x in enumerate(l) if P.DECL.match(x))
                l.insert(last + 1, f"{ind}{var} = {init};")
                emit(f"split_init@{i}", l)

    s, e = P._body_range(lines)
    for i in range(s, max(s, e - 1)):
        a, b = lines[i], lines[i + 1]
        if (a.rstrip().endswith(";") and b.rstrip().endswith(";")
                and not P.STMT_SKIP.match(a) and not P.STMT_SKIP.match(b)
                and not P.DECL.match(a) and not P.DECL.match(b)):
            l = list(lines)
            l[i], l[i + 1] = l[i + 1], l[i]
            emit(f"swap_stmt@{i}", l)

    def simple(x):
        return x.rstrip().endswith(";") and not P.STMT_SKIP.match(x) and not P.DECL.match(x)

    # swaps a distancia 2 (la sentencia central queda fija)
    for i in range(s, max(s, e - 2)):
        if simple(lines[i]) and simple(lines[i + 2]):
            l = list(lines)
            l[i], l[i + 2] = l[i + 2], l[i]
            emit(f"swap_stmt2@{i}", l)

    # orden init-de-for vs sentencias vecinas (el compilador emite el init del for en su sitio)
    for i in range(s, e):
        m = re.match(r"^(\s*)for\s*\(\s*([^;,]+?)\s*;(.*)$", lines[i])
        if m:
            ind, init, rest = m.groups()
            l = list(lines)
            l[i] = f"{ind}for (;{rest}"
            l.insert(i, f"{ind}{init};")
            emit(f"for_hoist@{i}", l)
            if i > s and simple(lines[i - 1]):
                l = list(lines)
                l[i] = f"{ind}for (;{rest}"
                l.insert(i - 1, f"{ind}{init};")
                emit(f"for_hoist_up@{i}", l)
        if i + 1 < len(lines) and simple(lines[i]):
            m2 = re.match(r"^(\s*)for\s*\(\s*;(.*)$", lines[i + 1])
            if m2:
                l = list(lines)
                l[i + 1] = f"{m2.group(1)}for ({lines[i].strip().rstrip(';')};{m2.group(2)}"
                l.pop(i)
                emit(f"for_merge@{i}", l)

    for i in range(s, e):
        if P.DECL.match(lines[i]):
            continue
        for m in P.COMM.finditer(lines[i]):
            l = list(lines)
            l[i] = lines[i][:m.start()] + f"{m.group(3)} {m.group(2)} {m.group(1)}" + lines[i][m.end():]
            emit(f"comm@{i}", l)
        for m in COMM_EXPR.finditer(lines[i]):
            op1, op, op2 = m.groups()
            if op1 != op2:
                l = list(lines)
                l[i] = lines[i][:m.start()] + f"{op2} {op} {op1}" + lines[i][m.end():]
                emit(f"comm_expr@{i}", l)
        for m in P.CMP.finditer(lines[i]):
            l = list(lines)
            l[i] = lines[i][:m.start()] + f"{m.group(3)} {P.FLIP[m.group(2)]} {m.group(1)}" + lines[i][m.end():]
            emit(f"cmp@{i}", l)
        for m in INC_RE.finditer(lines[i]):
            v, plus = m.group(1), "+" in m.group(2)
            op = "+" if plus else "-"
            for form in (f"{v}{op}{op};", f"{v} {op}= 1;", f"{v} = {v} {op} 1;"):
                l = list(lines)
                l[i] = lines[i][:m.start()] + form + lines[i][m.end():]
                emit(f"inc@{i}", l)
        if "=" in lines[i]:
            has_cast = re.search(r"=\s*\([us](?:8|16|32)\)\s*", lines[i])
            opts = CAST_OPTS + ([""] if has_cast else [])
            for c in opts:
                if has_cast:
                    new = re.sub(r"=\s*\([us](?:8|16|32)\)\s*", f"= {c}", lines[i], count=1)
                else:
                    new = re.sub(r"=\s*", f"= {c}", lines[i], count=1)
                if new != lines[i]:
                    l = list(lines)
                    l[i] = new
                    emit(f"cast@{i}", l)

    # ancho de acceso de punteros MMIO/ROM: *(u16 *)0x0300... -> *(u32 *)0x0300...
    for i in range(s, e):
        if P.DECL.match(lines[i]):
            continue
        for m in PCAST_RE.finditer(lines[i]):
            for t in PCAST_ALT:
                if t != m.group(1):
                    l = list(lines)
                    l[i] = lines[i][:m.start(1)] + t + lines[i][m.end(1):]
                    emit(f"ptr_cast@{i}->{t}", l)

    # usar la variable puntero ya cargada con la direccion en vez del literal: *(u16 *)0x... -> *var
    addr_var = {}
    for ln in lines[s:e]:
        am = re.match(r"^\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(0x[0-9A-Fa-f]+)\s*;", ln)
        if am:
            addr_var.setdefault(am.group(2).lower(), am.group(1))
    if addr_var:
        for i in range(s, e):
            for m in DEREF_RE.finditer(lines[i]):
                var = addr_var.get(m.group(1).lower())
                if var:
                    l = list(lines)
                    l[i] = lines[i][:m.start()] + f"*{var}" + lines[i][m.end():]
                    emit(f"deref_var@{i}", l)

    # extraer un argumento complejo de una llamada a una temporal asignada justo antes
    last_decl = max([j for j, x in enumerate(lines) if P.DECL.match(x)] or [s - 1])
    for i in range(s, e):
        cm = CALL_RE.match(lines[i])
        if not cm:
            continue
        ind, lhs, fn, argstr = cm.groups()
        args, depth, cur = [], 0, ""
        for ch in argstr:
            if ch == "," and depth == 0:
                args.append(cur.strip())
                cur = ""
                continue
            depth += ch in "(["
            depth -= ch in ")]"
            cur += ch
        args.append(cur.strip())
        for k, a in enumerate(args):
            if re.search(r"[+\-*/&|^<>\[]|\(", a) and not re.fullmatch(r"-?0x[0-9A-Fa-f]+|-?\d+", a):
                tmp = f"tmp_a{k}"
                if re.search(rf"\b{tmp}\b", "\n".join(lines)):
                    continue
                new_args = list(args)
                new_args[k] = tmp
                call = f"{ind}{(lhs + ' = ') if lhs else ''}{fn}({', '.join(new_args)});"
                l = list(lines)
                l[i] = call
                l.insert(i, f"{ind}{tmp} = {a};")
                l.insert(last_decl + 1, f"{ind}u32 {tmp};")
                emit(f"hoist_arg@{i}.{k}", l)

        # extraer TODOS los argumentos compuestos juntos antes de la llamada
        comp_indices = [k for k, a in enumerate(args) if re.search(r"[+\-*/&|^<>\[]|\(", a) and not re.fullmatch(r"-?0x[0-9A-Fa-f]+|-?\d+", a)]
        if len(comp_indices) >= 2:
            l = list(lines)
            new_args = list(args)
            tmps = []
            for k in comp_indices:
                tname = f"tmp_all_a{k}"
                new_args[k] = tname
                tmps.append((tname, args[k]))
            call = f"{ind}{(lhs + ' = ') if lhs else ''}{fn}({', '.join(new_args)});"
            l[i] = call
            for tname, expr in reversed(tmps):
                l.insert(i, f"{ind}{tname} = {expr};")
            for tname, _ in tmps:
                l.insert(last_decl + 1, f"{ind}u32 {tname};")
            emit(f"hoist_all_args@{i}", l)

    # tipos de los parametros de la firma
    for i, ln in enumerate(lines[:4]):
        sm = re.match(r"^(\s*(?:void|u32|u16|u8|s32|s16|s8|int|BOOL)\s+func_[0-9A-Fa-f]{8}\s*\()(.*)(\)\s*\{?\s*)$", ln)
        if not sm:
            continue
        head, plist, tail = sm.groups()
        parts = [x.strip() for x in plist.split(",")]
        for pi, part in enumerate(parts):
            pm = re.match(r"^(u8|u16|u32|s8|s16|s32|int|char|short|unsigned int)(\s*\*?\s*)(\w+)$", part)
            if not pm:
                continue
            ptype, sp, pname = pm.groups()
            alts = POINTEES + ["int", "char"] if "*" in sp else SCALARS + ["char"]
            for t in alts:
                if t != ptype:
                    np_ = list(parts)
                    np_[pi] = f"{t}{sp}{pname}"
                    l = list(lines)
                    l[i] = head + ", ".join(np_) + tail
                    emit(f"param{pi}->{t}", l)
        break

    for i, ln in enumerate(lines[:6]):
        m = RET_RE.match(ln)
        if m:
            for t in RET_TYPES:
                if t != m.group(2):
                    l = list(lines)
                    l[i] = f"{m.group(1)}{t}{m.group(3)}"
                    emit(f"ret->{t}", l)
            break

    for fn in (P._m_sink_zero, P._m_cond_assign, P._m_split_decl_init):
        l = list(lines)
        try:
            if fn(l, None):
                emit(fn.__name__, l)
        except Exception:
            pass

    uniq, seen = [], {norm(code)}
    for t, c in out:
        k = norm(c)
        if k not in seen:
            seen.add(k)
            uniq.append((t, c))
    return uniq


# ---------------------------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------------------------
_W = {}


def _init_worker():
    try:
        import psutil
        psutil.Process().nice(getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", 0x4000))
    except Exception:
        pass
    import lift  # noqa
    _W["lift"] = lift
    _W["rom"] = load_rom()
    _W["manifest"] = load_manifest()
    _W["by"] = {e["name"]: e for e in _W["manifest"]}


def _eval(job):
    name, code, preset = job
    lift = _W["lift"]
    e = _W["by"][name]
    target = rom_bytes(_W["rom"], e["addr"], e["size"])
    try:
        ok, got, _ = lift.try_candidate(e, code, _W["manifest"], preset)
    except Exception:
        return 0.0, False, False
    if not ok:
        return 0.0, False, False
    exact, sc = lift.score(e, target, got)
    return sc, bool(exact), True


# ---------------------------------------------------------------------------------------------
# Estado, fuentes y persistencia
# ---------------------------------------------------------------------------------------------
def _atomic_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def load_results():
    try:
        return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def engine_running():
    try:
        import psutil
    except ImportError:
        return False
    me = os.getpid()
    for p in psutil.process_iter(["pid", "cmdline"]):
        if p.info["pid"] == me:
            continue
        cl = " ".join(p.info.get("cmdline") or [])
        if re.search(r"(lift|sweep|run_sweep)\.py", cl) and "exact_permuter" not in cl:
            return True
    return False


def pick_source(e, st):
    cands = [TREE_DIR / "approx" / f"{e['name']}.c",
             (TREE_DIR / e["file"]).with_suffix(".wip.c"),
             TREE_DIR / "collection" / "approx" / f"{e['name']}.c",
             TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c"]
    for p in cands:
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            if e["name"] in txt and "{" in txt:
                return txt, p
    return None, None


def presets_for(e, st, mode):
    if e["mode"] != "THUMB":
        base = ["O2", "O1", "O2s", "O2_nocse"]
    elif mode == "all":
        base = list(CFLAG_PRESETS)
    else:
        base = list(AGBCC_PRESETS)
    first = st.get("preset")
    if first in base:
        base.remove(first)
        base.insert(0, first)
    return base


def write_status(status):
    status["ts"] = time.time()
    try:
        _atomic_json(STATUS_FILE, status)
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------
# Busqueda
# ---------------------------------------------------------------------------------------------
class Searcher:
    def __init__(self, pool, workers, args):
        self.pool, self.workers, self.args = pool, workers, args
        self.evals = 0

    def batch(self, name, items, deadline):
        """items: [(tag, code, preset)] -> [(score, exact, tag, code, preset)] con salida temprana si exacto."""
        out = []
        step = max(self.workers * 3, 8)
        for k in range(0, len(items), step):
            if time.time() > deadline or STOP_FILE.exists():
                break
            sl = items[k:k + step]
            res = list(self.pool.map(_eval, [(name, c, p) for _, c, p in sl]))
            self.evals += len(sl)
            for (tag, c, p), (sc, ex, ok) in zip(sl, res):
                if ok:
                    out.append((sc, ex, tag, c, p))
            if any(r[1] for r in res if r[2]):
                break
        return out

    def run(self, e, code, presets, deadline, on_progress):
        name = e["name"]
        a = self.args
        rng = random.Random(name)
        best = (-1.0, code, presets[0], "base")
        base = self.batch(name, [("base", code, p) for p in presets[:3]], deadline)
        if not base:
            return best[0], code, presets[0], False, "no compila"
        for sc, ex, tag, c, p in base:
            if ex:
                return 1.0, c, p, True, "base"
            if sc > best[0]:
                best = (sc, c, p, tag)
        base_sc = best[0]
        on_progress(best[0], self.evals)
        preset = best[2]

        # Etapa A: permutaciones completas de declaraciones
        perms = decl_permutations(best[1], a.max_decl_perm)
        if perms:
            res = self.batch(name, [(t, c, preset) for t, c in perms], deadline)
            for sc, ex, tag, c, p in res:
                if ex:
                    return 1.0, c, p, True, tag
                if sc > best[0]:
                    best = (sc, c, p, tag)
            on_progress(best[0], self.evals)

        # Etapa B: beam search con vecindario completo
        seen = {norm(best[1])}
        frontier = [(best[0], best[1])]
        stale = 0
        depth_limit = a.depth + (2 if best[0] >= 0.90 else 0)
        patience_limit = a.patience + (2 if best[0] >= 0.90 else 0)
        max_nb = a.max_neighbors * (2 if best[0] >= 0.90 else 1)

        for depth in range(depth_limit):
            if time.time() > deadline or STOP_FILE.exists():
                break
            per = max(32, max_nb // max(1, len(frontier)))
            cand = []
            for _, c in frontier:
                nb = [(t, n) for t, n in neighbors(c) if norm(n) not in seen]
                rng.shuffle(nb)
                for t, n in nb[:per]:
                    seen.add(norm(n))
                    cand.append((t, n, preset))
            if not cand:
                break
            res = self.batch(name, cand, deadline)
            improved = False
            for sc, ex, tag, c, p in res:
                if ex:
                    return 1.0, c, p, True, f"d{depth + 1}:{tag}"
                if sc > best[0] + 1e-9:
                    best, improved = (sc, c, p, f"d{depth + 1}:{tag}"), True
            pool = sorted(res, key=lambda r: -r[0])
            keep = {norm(c): (sc, c) for sc, c in frontier}
            beam_width = a.beam + (4 if best[0] >= 0.90 else 0)
            for sc, ex, tag, c, p in pool[:beam_width]:
                keep[norm(c)] = (sc, c)
            frontier = sorted(keep.values(), key=lambda x: -x[0])[:beam_width]
            on_progress(best[0], self.evals)
            stale = 0 if improved else stale + 1
            if stale >= patience_limit:
                break

        # Etapa C: otros presets sobre los mejores candidatos
        if len(presets) > 1 and time.time() < deadline:
            tops = [c for _, c in frontier[:3]] or [best[1]]
            items = [(f"preset:{p}", c, p) for c in tops for p in presets if p != preset]
            res = self.batch(name, items, deadline)
            for sc, ex, tag, c, p in res:
                if ex:
                    return 1.0, c, p, True, tag
                if sc > best[0]:
                    best = (sc, c, p, tag)
        return best[0], best[1], best[2], False, best[3]


# ---------------------------------------------------------------------------------------------
# Aplicacion a state.json (solo con el motor detenido)
# ---------------------------------------------------------------------------------------------
def apply_results(verbose=True):
    if engine_running():
        log("[perm] motor lift/sweep activo: resultados guardados en permute/results.json (usa --apply-only al detenerlo)")
        return 0
    import lift
    results = load_results()
    manifest = load_manifest()
    by = {e["name"]: e for e in manifest}
    rom = load_rom()
    applied = 0
    state = load_state()
    for name, r in results.items():
        if r.get("applied") or name not in by:
            continue
        e = by[name]
        cfile = PERM_DIR / "code" / f"{name}.c"
        if not cfile.exists():
            continue
        code = cfile.read_text(encoding="utf-8")
        cur = state.get(name, {})
        if r.get("exact"):
            target = rom_bytes(rom, e["addr"], e["size"])
            ok, got, _ = lift.try_candidate(e, code, manifest, r["preset"])
            if ok and lift.score(e, target, got)[0]:
                state = load_state()
                lift.save_matched(e, code, r["preset"], manifest, state, 0, "exact-permuter", target=target, rom=rom)
                r["applied"] = True
                applied += 1
                if verbose:
                    log(f"[perm] APLICADO MATCH 100% {name}")
            else:
                r["exact"] = False
                log(f"[perm] {name}: la re-verificacion fallo, se descarta como exacto")
        elif r["best"] > cur.get("best", 0) + 0.001 and cur.get("status") in ("wip", "approx"):
            path = TREE_DIR / e["file"]
            lift._write_atomic(path.with_suffix(".wip.c"), code)
            lift._write_atomic(TREE_DIR / "collection" / "wip" / f"{name}.wip.c", code)
            status = cur.get("status")
            if r["best"] >= 0.90:
                status = "approx"
                txt = f"/* paridad {r['best'] * 100:.1f}% preset {r['preset']} (exact-permuter) */\n" + code
                lift._write_atomic(TREE_DIR / "approx" / f"{name}.c", txt)
                lift._write_atomic(TREE_DIR / "collection" / "approx" / f"{name}.c", txt)
            state = load_state()
            state[name] = {**state.get(name, {}), "status": status, "best": round(r["best"], 4), "preset": r["preset"]}
            save_state(state)
            r["applied"] = True
            applied += 1
    _atomic_json(RESULTS_FILE, results)
    log(f"[perm] resultados aplicados a state.json: {applied}")
    return applied


# ---------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Permutador exacto determinista (sin IA)")
    ap.add_argument("--tree", default=None)
    ap.add_argument("--min-score", type=float, default=0.80)
    ap.add_argument("--max-score", type=float, default=0.9999)
    ap.add_argument("--statuses", default="wip,approx")
    ap.add_argument("--only", default="", help="funciones separadas por coma")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=0, help="0 = automatico segun engine_config")
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--beam", type=int, default=12)
    ap.add_argument("--max-neighbors", type=int, default=1200)
    ap.add_argument("--max-decl-perm", type=int, default=5040)
    ap.add_argument("--patience", type=int, default=3)
    ap.add_argument("--seconds", type=int, default=180, help="presupuesto por funcion")
    ap.add_argument("--presets", choices=["agbcc", "all"], default="agbcc")
    ap.add_argument("--retry", action="store_true", help="reintenta funciones ya procesadas")
    ap.add_argument("--dry-run", action="store_true", help="no escribe resultados")
    ap.add_argument("--no-apply", action="store_true")
    ap.add_argument("--apply-only", action="store_true")
    args = ap.parse_args()

    if args.apply_only:
        apply_results()
        return 0

    cfg = load_engine_config()
    workers = args.workers or max(1, min(int(cfg.get("threads", 8)), (os.cpu_count() or 8) - 2, 10))
    manifest = load_manifest()
    by = {e["name"]: e for e in manifest}
    state = load_state()
    results = {} if args.dry_run else load_results()
    only = {x.strip() for x in args.only.split(",") if x.strip()}
    statuses = {x.strip() for x in args.statuses.split(",")}

    queue = []
    for name, st in state.items():
        if name not in by or st.get("status") not in statuses:
            continue
        if only and name not in only:
            continue
        b = float(st.get("best", 0))
        if not (args.min_score <= b <= args.max_score) and not only:
            continue
        if not args.retry and not only and name in results and results[name].get("attempts", 0) > 0:
            continue
        queue.append((b, name))
    queue.sort(reverse=True)
    if args.limit:
        queue = queue[:args.limit]

    conflict = engine_running()
    log(f"[perm] cola: {len(queue)} funciones (>= {args.min_score * 100:.0f}%), workers={workers}, "
        f"presets={args.presets}, motor_activo={conflict}")
    if STOP_FILE.exists():
        STOP_FILE.unlink()

    status = {"running": True, "pid": os.getpid(), "started": time.time(), "queue_total": len(queue), "done": 0,
              "exact": 0, "improved": 0, "current": None, "recent": [], "workers": workers,
              "engine_conflict": conflict, "min_score": args.min_score, "dry_run": args.dry_run}
    write_status(status)

    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker) as pool:
        srch = Searcher(pool, workers, args)
        for b0, name in queue:
            if STOP_FILE.exists():
                log("[perm] parada solicitada")
                break
            e = by[name]
            st = state[name]
            code, src = pick_source(e, st)
            if not code:
                log(f"[perm] {name}: sin codigo candidato, se omite")
                continue
            presets = presets_for(e, st, args.presets)
            t0 = time.time()
            srch.evals = 0
            status["current"] = {"name": name, "base": b0, "best": b0, "evals": 0, "size": e["size"]}
            write_status(status)
            log(f"[perm] >> {name} ({e['size']} B) base={b0 * 100:.1f}% preset={presets[0]}")

            def prog(sc, ev, _n=name):
                status["current"].update({"best": round(sc, 4), "evals": ev, "secs": round(time.time() - t0, 1)})
                write_status(status)

            sc, best_code, preset, exact, how = srch.run(e, code, presets, t0 + args.seconds, prog)
            secs = time.time() - t0
            if exact:
                log(f"[perm] ** EXACTO ** {name} via {how} preset={preset} ({srch.evals} evals, {secs:.1f}s)")
                status["exact"] += 1
            else:
                log(f"[perm] {name}: mejor {sc * 100:.1f}% ({how}) {srch.evals} evals, {secs:.1f}s")
            improved = sc > b0 + 0.001
            status["improved"] += 1 if (improved and not exact) else 0
            status["done"] += 1
            status["recent"] = ([{"name": name, "base": round(b0, 4), "best": round(sc, 4), "exact": exact,
                                  "how": how, "secs": round(secs, 1)}] + status["recent"])[:40]
            status["current"] = None
            write_status(status)

            if not args.dry_run:
                r = results.get(name, {})
                r.update({"best": round(sc, 4), "exact": bool(exact), "preset": preset, "how": how,
                          "evals": srch.evals, "secs": round(secs, 1), "base": round(b0, 4),
                          "attempts": r.get("attempts", 0) + 1, "ts": time.time(), "applied": False})
                results[name] = r
                if exact or sc >= max(b0, r.get("best_saved", 0)):
                    cdir = PERM_DIR / "code"
                    cdir.mkdir(parents=True, exist_ok=True)
                    (cdir / f"{name}.c").write_text(best_code, encoding="utf-8")
                    r["best_saved"] = round(sc, 4)
                _atomic_json(RESULTS_FILE, results)

    status["running"] = False
    write_status(status)
    log(f"[perm] fin: {status['done']} procesadas, {status['exact']} exactas, {status['improved']} mejoradas")
    if not args.dry_run and not args.no_apply:
        apply_results()
    return 0


if __name__ == "__main__":
    sys.exit(main())
