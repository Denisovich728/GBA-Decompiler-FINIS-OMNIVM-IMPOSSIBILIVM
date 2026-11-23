"""Permutador avanzado: busqueda local sobre el C candidato (estilo decomp-permuter para ARM ADS 1.2).

Aplica mutaciones semanticamente equivalentes en C89 que alteran la asignacion de registros (r0-r7),
el layout de la pila y el orden de instrucciones en tcc.exe / armcc.exe:
  1. Reordenamiento de declaraciones locales (incluyendo punteros y arreglos).
  2. Mutacion de tipos escalares y calificadores (register / volatile).
  3. Hundimiento de asignacion cero dentro de condicional `if (*p == 0) { x = 0; ... }` (_m_sink_zero).
  4. Fusion/separacion de asignacion dentro de `if ((x = *p) == 0)` (_m_cond_assign).
  5. Separacion de inicializacion en declaracion (`u32 x = v;` -> `u32 x; x = v;`).
  6. Conmutacion de operandos, inversion de comparaciones, casts y tipos de puntero MMIO/ROM.
"""
import random
import re

TYPES = ["u32", "s32", "int", "u16", "s16", "u8", "s8", "unsigned int", "BOOL"]
PTR_TYPES = ["u8 *", "u16 *", "u32 *", "volatile u8 *", "volatile u16 *", "volatile u32 *"]
DECL = re.compile(
    r"^(\s+)(register\s+|volatile\s+)?(u8|u16|u32|s8|s16|s32|int|unsigned int|short|char|BOOL)"
    r"(\s*\*+|\s+)(\w+)(\s*(?:\[[^\]]+\])?\s*(?:=[^;]+)?;\s*)$"
)
STMT_SKIP = re.compile(r"^\s*(return|if|else|while|for|switch|case|default|break|continue|goto|\{|\}|#)")
COMM = re.compile(r"\b(\w+)\s*(\+|\*|&|\||\^|==|!=)\s*(\w+)\b")
CMP = re.compile(r"\b(\w+)\s*(<=|>=|<|>)\s*(\w+)\b")
FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}


def _body_range(lines):
    s = next((i for i, l in enumerate(lines) if "{" in l), 0)
    e = max(i for i, l in enumerate(lines) if "}" in l) if any("}" in l for l in lines) else len(lines)
    return s + 1, e


def _m_type(lines, rng):
    idx = [i for i, l in enumerate(lines) if DECL.match(l) and "*" not in DECL.match(l).group(4) and "[" not in DECL.match(l).group(6)]
    if not idx:
        return False
    i = rng.choice(idx)
    m = DECL.match(lines[i])
    t = rng.choice([x for x in TYPES if x != m.group(3)])
    lines[i] = f"{m.group(1)}{m.group(2) or ''}{t}{m.group(4)}{m.group(5)}{m.group(6)}"
    return True


def _m_register(lines, rng):
    idx = [i for i, l in enumerate(lines) if DECL.match(l) and "[" not in DECL.match(l).group(6) and "&" + DECL.match(l).group(5) not in "\n".join(lines)]
    if not idx:
        return False
    i = rng.choice(idx)
    m = DECL.match(lines[i])
    reg = "" if m.group(2) else "register "
    lines[i] = f"{m.group(1)}{reg}{m.group(3)}{m.group(4)}{m.group(5)}{m.group(6)}"
    return True


def _m_swap_decl(lines, rng):
    idx = [i for i, l in enumerate(lines) if DECL.match(l)]
    if len(idx) < 2:
        return False
    if rng.random() < 0.7:
        pairs = [(a, b) for a, b in zip(idx, idx[1:]) if b == a + 1]
        if not pairs:
            return False
        a, b = rng.choice(pairs)
    else:
        a, b = rng.sample(idx, 2)
    lines[a], lines[b] = lines[b], lines[a]
    return True


def _m_swap_stmt(lines, rng):
    s, e = _body_range(lines)
    ok = [i for i in range(s, e - 1) if lines[i].rstrip().endswith(";") and lines[i + 1].rstrip().endswith(";")
          and not STMT_SKIP.match(lines[i]) and not STMT_SKIP.match(lines[i + 1])
          and not DECL.match(lines[i]) and not DECL.match(lines[i + 1])]
    if not ok:
        return False
    i = rng.choice(ok)
    lines[i], lines[i + 1] = lines[i + 1], lines[i]
    return True


def _m_sink_zero(lines, rng):
    """Transforma `v = *p; if (v == 0) {` en `if (*p == 0) { v = 0;` para retrasar el str a la pila tras el bne."""
    txt = "\n".join(lines)
    pat = re.compile(
        r"([ \t]+)(\w+)\s*=\s*(?:\(\w+\)\s*)?(\*[^\n;]+?)\s*;\s*\n"
        r"([ \t]+)if\s*\(\s*(?:\2\s*==\s*0|0\s*==\s*\2)\s*\)\s*\{"
    )
    m = pat.search(txt)
    if not m:
        return False
    indent1, var, deref, indent2 = m.group(1), m.group(2), m.group(3).strip(), m.group(4)
    # Si hay una variable puntero asignada en la linea previa con la misma constante, usar *ptr
    m_ptr = re.search(r"\b(\w+)\s*=\s*" + re.escape(deref.lstrip("*").strip()) + r"\s*;", txt[:m.start()])
    cond_deref = f"*{m_ptr.group(1)}" if m_ptr else deref
    repl = f"{indent2}if ({cond_deref} == 0) {{\n{indent1}  {var} = 0;"
    new_txt = txt[:m.start()] + repl + txt[m.end():]
    lines[:] = new_txt.splitlines()
    return True


def _m_cond_assign(lines, rng):
    """Transforma `v = expr; if (v == 0)` en `if ((v = expr) == 0)` o viceversa."""
    txt = "\n".join(lines)
    pat = re.compile(
        r"([ \t]+)(\w+)\s*=\s*([^;]+);\s*\n"
        r"([ \t]+)if\s*\(\s*(?:\2\s*==\s*0|0\s*==\s*\2)\s*\)"
    )
    m = pat.search(txt)
    if not m:
        return False
    var, expr, indent2 = m.group(2), m.group(3).strip(), m.group(4)
    repl = f"{indent2}if (({var} = {expr}) == 0)"
    new_txt = txt[:m.start()] + repl + txt[m.end():]
    lines[:] = new_txt.splitlines()
    return True


def _m_split_decl_init(lines, rng):
    """Separa `u32 x = expr;` al inicio del bloque en `u32 x;` + `x = expr;` al empezar las sentencias."""
    idx = [i for i, l in enumerate(lines) if DECL.match(l) and "=" in DECL.match(l).group(6) and "[" not in DECL.match(l).group(6)]
    if not idx:
        return False
    i = rng.choice(idx)
    m = DECL.match(lines[i])
    var = m.group(5)
    init_val = m.group(6).split("=", 1)[1].rstrip().rstrip(";").strip()
    lines[i] = f"{m.group(1)}{m.group(2) or ''}{m.group(3)}{m.group(4)}{var};"
    # Insertar asignacion justo despues de la ultima declaracion
    last_decl = max(j for j, l in enumerate(lines) if DECL.match(l))
    lines.insert(last_decl + 1, f"{m.group(1)}{var} = {init_val};")
    return True


def _m_comm(lines, rng):
    s, e = _body_range(lines)
    cand = [(i, m) for i in range(s, e) for m in COMM.finditer(lines[i]) if not DECL.match(lines[i])]
    if not cand:
        return False
    i, m = rng.choice(cand)
    lines[i] = lines[i][:m.start()] + f"{m.group(3)} {m.group(2)} {m.group(1)}" + lines[i][m.end():]
    return True


def _m_cmp(lines, rng):
    s, e = _body_range(lines)
    cand = [(i, m) for i in range(s, e) for m in CMP.finditer(lines[i])]
    if not cand:
        return False
    i, m = rng.choice(cand)
    lines[i] = lines[i][:m.start()] + f"{m.group(3)} {FLIP[m.group(2)]} {m.group(1)}" + lines[i][m.end():]
    return True


def _m_inc(lines, rng):
    for i, l in enumerate(lines):
        m = re.search(r"\b(\w+)\s*(\+\+|--|\+= 1|-= 1|= \1 \+ 1|= \1 - 1)\s*;", l)
        if m:
            v, plus = m.group(1), ("+" in m.group(2))
            forms = [f"{v}{'++' if plus else '--'};", f"{v} {'+=' if plus else '-='} 1;",
                     f"{v} = {v} {'+' if plus else '-'} 1;"]
            lines[i] = l[:m.start()] + rng.choice(forms) + l[m.end():]
            return True
    return False


def _m_ret_type(lines, rng):
    """Muta el tipo de retorno de la firma de la funcion entre u16, u32, u8, s16, s32, s8."""
    for i, l in enumerate(lines[:5]):
        m = re.match(r"^(\s*)(u32|u16|u8|s32|s16|s8|int|BOOL)(\s+func_[0-9A-F]{8}\s*\(.*)$", l)
        if m:
            cur_t = m.group(2)
            cand_t = rng.choice([x for x in ("u16", "u32", "u8", "s16", "s32", "s8") if x != cur_t])
            lines[i] = f"{m.group(1)}{cand_t}{m.group(3)}"
            return True
    return False


def _m_cast(lines, rng):
    s, e = _body_range(lines)
    cand = [i for i in range(s, e) if "=" in lines[i] and not DECL.match(lines[i])]
    if not cand:
        return False
    i = rng.choice(cand)
    cast_t = rng.choice(["(u32)", "(u16)", "(u8)", "(s16)", ""])
    if "(u" in lines[i] or "(s" in lines[i]:
        lines[i] = re.sub(r"=\s*\([us](?:8|16|32)\)\s*", f"= {cast_t}", lines[i], count=1)
    elif cast_t:
        lines[i] = re.sub(r"=\s*", f"= {cast_t}", lines[i], count=1)
    else:
        return False
    return True


MUTS = [
    _m_swap_decl, _m_swap_decl,
    _m_type, _m_type,
    _m_ret_type,
    _m_register,
    _m_sink_zero,
    _m_cond_assign,
    _m_split_decl_init,
    _m_swap_stmt,
    _m_comm,
    _m_cmp,
    _m_inc,
    _m_cast,
]


def mutate(code, rng):
    lines = code.splitlines()
    done = 0
    for _ in range(rng.choice([1, 1, 2, 3])):
        if rng.choice(MUTS)(lines, rng):
            done += 1
    return ("\n".join(lines) + "\n") if done else None
