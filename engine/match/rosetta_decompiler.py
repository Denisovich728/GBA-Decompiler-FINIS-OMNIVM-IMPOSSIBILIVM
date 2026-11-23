"""FOMT-MATCH-ENGINE :: ROSETTA ZERO-TOKEN SEMANTIC & MATHEMATICAL DECOMPILER.

Motor de decompilacion 100% determinista, algebraico y semantico (CERO TOKENS / CERO LLM):
1. Indexador de Piedra Rosetta (838+ funciones 100% Byte-Perfect):
   Extrae esqueletos estructurales Thumb normalizados (independientes de literales y destinos BL)
   y transfiere plantillas C89 exactas por isomorfismo estructural a funciones pendientes.
2. Levantador Simbolico Directo Thumb -> C89:
   Sintetiza C89 compilable directamente desde el flujo de instrucciones Thumb para las funciones
   sin referencia de Ghidra (origin=ROM_SWEEP).
3. Barrido Universal de No-Rastreadas y Huerfanas:
   Evalua las 547 funciones no rastreadas (4B..4096B) y las 247 huerfanas con normalizacion C89
   avanzada (subpiezas ._offset_size_, simbolos globales g_08XXXXXX, punteros a codigo, etc.).
4. Solucionador Algebraico por Contraste ASM (Leyes de agbcc -O2):
   Aplica las leyes matematicas de generacion de codigo de GCC 2.95 / agbcc -O2:
   - Promocion de tablas en ROM a simbolos globales `g_08XXXXXX[idx]` (invierte orden lsls vs ldr [pc]).
   - Reenvio de retorno de constructores `func_YYYY(func_080005D4(sz), ...)` y reordenamiento de stack.
   - Reconstruccion de structs C89 con bitfields reales (`u32 f0:16; u32 f1:7; u32 f2:1; u32 f3:8;`).
   - Asociatividad de aritmetica de punteros y offsets escalados (`param_1 += C`, `v = A + C; v += B * K`, `(u8 *)param_1 + ((int)param_2 * K + C)`).
   - Extraccion multi-sitio de sub-objetos (`sub = (u32 *)(param_1 + off); func(sub, sub[1]);`).
   - Mutacion individual por sitio de ancho de acceso (`*(u8 *)` <-> `*(u16 *)` <-> `*(u32 *)`) y encadenamiento `zero = 0` / `one = 1`.
   - Restauracion de guardas de bucle `if (i < n)` y normalizacion booleana `((u32)(-x | x)) >> 0x1f`.
"""
import argparse
import json
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
CTL_DIR = TREE_DIR / "control"
STATUS_FILE = CTL_DIR / "status.json"
ENGINE_LOG = CTL_DIR / "engine.log"
STOP_FLAG = CTL_DIR / "stop.flag"

MD_THUMB = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
AGBCC_PRESET_LIST = ["agbcc_O2", "old_agbcc_O2", "agbcc_O1", "agbcc_O0"]

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(msg=""):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        with open(ENGINE_LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass


def write_hud_status(func_name: str, best_sc: float, last_sc: float, evals: int = 0, how: str = "", phase_label: str = "ROSETTA // CERO TOKENS"):
    try:
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        st = {
            "phase": phase_label,
            "func": func_name,
            "best_score": round(best_sc, 4),
            "last_score": round(last_sc, 4),
            "evals": evals,
            "how": how,
            "paused": False,
            "ts": time.time(),
        }
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------
# 1. EXTRACTOR DE ESQUELETOS THUMB E INDEXADOR ROSETTA (838+ FUNCIONES VERIFICADAS)
# ---------------------------------------------------------------------------------------------

def extract_thumb_features(rom: bytes, e: dict):
    """Extrae el flujo de instrucciones Thumb normalizado, la lista ordenada de literales de pool y llamadas BL."""
    if e.get("mode") != "THUMB":
        return None
    addr = e["addr"]
    size = e["size"]
    bts = common.rom_bytes(rom, addr, size)
    ins_list = list(MD_THUMB.disasm(bts, addr))
    if not ins_list:
        return None

    norm_ops = []
    literals = []
    lit_addr_to_idx = {}
    calls = []
    max_branch = addr

    for i in ins_list:
        m, op = i.mnemonic, i.op_str
        if m.startswith("b") and m not in ("bl", "bx") and op.startswith("#0x"):
            try:
                tgt = int(op[1:], 16)
                if addr < tgt < addr + size:
                    max_branch = max(max_branch, tgt)
                rel_off = tgt - i.address
                norm_ops.append(f"{m} REL_{rel_off}")
            except ValueError:
                norm_ops.append(f"{m} {op}")
        elif m == "ldr" and "[pc" in op:
            reg = op.split(",")[0].strip()
            base = (i.address + 4) & ~3
            m_imm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", op)
            disp = int(m_imm.group(1), 0) if m_imm else 0
            pool_addr = base + disp
            if pool_addr not in lit_addr_to_idx:
                off = pool_addr - common.ROM_BASE
                val = int.from_bytes(rom[off:off + 4], "little") if 0 <= off <= len(rom) - 4 else 0
                lit_addr_to_idx[pool_addr] = len(literals)
                literals.append(val)
            l_idx = lit_addr_to_idx[pool_addr]
            norm_ops.append(f"ldr {reg}, [LIT_{l_idx}]")
        elif m == "bl" and op.startswith("#0x"):
            tgt = int(op[1:], 16)
            c_idx = len(calls)
            calls.append(f"func_{tgt:08X}")
            norm_ops.append(f"bl CALL_{c_idx}")
        else:
            norm_ops.append(f"{m} {op}")

        is_ret = (m == "bx" and op in ("r0", "r1", "r2", "r3", "lr")) or (m == "pop" and "pc" in op)
        if is_ret and (i.address + i.size) > max_branch:
            break

    return {
        "skeleton": tuple(norm_ops),
        "literals": literals,
        "calls": calls,
    }


class RosettaCorpus:
    """Indice en memoria de las 838+ funciones 100% byte-perfect para transferencia isomorfica sin tokens."""

    def __init__(self, rom: bytes, manifest: list, state: dict):
        self.by_skeleton = {}
        self.count = 0
        by_name = {e["name"]: e for e in manifest}
        for name, st in state.items():
            if not isinstance(st, dict) or st.get("status") != "matched" or st.get("origin") == "stan_cpp" or name not in by_name:
                continue
            e = by_name[name]
            c_path = TREE_DIR / e["file"]
            if not c_path.exists():
                continue
            raw_c = c_path.read_text(encoding="utf-8", errors="replace")
            if "REFERENCIA Ghidra" in raw_c and "typedef" not in raw_c:
                col_p = TREE_DIR / "collection" / "matched" / f"{name}.c"
                if col_p.exists():
                    raw_c = col_p.read_text(encoding="utf-8", errors="replace")
            c_clean = lift.extract_c(raw_c, rom=rom, e=e)
            if not c_clean or name not in c_clean:
                continue
            feat = extract_thumb_features(rom, e)
            if not feat or not feat["skeleton"]:
                continue
            self.by_skeleton.setdefault(feat["skeleton"], []).append({
                "name": name,
                "code": c_clean,
                "literals": feat["literals"],
                "calls": feat["calls"],
                "preset": st.get("preset", "agbcc_O2"),
            })
            self.count += 1

    def add_matched(self, rom: bytes, e: dict, c_code: str, preset: str = "agbcc_O2"):
        """Incorpora en vivo una nueva funcion 100% emparejada al corpus Rosetta para retroalimentacion inmediata."""
        c_clean = lift.extract_c(c_code, rom=rom, e=e)
        if not c_clean or e["name"] not in c_clean:
            return
        feat = extract_thumb_features(rom, e)
        if not feat or not feat["skeleton"]:
            return
        self.by_skeleton.setdefault(feat["skeleton"], []).append({
            "name": e["name"],
            "code": c_clean,
            "literals": feat["literals"],
            "calls": feat["calls"],
            "preset": preset,
        })
        self.count += 1

    def instantiate_candidates(self, rom: bytes, e: dict) -> list[str]:
        """Si una funcion pendiente comparte esqueleto Thumb con una Piedra Rosetta, instancia su plantilla C89."""
        feat = extract_thumb_features(rom, e)
        if not feat:
            return []
        templates = self.by_skeleton.get(feat["skeleton"], [])
        if not templates:
            return []

        out = []
        for tpl in templates[:4]:
            cand = tpl["code"]
            # 1. Reemplazar nombre de la funcion
            cand = re.sub(rf"\b{re.escape(tpl['name'])}\b", e["name"], cand)
            # 2. Reemplazar llamadas BL posicionalmente usando placeholders para evitar colisiones
            if len(tpl["calls"]) == len(feat["calls"]):
                for idx, old_fn in enumerate(tpl["calls"]):
                    cand = re.sub(rf"\b{re.escape(old_fn)}\b", f"__ROSETTA_CALL_{idx}__", cand, count=1)
                for idx, new_fn in enumerate(feat["calls"]):
                    cand = cand.replace(f"__ROSETTA_CALL_{idx}__", new_fn)
            # 3. Reemplazar literales de pool posicionalmente (tanto en hex como en decimal o simbolo g_)
            if len(tpl["literals"]) == len(feat["literals"]):
                for idx, (old_val, new_val) in enumerate(zip(tpl["literals"], feat["literals"])):
                    if old_val == new_val:
                        continue
                    old_hex_u = f"0x{old_val:08X}"
                    old_hex_l = f"0x{old_val:08x}"
                    old_hex_short_u = f"0x{old_val:X}"
                    old_hex_short_l = f"0x{old_val:x}"
                    old_g = f"g_{old_val:08X}"
                    cand = cand.replace(old_g, f"__ROSETTA_G_{idx}__")
                    for pat in (old_hex_u, old_hex_l, old_hex_short_u, old_hex_short_l):
                        cand = re.sub(rf"\b{re.escape(pat)}\b", f"__ROSETTA_LIT_{idx}__", cand)
                for idx, new_val in enumerate(feat["literals"]):
                    cand = cand.replace(f"__ROSETTA_G_{idx}__", f"g_{new_val:08X}")
                    cand = cand.replace(f"__ROSETTA_LIT_{idx}__", f"0x{new_val:08X}")
            out.append(cand)
        return list(dict.fromkeys(out))


# ---------------------------------------------------------------------------------------------
# 2. LEVANTADOR SIMBOLICO DIRECTO THUMB -> C89 (PARA FUNCIONES SIN REFERENCIA GHIDRA)
# ---------------------------------------------------------------------------------------------

def lift_thumb_directly(rom: bytes, e: dict) -> list[str]:
    """Levanta funciones Thumb simples/medianas sin referencia de Ghidra directamente desde los opcodes."""
    if e.get("mode") != "THUMB":
        return []
    addr, size = e["addr"], e["size"]
    bts = common.rom_bytes(rom, addr, size)
    ins_list = list(MD_THUMB.disasm(bts, addr))
    if not ins_list:
        return []

    ret_type = lift._infer_thumb_epilogue(rom, e) or "void"
    name = e["name"]
    cands = []

    # Caso 1: Funcion hoja vacia `bx lr` (2 o 4 bytes)
    if ins_list[0].mnemonic == "bx" and ins_list[0].op_str == "lr":
        cands.append(f"void {name}(void) {{\n}}\n")
        return cands

    # Caso 2: Funcion hoja constante `movs r0, #imm; bx lr`
    if len(ins_list) >= 2 and ins_list[0].mnemonic == "movs" and ins_list[0].op_str.startswith("r0, #") and ins_list[1].mnemonic == "bx":
        imm = ins_list[0].op_str.split("#")[1]
        cands.append(f"u32 {name}(void) {{\n  return {imm};\n}}\n")
        cands.append(f"int {name}(void) {{\n  return {imm};\n}}\n")
        return cands

    # Caso 3: Simulador simbolico de bloque basico lineal (loads, stores, aritmetica y llamadas BL)
    regs = {f"r{i}": f"param_{i+1}" for i in range(4)}
    for i in range(4, 12):
        regs[f"r{i}"] = "0"
    stmts = []
    used_params = set()
    max_branch = addr
    call_str = None

    def mark_param(expr: str):
        for p_idx in range(1, 5):
            if f"param_{p_idx}" in expr:
                used_params.add(p_idx)

    for ins in ins_list:
        m, op = ins.mnemonic, ins.op_str
        parts = [p.strip() for p in op.split(",")]
        if m == "push":
            continue
        if m in ("sub", "add") and parts[0] == "sp":
            continue
        if m == "pop":
            if "pc" in op:
                break
            continue
        if m == "bx":
            break
        if m.startswith("b") and m != "bl":
            # Si hay saltos condicionales complejos, salir del simulador lineal y pasar a CFG con goto
            break
        if m == "ldr" and "[pc" in op:
            dst = parts[0]
            base = (ins.address + 4) & ~3
            m_imm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", op)
            disp = int(m_imm.group(1), 0) if m_imm else 0
            off = (base + disp) - common.ROM_BASE
            val = int.from_bytes(rom[off:off + 4], "little") if 0 <= off <= len(rom) - 4 else 0
            regs[dst] = f"0x{val:08X}"
        elif m == "movs" and len(parts) == 2:
            dst, src = parts[0], parts[1].lstrip("#")
            regs[dst] = regs.get(src, src)
        elif m in ("adds", "add") and len(parts) == 3:
            dst, s1, s2 = parts[0], parts[1], parts[2].lstrip("#")
            v1 = regs.get(s1, s1)
            v2 = regs.get(s2, s2)
            regs[dst] = v1 if v2 in ("0", "0x0") else f"({v1} + {v2})"
        elif m in ("adds", "add") and len(parts) == 2:
            dst, imm = parts[0], parts[1].lstrip("#")
            regs[dst] = f"({regs.get(dst, dst)} + {imm})"
        elif m in ("subs", "sub") and len(parts) == 2:
            dst, imm = parts[0], parts[1].lstrip("#")
            regs[dst] = f"({regs.get(dst, dst)} - {imm})"
        elif m in ("lsls", "lsl") and len(parts) == 3:
            dst, s1, sh = parts[0], parts[1], parts[2].lstrip("#")
            regs[dst] = f"({regs.get(s1, s1)} << {sh})"
        elif m in ("lsrs", "lsr") and len(parts) == 3:
            dst, s1, sh = parts[0], parts[1], parts[2].lstrip("#")
            regs[dst] = f"((u32){regs.get(s1, s1)} >> {sh})"
        elif m in ("ldr", "ldrh", "ldrb"):
            dst = parts[0]
            tp = "u32" if m == "ldr" else ("u16" if m == "ldrh" else "u8")
            m_mem = re.search(r"\[(r\d+)(?:,\s*#?(r\d+|0x[0-9a-fA-F]+|\d+))?\]", op)
            if m_mem:
                b_reg = regs.get(m_mem.group(1), m_mem.group(1))
                off_part = m_mem.group(2)
                if off_part:
                    off_v = regs.get(off_part, off_part)
                    addr_expr = f"{b_reg} + {off_v}"
                else:
                    addr_expr = b_reg
                mark_param(addr_expr)
                regs[dst] = f"*({tp} *)({addr_expr})"
        elif m in ("str", "strh", "strb"):
            src = parts[0]
            tp = "u32" if m == "str" else ("u16" if m == "strh" else "u8")
            m_mem = re.search(r"\[(r\d+)(?:,\s*#?(r\d+|0x[0-9a-fA-F]+|\d+))?\]", op)
            if m_mem:
                b_reg = regs.get(m_mem.group(1), m_mem.group(1))
                off_part = m_mem.group(2)
                addr_expr = f"{b_reg} + {regs.get(off_part, off_part)}" if off_part else b_reg
                val_expr = regs.get(src, src)
                mark_param(addr_expr)
                mark_param(val_expr)
                stmts.append(f"  *({tp} *)({addr_expr}) = {val_expr};")
        elif m == "bl" and op.startswith("#0x"):
            tgt = int(op[1:], 16)
            fn_call = f"func_{tgt:08X}"
            call_args = []
            for r_i in range(4):
                rv = regs.get(f"r{r_i}", f"param_{r_i+1}")
                if rv != f"param_{r_i+1}":
                    mark_param(rv)
                    call_args.append(rv)
                else:
                    break
            call_str = f"{fn_call}({', '.join(call_args)})"
            if ret_type != "void":
                stmts.append(f"  val = {call_str};")
                regs["r0"] = "val"
            else:
                stmts.append(f"  {call_str};")
                regs["r0"] = call_str

    max_p = max(used_params) if used_params else 0
    param_sig = ", ".join(f"int param_{i}" for i in range(1, max_p + 1)) or "void"
    if ret_type != "void":
        if regs.get("r0") == "val":
            stmts.append("  return val;")
        elif call_str is not None and regs.get("r0") != call_str and regs.get("r0") != "param_1" and regs.get("r0") != "0":
            stmts.append(f"  return {regs['r0']};")
        elif stmts and stmts[-1].strip().startswith("func_"):
            last_call = stmts[-1].strip().rstrip(";")
            stmts[-1] = f"  return {last_call};"
        else:
            mark_param(regs["r0"])
            max_p = max(used_params) if used_params else 0
            param_sig = ", ".join(f"int param_{i}" for i in range(1, max_p + 1)) or "void"
            stmts.append(f"  return {regs['r0']};")

    if stmts:
        val_decl = "  u32 val;\n" if any("val = " in s for s in stmts) else ""
        base_body = val_decl + "\n".join(stmts)
        cands.append(f"{ret_type} {name}({param_sig}) {{\n{base_body}\n}}\n")
        # Inferencia de tipos naturales en parametros (u16, u8, u32) ante truncation idiomática
        for p_i in range(1, max_p + 1):
            p_var = f"param_{p_i}"
            if f"((u32)({p_var} << 0x10) >> 0x10)" in base_body or f"(({p_var} << 0x10) >> 0x10)" in base_body:
                sub_body = base_body.replace(f"((u32)({p_var} << 0x10) >> 0x10)", p_var).replace(f"(({p_var} << 0x10) >> 0x10)", p_var)
                sub_sig = param_sig.replace(f"int {p_var}", f"u16 {p_var}")
                cands.append(f"{ret_type} {name}({sub_sig}) {{\n{sub_body}\n}}\n")
            if f"*(u8 *)({p_var})" in base_body or f"*(u8 *)({p_var} +" in base_body:
                ptr_sig = param_sig.replace(f"int {p_var}", f"u8 *{p_var}")
                cands.append(f"{ret_type} {name}({ptr_sig}) {{\n{base_body}\n}}\n")

    # Caso 4: Levantador universal Thumb por bloques basicos con goto (rescata funciones huerfanas)
    try:
        cfg_cand = lift_thumb_cfg_goto(rom, e, ins_list)
        if cfg_cand:
            cands.append(cfg_cand)
    except Exception:
        pass

    return cands


def lift_thumb_cfg_goto(rom: bytes, e: dict, ins_list: list) -> str:
    """Levanta cualquier funcion Thumb a un grafo de flujo de control (CFG) con etiquetas y goto C89."""
    addr = e["addr"]
    size = e["size"]
    name = e["name"]
    ret_type = lift._infer_thumb_epilogue(rom, e) or "u32"

    branch_targets = set()
    for ins in ins_list:
        m, op = ins.mnemonic, ins.op_str
        if m.startswith("b") and m != "bl" and op.startswith("#0x"):
            try:
                tgt = int(op[1:], 16)
                if addr <= tgt < addr + size:
                    branch_targets.add(tgt)
            except ValueError:
                pass

    cond_map = {
        "beq": "==", "bne": "!=",
        "bcs": ">=", "bhs": ">=",
        "bcc": "<",  "blo": "<",
        "bge": ">=", "blt": "<",
        "bgt": ">",  "ble": "<=",
        "bhi": ">",  "bls": "<=",
    }

    max_branch = max(branch_targets) if branch_targets else addr
    body_lines = []
    last_cmp = ("r0", "0")

    for ins in ins_list:
        if ins.address in branch_targets:
            body_lines.append(f"loc_{ins.address:08X}:")
        m, op = ins.mnemonic, ins.op_str
        parts = [p.strip() for p in op.split(",")]

        if m in ("push", "pop"):
            if m == "pop" and "pc" in op:
                body_lines.append("    return r0;")
                if ins.address >= max_branch:
                    break
            continue
        if m in ("add", "sub") and parts[0] == "sp":
            continue
        if m == "bx":
            if "lr" in op or op == "r0":
                body_lines.append("    return r0;")
            else:
                body_lines.append(f"    return {op};")
            if ins.address >= max_branch:
                break
            continue

        if m == "ldr" and "[pc" in op:
            dst = parts[0]
            base = (ins.address + 4) & ~3
            m_imm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", op)
            disp = int(m_imm.group(1), 0) if m_imm else 0
            pool_addr = base + disp
            off = pool_addr - common.ROM_BASE
            val = int.from_bytes(rom[off:off + 4], "little") if 0 <= off <= len(rom) - 4 else 0
            body_lines.append(f"    {dst} = 0x{val:08X};")
        elif m == "movs" and len(parts) == 2:
            body_lines.append(f"    {parts[0]} = {parts[1].lstrip('#')};")
        elif m in ("adds", "add") and len(parts) == 3:
            body_lines.append(f"    {parts[0]} = {parts[1]} + {parts[2].lstrip('#')};")
        elif m in ("adds", "add") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} += {parts[1].lstrip('#')};")
        elif m in ("subs", "sub") and len(parts) == 3:
            body_lines.append(f"    {parts[0]} = {parts[1]} - {parts[2].lstrip('#')};")
        elif m in ("subs", "sub") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} -= {parts[1].lstrip('#')};")
        elif m in ("lsls", "lsl") and len(parts) == 3:
            body_lines.append(f"    {parts[0]} = {parts[1]} << {parts[2].lstrip('#')};")
        elif m in ("lsrs", "lsr") and len(parts) == 3:
            body_lines.append(f"    {parts[0]} = (u32){parts[1]} >> {parts[2].lstrip('#')};")
        elif m in ("asrs", "asr") and len(parts) == 3:
            body_lines.append(f"    {parts[0]} = (int){parts[1]} >> {parts[2].lstrip('#')};")
        elif m in ("ands", "and") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} &= {parts[1]};")
        elif m in ("orrs", "orr") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} |= {parts[1]};")
        elif m in ("eors", "eor") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} ^= {parts[1]};")
        elif m in ("bics", "bic") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} &= ~{parts[1]};")
        elif m in ("mvns", "mvn") and len(parts) == 2:
            body_lines.append(f"    {parts[0]} = ~{parts[1]};")
        elif m in ("ldr", "ldrh", "ldrb"):
            dst = parts[0]
            tp = "u32" if m == "ldr" else ("u16" if m == "ldrh" else "u8")
            m_mem = re.search(r"\[(r\d+)(?:,\s*#?(r\d+|0x[0-9a-fA-F]+|\d+))?\]", op)
            if m_mem:
                b_reg = m_mem.group(1)
                off_part = m_mem.group(2)
                addr_expr = f"{b_reg} + {off_part.lstrip('#')}" if off_part else b_reg
                body_lines.append(f"    {dst} = *({tp} *)({addr_expr});")
        elif m in ("str", "strh", "strb"):
            src = parts[0]
            tp = "u32" if m == "str" else ("u16" if m == "strh" else "u8")
            m_mem = re.search(r"\[(r\d+)(?:,\s*#?(r\d+|0x[0-9a-fA-F]+|\d+))?\]", op)
            if m_mem:
                b_reg = m_mem.group(1)
                off_part = m_mem.group(2)
                addr_expr = f"{b_reg} + {off_part.lstrip('#')}" if off_part else b_reg
                body_lines.append(f"    *({tp} *)({addr_expr}) = {src};")
        elif m == "cmp" and len(parts) == 2:
            last_cmp = (parts[0], parts[1].lstrip("#"))
        elif m in cond_map and op.startswith("#0x"):
            tgt = int(op[1:], 16)
            c_op = cond_map[m]
            body_lines.append(f"    if ({last_cmp[0]} {c_op} {last_cmp[1]}) goto loc_{tgt:08X};")
        elif m == "b" and op.startswith("#0x"):
            tgt = int(op[1:], 16)
            body_lines.append(f"    goto loc_{tgt:08X};")
        elif m == "bl" and op.startswith("#0x"):
            tgt = int(op[1:], 16)
            body_lines.append(f"    r0 = func_{tgt:08X}(r0, r1, r2, r3);")

    if not body_lines:
        return ""
    if not body_lines[-1].strip().startswith("return"):
        body_lines.append("    return r0;")

    used_high_regs = [r for r in ("r4", "r5", "r6", "r7") if any(re.search(rf"\b{r}\b", bl) for bl in body_lines)]
    high_decl = [f"    register u32 {', '.join(used_high_regs)};"] if used_high_regs else []
    hdr = [
        f"{ret_type} {name}(u32 param_1, u32 param_2, u32 param_3, u32 param_4)",
        "{",
        "    register u32 r0 = param_1;",
        "    register u32 r1 = param_2;",
        "    register u32 r2 = param_3;",
        "    register u32 r3 = param_4;",
    ] + high_decl
    return "\n".join(hdr + body_lines + ["}", ""])


def mask_laws(code: str) -> list[str]:
    """Sintetiza patrones de extraccion de campos de bits Thumb ARM7TDMI (lsls / lsrs / asrs) a partir de mascaras Ghidra."""
    outs = []
    # 1. Mascara directa: (expr & mask) -> (((u32)(expr) << sh) >> sh)
    pat = r"\(\s*([A-Za-z_]\w*(?:\[\w+\])?|\*\([^;()]*\)\([^;()]*\))\s*&\s*(0x[0-9a-fA-F]+|\d+)U?\s*\)"
    for m in re.finditer(pat, code):
        v = int(m.group(2), 0)
        k = v.bit_length()
        if v and v == (1 << k) - 1 and k < 32:
            sh = 32 - k
            outs.append(code[:m.start()] + f"(((u32)({m.group(1)}) << {sh}) >> {sh})" + code[m.end():])
            outs.append(code[:m.start()] + f"(((s32)({m.group(1)}) << {sh}) >> {sh})" + code[m.end():])
    # 2. Campo desplazado: ((x >> n) & mask) -> ((((u32)x) << (32-n-k)) >> (32-k))
    for m in re.finditer(r"\(\(\s*(\w+)\s*>>\s*(\d+)\s*\)\s*&\s*(0x[0-9a-fA-F]+|\d+)\s*\)", code):
        n = int(m.group(2))
        v = int(m.group(3), 0)
        k = v.bit_length()
        if v == (1 << k) - 1 and n + k <= 32:
            outs.append(code[:m.start()] + f"((((u32){m.group(1)}) << {32-n-k}) >> {32-k})" + code[m.end():])
            outs.append(code[:m.start()] + f"((((s32){m.group(1)}) << {32-n-k}) >> {32-k})" + code[m.end():])
    return outs


# ---------------------------------------------------------------------------------------------
# 3. LEYES ALGEBRAICAS Y CONTRASTE ASM DETERMINISTA (AGBCC -O2)
# ---------------------------------------------------------------------------------------------

def generate_rosetta_algebraic_mutations(code: str, func_name: str, rom: bytes = None, e: dict = None) -> list[str]:
    """Genera el conjunto completo de transformaciones algebraicas C89 verificadas para agbcc -O2."""
    mutations = []

    def add_mut(c: str):
        if c and c != code and func_name in c:
            mutations.append(c)

    def inject_local(c: str, decl_line: str) -> str:
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
        # Insertar al FINAL del bloque de declaraciones locales para no alterar el orden de registros r4..r7 existentes
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

    # LEY 1: Promocion de accesos a tablas en ROM `*(u32 *)(idx * K + 0x08XXXXXX)` a simbolos globales `g_08XXXXXX`
    # Invierte el orden de emision `lsls` vs `ldr [pc]` en agbcc -O2. Soporta indices simples y expresiones compuestas.
    for m_tbl4 in re.finditer(r"\*\(\s*(u32|int|s32|u16|s16)\s*\*\s*\)\s*\(\s*([^;\n]+?)\s*\*\s*4\s*\+\s*0x(08[0-9a-fA-F]{6})\s*\)", code):
        tp, idx_v, hex_addr = m_tbl4.groups()
        g_sym = f"g_{hex_addr.upper()}"
        decl = f"extern const {tp} {g_sym}[];\n"
        m_c = decl + code[:m_tbl4.start()] + f"{g_sym}[{idx_v.strip()}]" + code[m_tbl4.end():]
        add_mut(m_c)

    for m_tbl8 in re.finditer(r"\*\(\s*(u32|int|s32)\s*\*\s*\)\s*\(\s*([^;\n]+?)\s*\*\s*8\s*\+\s*0x(08[0-9a-fA-F]{6})\s*\)", code):
        tp, idx_v, hex_addr = m_tbl8.groups()
        g_sym = f"g_{hex_addr.upper()}"
        s_name = f"s_{hex_addr.upper()}"
        decl = f"struct {s_name} {{ {tp} a; {tp} b; }};\nextern const struct {s_name} {g_sym}[];\n"
        m_c = decl + code[:m_tbl8.start()] + f"{g_sym}[{idx_v.strip()}].a" + code[m_tbl8.end():]
        add_mut(m_c)
        # Variante con llamada inline inmediata si la siguiente linea usa el resultado en otra llamada
        m_inline = re.search(r"(\w+)\s*=\s*(func_[0-9A-F]{8}\([^;]+\));\s*\n\s*(func_[0-9A-F]{8})\(([^,]+),\s*\1\);", m_c)
        if m_inline:
            v_tmp, call1, call2, arg1 = m_inline.groups()
            m_c2 = m_c.replace(m_inline.group(0), f"{call2}({arg1}, {call1});")
            m_c2 = re.sub(rf"^\s*\w+\s+{re.escape(v_tmp)}\s*;\s*\n", "", m_c2, flags=re.M)
            add_mut(m_c2)

    # LEY 2: Reenvio de retorno de constructor `func_YYYY(func_080005D4(sz), ...)` + reordenamiento de puntero en stack
    # Caso A: uVar1 = func_080005D4(sz); param_1[1] = uVar1; uVar1 = func_YYYY(uVar1, ...);
    m_ctor_a = re.search(
        r"(\w+)\s*=\s*(func_080005D4\([^)]+\));\s*\n\s*(\w+\[1\])\s*=\s*\1;\s*\n\s*\1\s*=\s*(func_[0-9A-F]{8})\(\s*\1\s*(,\s*[^;]+)?\);",
        code,
    )
    if m_ctor_a:
        v1, alloc_call, dst_slot, ctor_fn, rest_args = m_ctor_a.groups()
        rest_args = rest_args or ""
        repl = f"{dst_slot} = {ctor_fn}({alloc_call}{rest_args});"
        m_c = code.replace(m_ctor_a.group(0), repl)
        m_c = re.sub(rf"val\s*=\s*\*(\w+);\s*\*\1\s*=\s*0;\s*{re.escape(v1)}\s*=\s*val;\s*\n\s*(\w+\[2\])\s*=\s*{re.escape(v1)};", r"val = *\1;\n  *\1 = 0;\n  \2 = val;", m_c)
        m_c = re.sub(rf"^\s*\w+\s+{re.escape(v1)}\s*;\s*\n", "", m_c, flags=re.M)
        add_mut(m_c)

    # Caso B: uVar1 = func_080005D4(sz); uVar1 = func_YYYY(uVar1, ...); param_1[1] = uVar1; uVar1 = *param_2; param_1[2] = uVar1; *param_2 = 0;
    m_ctor_b = re.search(
        r"(\w+)\s*=\s*(func_080005D4\([^)]+\));\s*\n\s*\1\s*=\s*(func_[0-9A-F]{8})\(\s*\1\s*(,\s*[^;]+)?\);\s*\n\s*(\w+\[1\])\s*=\s*\1;\s*\n\s*\1\s*=\s*\*(\w+);\s*\n\s*(\w+\[2\])\s*=\s*\1;\s*\n\s*\*\6\s*=\s*0;",
        code,
    )
    if m_ctor_b:
        v1, alloc_call, ctor_fn, rest_args, slot1, p2, slot2 = m_ctor_b.groups()
        rest_args = rest_args or ""
        repl = f"{slot1} = {ctor_fn}({alloc_call}{rest_args});\n  val = *{p2};\n  *{p2} = 0;\n  {slot2} = val;"
        m_c = inject_local(code.replace(m_ctor_b.group(0), repl), "u32 val;")
        m_c = re.sub(rf"^\s*\w+\s+{re.escape(v1)}\s*;\s*\n", "", m_c, flags=re.M)
        add_mut(m_c)

    # Caso D (Universal): Cualquier permutacion post-constructor de `*param_2 = 0`, `uVar1 = *param_2`, `param_1[2] = uVar1`
    m_ctor_u = re.search(
        r"(\w+)\s*=\s*(?:\([^)]+\))?\s*(func_080005D4\([^)]+\));\s*\n"
        r"\s*\1\s*=\s*(?:\([^)]+\))?\s*(func_[0-9A-F]{8})\(\s*(?:\([^)]+\))?\s*\1\s*(,\s*[^;]+)?\);\s*\n"
        r"((?:\s*[^\n]+;\s*\n){3,4})",
        code,
    )
    if m_ctor_u:
        v1, alloc_call, ctor_fn, rest_args, tail_block = m_ctor_u.groups()
        rest_args = rest_args or ""
        m_p2 = re.search(r"\*(\w+)\s*=\s*0;", tail_block)
        m_s1 = re.search(r"(\w+\[1\])\s*=", tail_block)
        m_s2 = re.search(r"(\w+\[2\])\s*=", tail_block)
        if m_p2 and m_s1 and m_s2:
            p2 = m_p2.group(1)
            slot1 = m_s1.group(1)
            slot2 = m_s2.group(1)
            repl = f"{slot1} = {ctor_fn}({alloc_call}{rest_args});\n  val = *{p2};\n  *{p2} = 0;\n  {slot2} = val;\n"
            m_c = inject_local(code.replace(m_ctor_u.group(0), repl), "u32 val;")
            m_c = re.sub(rf"^\s*(?:register\s+)?\w+\s+{re.escape(v1)}\s*;\s*\n", "", m_c, flags=re.M)
            add_mut(m_c)

    # LEY 3: Reconstruccion de structs C89 con bitfields reales para mascaras compuestas `0xFFFF0000` / `0xFF80FFFF` / `0xFF7FFFFF` / `0x00FFFFFF`
    if "0xFFFF0000" in code and "0xFF80FFFF" in code and "0x00FFFFFF" in code:
        m_bf = re.search(
            r"(\w+)\s*=\s*(?:\([^)]+\))?\s*func_([0-9A-F]{8})\((0x[0-9a-fA-F]+|\d+)\);\s*(\w+)\s*=\s*\(\(\4\s*&\s*0xFFFF0000\s*\|\s*\1\s*\+\s*(0x[0-9a-fA-F]+|\d+)U?\s*&\s*0xffff\)\s*&\s*0xFF80FFFF\s*\|\s*(0x[0-9a-fA-F]+|\d+)\)\s*&\s*0xFF7FFFFF\s*&\s*0x00FFFFFF;",
            code,
            re.S,
        )
        if m_bf:
            v_tmp, fn_hex, fn_arg, v_stack, add_imm, or_imm = m_bf.groups()
            f1_val = int(or_imm, 0) >> 16
            sname = f"bf_{func_name}"
            s_decl = f"struct {sname} {{\n  u32 f0 : 16;\n  u32 f1 : 7;\n  u32 f2 : 1;\n  u32 f3 : 8;\n}};\n"
            bf_repl = (
                f"{v_stack}.f0 = func_{fn_hex}({fn_arg}) + {add_imm};\n"
                f"    {v_stack}.f1 = 0x{f1_val:x};\n"
                f"    {v_stack}.f2 = 0;\n"
                f"    {v_stack}.f3 = 0;"
            )
            m_c = s_decl + code.replace(m_bf.group(0), bf_repl)
            m_c = re.sub(rf"\b(?:u32|BOOL|int)\s+{re.escape(v_stack)}\s*;", f"struct {sname} {v_stack};", m_c)
            m_c = re.sub(rf"^\s*(?:register\s+)?\w+\s+{re.escape(v_tmp)}\s*;\s*\n", "", m_c, flags=re.M)
            # Inlinear llamada siguiente si usa uVar3 temporal
            m_u3 = re.search(r"(\w+)\s*=\s*(?:\(u32\))?(func_[0-9A-F]{8}\([^)]+\));\s*(func_[0-9A-F]{8})\(([^,]+),\s*\1,", m_c)
            if m_u3:
                u3_v, u3_call, next_fn, arg0 = m_u3.groups()
                m_c = m_c.replace(m_u3.group(0), f"{next_fn}({arg0}, {u3_call},")
                m_c = re.sub(rf"^\s*\w+\s+{re.escape(u3_v)}\s*;\s*\n", "", m_c, flags=re.M)
            # Asegurar que el chequeo de retorno de func_0809B8B0 sea (u8)
            m_c = re.sub(r"\b(\w+)\s*=\s*func_0809B8B0\(([^)]+)\);\s*if\s*\(\1\s*==\s*(?:'\\0'|0)\)", r"if ((u8)func_0809B8B0(\2) == 0)", m_c)
            m_c = re.sub(r"^\s*(?:char|s16|u8)\s+cVar1\s*;\s*\n", "", m_c, flags=re.M)
            m_c = m_c.replace("0x34 + param_1", "param_1 + 0x34")
            add_mut(m_c)

    # LEY 4: Asociatividad de punteros y offsets escalados
    # 4A: `iVar1 = param_1 + C + param_3 * K;` -> `int iVar1; iVar1 = param_1 + C; iVar1 += param_3 * K;`
    m_split_add = re.search(r"(\w+)\s*=\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*(\w+\s*\*\s*(?:0x[0-9a-fA-F]+|\d+));", code)
    if m_split_add:
        lhs, base_v, c_imm, scaled = m_split_add.groups()
        m_c = code.replace(m_split_add.group(0), f"{lhs} = {base_v} + {c_imm};\n  {lhs} += {scaled};")
        m_c = re.sub(rf"\b(?:u16|s16|u8)\s+{re.escape(lhs)}\s*;", f"int {lhs};", m_c)
        add_mut(m_c)

    # 4B: `piVar2 = (int *)(param_1 + C + param_2 * K);` -> `param_1 += C; piVar2 = (int *)(param_1 + param_2 * K);`
    m_inplace_add = re.search(r"(\w+)\s*=\s*\((\w+\s*\*)\)\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*(\w+\s*\*\s*(?:0x[0-9a-fA-F]+|\d+))\s*\);", code)
    if m_inplace_add:
        lhs, ptr_t, base_v, c_imm, scaled = m_inplace_add.groups()
        m_c = code.replace(m_inplace_add.group(0), f"{base_v} += {c_imm};\n  {lhs} = ({ptr_t})({base_v} + {scaled});")
        add_mut(m_c)

    # 4C: `func_XXXX(param_1 + param_2 * K + C);` -> `u8 *param_1, int param_2` con `param_1 + (param_2 * K + C)`
    m_ptr_off = re.search(r"(func_[0-9A-F]{8})\(\s*(\w+)\s*\+\s*(\w+\s*\*\s*(?:0x[0-9a-fA-F]+|\d+))\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\);", code)
    if m_ptr_off:
        fn_c, p1, scaled, c_imm = m_ptr_off.groups()
        p2 = scaled.split("*")[0].strip()
        m_c = code.replace(m_ptr_off.group(0), f"{fn_c}({p1} + ({scaled} + {c_imm}));")
        m_c = re.sub(rf"\bint\s+{re.escape(p1)}\b", f"u8 *{p1}", m_c)
        m_c = re.sub(rf"\bu32\s+{re.escape(p2)}\b", f"int {p2}", m_c)
        m_c = re.sub(rf"\b{re.escape(p2)}\s*<\s*(\w+)", rf"(u32){p2} < \1", m_c)
        add_mut(m_c)

    # LEY 5: Extraccion multi-sitio de sub-objetos (`sub = (u32 *)(param_1 + off); func1(sub, sub[1]); func2(sub, ...);`)
    sub_sites = list(re.finditer(
        r"(func_[0-9A-F]{8})\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*\*\(u32\s*\*\)\(\s*\2\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\);\s*\n\s*(func_[0-9A-F]{8})\(\s*\2\s*\+\s*\3\s*,",
        code,
    ))
    if sub_sites:
        m_c = inject_local(code, "u32 *sub;")
        for sm in sub_sites:
            fn1, base_v, off1, off2, fn2 = sm.groups()
            if int(off2, 0) == int(off1, 0) + 4:
                repl = f"sub = (u32 *)({base_v} + {off1});\n  {fn1}(sub, sub[1]);\n  {fn2}(sub,"
                m_c = m_c.replace(sm.group(0), repl)
        # Limpiar llamadas residuales `func_X(param_1 + 0x30, 2)` cuando `sub = (u32 *)(param_1 + 0x30)` ya fue extraido
        m_c = re.sub(r"(sub\s*=\s*\(u32\s*\*\)\((\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\);\s*\n\s*func_[0-9A-F]{8}\(sub,\s*sub\[1\]\);\s*\n\s*func_[0-9A-F]{8}\()\2\s*\+\s*\3\s*,", r"\1sub,", m_c)
        add_mut(m_c)

    # LEY 6: Mutacion individual por sitio de ancho de acceso + encadenamiento `one = 1` y `zero = 0`
    # 6A: Mutar cada `*(u8 *)`, `*(u16 *)`, `*(u32 *)`, `*(int *)` individualmente (no todos a la vez)
    ptr_deref_re = re.compile(r"\*\(\s*(u8|u16|u32|s8|s16|s32|int|char|short)\s*\*\s*\)")
    deref_matches = list(ptr_deref_re.finditer(code))
    if len(deref_matches) <= 35:
        for dm in deref_matches:
            cur_t = dm.group(1)
            for alt_t in ("u8", "u16", "u32"):
                if alt_t != cur_t:
                    m_c = code[:dm.start(1)] + alt_t + code[dm.end(1):]
                    add_mut(m_c)

    # 6B: Par de stores `= 1` al final de bloque donde el primero es u8 y el segundo es u32 compartiendo `one = 1`
    m_one_pair = re.search(
        r"\*\(u8\s*\*\)\(([^;]+)\)\s*=\s*1;\s*\n\s*\*\((?:u8|u32)\s*\*\)\(([^;]+)\)\s*=\s*1;",
        code,
    )
    if m_one_pair:
        a1, a2 = m_one_pair.groups()
        m_c = inject_local(code, "int one;")
        m_c = m_c.replace(m_one_pair.group(0), f"*(u8 *)({a1}) = (one = 1);\n    *(u32 *)({a2}) = one;")
        add_mut(m_c)

    # 6C: Puntero local `p = (u8 *)(param_1 + 0x8C4); zero = 0; *p = 1; iVar1 = 0x8C5; *(u8 *)(param_1 + 0x8C5) = zero;`
    m_8c4 = re.search(
        r"\*\(u8\s*\*\)\((\w+\s*\+\s*0x[0-9a-fA-F]+)\)\s*=\s*1;\s*\n\s*(\w+\s*=\s*0x[0-9a-fA-F]+;)\s*\n\s*\*\((?:u32|u8)\s*\*\)\(([^)]+)\)\s*=\s*0;",
        code,
    )
    if m_8c4:
        addr1, iv_assign, addr2 = m_8c4.groups()
        m_c = inject_local(inject_local(code, "u8 *p;"), "int zero;")
        m_c = m_c.replace(
            m_8c4.group(0),
            f"p = (u8 *)({addr1});\n  zero = 0;\n  *p = 1;\n  {iv_assign}\n  *(u8 *)({addr2}) = zero;",
        )
        add_mut(m_c)

    # 6D: Encadenamiento de `zero = 0` sobre secuencias de stores de cero en estructuras recien alojadas
    m_zero_seq = re.search(r"(\*\(u16\s*\*\)\([^;]+\))\s*=\s*0;\s*\n\s*(\w+\[2\])\s*=\s*0;\s*\n\s*(\*\(u8\s*\*\)\([^;]+\))\s*=\s*0;", code)
    if m_zero_seq:
        s1, s2, s3 = m_zero_seq.groups()
        m_c = inject_local(code, "u32 zero;")
        m_c = m_c.replace(m_zero_seq.group(0), f"{s1} = zero = 0;\n  {s2} = zero;\n  {s3} = zero;")
        add_mut(m_c)

    # LEY 7: Restauracion de guarda de bucle `uVar3 = 0; if (uVar2 != 0)` -> `uVar3 = 0; if (uVar3 < uVar2)`
    m_loop_guard = re.search(r"(\w+)\s*=\s*0;\s*\n\s*if\s*\(\s*(\w+)\s*!=\s*0\s*\)\s*\{", code)
    if m_loop_guard:
        iv, bound_v = m_loop_guard.groups()
        if f"while ({iv} < {bound_v})" in code:
            m_c = code.replace(m_loop_guard.group(0), f"{iv} = 0;\n  if ({iv} < {bound_v}) {{")
            add_mut(m_c)

    # LEY 8: Normalizacion booleana `(-X | X >> 0x1f)` -> `(((u32)(-X | X)) >> 0x1f)` y `(X != 0)`
    if ">> 0x1f" in code or ">> 31" in code:
        m_c1 = re.sub(r"\(\s*-(\w+)\s*\|\s*\1\s*>>\s*(?:0x1f|31)\s*\)", r"(((u32)(-\1 | \1)) >> 0x1f)", code)
        add_mut(m_c1)
        m_c2 = re.sub(r"\(\s*-(\w+)\s*\|\s*\1\s*>>\s*(?:0x1f|31)\s*\)", r"(\1 != 0)", code)
        add_mut(m_c2)

    # LEY 9: decremento de byte en struct `*(int *)(param_1 + K) = (char)param_1[K] + -1;` -> `*(u8 *)(param_1 + K) = *(u8 *)(param_1 + K) - 1;`
    m_dec_b = re.search(r"if\s*\(\(\(([^)]+)\)\s*&&\s*\(([^)]+)\)\)\s*&&\s*\(\(char\)(\w+)\[(\d+)\]\s*!=\s*'\\0'\)\)\s*\{\s*\n\s*\*\(int\s*\*\)\(\3\s*\+\s*\4\)\s*=\s*\(char\)\3\[\4\]\s*\+\s*-1;", code)
    if m_dec_b:
        c1, c2, p_v, idx_s = m_dec_b.groups()
        repl = f"if (({c1}) && ({c2}) && (*(u8 *)({p_v} + {idx_s}) != 0)) {{\n    *(u8 *)({p_v} + {idx_s}) = *(u8 *)({p_v} + {idx_s}) - 1;"
        add_mut(code.replace(m_dec_b.group(0), repl))

    # LEY 10: Eliminacion de casts espurios `(s16)` / `(u16)` sobre retornos de llamadas cuando `iVar1` fue mutado
    for m_cast_call in re.finditer(r"(\w+)\s*=\s*\([us]16\)\s*(func_[0-9A-F]{8}\([^;]+\));", code):
        v_lhs, f_call = m_cast_call.groups()
        m_c = code.replace(m_cast_call.group(0), f"{v_lhs} = {f_call};")
        m_c_int = re.sub(rf"\b(?:u16|s16)\s+{re.escape(v_lhs)}\b", f"int {v_lhs}", m_c)
        add_mut(m_c)
        add_mut(m_c_int)

    # LEY 11: Bitfield shift masks `(X & 0x3F)` -> `(((u32)(X) << 26) >> 26)`
    for pat, shift in [
        (r"\(\s*([^()]+)\s*&\s*0x3f\s*\)", 26),
        (r"\(\s*([^()]+)\s*&\s*0x1f\s*\)", 27),
        (r"\(\s*([^()]+)\s*&\s*0x7f\s*\)", 25),
        (r"\(\s*([^()]+)\s*&\s*0x0f\s*\)", 28),
    ]:
        if re.search(pat, code, re.I):
            add_mut(re.sub(pat, rf"(((u32)(\1) << {shift}) >> {shift})", code, flags=re.I))

    # LEY 12: C++ Inlined Constructor Wrapper (`static inline u32 *ctor_inl(u32 *v, ...)`)
    # Cuando una funcion reserva con func_080005D4(sz), llama a un constructor base y escribe vtable/campos antes de `return v;`
    m_ctor_block = re.search(
        r"(\w+)\s*=\s*(?:\([^)]+\)\s*)?(func_080005D4\s*\([^)]+\))\s*;\s*\n"
        r"((?:[ \t]+[^\n]+\n){1,8}?)"
        r"[ \t]*return\s+(?:\([^)]+\)\s*)?\1\s*;",
        code,
    )
    if m_ctor_block:
        v_obj, alloc_call, body_mid = m_ctor_block.groups()
        sig_m = re.search(r"(?:u32|int|void)\s*\*?\s*(func_[0-9A-F]{8})\s*\(([^)]*)\)", code)
        if sig_m:
            fn_n, params_s = sig_m.groups()
            p_list = [p.strip() for p in params_s.split(",") if p.strip() and p.strip() != "void"]
            p_names = [re.findall(r"\b\w+\b", p)[-1] for p in p_list]
            used_p = [(p_decl, p_nm) for p_decl, p_nm in zip(p_list, p_names) if re.search(rf"\b{re.escape(p_nm)}\b", body_mid)]
            inl_params = ["int " + v_obj] + [p_decl for p_decl, _ in used_p]
            inl_args = ["(int)" + alloc_call] + [p_nm for _, p_nm in used_p]
            inl_def = f"static inline int ctor_{fn_n[-6:].lower()}({', '.join(inl_params)}) {{\n{body_mid}  return {v_obj};\n}}\n"
            new_c = inl_def + code[:m_ctor_block.start()] + f"return ctor_{fn_n[-6:].lower()}({', '.join(inl_args)});" + code[m_ctor_block.end():]
            add_mut(new_c)

    # LEY 13: Call-Chain Return Forwarding (`v = f1(...); v = f2(v, ...); f3(..., v);` -> `f3(..., f2(f1(...), ...));`)
    m_chain2 = re.search(
        r"[ \t]*(\w+)\s*=\s*(func_[0-9A-F]{8}\s*\([^;\n]*\))\s*;\s*\n"
        r"[ \t]*\1\s*=\s*(func_[0-9A-F]{8})\s*\(\s*\1\b([^;\n]*)\)\s*;\s*\n"
        r"([ \t]*func_[0-9A-F]{8}\s*\([^;\n]*\b\1\b[^;\n]*\)\s*;)",
        code,
    )
    if m_chain2:
        v_ch, call1, fn2, rest2, call3_line = m_chain2.groups()
        inlined_12 = f"{fn2}({call1}{rest2})"
        new_call3 = re.sub(rf"\b{re.escape(v_ch)}\b", inlined_12, call3_line, count=1)
        add_mut(code[:m_chain2.start()] + new_call3 + code[m_chain2.end():])
        add_mut(code[:m_chain2.start()] + f"  {v_ch} = {inlined_12};\n" + call3_line + code[m_chain2.end():])

    # LEY 14: Encadenamiento de constantes cero en stores de bytes/words consecutivos (`*(u8 *)(p + off1) = (z = 0); *(u8 *)(p + off2) = z;`)
    m_two_zeros = re.search(
        r"([ \t]*\*\(\s*(?:u8|u16|u32)\s*\*\s*\)\s*\([^;\n]+\))\s*=\s*0\s*;\s*\n"
        r"([ \t]*\*\(\s*(?:u8|u16|u32)\s*\*\s*\)\s*\([^;\n]+\))\s*=\s*0\s*;\s*\n"
        r"([ \t]*\*\(\s*(?:u8|u16|u32)\s*\*\s*\)\s*\([^;\n]+\))\s*=\s*0\s*;",
        code,
    )
    if m_two_zeros:
        lhs1, lhs2, lhs3 = m_two_zeros.groups()
        for t1, t2 in [("u8", "u8"), ("u32", "u8")]:
            lhs2_b = re.sub(r"\*\(\s*(?:u8|u16|u32)\s*\*\s*\)", f"*({t1} *)", lhs2, count=1)
            lhs3_b = re.sub(r"\*\(\s*(?:u8|u16|u32)\s*\*\s*\)", f"*({t2} *)", lhs3, count=1)
            c_z = code[:m_two_zeros.start()] + f"{lhs1} = 0;\n{lhs2_b} = (z_pair = 0);\n{lhs3_b} = z_pair;" + code[m_two_zeros.end():]
            add_mut(inject_local(c_z, "u32 z_pair;"))
            c_z_plain = code[:m_two_zeros.start()] + f"{lhs1} = 0;\n{lhs2_b} = 0;\n{lhs3_b} = 0;" + code[m_two_zeros.end():]
            add_mut(c_z_plain)

    # LEY 15: Desreferencia de punteros 32-bit en IWRAM/EWRAM (`*(u16 *)0x0300XXXX` -> `*(int *)0x0300XXXX` / `*(u32 *)0x0300XXXX`)
    if re.search(r"\*\(\s*u16\s*\*\s*\)\s*0x0[23][0-9A-Fa-f]{6}\b", code):
        add_mut(re.sub(r"\*\(\s*u16\s*\*\s*\)\s*(0x0[23][0-9A-Fa-f]{6})\b", r"(*(int *)\1)", code))
        add_mut(re.sub(r"\*\(\s*u16\s*\*\s*\)\s*(0x0[23][0-9A-Fa-f]{6})\b", r"(*(u32 *)\1)", code))

    # LEY 16: Eliminacion / insercion de cast `(u32)` en comparaciones `if ((u32)param_X < K)` <-> `if (param_X < K)` (bhi/bls vs bgt/ble)
    for m_ucmp in re.finditer(r"\bif\s*\(\s*\(\s*u32\s*\)\s*(\w+)\s*([<>]=?)\s*([^)]+)\)", code):
        v_c, op_c, rhs_c = m_ucmp.groups()
        add_mut(code.replace(m_ucmp.group(0), f"if ({v_c} {op_c} {rhs_c})"))

    # LEY 17: Shift-Aritmetica e Inversion de Multiplicacion/Desplazamiento
    # x * 2 <-> x << 1 <-> x + x; x * 4 <-> x << 2; x * 8 <-> x << 3; x * 16 <-> x << 4
    for m_mul in re.finditer(r"\b(\w+)\s*\*\s*(2|4|8|16)\b", code):
        v_nm, factor_s = m_mul.groups()
        factor = int(factor_s)
        shift = {2: 1, 4: 2, 8: 3, 16: 4}[factor]
        add_mut(code[:m_mul.start()] + f"({v_nm} << {shift})" + code[m_mul.end():])
        if factor == 2:
            add_mut(code[:m_mul.start()] + f"({v_nm} + {v_nm})" + code[m_mul.end():])
    for m_sh in re.finditer(r"\b(\w+)\s*<<\s*([1-4])\b", code):
        v_nm, sh_s = m_sh.groups()
        factor = 1 << int(sh_s)
        add_mut(code[:m_sh.start()] + f"({v_nm} * {factor})" + code[m_sh.end():])

    # LEY 18: Equivalencia de Indice de Array y Aritmetica de Punteros
    # *(p + i) <-> p[i]
    for m_ptr_idx in re.finditer(r"\*\s*\(\s*(\w+)\s*\+\s*(\w+)\s*\)", code):
        p_nm, idx_nm = m_ptr_idx.groups()
        add_mut(code[:m_ptr_idx.start()] + f"{p_nm}[{idx_nm}]" + code[m_ptr_idx.end():])
    for m_arr_idx in re.finditer(r"\b(\w+)\[(\w+)\]", code):
        p_nm, idx_nm = m_arr_idx.groups()
        add_mut(code[:m_arr_idx.start()] + f"*({p_nm} + {idx_nm})" + code[m_arr_idx.end():])

    # LEY 19: Operadores Logicos vs Bitwise en Condicionales
    # if (a && b) <-> if (a & b); if (a || b) <-> if (a | b)
    if " && " in code:
        add_mut(code.replace(" && ", " & "))
    if " || " in code:
        add_mut(code.replace(" || ", " | "))
    if " & " in code and " && " not in code:
        add_mut(code.replace(" & ", " && "))

    # LEY 20: Operador Ternario vs Bloque If-Else
    # if (c) var = a; else var = b; <-> var = (c) ? a : b;
    m_if_else = re.search(
        r"if\s*\(([^)]+)\)\s*\{\s*\n\s*(\w+)\s*=\s*([^;]+);\s*\n\s*\}\s*\n\s*else\s*\{\s*\n\s*\2\s*=\s*([^;]+);\s*\n\s*\}",
        code,
    )
    if m_if_else:
        c_expr, dst_v, val_a, val_b = m_if_else.groups()
        repl_t = f"{dst_v} = ({c_expr}) ? ({val_a.strip()}) : ({val_b.strip()});"
        add_mut(code.replace(m_if_else.group(0), repl_t))

    # LEY 21: Inversion de Forma de Bucle (while <-> do-while)
    m_while = re.search(r"while\s*\(([^)]+)\)\s*\{((?:[^{}]*|\{[^{}]*\})*)\}", code)
    if m_while:
        cond_w, body_w = m_while.groups()
        repl_dowhile = f"do {{{body_w}}} while ({cond_w});"
        add_mut(code.replace(m_while.group(0), repl_dowhile))

    # LEY 22: Asignacion Simultanea y Orden de Cero en Multi-Registros
    # r1 = 0; r2 = 0; <-> r2 = 0; r1 = 0; <-> r1 = r2 = 0; <-> r2 = r1 = 0;
    m_two_z_assign = re.search(
        r"(\b\w+\b)\s*=\s*0\s*;\s*\n\s*(\b\w+\b)\s*=\s*0\s*;",
        code,
    )
    if m_two_z_assign:
        z1, z2 = m_two_z_assign.groups()
        if z1 != z2:
            add_mut(code.replace(m_two_z_assign.group(0), f"{z2} = 0;\n  {z1} = 0;"))
            add_mut(code.replace(m_two_z_assign.group(0), f"{z1} = {z2} = 0;"))
            add_mut(code.replace(m_two_z_assign.group(0), f"{z2} = {z1} = 0;"))

    # LEY 23: Operador de Post-Incremento / Pre-Incremento / Asignacion Compuesta
    # *p++ = val <-> *p = val; p++
    m_ptr_post = re.search(r"\*(\w+)\+\+\s*=\s*([^;]+);", code)
    if m_ptr_post:
        p_v, val_e = m_ptr_post.groups()
        add_mut(code.replace(m_ptr_post.group(0), f"*{p_v} = {val_e};\n  {p_v}++;"))
    m_ptr_split = re.search(r"\*(\w+)\s*=\s*([^;]+);\s*\n\s*\1\+\+;", code)
    if m_ptr_split:
        p_v, val_e = m_ptr_split.groups()
        add_mut(code.replace(m_ptr_split.group(0), f"*{p_v}++ = {val_e};"))

    # LEY 24: Truncamiento y Enmascaramiento de Comparaciones (u8/u16/s16/s8)
    for m_cmp_cast in re.finditer(r"\bif\s*\(\s*(\w+)\s*([<>!=]=?)\s*(0x[0-9a-fA-F]+|\d+)\s*\)", code):
        v_cmp, op_cmp, imm_cmp = m_cmp_cast.groups()
        for ct in ("(u8)", "(s8)", "(u16)", "(s16)", "(u32)", "(int)"):
            add_mut(code[:m_cmp_cast.start()] + f"if ({ct}{v_cmp} {op_cmp} {imm_cmp})" + code[m_cmp_cast.end():])

    # LEY 25: Chequeo de Retorno de 8-bit e Inlining de Condiciones (`cVar1 = f(); if (cVar1 == '\0')` -> `if ((u8)f() == 0)`)
    # Invierte el orden de comparacion y emite `lsls r0, r0, #0x18; cmp r0, #0`
    for m_ret8 in re.finditer(
        r"[ \t]*(\w+)\s*=\s*(func_[0-9A-F]{8}\([^;\n]+\))\s*;\s*\n"
        r"([ \t]*)if\s*\(\s*\1\s*==\s*(?:'\\0'|0)\s*\)",
        code,
    ):
        v_nm, f_call, ind_c = m_ret8.groups()
        c_inl = code[:m_ret8.start()] + f"{ind_c}if ((u8){f_call} == 0)" + code[m_ret8.end():]
        c_inl_clean = re.sub(rf"^\s*(?:int|char|s16|u8|u32)\s+{re.escape(v_nm)}\s*;\s*\n", "", c_inl, flags=re.M)
        add_mut(c_inl_clean)
        add_mut(c_inl)

    # Inlining directo de llamadas en condiciones `var = func_X(...); if (var == K)` -> `if (func_X(...) == K)`
    for m_ret_cmp in re.finditer(
        r"[ \t]*(\w+)\s*=\s*(func_[0-9A-F]{8}\([^;\n]+\))\s*;\s*\n"
        r"([ \t]*)if\s*\(\s*\1\s*==\s*([^)]+)\)",
        code,
    ):
        v_nm, f_call, ind_c, k_val = m_ret_cmp.groups()
        c_inl = code[:m_ret_cmp.start()] + f"{ind_c}if ({f_call} == {k_val})" + code[m_ret_cmp.end():]
        c_inl_clean = re.sub(rf"^\s*(?:int|char|s16|u8|u32)\s+{re.escape(v_nm)}\s*;\s*\n", "", c_inl, flags=re.M)
        add_mut(c_inl_clean)
        add_mut(c_inl)

    # LEY 29: Eliminacion e Inlining de Temporales de Direccion ROM 32-bit (`iVar1 = 0x08XXXXXX;`)
    # Previene truncamiento de s16/u16 y restaura el pool literal en agbcc_O1 / agbcc_O2
    for m_rom_tmp in re.finditer(
        r"[ \t]*(\w+)\s*=\s*(?:\([^)]+\))?\s*(0x0[2345678][0-9A-Fa-f]{6})\s*;\s*\n",
        code,
    ):
        v_rom, addr_hex = m_rom_tmp.groups()
        body_no_assign = code[:m_rom_tmp.start()] + code[m_rom_tmp.end():]
        if re.search(rf"\b{re.escape(v_rom)}\b", body_no_assign):
            c_rom1 = re.sub(rf"\b{re.escape(v_rom)}\b", addr_hex, body_no_assign)
            c_rom1 = re.sub(rf"^\s*(?:register\s+)?\w+\s+{re.escape(v_rom)}\s*;\s*\n", "", c_rom1, flags=re.M)
            add_mut(c_rom1)
            # Conmutar (addr + idx) <-> (idx + addr)
            c_rom2 = re.sub(rf"\b{re.escape(addr_hex)}\s*\+\s*(\w+)", rf"\1 + {addr_hex}", c_rom1)
            add_mut(c_rom2)

    # LEY 30: Hoisting de Cargas Consecutivas en Condiciones `&&` + Correccion de Escalamiento de Punteros `(int)imm + ptr`
    m_ptr_scale = re.sub(r"\(\s*int\s*\)\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*(param_\d+)", r"(int)\2 + \1", code)
    if m_ptr_scale != code:
        add_mut(m_ptr_scale)
    for base_src in (code, m_ptr_scale):
        m_and_loads = re.search(
            r"([ \t]*)if\s*\(\s*\(\s*(\*\([^)]+\)\([^)]+\))\s*==\s*([^)]+)\)\s*&&\s*\(\s*(\*\([^)]+\)\([^)]+\))\s*==\s*([^)]+)\)\s*\)",
            base_src,
        )
        if m_and_loads:
            ind_a, ld1, val1, ld2, val2 = m_and_loads.groups()
            repl_hoist = f"{ind_a}hx = {ld1};\n{ind_a}hy = {ld2};\n{ind_a}if (hx == {val1.strip()} && hy == {val2.strip()})"
            c_hoist = inject_local(inject_local(base_src.replace(m_and_loads.group(0), repl_hoist), "int hy;"), "int hx;")
            add_mut(c_hoist)

    # LEY 31: Inversion de Cola `do { ... } while(1)` preservando Etiqueta Interna contra GCC `loop.c` Strength Reduction
    m_do_lab = re.search(
        r"do\s*\{\s*\n"
        r"([ \t]*if\s*\([^)]+\)\s*\{\s*\n\s*(LAB_[0-9a-fA-F_]+):\s*\n\s*return\s+(\w+);\s*\n\s*\})\s*\n"
        r"((?:[ \t]*[^\n]+\n)+?)"
        r"[ \t]*if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*\{\s*\n\s*\3\s*=\s*0;\s*\n\s*goto\s+\2;\s*\n\s*\}\s*\n"
        r"([ \t]*[^\n]+;\s*\n)"
        r"\s*\}\s*while\s*\(\s*(?:true|1)\s*\);",
        code,
    )
    if m_do_lab:
        first_if_blk, lab_nm, ret_v, mid_stmts, iv_c, bnd_c, step_stmt = m_do_lab.groups()
        m_cond1 = re.search(r"if\s*\(([^)]+)\)", first_if_blk)
        if m_cond1:
            cond1_str = m_cond1.group(1)
            new_do = (
                f"do {{\n"
                f"    if ({cond1_str})\n"
                f"      goto {lab_nm};\n"
                f"{mid_stmts}"
                f"    if ({iv_c} < {bnd_c}) {{\n"
                f"  {step_stmt}"
                f"    }} else {{\n"
                f"      {ret_v} = 0;\n"
                f"{lab_nm}:\n"
                f"      return {ret_v};\n"
                f"    }}\n"
                f"  }} while (1);"
            )
            c_do = code.replace(m_do_lab.group(0), new_do)
            c_do_u32 = re.sub(r"^\s*(?:u8|u16|s8|s16|int)\s+(func_[0-9A-Fa-f]{8})", r"u32 \1", c_do, flags=re.M)
            add_mut(c_do_u32)
            add_mut(c_do)

    # LEY 32: ABI GBA 8vo Argumento `struct __attribute__((packed)) _s1 { u8 a; }` (emite `add rX, sp, #0xc; strb`)
    for m_call8 in re.finditer(r"\b(func_[0-9A-F]{8})\s*\(([^;]+)\)\s*;", code):
        callee8, args8_str = m_call8.groups()
        if callee8 == func_name:
            continue
        parts8 = []
        d8 = 0
        cur8 = []
        for ch in args8_str:
            if ch == "(":
                d8 += 1
            elif ch == ")":
                d8 -= 1
            if ch == "," and d8 == 0:
                parts8.append("".join(cur8).strip())
                cur8 = []
            else:
                cur8.append(ch)
        parts8.append("".join(cur8).strip())
        if len(parts8) == 8 and "_s1" not in parts8[7]:
            a8 = parts8[7]
            parts8[7] = f"(struct _s1){{{a8}}}"
            new_call8 = f"{callee8}(" + ", ".join(parts8) + ");"
            proto8 = f"struct __attribute__((packed)) _s1 {{ u8 a; }};\nu32 {callee8}(u32, u32, u32, u32, u32, u32, u32, struct _s1);\n"
            c_p8 = proto8 + code.replace(m_call8.group(0), new_call8)
            add_mut(c_p8)
            m_al8 = re.search(r"(\w+)\s*=\s*(func_080005D4\([^)]+\));\s*\n\s*return\s+" + callee8 + r"\(\s*\1\s*,", c_p8)
            if m_al8:
                va8, ca8 = m_al8.groups()
                c_p8_inl = c_p8.replace(m_al8.group(0), f"return {callee8}({ca8},")
                c_p8_inl = re.sub(rf"^\s*(?:register\s+)?\w+\s+{re.escape(va8)}\s*;\s*\n", "", c_p8_inl, flags=re.M)
                add_mut(c_p8_inl)

    # LEY 33: Hoisting de Carga de Sub-Puntero antes de Comparacion Booleana (`ldr r0, [r0, #off]` antes de `movs r1, #0`)
    m_sub_eq0 = re.search(
        r"return\s+\(\(u32\)\(\*\((?:char|u8|s8)\s*\*\)\(\*\(int\s*\*\)\((\w+\s*\+\s*[^)]+)\)\s*\+\s*([^)]+)\)\s*==\s*(?:'\\0'|0)\)\);",
        code,
    )
    if m_sub_eq0:
        off1_e, off2_e = m_sub_eq0.groups()
        c_sub_eq0 = inject_local(
            code.replace(m_sub_eq0.group(0), f"hp = *(int *)({off1_e});\n  return *(u8 *)(hp + {off2_e}) == 0;"),
            "int hp;",
        )
        add_mut(c_sub_eq0)

    # LEY 34: Hoisting de Desplazamiento de Bit de Signo (`ldrb; lsls` antes de `movs r2, #0`)
    m_sh_sign = re.search(
        r"(\w+)\s*=\s*0;\s*\n\s*if\s*\(\(\s*int\s*\)\(\(u32\)\*\(u8\s*\*\)\(([^)]+)\)\s*\*\s*0x40000000\)\s*<\s*0\)\s*\{\s*\n\s*\1\s*=\s*([^;]+);\s*\n\s*\}",
        code,
    )
    if m_sh_sign:
        rv_s, addr_s, val_s = m_sh_sign.groups()
        repl_sh = f"hv = *(u8 *)({addr_s}) << 30;\n  {rv_s} = 0;\n  if (hv < 0)\n    {rv_s} = {val_s};"
        c_sh = inject_local(code.replace(m_sh_sign.group(0), repl_sh), "int hv;")
        add_mut(c_sh)

    # LEY 35: Hoisting de Miembro Puntero antes de Rango `&&` (`ldr r1, [r0, #4]` antes de `subs r0, #K; cmp r0, #M`)
    m_rng_and = re.search(
        r"if\s*\(\(\s*([^&]+?)\s*<\s*(\d+|0x[0-9a-fA-F]+)\)\s*&&\s*\n?\s*\((\w+)\s*=\s*\*\(int\s*\*\*\)\(\*\(int\s*\*\)\((\w+\s*\+\s*\d+)\)\s*\+\s*([^)]+)\),\s*\n?\s*(\w+)\s*=\s*(func_[0-9A-F]{8}\([^)]+\)),\s*\6\s*!=\s*0\)\)\s*\{\s*\n\s*(\w+)\s*=\s*(func_[0-9A-F]{8}\([^)]*\));\s*\n\s*\}\s*\n\s*else\s*\{\s*\n\s*\8\s*=\s*0;\s*\n\s*\}\s*\n\s*return\s+\8;",
        code,
    )
    if m_rng_and:
        rng_e, rng_b, piv_v, p1_off, off2_v, iv_v, call1_e, uv_v, call2_e = m_rng_and.groups()
        rng_clean = rng_e.replace("U", "")
        repl_rng = (
            f"hsub = *(int *)({p1_off});\n"
            f"  if ((u32)({rng_clean}) < {rng_b}) {{\n"
            f"    {piv_v} = *(int **)(hsub + {off2_v});\n"
            f"    if ({call1_e} != 0)\n"
            f"      return {call2_e};\n"
            f"  }}\n"
            f"  return 0;"
        )
        c_rng = inject_local(code.replace(m_rng_and.group(0), repl_rng), "int hsub;")
        add_mut(c_rng)

    # LEY 36: Restauracion de Argumento `&uStack_XX` Omitido por Ghidra tras `strb r1, [r0]; bl func_X`
    for m_stk_arg in re.finditer(
        r"(\b\w*Stack_[0-9a-fA-F]+\b)\s*=\s*(func_[0-9A-F]{8}\([^;\n]+\));\s*\n"
        r"([ \t]*(?:return\s+|\w+\s*=\s*(?:\(\w+\))?)?)(func_[0-9A-F]{8})\(\s*(\w+)?\s*\);",
        code,
    ):
        stk_v, rhs_call, pfx_c, next_fn, old_arg = m_stk_arg.groups()
        # Si stk_v no vuelve a usarse en el resto de la funcion, Ghidra omitio `&stk_v` en next_fn
        if len(re.findall(rf"\b{re.escape(stk_v)}\b", code)) <= 2:
            c_stk = code[:m_stk_arg.start()] + f"{stk_v} = {rhs_call};\n{pfx_c}{next_fn}(&{stk_v});" + code[m_stk_arg.end():]
            add_mut(c_stk)
            c_stk_u8 = re.sub(rf"\b(?:BOOL|int|u32)\s+{re.escape(stk_v)}\s*;", f"u8 {stk_v}[4];", c_stk)
            if c_stk_u8 != c_stk:
                c_stk_u8 = c_stk_u8.replace(f"{stk_v} = {rhs_call};", f"{stk_v}[0] = {rhs_call};").replace(f"(&{stk_v})", f"({stk_v})")
                # Inlinear 5to argumento de llamada subsiguiente si usa temporal de 1 uso
                m_arg5 = re.search(r"(\w+)\s*=\s*(?:\(u16\))?(func_[0-9A-F]{8}\([^)]+\));\s*\n(\s*func_[0-9A-F]{8}\([^,]+,[^,]+,[^,]+,[^,]+,\s*)\1\s*\);", c_stk_u8)
                if m_arg5:
                    v5, c5, call5_pfx = m_arg5.groups()
                    c_stk_u8 = c_stk_u8.replace(m_arg5.group(0), f"{call5_pfx}{c5});")
                add_mut(c_stk_u8)

    # LEY 37: Correccion de Trampa `char` Sin Signo en `agbcc` (`char cVar != -1` evalua como tautologia `1` y elimina el branch)
    if "!= -1" in code:
        c_u8_ff = re.sub(r"\bchar\s+(\w+)\s*;", r"u8 \1;", code)
        c_u8_ff = re.sub(r"\b(\w+)\s*!=\s*-1\b", r"\1 < 0xff", c_u8_ff)
        add_mut(c_u8_ff)
        c_s8_m1 = re.sub(r"\bchar\s+(\w+)\s*;", r"s8 \1;", code)
        add_mut(c_s8_m1)

    # LEY 38: Ensanchamiento de Parametro Estrecho en Firma (`u8`/`u16`/`s8`/`s16 param_K` -> `int`/`u32 param_K` con cast en el uso)
    m_hdr_p = re.search(rf"\b{re.escape(func_name)}\s*\(([^)]+)\)", code)
    if m_hdr_p:
        p_str = m_hdr_p.group(1)
        for m_np in re.finditer(r"\b(u8|u16|s8|s16)\s+(param_\d+)\b", p_str):
            nt, np_name = m_np.groups()
            w_type = "int" if nt == "s8" else "u32"
            new_p_str = p_str.replace(m_np.group(0), f"{w_type} {np_name}")
            body_start = m_hdr_p.end()
            body_code = code[body_start:]
            # Variante A: sin cast adicional (si se usa como puntero o indice ya enmascarado)
            add_mut(code[:m_hdr_p.start(1)] + new_p_str + body_code)
            # Variante B: con cast `(nt)np_name` en llamadas dentro del cuerpo
            body_cast = re.sub(rf"(,\s*)\b{re.escape(np_name)}\b(\s*[,)])", rf"\1({nt}){np_name}\2", body_code)
            if body_cast != body_code:
                add_mut(code[:m_hdr_p.start(1)] + new_p_str + body_cast)

    # LEY 39: Hoisting de `u8 zero = 0;` antes de Inicializacion Dual `*param_1 = 1; param_1[1] = 0;`
    if "*param_1 = 1;" in code and "param_1[1] = 0;" in code:
        c_z0 = re.sub(
            r"\*param_1\s*=\s*1;\s*\n?\s*param_1\[1\]\s*=\s*0;",
            "{ u8 zero = 0; *param_1 = 1; param_1[1] = zero; }",
            code,
        )
        add_mut(c_z0)

    # LEY 40: Hoisting de Puntero Base `int v = *param_1;` antes de Despacho Virtual Multi-Desreferencia
    m_vdisp = re.search(
        r"(func_[0-9A-F]{8})\(\s*(param_\d+)\s*,\s*(\*\(u32\s*\*\)\s*\2\[\d+\])\s*,\s*([^,]+)\s*,\s*\*\(u32\s*\*\)\(\*\2\s*\+\s*([^)]+)\)\s*\);",
        code,
    )
    if m_vdisp:
        v_fn, v_p, v_a2, v_a3, v_off = m_vdisp.groups()
        c_vd = inject_local(
            code.replace(m_vdisp.group(0), f"v = *{v_p};\n  {v_fn}({v_p}, {v_a2}, {v_a3}, *(u32 *)(v + {v_off}));"),
            "int v;",
        )
        add_mut(c_vd)

    # LEY 41: Expansion de Ternario con Llamada sobre Stack Buffer (`param_1[1] == 0 ? func_X(&buf, K) : param_1[0]`)
    m_tern_buf = re.search(
        r"return\s+(\w+\[\d+\])\s*==\s*0\s*\?\s*(func_[0-9A-F]{8})\(&?(\w+),\s*([^)]+)\)\s*:\s*(?:\(\w+\))?(\*?\w+(?:\[\d+\])?)\s*;",
        code,
    )
    if m_tern_buf:
        cond_t, fn_t, buf_t, imm_t, alt_t = m_tern_buf.groups()
        repl_tb = f"if ({cond_t} != 0)\n    return {alt_t};\n  {fn_t}(&{buf_t}, {imm_t});\n  return {buf_t}[0];"
        c_tb = re.sub(rf"\bu16\s+{re.escape(func_name)}\b", f"u8 {func_name}", code.replace(m_tern_buf.group(0), repl_tb))
        add_mut(c_tb)

    # LEY 42: Conversion de Modificacion `*(u16 *)&uStack_c` a Struct `{ u16 a; u16 b; }`
    m_u16_stk = re.search(
        r"u32\s+(uStack_[0-9a-fA-F]+)\s*;\s*\n\s*(func_[0-9A-F]{8})\(&\1\);\s*\n\s*\*\(u16\s*\*\)\s*&\1\s*=\s*\(u16\)\(\(short\)\1\s*\+\s*([^)]+)\);\s*\n\s*\*(\w+)\s*=\s*\1;",
        code,
    )
    if m_u16_stk:
        st_v, st_fn, st_k, st_p = m_u16_stk.groups()
        repl_st = f"struct {{ u16 a; u16 b; }} {st_v};\n  {st_fn}(&{st_v});\n  {st_v}.a += {st_k};\n  *{st_p} = *(u32 *)&{st_v};"
        c_st = re.sub(rf"\bu32\s+{re.escape(func_name)}\b", f"u32 *{func_name}", code.replace(m_u16_stk.group(0), repl_st))
        add_mut(c_st)

    # LEY 43: Escalera de Retornos Tempranos (Guard Ladder Early Returns) en vez de Anidamiento if-else
    # Transforma `if (c1) { ret = v1; } else if (c2) { ret = v2; } else { ret = v3; } return ret;`
    m_ladder = re.search(
        r"if\s*\(([^)]+)\)\s*\{\s*\n?\s*(\w+)\s*=\s*([^;]+);\s*\n?\s*\}\s*\n?\s*else\s+if\s*\(([^)]+)\)\s*\{\s*\n?\s*\2\s*=\s*([^;]+);\s*\n?\s*\}\s*\n?\s*else\s*\{\s*\n?\s*\2\s*=\s*([^;]+);\s*\n?\s*\}\s*\n?\s*return\s+\2\s*;",
        code,
    )
    if m_ladder:
        c1, rv, v1, c2, v2, v3 = m_ladder.groups()
        # Variante A: retorno lineal temprano
        repl_la = f"if ({c1})\n    return {v1};\n  if ({c2})\n    return {v2};\n  return {v3};"
        c_la = code.replace(m_ladder.group(0), repl_la)
        add_mut(c_la)

        # Variante B: transformar `< 0xK` a `<= 0xK - 1` dentro de las condiciones
        def _sub_le(cond_str):
            def _repl_num(m):
                val = int(m.group(1), 0)
                return f"<= {val - 1}"
            return re.sub(r"<\s*(0x[0-9a-fA-F]+|\d+)", _repl_num, cond_str)

        c1_le = _sub_le(c1)
        c2_le = _sub_le(c2)
        repl_lb = f"if ({c1_le})\n    return {v1};\n  if ({c2_le})\n    return {v2};\n  return {v3};"
        c_lb = code.replace(m_ladder.group(0), repl_lb)
        add_mut(c_lb)

    # LEY 44: Desanidamiento de Retornos Condicionales Booleanos Invertidos (`if (c == 0) { ... } else { ret = K; }`)
    m_inv_nest = re.search(
        r"(\w+)\s*=\s*(func_[0-9A-F]{8}\([^)]*\));\s*\n\s*if\s*\(\1\s*==\s*(?:0|'\\0')\)\s*\{\s*\n\s*\1\s*=\s*(func_[0-9A-F]{8}\([^)]*\));\s*\n\s*if\s*\(\1\s*==\s*(?:0|'\\0')\)\s*\{\s*\n\s*(\w+)\s*=\s*([^;]+);\s*\n\s*\}\s*\n\s*else\s*\{\s*\n\s*\4\s*=\s*([^;]+);\s*\n\s*\}\s*\n\s*\}\s*\n\s*else\s*\{\s*\n\s*\4\s*=\s*([^;]+);\s*\n\s*\}\s*\n\s*return\s+\4;",
        code,
    )
    if m_inv_nest:
        cv, fn1, fn2, rv, v_eq0, v_ne0, v_top_ne0 = m_inv_nest.groups()
        repl_inv = (
            f"if ({fn1} != 0)\n"
            f"    return {v_top_ne0};\n"
            f"  if ({fn2} == 0)\n"
            f"    return {v_eq0};\n"
            f"  return {v_ne0};"
        )
        c_inv = code.replace(m_inv_nest.group(0), repl_inv)
        add_mut(c_inv)

    # LEY 45: Retorno de Puntero Parametro Pasado en `r0` (`adds r0, r4, #0; bx r1`)
    if re.search(r"\*param_1\s*=\s*[^;]+;\s*\n\s*return\s*;", code):
        c_ret_p = re.sub(r"void\s+" + re.escape(func_name), f"u32 *{func_name}", code)
        c_ret_p = re.sub(r"return\s*;", "return param_1;", c_ret_p)
        add_mut(c_ret_p)

    # LEY 46: Ley de Mascara de Bits Generica y Campos Desplazados (lsls / lsrs / asrs)
    for m_ml in mask_laws(code):
        add_mut(m_ml)

    return list(dict.fromkeys(mutations))


# ---------------------------------------------------------------------------------------------
# 4. PIPELINE PRINCIPAL ROSETTA (BARRIDO UNIVERSAL + CONTRASTE ALGEBRAICO CERO TOKENS)
# ---------------------------------------------------------------------------------------------

def get_best_existing_code(e: dict) -> str:
    name = e["name"]
    cands = [
        TREE_DIR / "approx" / f"{name}.c",
        TREE_DIR / "permute" / "code" / f"{name}.c",
        (TREE_DIR / e["file"]).with_suffix(".wip.c"),
        TREE_DIR / "collection" / "approx" / f"{name}.c",
        TREE_DIR / "collection" / "wip" / f"{name}.wip.c",
    ]
    for p in cands:
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            if name in txt and "{" in txt:
                return txt
    return ""


def get_raw_ghidra_code(e: dict) -> str:
    p = TREE_DIR / e["file"]
    g = p.with_suffix(".ghidra.txt")
    if g.exists():
        return g.read_text(encoding="utf-8", errors="replace")
    if p.exists():
        return p.read_text(encoding="utf-8", errors="replace")
    return ""


def run_rosetta_pipeline(args):
    if STOP_FLAG.exists():
        try:
            STOP_FLAG.unlink()
        except OSError:
            pass

    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()
    by_name = {e["name"]: e for e in manifest}

    log("=" * 78)
    log(" FOMT-MATCH-ENGINE :: MOTOR ROSETTA SEMANTICO Y MATEMATICO (CERO TOKENS)")
    log("=" * 78)
    rosetta = RosettaCorpus(rom, manifest, state)
    log(f" [*] Corpus Piedra Rosetta indexado: {rosetta.count} funciones 100% Byte-Perfect")
    log(f" [*] Esqueletos estructurales Thumb unicos: {len(rosetta.by_skeleton)}")
    log("=" * 78)

    new_matches = 0
    improved_count = 0
    rescued_orphans = 0
    evaluated_untracked = 0

    # FASE A: Evaluar las 547 funciones no rastreadas + 247 huerfanas con Limpieza C89 + Rosetta + Levantador Directo
    if not args.skip_untracked:
        untracked_and_orphans = []
        for e in manifest:
            name = e["name"]
            st = state.get(name)
            if st is None or st.get("status") == "orphan":
                untracked_and_orphans.append(e)

        if args.limit_untracked > 0:
            untracked_and_orphans = untracked_and_orphans[:args.limit_untracked]

        log(f"\n>>> FASE A: BARRIDO MATEMATICO DE NO-RASTREADAS Y HUERFANAS ({len(untracked_and_orphans)} funciones) <<<")
        for idx, e in enumerate(untracked_and_orphans, 1):
            if STOP_FLAG.exists():
                log("[!] Detencion solicitada (stop.flag).")
                break

            name = e["name"]
            was_orphan = name in state and state[name].get("status") == "orphan"
            target = common.rom_bytes(rom, e["addr"], e["size"])
            presets = AGBCC_PRESET_LIST if e["mode"] == "THUMB" else list(common.ADS_PRESETS)

            cand_pool = []
            # 1. Intentar plantilla isomorfica de Piedra Rosetta
            for rc in rosetta.instantiate_candidates(rom, e):
                cand_pool.append(("rosetta-isomorphic", rc))

            # 2. Intentar semilla Ghidra limpiada con el normalizador C89 mejorado
            raw_g = get_raw_ghidra_code(e)
            cleaned = ""
            if raw_g and "sin referencia de Ghidra" not in raw_g:
                cleaned = lift.extract_c(lift.clean_ghidra_ref(raw_g, rom=rom, e=e), rom=rom, e=e)
                if cleaned and name in cleaned and "{" in cleaned:
                    cand_pool.append(("rosetta-seed-c89", cleaned))
            else:
                # 3. Intentar levantador simbolico directo Thumb -> C89 solo cuando no hay Ghidra
                for dc in lift_thumb_directly(rom, e):
                    cand_pool.append(("rosetta-thumb-lifter", dc))

            best_sc = -1.0
            best_code = None
            best_pr = None
            best_tag = None
            matched_now = False

            for tag, c_cand in cand_pool:
                sc, pr, got, ex, _ = lift.evaluate(e, c_cand, manifest, target, [presets[0]])
                if ex:
                    lift.save_matched(e, c_cand, pr, manifest, state, 0, tag, target=target, rom=rom, model="rosetta-math", phase_num=1)
                    new_matches += 1
                    matched_now = True
                    log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ({e['size']}B) via {tag} [{pr}]!")
                    write_hud_status(name, 1.0, 1.0, how=tag, phase_label="ROSETTA MATCH 100%!")
                    break
                if pr is not None and sc > best_sc:
                    best_sc, best_code, best_pr, best_tag = sc, c_cand, pr, tag

            # Si la semilla base alcanzo >= 85%, probar segundo preset y mutaciones algebraicas inmediatamente
            if not matched_now and best_code is not None and best_sc >= 0.85:
                extra_cands = [(best_tag, best_code)] + [
                    ("rosetta-seed-algebra", m) for m in generate_rosetta_algebraic_mutations(best_code, name, rom=rom, e=e)[:10]
                ]
                for tag, c_cand in extra_cands:
                    sc, pr, got, ex, _ = lift.evaluate(e, c_cand, manifest, target, presets[:2])
                    if ex:
                        lift.save_matched(e, c_cand, pr, manifest, state, 0, tag, target=target, rom=rom, model="rosetta-math", phase_num=1)
                        new_matches += 1
                        matched_now = True
                        log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ({e['size']}B) via {tag} [{pr}]!")
                        write_hud_status(name, 1.0, 1.0, how=tag, phase_label="ROSETTA MATCH 100%!")
                        break
                    if pr is not None and sc > best_sc:
                        best_sc, best_code, best_pr, best_tag = sc, c_cand, pr, tag

            if matched_now:
                continue

            if best_code is not None and best_sc > 0.0:
                if was_orphan:
                    rescued_orphans += 1
                else:
                    evaluated_untracked += 1
                status_str = "approx" if best_sc >= 0.90 else "wip"
                path = TREE_DIR / e["file"]
                lift._write_atomic(path.with_suffix(".wip.c"), best_code)
                lift._write_atomic(TREE_DIR / "collection" / "wip" / f"{name}.wip.c", best_code)
                if status_str == "approx":
                    ap_txt = f"/* paridad {best_sc * 100:.1f}% preset {best_pr} ({best_tag}) */\n" + best_code
                    lift._write_atomic(TREE_DIR / "approx" / f"{name}.c", ap_txt)
                    lift._write_atomic(TREE_DIR / "collection" / "approx" / f"{name}.c", ap_txt)
                state[name] = {
                    "status": status_str,
                    "best": round(best_sc, 4),
                    "preset": best_pr,
                    "how": best_tag,
                    "phase": 1,
                    "addr": e["addr"],
                    "size": e["size"],
                }
                if best_sc >= 0.85 or was_orphan:
                    log(f"  [^] [{'RESCATE ORPHAN' if was_orphan else 'NUEVA EVAL'}] {name} ({e['size']}B) -> {best_sc*100:.1f}% ({status_str}, {best_tag})")
            elif name not in state:
                state[name] = {"status": "orphan", "best": 0.0, "preset": None, "phase": 1, "addr": e["addr"], "size": e["size"]}

            if idx % 25 == 0:
                common.save_state(state)
                write_hud_status(name, max(0.0, best_sc), 0.0, evals=idx, phase_label=f"ROSETTA FASE A [{idx}/{len(untracked_and_orphans)}]")

        common.save_state(state)

    # Re-indexar Rosetta por si hubo nuevos matches en Fase A
    if new_matches > 0:
        rosetta = RosettaCorpus(rom, manifest, state)

    # FASE B: Solucionador Algebraico y de Contraste sobre todas las funciones candidatas en [min_score .. max_score]
    candidates = []
    for e in manifest:
        name = e["name"]
        st = state.get(name, {})
        if st.get("status") == "matched":
            continue
        sc = float(st.get("best", 0.0) or 0.0)
        if args.min_score <= sc <= args.max_score:
            candidates.append((sc, e))

    candidates.sort(key=lambda x: -x[0])
    if args.limit > 0:
        candidates = candidates[:args.limit]

    log(f"\n>>> FASE B: SOLUCIONADOR ALGEBRAICO ROSETTA ({len(candidates)} funciones en [{args.min_score*100:.1f}% - {args.max_score*100:.1f}%]) <<<")

    for idx, (b0, e) in enumerate(candidates, 1):
        if STOP_FLAG.exists():
            log("[!] Detencion solicitada (stop.flag).")
            break

        name = e["name"]
        target = common.rom_bytes(rom, e["addr"], e["size"])
        presets = AGBCC_PRESET_LIST if e["mode"] == "THUMB" else list(common.ADS_PRESETS)

        raw_code = get_best_existing_code(e)
        if not raw_code:
            continue
        c_clean = lift.extract_c(raw_code, rom=rom, e=e)

        # 1. Probar plantillas isomorficas de Rosetta + mutaciones algebraicas
        mut_list = []
        for rc in rosetta.instantiate_candidates(rom, e):
            mut_list.append(("rosetta-isomorphic", rc))
        for alg_m in generate_rosetta_algebraic_mutations(c_clean, name, rom=rom, e=e):
            mut_list.append(("rosetta-algebra", alg_m))

        # Tambien generar mutaciones desde la semilla limpia de Ghidra (por si un permutador previo corrompio tipos como u16 iVar1)
        raw_g = get_raw_ghidra_code(e)
        if raw_g and "sin referencia de Ghidra" not in raw_g:
            g_clean = lift.extract_c(lift.clean_ghidra_ref(raw_g, rom=rom, e=e), rom=rom, e=e)
            if g_clean and g_clean != c_clean:
                mut_list.append(("rosetta-ghidra-reclean", g_clean))
                for alg_g in generate_rosetta_algebraic_mutations(g_clean, name, rom=rom, e=e):
                    mut_list.append(("rosetta-ghidra-algebra", alg_g))

        best_sc = b0
        best_code = None
        best_pr = state.get(name, {}).get("preset", "agbcc_O2")
        best_tag = ""
        matched = False

        for m_idx, (tag, m_code) in enumerate(mut_list, 1):
            sc, pr, got, ex, _ = lift.evaluate(e, m_code, manifest, target, presets[:3])
            if ex:
                lift.save_matched(e, m_code, pr, manifest, state, m_idx, tag, target=target, rom=rom, model="rosetta-math", phase_num=2)
                new_matches += 1
                matched = True
                log(f"  [+] [MATCH 100% ZERO-DIFF] {name} ({b0*100:.1f}% -> 100.0%, {e['size']}B) via {tag} #{m_idx} [{pr}]!")
                write_hud_status(name, 1.0, b0, evals=m_idx, how=tag, phase_label="ROSETTA MATCH 100%!")
                break
            if pr is not None and sc > best_sc + 1e-5:
                best_sc, best_code, best_pr, best_tag = sc, m_code, pr, tag

        if matched:
            continue

        if best_code is not None and best_sc > b0 + 1e-5:
            improved_count += 1
            status_str = "approx" if best_sc >= 0.90 else "wip"
            log(f"  [^] [MEJORA ALGEBRAICA] {name}: {b0*100:.1f}% -> {best_sc*100:.1f}% via {best_tag} [{best_pr}]")
            path = TREE_DIR / e["file"]
            lift._write_atomic(path.with_suffix(".wip.c"), best_code)
            lift._write_atomic(TREE_DIR / "collection" / "wip" / f"{name}.wip.c", best_code)
            if status_str == "approx":
                ap_txt = f"/* paridad {best_sc * 100:.1f}% preset {best_pr} ({best_tag}) */\n" + best_code
                lift._write_atomic(TREE_DIR / "approx" / f"{name}.c", ap_txt)
                lift._write_atomic(TREE_DIR / "collection" / "approx" / f"{name}.c", ap_txt)
            state[name] = {
                **state.get(name, {}),
                "status": status_str,
                "best": round(best_sc, 4),
                "preset": best_pr,
                "how": best_tag,
            }
            common.save_state(state)

        if idx % 15 == 0:
            write_hud_status(name, best_sc, b0, evals=len(mut_list), phase_label=f"ROSETTA FASE B [{idx}/{len(candidates)}]")

    common.save_state(state)
    common.sync_collection(state)
    write_hud_status("", 0.0, 0.0, phase_label="STANDBY")

    total_matched = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "matched")
    total_approx = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "approx")
    total_wip = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "wip")
    total_orphan = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "orphan")

    log("\n" + "=" * 78)
    log(" RESUMEN DE EJECUCION :: MOTOR ROSETTA SEMANTICO Y MATEMATICO (CERO TOKENS)")
    log("=" * 78)
    log(f" [+] Nuevos Matches 100% Zero-Diff:    {new_matches}")
    log(f" [^] Funciones Mejoradas en Paridad:   {improved_count}")
    log(f" [*] Funciones Huerfanas Rescatadas:   {rescued_orphans}")
    log(f" [*] Funciones No-Rastreadas Incorporadas: {evaluated_untracked}")
    log("-" * 78)
    log(f" [*] MARCADOR GLOBAL ROM: {total_matched} / {len(manifest)} Matches 1:1 ({total_matched / len(manifest) * 100:.2f}%)")
    log(f" [*] Distribucion: {total_matched} matched | {total_approx} approx (>=90%) | {total_wip} wip | {total_orphan} orphan")
    log("=" * 78)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Motor Rosetta de Decompilacion Semantica y Matematica (Cero Tokens)")
    ap.add_argument("--min-score", type=float, default=0.75, help="Paridad minima para Fase B algebraica (default: 0.75)")
    ap.add_argument("--max-score", type=float, default=0.9999, help="Paridad maxima (default: 0.9999)")
    ap.add_argument("--limit", type=int, default=0, help="Limite de funciones en Fase B (0 = todas)")
    ap.add_argument("--limit-untracked", type=int, default=0, help="Limite de funciones en Fase A (0 = todas)")
    ap.add_argument("--skip-untracked", action="store_true", help="Omitir Fase A y ejecutar solo Fase B algebraica")
    args = ap.parse_args()
    return run_rosetta_pipeline(args)


if __name__ == "__main__":
    sys.exit(main())

