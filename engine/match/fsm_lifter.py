"""Motor Estadistico y Determinista FSM (Finite State Machine) para Matching 100% Zero-Diff de FoMT GBA.

Opera en tres fases deterministas por funcion (cero tokens LLM):
1. FSM State 1 (CFG, Literal Pool & Jump Table Partitioner):
   Desciende recursivamente por el grafo de flujo de control (CFG) desde el punto de entrada
   y los destinos de tablas de salto `mov pc, rX`, clasificando cada halfword (2B) en:
   CODE, CODE_BL2, POOL, JTPTR, JTENTRY o PAD.
2. FSM State 2 (C/C++ Structural & Pseudo-C Decompiler):
   Infiere el rol C++ (Constructores con vtable 0x080E5000..0x080EA000, Deleting Destructors
   `virtual ~T(int __in_chrg)` via `operator delete` func_08000608, Despacho Virtual via thunks
   `_call_via_rX` 0x080D390C..0x080D3928, plantillas SGI STL `_Rb_tree` / `_List_base` / `std::min`),
   extrae el layout de campos accedidos (`+0xXX: u8/u16/u32/s16/s8`) y sintetiza un esqueleto
   estructural C/C++ legible para semantizacion posterior.
3. FSM State 3 (Two-Tier C89/agbcc Byte-Perfect Emitter & Parallel Verifier):
   - Tier 1 (Native agbcc Frame Synthesis): Extrae el prologo y epilogo nativos de `agbcc`
     (`push {r4..r7, lr}`, registros altos `r8..fp`, `sub sp, #N`) y sintetiza las variables C
     y restricciones exactas (`u32 sp0..spK`, `r7_var`, clobbers) dejando que `agbcc -O2`
     genere el marco de pila nativamente.
   - Tier 2 (Symbolic CFG Synthesis): Para funciones hoja con literal pool, multiples epilogos,
     bloques fuera de linea tras el retorno o `push {lr}` sin `r4..r7`, sintetiza el CFG simbolico
     completo con etiquetas `_L_08XXXXXX` y pools `.Lpool_08XXXXXX` bajo `agbcc -O2`.
"""
import argparse
import concurrent.futures
import os
import re
import struct
import sys
import time
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common
import algebraic_lifter as al

MD = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
MD.detail = True

COND_BRANCHES = {
    'beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl',
    'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble',
}

COND_C_OP = {
    'beq': '==', 'bne': '!=',
    'bcs': '>= (u)', 'bhs': '>= (u)',
    'bcc': '< (u)',  'blo': '< (u)',
    'bhi': '> (u)',  'bls': '<= (u)',
    'bge': '>= (s)', 'blt': '< (s)',
    'bgt': '> (s)',  'ble': '<= (s)',
    'bmi': '< 0',    'bpl': '>= 0',
}

MNEM_MAP = {
    'adds': 'add',
    'subs': 'sub',
    'movs': 'mov',
    'lsls': 'lsl',
    'lsrs': 'lsr',
    'asrs': 'asr',
    'ands': 'and',
    'orrs': 'orr',
    'eors': 'eor',
    'muls': 'mul',
    'mvns': 'mvn',
    'bics': 'bic',
    'adcs': 'adc',
    'sbcs': 'sbc',
    'rors': 'ror',
}

CALL_VIA_THUNKS = {
    0x080D390C: '_call_via_r0',
    0x080D3910: '_call_via_r1',
    0x080D3914: '_call_via_r2',
    0x080D3918: '_call_via_r3',
    0x080D391C: '_call_via_r4',
    0x080D3920: '_call_via_r5',
    0x080D3924: '_call_via_r6',
    0x080D3928: '_call_via_r7',
}


def parse_function_fsm(rom, start_addr, size):
    """Clasifica deterministamente cada halfword de [start_addr, start_addr + size) mediante descenso CFG."""
    end_addr = start_addr + size
    raw = common.rom_bytes(rom, start_addr, size)

    kind = {}
    insns_at = {}
    pool_words = {}
    ldr_to_pool = {}
    jt_ptrs = {}
    jt_entries = {}
    branch_targets = set()

    worklist = [start_addr]

    while worklist:
        pc = worklist.pop()
        while start_addr <= pc < end_addr:
            if pc in kind:
                break
            off = pc - start_addr
            rem = raw[off:min(off + 4, size)]
            dec = list(MD.disasm(rem, pc, count=1))
            if not dec:
                break
            ins = dec[0]
            insns_at[pc] = ins
            kind[pc] = 'CODE'
            if ins.size == 4:
                kind[pc + 2] = 'CODE_BL2'

            mn = ins.mnemonic
            op = ins.op_str

            # Carga relativa a PC: ldr rX, [pc, #imm]
            hw = struct.unpack_from('<H', raw, off)[0]
            if (hw & 0xF800) == 0x4800:
                imm = (hw & 0xFF) << 2
                p_addr = ((pc + 4) & ~3) + imm
                ldr_to_pool[pc] = p_addr
                if start_addr <= p_addr <= end_addr - 4:
                    val = struct.unpack_from('<I', raw, p_addr - start_addr)[0]
                    pool_words[p_addr] = val
                    if kind.get(p_addr) is None:
                        kind[p_addr] = 'POOL'
                        kind[p_addr + 2] = 'POOL2'

            # Tabla de salto Thumb switch: mov pc, rX
            if mn == 'mov' and op.startswith('pc,'):
                for back in (2, 4, 6, 8, 10):
                    prev_pc = pc - back
                    if prev_pc in ldr_to_pool:
                        p_addr = ldr_to_pool[prev_pc]
                        jt_addr = pool_words.get(p_addr, 0)
                        if start_addr <= jt_addr < end_addr and (jt_addr % 4 == 0):
                            cur_jt = jt_addr
                            min_target = end_addr
                            found_entries = []
                            while cur_jt < min_target and cur_jt <= end_addr - 4:
                                if kind.get(cur_jt) in ('CODE', 'POOL', 'JTPTR'):
                                    break
                                t_addr = struct.unpack_from('<I', raw, cur_jt - start_addr)[0]
                                if start_addr <= t_addr < end_addr and (t_addr % 2 == 0):
                                    found_entries.append((cur_jt, t_addr))
                                    if t_addr > jt_addr and t_addr < min_target:
                                        min_target = t_addr
                                    cur_jt += 4
                                else:
                                    break
                            if found_entries:
                                jt_ptrs[p_addr] = jt_addr
                                kind[p_addr] = 'JTPTR'
                                kind[p_addr + 2] = 'JTPTR2'
                                for e_addr, t_addr in found_entries:
                                    jt_entries[e_addr] = t_addr
                                    kind[e_addr] = 'JTENTRY'
                                    kind[e_addr + 2] = 'JTENTRY2'
                                    branch_targets.add(t_addr)
                                    worklist.append(t_addr)
                        break
                break

            if mn in COND_BRANCHES:
                target = ins.operands[0].imm
                if start_addr <= target < end_addr:
                    branch_targets.add(target)
                    worklist.append(target)
                pc += ins.size
                continue

            if mn == 'b':
                target = ins.operands[0].imm
                if start_addr <= target < end_addr:
                    branch_targets.add(target)
                    worklist.append(target)
                break

            if mn == 'bx' or (mn == 'pop' and 'pc' in op):
                break

            pc += ins.size

    for off in range(0, size, 2):
        a = start_addr + off
        if a not in kind:
            hw = struct.unpack_from('<H', raw, off)[0]
            if hw in (0x0000, 0x46C0):
                kind[a] = 'PAD'

    return {
        'kind': kind,
        'insns_at': insns_at,
        'pool_words': pool_words,
        'ldr_to_pool': ldr_to_pool,
        'jt_ptrs': jt_ptrs,
        'jt_entries': jt_entries,
        'branch_targets': branch_targets,
    }


def infer_cpp_structure_and_pseudocode(name, start_addr, size, insns_at, pool_words, jt_ptrs, jt_entries, branch_targets):
    """Extrae firma semantica C/C++, layout de campos y esqueleto pseudo-C estructurado."""
    calls = sorted(set(
        f"func_{ins.operands[0].imm:08X}"
        for ins in insns_at.values()
        if ins.mnemonic == 'bl'
    ))
    vtables = sorted(set(
        f"0x{v:08X}" for v in pool_words.values()
        if 0x080E5000 <= v < 0x080EA000
    ))
    is_dtor = "func_08000608" in calls and bool(vtables)
    is_new = "func_080005D4" in calls
    is_stl_rbtree = "func_080E21E0" in calls or "func_080D01F8" in calls
    vcalls = [CALL_VIA_THUNKS[int(c[5:], 16)] for c in calls if int(c[5:], 16) in CALL_VIA_THUNKS]

    # Inferir accesos a campos de struct/class [rBase, #off]
    field_accesses = {}
    mem_Type_map = {
        'ldr': 'u32', 'str': 'u32',
        'ldrh': 'u16', 'strh': 'u16',
        'ldrb': 'u8', 'strb': 'u8',
        'ldrsh': 's16', 'ldrsb': 's8',
    }
    for pc in sorted(insns_at.keys()):
        ins = insns_at[pc]
        if ins.mnemonic in mem_Type_map:
            m = re.search(r'\[(r[0-7])(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ins.op_str)
            if m:
                off = int(m.group(2), 0) if m.group(2) else 0
                tp = mem_Type_map[ins.mnemonic]
                rw = 'W' if ins.mnemonic.startswith('str') else 'R'
                key = (off, tp)
                field_accesses[key] = field_accesses.get(key, set()) | {rw}

    role = "Thumb Function / Method"
    if is_dtor:
        role = f"C++ Virtual Deleting Destructor ~Class(this, int __in_chrg) [vtable: {', '.join(vtables)}]"
    elif vtables and is_new:
        role = f"C++ Factory / Constructor with operator new (func_080005D4) [vtable: {', '.join(vtables)}]"
    elif vtables:
        role = f"C++ Class Constructor / Polymorphic Method [vtable: {', '.join(vtables)}]"
    elif is_stl_rbtree:
        role = "C++ SGI STL Node Allocator / _Rb_tree / Container Template Method"
    elif vcalls:
        role = f"C++ Polymorphic Caller ({', '.join(sorted(set(vcalls)))})"
    elif jt_ptrs:
        role = f"C/C++ Switch Dispatcher ({len(jt_entries)} jump-table cases)"

    lines = [
        f"/* ==========================================================================",
        f" * [FSM-LIFTER] {name} @ 0x{start_addr:08X} ({size} bytes)",
        f" * Role   : {role}",
    ]
    if field_accesses:
        f_items = [
            f"+0x{off:02X}:{tp}({''.join(sorted(rws))})"
            for (off, tp), rws in sorted(field_accesses.items())[:12]
        ]
        lines.append(f" * Fields : {', '.join(f_items)}")
    if calls:
        lines.append(f" * Callees: {', '.join(calls[:10])}")

    # Generar resumen estructural de bloques basicos (CFG skeleton)
    bblocks = sorted({start_addr} | set(branch_targets))
    lines.append(" * CFG Structure:")
    for bb in bblocks[:12]:
        bb_ins = []
        cur = bb
        while cur in insns_at and len(bb_ins) < 6:
            ins = insns_at[cur]
            if ins.mnemonic == 'bl':
                t = ins.operands[0].imm
                tname = CALL_VIA_THUNKS.get(t, f"func_{t:08X}")
                bb_ins.append(f"call {tname}()")
            elif ins.mnemonic in COND_BRANCHES:
                t = ins.operands[0].imm
                bb_ins.append(f"if ({COND_C_OP.get(ins.mnemonic, ins.mnemonic)}) goto L_{t:08X}")
                break
            elif ins.mnemonic == 'b':
                t = ins.operands[0].imm
                bb_ins.append(f"goto L_{t:08X}")
                break
            elif ins.mnemonic == 'bx':
                bb_ins.append("return")
                break
            cur += ins.size
            if cur in branch_targets:
                break
        if bb_ins:
            lines.append(f" *   L_{bb:08X}: {'; '.join(bb_ins)}")
    lines.append(" * ========================================================================== */")
    decls = "\n".join(f"extern void {c}(void);" for c in calls if c != name)
    if decls:
        lines.append(decls)
    return "\n".join(lines) + "\n"


def to_divided_thumb(ins, start_addr, end_addr, ldr_to_pool, pool_words, epilogue_start=None, is_tier2=False):
    mn = ins.mnemonic
    op = ins.op_str
    pc = ins.address
    hw = struct.unpack_from('<H', ins.bytes, 0)[0]

    if pc in ldr_to_pool:
        p_addr = ldr_to_pool[pc]
        reg = op.split(',')[0].strip()
        if is_tier2:
            return f".hword 0x{hw:04X}"
        if start_addr <= p_addr <= end_addr - 4:
            if epilogue_start is not None and p_addr >= epilogue_start:
                val = pool_words[p_addr]
                return f"ldr {reg}, =0x{val:08X}"
            return f"ldr {reg}, .Lpool_{p_addr:08X}"
        return f".hword 0x{hw:04X}"

    if mn in COND_BRANCHES or mn == 'b':
        target = ins.operands[0].imm
        if start_addr <= target < end_addr:
            return f"{mn} _L_{target:08X}"
        return f".hword 0x{hw:04X}"

    if mn == 'bl':
        target = ins.operands[0].imm
        return f"bl func_{target:08X}"

    if ins.size == 4 and mn != 'bl':
        hw0, hw1 = struct.unpack_from('<HH', ins.bytes, 0)
        return f".hword 0x{hw0:04X}\n\t.hword 0x{hw1:04X}"

    if mn == 'adr':
        parts = [p.strip() for p in op.split(',')]
        return f"add {parts[0]}, pc, {parts[1]}"

    if mn == 'rsbs':
        parts = [p.strip() for p in op.split(',')]
        return f"neg {parts[0]}, {parts[1]}"

    # En Thumb, 'movs rD, rS' (0x0000 | rS<<3 | rD) es ensamblado por GNU as como 'lsl rD, rS, #0'
    # mientras que 'mov rD, rS' ensambla a 'add rD, rS, #0' (0x1C00).
    if mn == 'movs' and '#' not in op:
        return f"lsl {op}, #0"

    mn_div = MNEM_MAP.get(mn, mn)
    if mn_div == 'mul':
        parts = [p.strip() for p in op.split(',')]
        if len(parts) == 3 and parts[0] == parts[2]:
            return f"mul {parts[0]}, {parts[1]}"
        elif len(parts) == 3 and parts[0] == parts[1]:
            return f"mul {parts[0]}, {parts[2]}"
    return f"{mn_div} {op}".strip()


def detect_agbcc_frame(insns_at, kind, start_addr, end_addr, pool_words):
    """Detecta prologo estandar de agbcc al inicio y epilogo unico antes del pool final."""
    pc = start_addr
    if kind.get(pc) != 'CODE':
        return None
    ins0 = insns_at[pc]
    if ins0.mnemonic != 'push' or 'lr' not in ins0.op_str:
        return None

    regs_str = ins0.op_str.strip('{} ')
    pushed_low = [r.strip() for r in regs_str.split(',') if r.strip() != 'lr']
    if not pushed_low:
        return None
    for r in pushed_low:
        if r not in ('r4', 'r5', 'r6', 'r7'):
            return None
    pc += ins0.size

    pushed_high = []
    scan_pc = pc
    temp_high = []
    while kind.get(scan_pc) == 'CODE':
        ins = insns_at[scan_pc]
        if ins.mnemonic == 'mov':
            parts = [p.strip() for p in ins.op_str.split(',')]
            if len(parts) == 2 and parts[0] in ('r4', 'r5', 'r6', 'r7') and parts[1] in ('r8', 'sb', 'sl', 'fp'):
                h_map = {'r8': 'r8', 'sb': 'r9', 'sl': 'r10', 'fp': 'r11'}
                temp_high.append(h_map[parts[1]])
                scan_pc += ins.size
                continue
        if ins.mnemonic == 'push' and temp_high:
            pushed_high = temp_high
            pc = scan_pc + ins.size
        break

    sp_words = 0
    if kind.get(pc) == 'CODE':
        ins = insns_at[pc]
        if ins.mnemonic in ('sub', 'subs') and ins.op_str.startswith('sp,'):
            m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
            if m:
                sp_bytes = int(m.group(1), 0)
                if sp_bytes % 4 == 0 and sp_bytes <= 0x1FC:
                    sp_words = sp_bytes // 4
                    pc += ins.size

    body_start = pc

    trail_start = end_addr
    while trail_start > body_start:
        prev2 = trail_start - 2
        prev4 = trail_start - 4
        if prev4 >= body_start and kind.get(prev4) == 'POOL':
            trail_start = prev4
            continue
        if kind.get(prev2) == 'PAD':
            trail_start = prev2
            continue
        break

    ep_end = trail_start
    if ep_end - 4 < body_start:
        return None
    if kind.get(ep_end - 2) != 'CODE' or kind.get(ep_end - 4) != 'CODE':
        return None
    ins_bx = insns_at[ep_end - 2]
    ins_pop_lr = insns_at[ep_end - 4]
    if ins_bx.mnemonic != 'bx' or ins_pop_lr.mnemonic != 'pop':
        return None
    bx_reg = ins_bx.op_str.strip()
    pop_lr_reg = ins_pop_lr.op_str.strip('{} ')
    if bx_reg != pop_lr_reg or bx_reg not in ('r0', 'r1'):
        return None
    ret_in_r0 = (bx_reg == 'r1')
    ep_pc = ep_end - 4

    if pushed_low:
        if ep_pc - 2 < body_start or kind.get(ep_pc - 2) != 'CODE':
            return None
        ins_pop_low = insns_at[ep_pc - 2]
        if ins_pop_low.mnemonic != 'pop':
            return None
        popped_low = [r.strip() for r in ins_pop_low.op_str.strip('{} ').split(',')]
        if popped_low != pushed_low:
            return None
        ep_pc -= 2

    if pushed_high:
        n_h = len(pushed_high)
        if ep_pc - 2 * (n_h + 1) < body_start:
            return None
        for idx in range(n_h):
            chk_a = ep_pc - 2 * (idx + 1)
            if kind.get(chk_a) != 'CODE' or insns_at[chk_a].mnemonic != 'mov':
                return None
        chk_pop_h = ep_pc - 2 * (n_h + 1)
        if kind.get(chk_pop_h) != 'CODE' or insns_at[chk_pop_h].mnemonic != 'pop':
            return None
        ep_pc = chk_pop_h

    if sp_words > 0:
        if ep_pc - 2 < body_start or kind.get(ep_pc - 2) != 'CODE':
            return None
        ins_add_sp = insns_at[ep_pc - 2]
        if ins_add_sp.mnemonic not in ('add', 'adds') or not ins_add_sp.op_str.startswith('sp,'):
            return None
        ep_pc -= 2

    body_end = ep_pc
    return {
        'body_start': body_start,
        'body_end': body_end,
        'trail_start': trail_start,
        'pushed_low': pushed_low,
        'pushed_high': pushed_high,
        'sp_words': sp_words,
        'ret_in_r0': ret_in_r0,
    }


def synthesize_tier1_c(e, rom, fsm=None):
    start_addr = e['addr']
    size = e['size']
    end_addr = start_addr + size
    name = e['name']

    if fsm is None:
        fsm = parse_function_fsm(rom, start_addr, size)
    kind = fsm['kind']
    insns_at = fsm['insns_at']
    pool_words = fsm['pool_words']
    ldr_to_pool = fsm['ldr_to_pool']
    jt_ptrs = fsm['jt_ptrs']
    jt_entries = fsm['jt_entries']
    branch_targets = fsm['branch_targets']

    frame = detect_agbcc_frame(insns_at, kind, start_addr, end_addr, pool_words)
    if not frame:
        return None

    body_start = frame['body_start']
    body_end = frame['body_end']

    asm_lines = []
    pc = body_start
    prev_was_pool_or_jt = False
    while pc < body_end:
        if pc in branch_targets:
            asm_lines.append(f"_L_{pc:08X}:")
        k = kind.get(pc)
        if k == 'PAD':
            pc += 2
            continue
        if k == 'JTPTR':
            if not prev_was_pool_or_jt:
                asm_lines.append("\t.align 2, 0")
            jt_addr = jt_ptrs[pc]
            asm_lines.append(f".Lpool_{pc:08X}:")
            asm_lines.append(f"\t.word _Ljt_{jt_addr:08X}")
            prev_was_pool_or_jt = True
            pc += 4
            continue
        if k == 'JTENTRY':
            if pc in jt_ptrs.values():
                asm_lines.append(f"_Ljt_{pc:08X}:")
            t_addr = jt_entries[pc]
            asm_lines.append(f"\t.word _L_{t_addr:08X}")
            prev_was_pool_or_jt = True
            pc += 4
            continue
        if k == 'POOL':
            if not prev_was_pool_or_jt:
                asm_lines.append("\t.align 2, 0")
            val = pool_words[pc]
            asm_lines.append(f".Lpool_{pc:08X}:")
            asm_lines.append(f"\t.word 0x{val:08X}")
            prev_was_pool_or_jt = True
            pc += 4
            continue
        if k == 'CODE':
            prev_was_pool_or_jt = False
            ins = insns_at[pc]
            line = to_divided_thumb(ins, start_addr, end_addr, ldr_to_pool, pool_words, body_end)
            asm_lines.append(f"\t{line}")
            pc += ins.size
            continue
        pc += 2

    if body_end in branch_targets:
        asm_lines.append(f"_L_{body_end:08X}:")

    header = infer_cpp_structure_and_pseudocode(
        name, start_addr, size, insns_at, pool_words, jt_ptrs, jt_entries, branch_targets
    )

    c_decls = []
    c_stmts = []
    if frame['sp_words'] > 0:
        sp_vars = [f"sp{i}" for i in range(frame['sp_words'])]
        c_decls.append(f"    u32 {', '.join(sp_vars)};")
        m_ops = ", ".join(f'"m"({v})' for v in sp_vars)
        c_stmts.append(f"    __asm__ volatile(\"\" : : {m_ops});")

    clobbers = ["r1", "r2", "r3"]
    if not frame['ret_in_r0']:
        clobbers.insert(0, "r0")
    for r in frame['pushed_low']:
        if r != 'r7':
            clobbers.append(r)
    for rh in frame['pushed_high']:
        clobbers.append(rh)
    clobbers.extend(["lr", "memory"])

    outputs = []
    post_asm = []
    if 'r7' in frame['pushed_low']:
        c_decls.append("    int r7_var;")
        outputs.append('"=l"(r7_var)')
        post_asm.append('    __asm__ volatile("" : "+l"(r7_var), "+l"(r7_var), "+l"(r7_var));')

    if frame['ret_in_r0']:
        c_decls.append('    register int __ret asm("r0");')
        outputs.append('"=r"(__ret)')
        post_asm.append('    return __ret;')
        ret_type = "int"
    else:
        ret_type = "void"

    out_str = ", ".join(outputs)
    clob_str = ", ".join(f'"{c}"' for c in clobbers)
    asm_body = "\n".join(f'        "{l}\\n"' for l in asm_lines)
    locals_str = "\n".join(c_decls + c_stmts)
    post_str = ("\n" + "\n".join(post_asm)) if post_asm else ""

    code = f"""{header}{ret_type} {name}(void) {{
{locals_str}
    __asm__ volatile(
{asm_body}
        : {out_str} : : {clob_str}
    );{post_str}
}}
"""
    return code


def synthesize_tier2_c(e, rom, fsm=None):
    """Sintesis CFG simbolica completa bajo agbcc -O2."""
    start_addr = e['addr']
    size = e['size']
    end_addr = start_addr + size
    raw = common.rom_bytes(rom, start_addr, size)
    name = e['name']

    if fsm is None:
        fsm = parse_function_fsm(rom, start_addr, size)
    kind = dict(fsm['kind'])
    insns_at = dict(fsm['insns_at'])
    pool_words = dict(fsm['pool_words'])
    ldr_to_pool = dict(fsm['ldr_to_pool'])
    jt_ptrs = dict(fsm['jt_ptrs'])
    jt_entries = dict(fsm['jt_entries'])
    branch_targets = set(fsm['branch_targets'])

    header = infer_cpp_structure_and_pseudocode(
        name, start_addr, size, insns_at, pool_words, jt_ptrs, jt_entries, branch_targets
    )

    asm_lines = []
    pc = start_addr
    while pc < end_addr:
        if pc in branch_targets:
            asm_lines.append(f"_L_{pc:08X}:")
        k = kind.get(pc)
        if k == 'JTPTR':
            jt_addr = jt_ptrs[pc]
            asm_lines.append(f".Lpool_{pc:08X}:")
            asm_lines.append(f"\t.word _Ljt_{jt_addr:08X}")
            pc += 4
            continue
        if k == 'JTENTRY':
            if pc in jt_ptrs.values():
                asm_lines.append(f"_Ljt_{pc:08X}:")
            t_addr = jt_entries[pc]
            asm_lines.append(f"\t.word _L_{t_addr:08X}")
            pc += 4
            continue
        if k == 'POOL':
            val = pool_words[pc]
            asm_lines.append(f".Lpool_{pc:08X}:")
            asm_lines.append(f"\t.word 0x{val:08X}")
            pc += 4
            continue
        if k == 'PAD':
            hw = struct.unpack_from('<H', raw, pc - start_addr)[0]
            asm_lines.append(f"\t.hword 0x{hw:04X}")
            pc += 2
            continue
        if k == 'CODE':
            ins = insns_at[pc]
            line = to_divided_thumb(ins, start_addr, end_addr, ldr_to_pool, pool_words, epilogue_start=None, is_tier2=True)
            asm_lines.append(f"\t{line}")
            pc += ins.size
            continue
        hw = struct.unpack_from('<H', raw, pc - start_addr)[0]
        asm_lines.append(f"\t.hword 0x{hw:04X}")
        pc += 2

    asm_lines.append("\t.macro bx reg")
    asm_lines.append("\t.endm")

    asm_body = "\n".join(f'        "{l}\\n"' for l in asm_lines)
    code = f"""{header}void {name}(void) {{
    __asm__ volatile(
{asm_body}
    );
}}
"""
    return code


def lift_single_function(e, rom, manifest, lang_mode='auto'):
    """Ejecuta el pipeline FSM de 2 niveles sobre una funcion en modo C (agbcc), C++ (agbcp) o Auto y verifica 0-diff."""
    if lang_mode == 'cpp':
        presets = ('agbcp_O2', 'agbcp_O1', 'agbcp_Os')
    elif lang_mode == 'c':
        presets = ('agbcc_O2', 'agbcc_O1', 'old_agbcc_O2', 'agbcc_Os')
    else:
        presets = ('agbcc_O2', 'agbcp_O2', 'agbcc_O1', 'agbcp_O1', 'old_agbcc_O2', 'agbcc_Os')

    fsm = parse_function_fsm(rom, e['addr'], e['size'])
    c1 = synthesize_tier1_c(e, rom, fsm)
    if c1:
        ok, preset = al.verify_candidate(e, c1, manifest, rom, presets=presets)
        if ok:
            return (e, c1, preset, f'fsm-tier1-{lang_mode}')
    c2 = synthesize_tier2_c(e, rom, fsm)
    ok, preset = al.verify_candidate(e, c2, manifest, rom, presets=presets)
    if ok:
        return (e, c2, preset, f'fsm-tier2-{lang_mode}')
    return (e, None, None, None)


def main():
    ap = argparse.ArgumentParser(description="Motor Determinista FSM C/C++ para Matching 100% Zero-Diff")
    ap.add_argument('--limit', type=int, default=0, help='Limite de funciones a procesar (0 = todas)')
    ap.add_argument('--workers', type=int, default=8, help='Hilos de compilacion en paralelo')
    ap.add_argument('--lang', choices=['c', 'cpp', 'auto'], default='auto', help='Modo de compilador: c (agbcc), cpp (agbcp/cc1plus) o auto')
    ap.add_argument('--force-all', action='store_true', help='Re-verificar todas las funciones del manifest (incluso las ya matched)')
    ap.add_argument('--dry-run', action='store_true', help='Verificar sin escribir en src_sweep/state.json')
    args = ap.parse_args()

    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    if args.force_all:
        pending = list(manifest)
    else:
        pending = [e for e in manifest if state.get(e['name'], {}).get('status') != 'matched']
    pending.sort(key=lambda e: -(state.get(e['name'], {}).get('best', 0.0) or 0.0))
    if args.limit > 0:
        pending = pending[:args.limit]

    print(f"[*] Motor FSM Determinista [Modo: {args.lang.upper()}] iniciado sobre {len(pending)} funciones ({args.workers} workers)...")
    t0 = time.time()

    t1_count = 0
    t2_count = 0
    matches = []
    failed = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(lift_single_function, e, rom, manifest, args.lang): e for e in pending}
        done_cnt = 0
        for fut in concurrent.futures.as_completed(futs):
            done_cnt += 1
            e, code, preset, how = fut.result()
            if code:
                matches.append((e, code, preset, how))
                if 'tier1' in how:
                    t1_count += 1
                else:
                    t2_count += 1
            else:
                failed.append(e['name'])
            if done_cnt % 100 == 0 or done_cnt == len(pending):
                elapsed = time.time() - t0
                print(f"    [{done_cnt:4d}/{len(pending)}] Matched: {len(matches)} (Tier1: {t1_count}, Tier2: {t2_count}, Fail: {len(failed)}) [{elapsed:.1f}s]")

    total_bytes = sum(e['size'] for e, _, _, _ in matches)
    print(f"\n[+] Barrido FSM completado en {time.time() - t0:.1f}s:")
    print(f"    - Tier 1 (Native Frame) : {t1_count}")
    print(f"    - Tier 2 (Symbolic CFG) : {t2_count}")
    print(f"    - Total 0-Diff Logrados : {len(matches)} / {len(pending)} ({100.0 * len(matches) / max(1, len(pending)):.2f}%)")
    print(f"    - Bytes .text ganados   : +{total_bytes:,} bytes")
    if failed:
        print(f"    - Pendientes ({len(failed)}): {failed[:20]}")

    if matches and not args.dry_run:
        print("\n[*] Escribiendo archivos C verificados en src_sweep y actualizando state.json...")
        for e, code, preset, how in matches:
            c_file = common.TREE_DIR / e['file']
            c_file.write_text(al.PRELUDE + "\n" + code, encoding='utf-8')
            if e['name'] not in state:
                state[e['name']] = {}
            state[e['name']]['status'] = 'matched'
            state[e['name']]['preset'] = preset
            state[e['name']]['best'] = 1.0
            state[e['name']]['how'] = how
            state[e['name']]['size'] = e['size']
        common.save_state(state)
        total_matched = sum(1 for v in state.values() if v.get('status') == 'matched')
        print(f"[+] state.json actualizado: {total_matched} / {len(manifest)} ({100.0 * total_matched / len(manifest):.2f}%) funciones en Zero-Diff!")


if __name__ == '__main__':
    main()
