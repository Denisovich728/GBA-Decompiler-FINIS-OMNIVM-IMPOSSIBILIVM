"""FOMT-MATCH-ENGINE :: SINTETIZADOR ALGEBRAICO DETERMINISTA (0 TOKENS).

Deduce codigo C exacto para funciones sin saltos (M = 1, bloques basicos puros)
utilizando analisis algebraico de instrucciones Thumb, mapeo de memoria y biyeccion
canonica con GCC 2.95.2 (agbcc).

Patrones implementados:
  P0: NOP / Dummy function (bx lr / movs r0, r0)
  P1: Retorno constante (movs r0, #imm; bx lr)
  P2: Desreferencia simple / Getter escalar (ldr/ldrh/ldrb r0, [r0, #offset]; bx lr)
  P3: Doble desreferencia / Pointer to struct member (ldr r0, [r0]; ldr/ldrh/ldrb r0, [r0, #off]; bx lr)
  P4: Setter directo a cero o constante (movs r1, #c; str/strh/strb r1, [r0, #off]; bx lr)
  P5: Pointer offset addition / Struct pointer navigation (ldr r0, [r0]; adds r0, #offset; bx lr)
  P6: Retorno de argumento directo / Identidad (bx lr)
  P7: Bitfield accessor / Mascara de bits (ldrb r0, [r0, #off]; movs r1, #mask; ands r0, r1; bx lr)
  P8: Literal pointer store (ldr r1, [pc, #imm]; str r1, [r0]; bx lr)

Uso:
  python tools/match/algebraic_lifter.py --scan          # Muestra funciones elegibles
  python tools/match/algebraic_lifter.py --run           # Ejecuta sintesis y aplica matches exactos
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import common
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

PRELUDE = """typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed char s8;
typedef short s16;
typedef int s32;
#ifndef __cplusplus
typedef u32 bool;
#define true 1
#define false 0
#endif
#define NULL 0
"""


def get_clean_insns(rom, addr, size):
    off = addr - 0x08000000
    code = rom[off:off+size]
    insns = list(MD.disasm(code, addr))
    # Filtrar padding final (movs r0, r0 tras bx lr o pop pc)
    clean = []
    for i in insns:
        clean.append(i)
        if i.mnemonic == 'bx' and i.op_str in ('lr', 'r0', 'r1', 'r2', 'r3'):
            break
        if i.mnemonic == 'pop' and 'pc' in i.op_str:
            break
    return clean


def synthesize_candidate(e, insns, rom):
    name = e['name']
    try:
        from retro_exact_map import RETRO_EXACT_MAP
        if name in RETRO_EXACT_MAP:
            return RETRO_EXACT_MAP[name] + "\n"
    except ImportError:
        pass
    n = len(insns)
    if n == 0:
        return None

    # Mnemónicos y operandos (sin partir comas dentro de corchetes [...] o llaves {...})
    ops = [(i.mnemonic, [x.strip() for x in re.split(r',\s*(?![^\[\{]*[\]\}])', i.op_str)]) for i in insns]

    # --- P0: NOP / Return void ---
    # [bx lr]
    if n == 1 and ops[0][0] == 'bx' and ops[0][1][0] == 'lr':
        return f"void {name}(void) {{\n}}\n"

    # --- P1: Return Constant ---
    # [movs r0, #imm; bx lr]
    if n == 2 and ops[0][0] == 'movs' and ops[0][1][0] == 'r0' and ops[1][0] == 'bx' and ops[1][1][0] == 'lr':
        imm_str = ops[0][1][1].lstrip('#')
        imm = int(imm_str, 0)
        return f"u32 {name}(void) {{\n    return {imm};\n}}\n"

    # --- P4: Setter simple a cero o constante ---
    # [movs r1, #c; str/strh/strb r1, [r0, #off]; bx lr]
    if n == 3 and ops[0][0] == 'movs' and ops[0][1][0] == 'r1' and ops[2][0] == 'bx':
        st_mnem = ops[1][0]
        if st_mnem in ('str', 'strh', 'strb') and ops[1][1][0] == 'r1':
            imm_c = ops[0][1][1].lstrip('#')
            val = int(imm_c, 0)
            mem = ops[1][1][1] # [r0] o [r0, #off]
            m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', mem)
            if m_off:
                off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
                tp = 'u32' if st_mnem == 'str' else ('u16' if st_mnem == 'strh' else 'u8')
                if off_val == 0:
                    return f"void {name}({tp} *arg0) {{\n    *arg0 = {val};\n}}\n"
                else:
                    return f"void {name}(u8 *arg0) {{\n    *({tp} *)(arg0 + {off_val}) = {val};\n}}\n"

    # --- P4b: Setter con valor pasado en arg1 ---
    # [str/strh/strb r1, [r0, #off]; bx lr]
    if n == 2 and ops[1][0] == 'bx' and ops[0][0] in ('str', 'strh', 'strb') and ops[0][1][0] == 'r1':
        st_mnem = ops[0][0]
        mem = ops[0][1][1]
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', mem)
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            tp = 'u32' if st_mnem == 'str' else ('u16' if st_mnem == 'strh' else 'u8')
            if off_val == 0:
                return f"void {name}({tp} *arg0, {tp} arg1) {{\n    *arg0 = arg1;\n}}\n"
            else:
                return f"void {name}(u8 *arg0, {tp} arg1) {{\n    *({tp} *)(arg0 + {off_val}) = arg1;\n}}\n"

    # --- P4c: Zeroing multiple words (bzero / zero struct) ---
    # [movs r1, #0; str r1, [r0]; str r1, [r0, #4]...; bx lr]
    if n >= 3 and ops[0] == ('movs', ['r1', '#0']) and ops[-1][0] == 'bx':
        all_strs = True
        str_lines = []
        for op in ops[1:-1]:
            if op[0] == 'str' and op[1][0] == 'r1':
                m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', op[1][1])
                off_val = int(m_off.group(1), 0) if (m_off and m_off.group(1)) else 0
                idx = off_val // 4
                str_lines.append(f"    arg0[{idx}] = 0;")
            else:
                all_strs = False
                break
        if all_strs and str_lines:
            return f"void {name}(u32 *arg0) {{\n" + "\n".join(str_lines) + "\n}\n"

    # --- P2b: Adds r0, #off + ldr/ldrb (offset grande que excede inmediato Thumb) ---
    # [adds r0, #off; ldr/ldrh/ldrb r0, [r0]; bx lr]
    if n == 3 and ops[0][0] in ('adds', 'add') and ops[0][1][0] == 'r0' and ops[2][0] == 'bx':
        imm_off = ops[0][1][1].lstrip('#')
        off_val = int(imm_off, 0)
        ld_mnem = ops[1][0]
        if ld_mnem in ('ldr', 'ldrh', 'ldrb', 'ldsh', 'ldsb') and ops[1][1] == ['r0', '[r0]']:
            tp_ret = 'u32' if ld_mnem == 'ldr' else ('u16' if ld_mnem == 'ldrh' else ('u8' if ld_mnem == 'ldrb' else ('s16' if ld_mnem == 'ldsh' else 's8')))
            return f"{tp_ret} {name}(u8 *arg0) {{\n    return *({tp_ret} *)(arg0 + {off_val});\n}}\n"

    # --- P9: Global variable reader via literal pool ---
    # [ldr r0, [pc, #imm]; ldr/ldrh/ldrb r0, [r0]; bx lr]
    if n == 3 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and '[pc' in ops[0][1][1] and ops[2][0] == 'bx':
        ld_mnem = ops[1][0]
        if ld_mnem in ('ldr', 'ldrh', 'ldrb', 'ldsh', 'ldsb') and ops[1][1] == ['r0', '[r0]']:
            ins = insns[0]
            base = (ins.address + 4) & ~3
            m_imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
            disp = int(m_imm.group(1), 0) if m_imm else 0
            pool_addr = base + disp
            rom_off = pool_addr - 0x08000000
            val = int.from_bytes(rom[rom_off:rom_off+4], 'little')
            tp_ret = 'u32' if ld_mnem == 'ldr' else ('u16' if ld_mnem == 'ldrh' else ('u8' if ld_mnem == 'ldrb' else 's16'))
            return f"{tp_ret} {name}(void) {{\n    return *({tp_ret} *)0x{val:08X};\n}}\n"

    # --- P2: Getter simple de memoria ---
    # [ldr/ldrh/ldrb r0, [r0, #off]; bx lr]
    if n == 2 and ops[1][0] == 'bx' and ops[1][1][0] == 'lr':
        ld_mnem = ops[0][0]
        if ld_mnem in ('ldr', 'ldrh', 'ldrb', 'ldsh', 'ldsb') and ops[0][1][0] == 'r0':
            mem = ops[0][1][1]
            m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', mem)
            if m_off:
                off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
                tp_ret = 'u32' if ld_mnem == 'ldr' else ('u16' if ld_mnem == 'ldrh' else ('u8' if ld_mnem == 'ldrb' else ('s16' if ld_mnem == 'ldsh' else 's8')))
                if off_val == 0:
                    return f"{tp_ret} {name}({tp_ret} *arg0) {{\n    return *arg0;\n}}\n"
                else:
                    return f"{tp_ret} {name}(u8 *arg0) {{\n    return *({tp_ret} *)(arg0 + {off_val});\n}}\n"

    # --- P3: Doble desreferencia / struct member pointer ---
    # [ldr r0, [r0]; ldr/ldrh/ldrb r0, [r0, #off]; bx lr]
    if n == 3 and ops[0] == ('ldr', ['r0', '[r0]']) and ops[2][0] == 'bx':
        ld_mnem = ops[1][0]
        if ld_mnem in ('ldr', 'ldrh', 'ldrb', 'ldsh', 'ldsb') and ops[1][1][0] == 'r0':
            mem = ops[1][1][1]
            m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', mem)
            if m_off:
                off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
                tp_ret = 'u32' if ld_mnem == 'ldr' else ('u16' if ld_mnem == 'ldrh' else ('u8' if ld_mnem == 'ldrb' else ('s16' if ld_mnem == 'ldsh' else 's8')))
                if off_val == 0:
                    return f"{tp_ret} {name}({tp_ret} **arg0) {{\n    return **arg0;\n}}\n"
                else:
                    return f"{tp_ret} {name}(u8 **arg0) {{\n    return *({tp_ret} *)(*arg0 + {off_val});\n}}\n"

    # --- P5: Pointer Navigation / Offset Addition ---
    # [ldr r0, [r0]; adds r0, #off; bx lr]
    if n == 3 and ops[0] == ('ldr', ['r0', '[r0]']) and ops[1][0] in ('adds', 'add') and ops[2][0] == 'bx':
        if ops[1][1][0] == 'r0':
            imm_off = ops[1][1][1].lstrip('#')
            off_val = int(imm_off, 0)
            return f"void *{name}(u8 **arg0) {{\n    return *arg0 + {off_val};\n}}\n"

    # --- P10: Pointer offset return ---
    # [adds r0, #imm; bx lr]
    if n == 2 and ops[0][0] in ('adds', 'add') and ops[0][1][0] == 'r0' and ops[1][0] == 'bx' and ops[1][1][0] == 'lr':
        imm_off = ops[0][1][1].lstrip('#')
        off_val = int(imm_off, 0)
        return f"u8 *{name}(u8 *arg0) {{\n    return arg0 + {off_val};\n}}\n"

    # --- P11: Bitfield Getter (ldrb + lsls + lsrs + bx lr) ---
    # [ldrb r0, [r0...]; lsls r0, r0, #s1; lsrs r0, r0, #s2; bx lr]
    if n == 4 and ops[0][0] == 'ldrb' and ops[0][1][0] == 'r0' and ops[1][0] == 'lsls' and ops[2][0] == 'lsrs' and ops[3][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            s1 = int(ops[1][1][2].lstrip('#'), 0)
            s2 = int(ops[2][1][2].lstrip('#'), 0)
            # Algebra: (x << s1) >> s2
            access = f"*arg0" if off_val == 0 else f"*(arg0 + {off_val})"
            return f"u32 {name}(u8 *arg0) {{\n    return ((u32){access} << {s1}) >> {s2};\n}}\n"

    # --- P12: Bit Setter (ldrb + movs + orrs + strb + bx lr) ---
    # [ldrb r1, [r0...]; movs r2, #imm; orrs r1, r2; strb r1, [r0...]; bx lr]
    if n >= 5 and ops[0][0] == 'ldrb' and ops[1][0] == 'movs' and ops[2][0] == 'orrs' and ops[3][0] == 'strb' and ops[4][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            mask_val = int(ops[1][1][1].lstrip('#'), 0)
            access = f"*arg0" if off_val == 0 else f"*(arg0 + {off_val})"
            return f"void {name}(u8 *arg0) {{\n    {access} |= {mask_val};\n}}\n"

    # --- P13: Tail-call simple (push {lr}; bl target; pop {rX}; bx rX) ---
    if n in (4, 5) and ops[0][0] == 'push' and ops[1][0] == 'bl':
        target_str = ops[1][1][0].lstrip('#')
        target_addr = int(target_str, 0)
        target_func = f"func_{target_addr:08X}"
        pop_reg = ops[2][1][0].strip('{}')
        if pop_reg == 'r0':
            return f"void {target_func}(void);\nvoid {name}(void) {{\n    {target_func}();\n}}\n"
        else:
            return f"int {target_func}(void);\nint {name}(void) {{\n    return {target_func}();\n}}\n"

    # --- P8: Literal pointer store ---
    # [ldr r1, [pc, #imm]; str r1, [r0]; bx lr]
    if n == 3 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and '[pc' in ops[0][1][1] and ops[1] == ('str', ['r1', '[r0]']) and ops[2][0] == 'bx':
        # Leer el literal de la ROM
        ins = insns[0]
        base = (ins.address + 4) & ~3
        m_imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        disp = int(m_imm.group(1), 0) if m_imm else 0
        pool_addr = base + disp
        rom_off = pool_addr - 0x08000000
        val = int.from_bytes(rom[rom_off:rom_off+4], 'little')
        return f"void {name}(u32 *arg0) {{\n    *arg0 = 0x{val:08X};\n}}\n"

    def read_pc_lit(ins_obj):
        base = (ins_obj.address + 4) & ~3
        m_imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins_obj.op_str)
        disp = int(m_imm.group(1), 0) if m_imm else 0
        pool_addr = base + disp
        rom_off = pool_addr - 0x08000000
        return int.from_bytes(rom[rom_off:rom_off+4], 'little')

    # --- P14: Setter con offset grande (adds r0, #off; movs r1, #val; str/strh/strb r1, [r0]; bx lr) ---
    if n == 4 and ops[0][0] in ('adds', 'add') and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[1][1][0] == 'r1' and ops[2][0] in ('str', 'strh', 'strb') and ops[3][0] == 'bx':
        if ops[2][1] == ['r1', '[r0]']:
            off_val = int(ops[0][1][1].lstrip('#'), 0)
            val = int(ops[1][1][1].lstrip('#'), 0)
            st_mnem = ops[2][0]
            tp = 'u32' if st_mnem == 'str' else ('u16' if st_mnem == 'strh' else 'u8')
            return f"void {name}(u8 *arg0) {{\n    *({tp} *)(arg0 + {off_val}) = {val};\n}}\n"

    # --- P15: Signed getter con registro offset (movs r1, #off; ldrsh/ldrsb r0, [r0, r1]; bx lr) ---
    if n == 3 and ops[0][0] == 'movs' and ops[0][1][0] == 'r1' and ops[1][0] in ('ldrsh', 'ldrsb', 'ldsh', 'ldsb') and ops[2][0] == 'bx':
        off_val = int(ops[0][1][1].lstrip('#'), 0)
        tp = 's16' if 'h' in ops[1][0] else 's8'
        return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + {off_val});\n}}\n"

    # --- P16: Pointer member + offset (ldr r0, [r0, #off1]; adds r0, #off2; bx lr) ---
    if n == 3 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] in ('adds', 'add') and ops[1][1][0] == 'r0' and ops[2][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off1 = int(m_off.group(1), 0) if m_off.group(1) else 0
            off2 = int(ops[1][1][1].lstrip('#'), 0)
            return f"u8 *{name}(u8 *arg0) {{\n    return *(u8 **)(arg0 + {off1}) + {off2};\n}}\n"

    # --- P17: Word/Halfword Bitfield Getter (ldr/ldrh r0, [r0...]; lsls r0, r0, #s1; lsrs/asrs r0, r0, #s2; bx lr) ---
    if n == 4 and ops[0][0] in ('ldr', 'ldrh') and ops[0][1][0] == 'r0' and ops[1][0] == 'lsls' and ops[2][0] in ('lsrs', 'asrs') and ops[3][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            s1 = int(ops[1][1][2].lstrip('#'), 0)
            s2 = int(ops[2][1][2].lstrip('#'), 0)
            cast_tp = 'u32' if ops[2][0] == 'lsrs' else 's32'
            mem_tp = 'u32' if ops[0][0] == 'ldr' else 'u16'
            access = f"*({mem_tp} *)(arg0 + {off_val})" if off_val else f"*({mem_tp} *)arg0"
            return f"{cast_tp} {name}(u8 *arg0) {{\n    return (({cast_tp}){access} << {s1}) >> {s2};\n}}\n"

    # --- P18: Table lookup via global symbol (ldr r0, [pc, #imm]; lsls r1, r1, #1/#2; adds r1, r1, r0; ldrh/ldr r0, [r1]; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and '[pc' in ops[0][1][1] and ops[1][0] == 'lsls' and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldrh', 'ldr', 'ldrb') and ops[4][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        ld_m = ops[3][0]
        tp = 'u16' if ld_m == 'ldrh' else ('u32' if ld_m == 'ldr' else 'u8')
        return f"extern const {tp} g_{lit_val:08X}[];\n{tp} {name}(void *arg0, u32 arg1) {{\n    return g_{lit_val:08X}[arg1];\n}}\n"

    # --- P19a: Pointer member + literal offset deref (ldr r0, [r0, #off]; ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb/ldrh/ldr r0, [r0]; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'ldr' and ops[1][1][0] == 'r1' and '[pc' in ops[1][1][1] and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldrb', 'ldrh', 'ldr') and ops[4][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off and ops[3][1] == ['r0', '[r0]']:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            lit_val = read_pc_lit(insns[1])
            ld_m = ops[3][0]
            tp = 'u8' if ld_m == 'ldrb' else ('u16' if ld_m == 'ldrh' else 'u32')
            idx = off_val // 4
            return f"{tp} {name}(u32 *arg0) {{\n    return *({tp} *)(arg0[{idx}] + 0x{lit_val:X});\n}}\n"

    # --- P19b: Pointer member + literal offset (ldr r0, [r0, #off]; ldr r1, [pc, #imm]; adds r0, r0, r1; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'ldr' and ops[1][1][0] == 'r1' and '[pc' in ops[1][1][1] and ops[2][0] in ('adds', 'add') and ops[3][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            lit_val = read_pc_lit(insns[1])
            idx = off_val // 4
            return f"u32 {name}(u32 *arg0) {{\n    return arg0[{idx}] + 0x{lit_val:X};\n}}\n"

    # --- P20: Mul + add literal (ldr r0, [pc, #imm]; muls r0, r1, r0; adds r0, #off; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1][0] == 'muls' and ops[2][0] in ('adds', 'add') and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        off_val = int(ops[2][1][1].lstrip('#'), 0)
        return f"u32 {name}(u32 arg0, u32 arg1) {{\n    u32 c;\n    asm(\"ldr %0, =0x{lit_val:X}\" : \"=r\"(c));\n    return arg1 * c + {off_val};\n}}\n"

    # --- P21: Global word shift (ldr r0, [pc, #imm]; ldr r0, [r0]; lsrs r0, r0, #s; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1] == ('ldr', ['r0', '[r0]']) and ops[2][0] == 'lsrs' and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        sh = int(ops[2][1][2].lstrip('#'), 0)
        return f"u32 {name}(void) {{\n    return *(u32 *)0x{lit_val:08X} >> {sh};\n}}\n"

    # --- P22a: Atomic swap word through double pointer (ldr r2, [r0]; ldr r0, [r2]; str r1, [r2]; bx lr) ---
    if n == 4 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1] == ('ldr', ['r0', '[r2]']) and ops[2] == ('str', ['r1', '[r2]']) and ops[3][0] == 'bx':
        return f"u32 {name}(u32 **arg0, u32 arg1) {{\n    u32 *p = *arg0;\n    u32 old = *p;\n    *p = arg1;\n    return old;\n}}\n"

    # --- P22b: Atomic swap s16 through double pointer (ldr r2, [r0]; ldrh r0, [r2, #off]; strh r1, [r2, #off]; lsls; asrs; bx lr) ---
    if n == 6 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1][0] == 'ldrh' and ops[2][0] == 'strh' and ops[3][0] == 'lsls' and ops[4][0] == 'asrs' and ops[5][0] == 'bx':
        m_off = re.search(r'\[r2(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[1][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            idx = off_val // 2
            return f"s16 {name}(s16 **arg0, s16 arg1) {{\n    s16 *p = *arg0;\n    s16 old = p[{idx}];\n    p[{idx}] = arg1;\n    return old;\n}}\n"

    # --- P23: 1-case switch (push {lr}; cmp r1, #c; beq L; movs r0, #0; b Lend; movs r0, #hi; lsls r0, r0, #sh; pop {r1}; bx r1) ---
    if n == 9 and ops[0][0] == 'push' and ops[1][0] == 'cmp' and ops[2][0] == 'beq' and ops[3][0] == 'movs' and ops[4][0] == 'b' and ops[5][0] == 'movs' and ops[6][0] == 'lsls' and ops[7][0] == 'pop' and ops[8][0] == 'bx':
        cmp_reg = ops[1][1][0]
        c_val = int(ops[1][1][1].lstrip('#'), 0)
        def_val = int(ops[3][1][1].lstrip('#'), 0)
        hi_val = int(ops[5][1][1].lstrip('#'), 0)
        sh_val = int(ops[6][1][2].lstrip('#'), 0)
        case_ret = hi_val << sh_val
        arg_expr = "arg1" if cmp_reg == "r1" else "arg0"
        return f"int {name}(int arg0, int arg1) {{\n    switch ({arg_expr}) {{\n    case {c_val}: return {case_ret};\n    default: return {def_val};\n    }}\n}}\n"

    # --- P24: 2-case switch con case 0 == default (push {lr}; cmp r0, #0; beq L1; cmp r0, #1; beq L2; movs r0, #v0; b Lend; movs r0, #v1; pop {r1}; bx r1) ---
    if n == 9 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#0']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r0', '#1']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(int arg0) {{\n    switch (arg0) {{\n    case 0: return {v0};\n    case 1: return {v1};\n    default: return {v0};\n    }}\n}}\n"
    if n == 10 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#0']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r0', '#1']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop' and ops[9][0] == 'bx':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(int arg0) {{\n    switch (arg0) {{\n    case 0: return {v0};\n    case 1: return {v1};\n    default: return {v0};\n    }}\n}}\n"
    # Variante u32 bls (#1):
    if n == 10 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#1']) and ops[2][0] == 'bls' and ops[3] == ('cmp', ['r0', '#2']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop' and ops[9][0] == 'bx':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(u32 arg0) {{\n    switch (arg0) {{\n    case 0:\n    case 1: return {v0};\n    case 2: return {v1};\n    default: return {v0};\n    }}\n}}\n"

    # --- P25: Self-relative pointer offset (ldr r1, [r0]; adds r1, #off; adds r0, r0, r1; bx lr) ---
    if n == 4 and ops[0] == ('ldr', ['r1', '[r0]']) and ops[1][0] in ('adds', 'add') and ops[1][1][0] == 'r1' and ops[2] in (('adds', ['r0', 'r0', 'r1']), ('add', ['r0', 'r0', 'r1'])) and ops[3][0] == 'bx':
        off_val = int(ops[1][1][1].lstrip('#'), 0)
        return f"u8 *{name}(u32 *arg0) {{\n    return (u8 *)arg0 + (*arg0 + {off_val});\n}}\n"

    # --- P26: Pair copy (ldr r2, [r1, #4]; ldr r1, [r1]; str r1, [r0, #off1]; str r2, [r0, #off2]; bx lr) ---
    if n == 5 and ops[0] == ('ldr', ['r2', '[r1, #4]']) and ops[1] == ('ldr', ['r1', '[r1]']) and ops[2][0] == 'str' and ops[3][0] == 'str' and ops[4][0] == 'bx':
        m1 = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[2][1][1])
        m2 = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[3][1][1])
        if m1 and m2:
            o1 = int(m1.group(1), 0) if m1.group(1) else 0
            o2 = int(m2.group(1), 0) if m2.group(1) else 0
            return f"void {name}(u8 *arg0, u32 *arg1) {{\n    u32 b = arg1[1];\n    u32 a = arg1[0];\n    *(u32 *)(arg0 + {o1}) = a;\n    *(u32 *)(arg0 + {o2}) = b;\n}}\n"

    # --- P27: Shifted offset getter/setter (movs r1/r2, #v; lsls r1/r2, #s; adds r0, r0, r1/r2; ldr/ldrb/strh/strb ...; bx lr) ---
    if n == 5 and ops[0][0] == 'movs' and ops[1][0] == 'lsls' and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldr', 'ldrh', 'ldrb') and ops[4][0] == 'bx':
        if ops[0][1][0] == 'r1' and ops[2][1] == ['r0', 'r0', 'r1'] and ops[3][1] == ['r0', '[r0]']:
            v = int(ops[0][1][1].lstrip('#'), 0)
            s = int(ops[1][1][2].lstrip('#'), 0)
            tp = 'u32' if ops[3][0] == 'ldr' else ('u16' if ops[3][0] == 'ldrh' else 'u8')
            return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + ({v} << {s}));\n}}\n"
    if n == 6 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[2][0] == 'lsls' and ops[3][0] in ('adds', 'add') and ops[4][0] in ('ldr', 'ldrh', 'ldrb', 'str', 'strh', 'strb') and ops[5][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            v = int(ops[1][1][1].lstrip('#'), 0)
            s = int(ops[2][1][2].lstrip('#'), 0)
            mn = ops[4][0]
            if mn.startswith('ldr'):
                tp = 'u32' if mn == 'ldr' else ('u16' if mn == 'ldrh' else 'u8')
                return f"{tp} {name}(u8 **arg0) {{\n    return *({tp} *)(arg0[{idx}] + ({v} << {s}));\n}}\n"
            else:
                tp = 'u32' if mn == 'str' else ('u16' if mn == 'strh' else 'u8')
                return f"void {name}(u8 **arg0, {tp} arg1) {{\n    *({tp} *)(arg0[{idx}] + ({v} << {s})) = arg1;\n}}\n"
    if n == 7 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[2][0] == 'lsls' and ops[3][0] in ('adds', 'add') and ops[4] == ('movs', ['r1', '#0']) and ops[5][0] in ('ldrsh', 'ldrsb') and ops[6][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            v = int(ops[1][1][1].lstrip('#'), 0)
            s = int(ops[2][1][2].lstrip('#'), 0)
            tp = 's16' if 'h' in ops[5][0] else 's8'
            return f"{tp} {name}(u8 **arg0) {{\n    return *({tp} *)(arg0[{idx}] + ({v} << {s}));\n}}\n"

    # --- P28: Literal offset byte/half/word getter (ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb/ldrh/ldr r0, [r0]; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r0', 'r0', 'r1']) and ops[2][0] in ('ldrb', 'ldrh', 'ldr') and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        tp = 'u8' if ops[2][0] == 'ldrb' else ('u16' if ops[2][0] == 'ldrh' else 'u32')
        return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + 0x{lit_val:X});\n}}\n"

    # --- P29: Literal offset bitfield getter (ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb r0, [r0]; lsls r0, r0, #s1; lsrs r0, r0, #s2; bx lr) ---
    if n == 6 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r0', 'r0', 'r1']) and ops[2] == ('ldrb', ['r0', '[r0]']) and ops[3][0] == 'lsls' and ops[4][0] == 'lsrs' and ops[5][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        s1 = int(ops[3][1][2].lstrip('#'), 0)
        s2 = int(ops[4][1][2].lstrip('#'), 0)
        return f"u32 {name}(u8 *arg0) {{\n    return ((u32)arg0[0x{lit_val:X}] << {s1}) >> {s2};\n}}\n"

    # --- P30: Double literal offset clear (ldr r2, [pc]; adds r1, r0, r2; movs r2, #0; strb r2, [r1]; ldr r1, [pc]; adds r0, r0, r1; strb r2, [r0]; bx lr) ---
    if n == 8 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[2] == ('movs', ['r2', '#0']) and ops[3] == ('strb', ['r2', '[r1]']) and ops[4][0] == 'ldr' and '[pc' in ops[4][1][1] and ops[6] == ('strb', ['r2', '[r0]']) and ops[7][0] == 'bx':
        l1 = read_pc_lit(insns[0])
        l2 = read_pc_lit(insns[4])
        return f"void {name}(u8 *arg0) {{\n    arg0[0x{l1:X}] = 0;\n    arg0[0x{l2:X}] = 0;\n}}\n"

    # --- P31: Non-zero check (ldr r1, [r0, #off]; rsbs r0, r1, #0; orrs r0, r1; lsrs r0, r0, #31; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and ops[1] == ('rsbs', ['r0', 'r1', '#0']) and ops[2] == ('orrs', ['r0', 'r1']) and ops[3] == ('lsrs', ['r0', 'r0', '#0x1f']) and ops[4][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            return f"u32 {name}(int *arg0) {{\n    int v = arg0[{idx}];\n    return ((u32)(-v | v)) >> 31;\n}}\n"

    # --- P32: Double pointer byte swap to const (ldr r2, [r0]; ldrb r0, [r2, #off]; movs r1, #val; strb r1, [r2, #off]; bx lr) ---
    if n == 5 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1][0] == 'ldrb' and ops[2][0] == 'movs' and ops[3][0] == 'strb' and ops[4][0] == 'bx':
        m_off = re.search(r'\[r2(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[1][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            val = int(ops[2][1][1].lstrip('#'), 0)
            return f"u8 {name}(u8 **arg0) {{\n    u8 *p = *arg0;\n    u8 r = p[{off_val}];\n    p[{off_val}] = {val};\n    return r;\n}}\n"

    # --- P33: Move & clear pointer via literal offset (ldr r2, [pc]; adds r1, r1, r2; ldr r3, [r1]; movs r2, #0; str r2, [r1]; str r3, [r0]; bx lr) ---
    if n == 7 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r1', 'r1', 'r2']) and ops[2] == ('ldr', ['r3', '[r1]']) and ops[3] == ('movs', ['r2', '#0']) and ops[4] == ('str', ['r2', '[r1]']) and ops[5] == ('str', ['r3', '[r0]']) and ops[6][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        return f"void {name}(u32 *arg0, u8 *arg1) {{\n    u32 *p = (u32 *)(arg1 + 0x{lit_val:X});\n    u32 v = *p;\n    *p = 0;\n    *arg0 = v;\n}}\n"

    # --- P34: Tagged union setters (func_0809C0A0/AC/BC/C8) ---
    if n == 5 and ops[0] == ('ldr', ['r1', '[r1]']) and ops[1] == ('str', ['r1', '[r0, #0x10]']) and ops[2][0] == 'movs' and ops[3] == ('str', ['r1', '[r0, #0xc]']) and ops[4][0] == 'bx':
        tag = int(ops[2][1][1].lstrip('#'), 0)
        return f"void {name}(u32 *arg0, u32 *arg1) {{\n    arg0[4] = arg1[0];\n    arg0[3] = {tag};\n}}\n"
    if n == 7 and ops[0] == ('ldr', ['r2', '[r1, #4]']) and ops[1] == ('ldr', ['r1', '[r1]']) and ops[2] == ('str', ['r1', '[r0, #0x10]']) and ops[3] == ('str', ['r2', '[r0, #0x14]']) and ops[4][0] == 'movs' and ops[5] == ('str', ['r1', '[r0, #0xc]']) and ops[6][0] == 'bx':
        tag = int(ops[4][1][1].lstrip('#'), 0)
        return f"void {name}(u32 *arg0, u32 *arg1) {{\n    u32 y = arg1[1], x = arg1[0];\n    arg0[4] = x;\n    arg0[5] = y;\n    arg0[3] = {tag};\n}}\n"

    # --- P35: 3-case pointer offset switch (func_080A05A8/C4/AD8/AF4) ---
    if n == 14 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r1', '#1']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r1', '#1']) and ops[4][0] == 'blo' and ops[5] == ('cmp', ['r1', '#2']) and ops[6][0] == 'beq' and ops[7][0] == 'adds' and ops[8][0] == 'b' and ops[9][0] == 'adds' and ops[10][0] == 'b' and ops[11][0] == 'adds':
        o0 = int(ops[7][1][1].lstrip('#'), 0)
        o1 = int(ops[9][1][1].lstrip('#'), 0)
        o2 = int(ops[11][1][1].lstrip('#'), 0)
        return f"u8 *{name}(u8 *arg0, u32 arg1) {{\n    switch (arg1) {{\n    default:\n    case 0: return arg0 + {o0};\n    case 1: return arg0 + {o1};\n    case 2: return arg0 + {o2};\n    }}\n}}\n"

    # --- P36: Struct bitfield + 3 fields copy (func_080DD410..func_080DE05C) ---
    if n == 17 and ops[0] == ('ldrb', ['r3', '[r1]']) and ops[1] == ('movs', ['r2', '#0x10']) and ops[2] == ('rsbs', ['r2', 'r2', '#0']) and ops[4][0] == 'movs' and ops[7] == ('ldr', ['r2', '[r0, #0x50]']) and ops[16][0] == 'bx':
        bf_val = int(ops[4][1][1].lstrip('#'), 0)
        return f"struct B {{ u8 f:4; u32 x; u16 y, z; }};\nvoid {name}(u8 *arg0, struct B *arg1) {{\n    arg1->f = {bf_val};\n    arg1->x = *(u32 *)(arg0 + 0x50);\n    arg1->y = *(u16 *)(arg0 + 0x54);\n    arg1->z = *(u16 *)(arg0 + 0x56);\n}}\n"

    # --- P37: 8-arg call wrapper to func_08039F90 (func_080DD3A8..func_080DE080) ---
    if n in (21, 22) and ops[0][0] == 'push' and ops[1] == ('sub', ['sp', '#0x10']) and ops[3] == ('adds', ['r4', '#0x54']) and any(op[0] == 'bl' and '8039f90' in op[1][0] for op in ops):
        if n == 21:
            v6 = int(ops[12][1][1].lstrip('#'), 0)
            v7 = int(ops[14][1][1].lstrip('#'), 0)
            return f"void func_08039F90(u8 *, u32, u32, u32, int, int, int, int);\nvoid {name}(u8 *a, u32 b, u32 c, u32 d) {{\n    func_08039F90(a, b, c, d, *(s16 *)(a + 0x54), *(s16 *)(a + 0x56), {v6}, {v7});\n}}\n"
        elif n == 22:
            v7 = int(ops[15][1][1].lstrip('#'), 0)
            return f"void func_08039F90(u8 *, u32, u32, u32, int, int, int, int);\nvoid {name}(u8 *a, u32 b, u32 c, u32 d) {{\n    func_08039F90(a, b, c, d, *(s16 *)(a + 0x54), *(s16 *)(a + 0x56), *(int *)(a + 0x68) >> 16, {v7});\n}}\n"

    # --- P38: Casos exactos verificados del barrido <= 48B ---
    exact_map = {
        "func_08008CD0": "u32 func_08008CD0(u32 **a) { return ((*a)[1] >> 31) ^ 1; }\n",
        "func_08008D3C": f"struct S {{ u32 a; u8 b; }}; extern struct S g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[]; void func_08008B54(u32 *, u8); u32 func_08008D3C(u16 i) {{ u32 x; func_08008B54(&x, g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[i].b); return x; }}\n",
        "func_0800934C": f"struct S {{ u32 p0; s16 a; u32 b; u8 c; u16 d; }}; void func_0800934C(struct S **p, s16 a, u32 b, int c) {{ struct S *s = *p; register int v asm(\"r0\") = a; u8 f; if (v < 0) v = -v; v = -v; f = ((u32)(-c | c)) >> 31; s->a = v; s->b = b; s->c = f; s->d = 0x{read_pc_lit(insns[15]) if n>15 else 0:X}; }}\n",
        "func_080142F0": f"void func_080142F0(u8 **a) {{ (*(u8 **)(a[1] + 0x8c))[0x{read_pc_lit(insns[3]) if n>3 else 0:X}] = 1; }}\n",
        "func_08014304": f"void func_08014304(u8 **a) {{ (*(u8 **)(a[1] + 0x8c))[0x{read_pc_lit(insns[3]) if n>3 else 0:X}] = 0; }}\n",
        "func_08016D80": f"struct S {{ u8 a; u32 b; }}; void func_08016D80(void) {{ struct S *p = (struct S *)(*(u8 **)0x{read_pc_lit(insns[0]):08X} + (0xdb << 2)); p->a = 0; p->b = 0x8d << 2; }}\n",
        "func_08016D9C": f"u32 func_08016D9C(void) {{ u32 *p = (u32 *)(*(u8 **)0x{read_pc_lit(insns[0]):08X} + (0xdb << 2)); return p[1]; }}\n",
        "func_0801A8C0": "int func_0801A8C0(void *a, u32 b) { if (b <= 5) return 3; if (b <= 11) return 0; if (b > 17) return 2; return 1; }\n",
        "func_08021F88": f"extern u16 g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[][7]; int func_0809BC10(u32); u16 func_08021F88(u32 *a, int b) {{ return g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[func_0809BC10(a[13])][b]; }}\n",
        "func_080220D4": "int func_080220D4(u8 **a) { u8 *p = a[13]; switch (*(int *)(p + 0x20)) { default: return 0; case 0: return p[0x26]; case 1: return 2; case 2: return 1; } }\n",
        "func_08022950": "struct S { u8 pad[0x24]; int m; u8 pad2[2]; u8 b:7; }; int func_08022950(struct S **a) { struct S *p = a[13]; switch (p->m) { case 0: return *(u8 *)((u8 *)p + 0x2a); case 1: return p->b != 0 ? 4 : 1; default: return 0; } }\n",
        "func_08022980": f"extern u16 g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[][5]; int func_0809BCAC(u32); u16 func_08022980(u32 *a, int b) {{ return g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[func_0809BCAC(a[13])][b]; }}\n",
        "func_08023804": "int func_08023804(u32 a) { switch (a) { case 0: return 9; case 1: return 11; case 2: return 12; default: return 9; } }\n",
        "func_08024C88": "void func_08024C88(u8 *a) { a[0x3c] = 8; a[0x3d] = 0xff; }\n",
        "func_08025AFC": "int func_08025AFC(u16 *a) { register int v asm(\"r0\") = a[2]; asm(\"\" : \"+r\"(v)); if (v <= 8) return 1; else return 0; }\n",
        "func_08032A64": "int func_08032A64(u8 *a) { u8 *p = a + 0x30; int r = 0; if (*(u16 *)(p + 0xe) != 0) r = ((u32)(-(*(s16 *)(p + 0x10)) | *(s16 *)(p + 0x10))) >> 31; return r; }\n",
        "func_08034248": f"extern const u16 g_{read_pc_lit(insns[0]):08X}[][5]; u16 func_08034248(u8 *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a[0x30]][b]; }}\n",
        "func_080380EC": "void func_080380EC(u8 *a, u8 b) { a[0x24] = b; *(u32 *)(a + 0x1c) = 0xa8 << 13; *(u32 *)(a + 0x20) = 0xc0 << 10; a[0x25] = 1; }\n",
        "func_08038E90": "void func_08038E90(u8 **a) { u8 *p = a[3]; *(u32 *)(p + 0x4c) = 0x90 << 17; p[0x50] = 1; }\n",
        "func_08039D98": "int func_08039D98(u8 *a) { return *(u32 *)(*(u32 *)(a + 0x34) + 0xC) != 4; }\n",
        "func_0803A320": f"extern const s16 g_{read_pc_lit(insns[0]):08X}[]; s16 func_0803A320(void *a, s16 b) {{ return g_{read_pc_lit(insns[0]):08X}[b]; }}\n",
        "func_0803A334": f"extern const s16 g_{read_pc_lit(insns[0]):08X}[]; s16 func_0803A334(void *a, s16 b) {{ return g_{read_pc_lit(insns[0]):08X}[(b + 0x40) & 0xff]; }}\n",
        "func_0803A820": "int func_0803A820(u8 *a) { u8 *p = a + 0x30; int r = 0; if (*(u16 *)(p + 0xe) != 0) r = ((u32)(-(*(s16 *)(p + 0x10)) | *(s16 *)(p + 0x10))) >> 31; return r; }\n",
        "func_0803BDE4": "void func_0803BDE4(u16 *a, u16 b, u16 c) { a[0] = b; a[1] = c; }\n",
        "func_0803BDEC": "void func_0803BDEC(u16 *a, int b, int c) { a[0] += b; a[1] += c; }\n",
        "func_0803BE9C": "struct S { u8 pad[11]; u16 x:7; u16 y:8; }; int func_0803BE9C(struct S **a) { return (*a)->y; }\n",
        "func_0803BEEC": "s16 func_0803BEEC(s16 **a) { return (*a)[0]; }\n",
        "func_0803BEF4": "s16 func_0803BEF4(s16 **a) { return (*a)[1]; }\n",
        "func_0803BFF0": "u32 func_0803C028(u32, u32, u32, u32, u32, u32, u32); u32 func_0803BFF0(u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) { return func_0803C028(a, b, c, d, e, f, 0); }\n",
        "func_0803C00C": "u32 func_0803C028(u32, u32, u32, u32, u32, u32, u32); u32 func_0803C00C(u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { return func_0803C028(a, b, c, d, e, f, g); }\n",
        "func_0804EE9C": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804EE30(u32, u32, u16, u16, u32); int func_0804EE9C(struct S *s) { func_0804EE30(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEBC": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804EDB4(u32, u32, u16, u16, u32); int func_0804EEBC(struct S *s) { func_0804EDB4(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEDC": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804ED28(u32, u32, u16, u16, u32); int func_0804EEDC(struct S *s) { func_0804ED28(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEFC": "struct S { u32 p0, p1, p2, a; u16 e, b; u32 c, d, f; }; void func_0804E9F4(u32, u16, u32, u32, u16, u32); int func_0804EEFC(struct S *s) { func_0804E9F4(s->a, s->b, s->c, s->d, s->e, s->f); return 0; }\n",
        "func_08050B3C": "struct S { u8 pad[0x1dc]; u8 b0:1; }; void func_08050B3C(struct S *a) { a->b0 = 0; }\n",
        "func_08050C18": "struct S { u8 pad[0x1f0]; u8 b0:1; }; void func_08050C18(struct S *a) { a->b0 = 0; }\n",
        "func_08050C64": "void func_08050C64(u8 *a) { a[0x500] = 0; }\n",
        "func_08050D3C": "u32 func_0804F7A4(u32, u32, u32, u32, u32, u32, u32); u32 func_08050D3C(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { return func_0804F7A4(*a, b, c, d, e, f, g); }\n",
        "func_08050E0C": "void func_08050478(u32, u32, u32, u32, u32, u32, u32, u32); void func_08050E0C(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g, u32 h) { func_08050478(*a, b, c, d, e, f, g, h); }\n",
        "func_08050E30": "void func_08050664(u32, u32, u32, u32, u32, u32, u32); void func_08050E30(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { func_08050664(*a, b, c, d, e, f, g); }\n",
        "func_080512B8": "int func_080512B8(u8 *a, int b) { int v = b + a[0x18]; if (v > 2) v -= 3; return v; }\n",
        "func_080522D8": "struct S { u8 a; u16 b; }; void func_080522D8(struct S *p, struct S *q, int i) { struct S *s = &p[i]; q->a = s->a; q->b = s->b; }\n",
        "func_080522E8": "struct S { u8 a; u16 b; }; void func_080522E8(struct S *p, struct S *q, int i) { struct S *s = &p[i]; s->a = q->a; s->b = q->b; }\n",
        "func_08075678": "void func_08075334(u32, u32, u32, u32, u32); void func_08075678(u32 a, u32 b, u32 c, u32 *d) { func_08075334(a, b, c, d[2], d[4]); }\n",
        "func_08075690": f"struct S {{ u32 x, y; }}; extern struct S g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[]; void func_08075334(u32, u32, u32, u32, u32); void func_08075690(u32 a, u32 b, u32 c, int d) {{ struct S *p = &g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[d]; func_08075334(a, b, c, p->x, p->y); }}\n",
        "func_08075AE8": "void func_080E2BB4(u32, u32, u32, u32, u32); void func_08075AE8(u32 *a, u32 b, u32 c, u32 d, u32 e) { func_080E2BB4(*a, b, c, d, e); }\n",
        "func_08075E00": "void func_08008E64(u32, u32, u32); int func_08075E00(u32 *a) { func_08008E64(a[3], a[4], a[5]); if (a[7] != 0) func_08008E64(a[6], a[7], a[8]); return 0; }\n",
        "func_08093BFC": "int func_080088CC(void *); int func_08093BFC(void *a) { if (func_080088CC(a) & 2) return 1; return 0; }\n",
        "func_08093D4C": "int func_080088CC(void *); int func_08093D4C(void *a) { if (func_080088CC(a) & 2) return 1; return 0; }\n",
        "func_0809424C": f"void func_0809424C(u32 *a) {{ a[0] = 0x{read_pc_lit(insns[0]):08X}; a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; a[2] = 0; ((u8 *)a)[0xd] = 1; }}\n",
        "func_0809C318": "int func_0809C22C(void *); u8 func_0809C318(u8 *a) { register u8 *p asm(\"r4\") = a; int i = func_0809C22C(p); p += 6; p += i; return *p; }\n",
        "func_0809C694": "int func_0809C694(u16 *a, u16 b) { return a[6] == b; }\n",
        "func_0809C6B0": "void func_0809C6B0(u16 *a) { u32 v; asm(\"ldr %0, =0xFFFF\" : \"=r\"(v)); a[6] = v; }\n",
        "func_0809CE1C": "u32 func_0809CE1C(u8 *a, int b) { return *(u32 *)(a + (b << 3)); }\n",
        "func_0809CE24": "u32 func_0809CE24(u8 *a, int b) { b <<= 3; a += 4; return *(u32 *)(a + b); }\n",
        "func_0809E988": "struct S { u8 x[8]; }; void func_0809E988(struct S *a, int b, struct S *c) { a[b] = *c; }\n",
        "func_0809EAE0": "struct S { u8 pad[0x26]; u8 b:1; }; int func_0809EAE0(struct S *a) { return a->b; }\n",
        "func_0809EAEC": "struct S { u8 pad[0x26]; u8 b:1; }; void func_0809EAEC(struct S *a) { a->b = 1; }\n",
        "func_0809EB70": "struct S { u8 pad[0x14]; u8 a:4; u8 b:3; }; int func_0809EB70(struct S *s) { return (s->a << 28) != 0 && s->b == 0; }\n",
        "func_0809EBD4": "struct S { u8 pad[0x14]; u8 a:4; u8 b:4; u8 c:1; u8 d:1; }; void func_0809EBD4(struct S *s) { s->a = 0; s->c = 0; }\n",
        "func_0809ECE0": "struct S { u8 pad[0x14]; u16 a:6; u16 b:3; }; int func_0809ECE0(struct S *s) { return (s->a << 26) != 0 && s->b == 0; }\n",
        "func_0809EE20": "struct S { u8 pad[0x14]; u16 a:6; u16 b:3; }; void func_0809EE20(struct S *s, u32 x, u32 y) { s->a = x; s->b = y; }\n",
        "func_0809EE8C": "void func_0809E2D4(void *); void *func_0809EE8C(u8 *a) { func_0809E2D4(a); { register u32 z1 asm(\"r1\") = 0; register u32 z0 asm(\"r0\") = 0; asm(\"\" : \"+r\"(z1), \"+r\"(z0)); *(u16 *)(a + 0x14) = z0; a[0x16] = z1; } return a; }\n",
        "func_0809EEA4": "int func_0809EEA4(u8 *a, u32 b) { u32 m = 1 << b; if (b < a[0x16] && (*(u16 *)(a + 0x14) & m) == 0) return 1; return 0; }\n",
        "func_0809EED0": "int func_0809EED0(u8 *a) { if (a[0x16] != 10) { a[0x16]++; return 1; } return 0; }\n",
        "func_080A03A4": "struct S { u8 p[3]; u8 a:2; u8 b:3; }; void func_080A03A4(struct S *p, u32 v) { p->b = v; }\n",
        "func_080A1478": "void func_080A1478(u32 *a, u32 *b) { a[11] = *b; }\n",
        "func_080A4698": f"struct S {{ u8 x[40]; }}; extern struct S g_{read_pc_lit(insns[4]) if n>4 else 0:08X}[]; struct S *func_080A4698(int a) {{ return &g_{read_pc_lit(insns[4]) if n>4 else 0:08X}[a]; }}\n",
        "func_080A6640": "void func_080A5760(void *); void func_080A6640(u8 *a) { register u8 *p asm(\"r4\") = a; func_080A5760(p); { register u8 *q asm(\"r1\") = p + 0xb4; register u8 z asm(\"r0\") = 0; q[0] = z; q[1] = z; p += 0xb8; p[0] = z; p[1] = z; } }\n",
        "func_080AAF28": f"extern u16 g_{read_pc_lit(insns[1]) if n>1 else 0:08X}[][2]; u16 func_080AAF28(int a, u8 b) {{ return g_{read_pc_lit(insns[1]) if n>1 else 0:08X}[a][b]; }}\n",
        "func_080AB788": "u32 func_080D11E4(void); u32 func_080AB788(u32 a) { return ((func_080D11E4() & 0xFFFF) * a) >> 16; }\n",
        "func_080ADD08": "struct S { u32 x[8]; }; struct S *func_080ADD08(struct S *a, struct S **b) { *a = **b; return a; }\n",
        "func_080ADD44": "struct S { u32 a; u16 b, c; u32 d, e, f; u8 g; }; void func_080ADD44(struct S *p) { p->a = 0; p->b = 0x100; p->c = 0; p->d = 0; p->e = 0; p->f = 0; p->g = 0; }\n",
        "func_080ADD5C": "struct S { u32 a; u16 b, c; u32 d, e, f; u8 g; }; void func_080ADD5C(struct S *p, int x, u32 y) { p->d = x; p->e = y; p->f = 0; p->g = 0; p->a = ((u32)(-x | x)) >> 31; p->c = 0; }\n",
        "func_080B3990": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B3990(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})] + *(u32 *)(a + (0x93 << 4)) * 0x54; }}\n",
        "func_080B39BC": f"struct S {{ u8 pad[0x87 << 4]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39BC(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B39D8": f"struct S {{ u8 pad[0x{read_pc_lit(insns[2]) if n>2 else 0:X}]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39D8(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B39F4": f"struct S {{ u8 pad[0x{read_pc_lit(insns[2]) if n>2 else 0:X}]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39F4(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B3A10": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B3A10(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})]; }}\n",
        "func_080B9F0C": "struct Elem { u32 p0, a, p2, b; u32 rest[12]; }; struct S { u8 pad[0x68]; struct Elem e[4]; }; u32 func_080D11E4(void); void func_080B9F0C(struct S *s, u8 i) { u32 v; s->e[i].a = 2; v = (func_080D11E4() & 0xFFFF) >> 14; s->e[i].b = v; }\n",
        "func_080B9F38": "struct Elem { u32 p0, a, p2, b; u32 rest[12]; }; struct S { u8 pad[0x68]; struct Elem e[4]; }; u32 func_080D11E4(void); void func_080B9F38(struct S *s, u8 i) { u32 v; s->e[i].a = 4; v = (func_080D11E4() & 0xFFFF) >> 14; s->e[i].b = v; }\n",
        "func_080C0B58": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C0B58(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + (0xc3 << 3))]; }}\n",
        "func_080C7B38": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C7B38(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})] + *(u32 *)(a + (0x98 << 4)) * 0x54; }}\n",
        "func_080C7B64": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C7B64(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})]; }}\n",
        "func_080CADA0": "void func_080CADA0(u32 *a, u32 b, u32 c, u32 d) { a[1] = b; a[2] = c; a[0] = d; }\n",
        "func_080CC134": f"void func_080CC134(u32 *a, void *b, int c) {{ *a = ((u32 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X})[c]; }}\n",
        "func_080CC144": f"void func_080CC144(u32 *a) {{ *a = *(u32 *)0x{read_pc_lit(insns[0]):08X}; }}\n",
        "func_080CC720": "u8 *func_080CC720(u8 *a) { return a + (0xa0 << 2); }\n",
        "func_080CD534": f"struct S {{ u32 a:8; u32 b:24; }}; void func_080CD534(struct S *out, void *b, int c) {{ struct S v = ((struct S *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X})[c]; v.a += 0x78; *out = v; }}\n",
        "func_080CD558": f"struct S {{ u32 a:8; u32 b:24; }}; void func_080CD558(struct S *out) {{ struct S v = *(struct S *)0x{read_pc_lit(insns[0]):08X}; v.a += 0x78; *out = v; }}\n",
        "func_080D01E0": f"void func_080D01E0(u32 *a, u32 b) {{ *(u32 **)0x{read_pc_lit(insns[0]):08X} = a; a[0] = b - 16; a[1] = 0; a[2] = 0; a[3] = 0; }}\n",
        "func_080D0444": f"void func_080D0444(u32 a, u32 b) {{ u32 *p = *(u32 **)0x{read_pc_lit(insns[0]):08X}; p[1] = a; p[2] = b; }}\n",
        "func_080D06D0": f"u32 func_080D06D0(void) {{ return (*(u32 **)0x{read_pc_lit(insns[0]):08X})[6]; }}\n",
        "func_080D0A54": f"void func_080D0A54(u32 a) {{ **(u32 **)0x{read_pc_lit(insns[0]):08X} = 0; *(u32 *)(*(u8 **)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} + (0xc0 << 1)) = a; }}\n",
        "func_080D0A74": f"void func_080D0A74(void) {{ **(u32 **)0x{read_pc_lit(insns[0]):08X} = 0; *(u32 *)(*(u8 **)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} + (0xc0 << 1)) = 0; }}\n",
        "func_080D0ABC": f"void func_080D0ABC(void) {{ u16 v = *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X}; *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X} = 0; *(volatile u16 *)0x{read_pc_lit(insns[5]) if n>5 else 0:08X} |= 0x80; *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X} = v; }}\n",
        "func_080D0B88": f"void func_080D0B88(void) {{ u32 *p = *(u32 **)0x{read_pc_lit(insns[0]):08X}; p[13] = 0; p[14] = 0; *(u32 **)0x{read_pc_lit(insns[5]) if n>5 else 0:08X} = &p[15]; p[15] = 0; }}\n",
        "func_080D6E98": "struct S { u8 a, b; u32 c, d; }; void func_080D6E98(struct S *p) { p->c = -1; p->d = -1; p->a = 1; p->b = 0; }\n",
        "func_080D6F0C": "struct S { u8 a, b; u32 c, d; }; void func_080D6F0C(struct S *p) { p->d = 0; p->c = 0; p->a = 0; p->b = 1; }\n",
        "func_080E0D50": "void func_08008E64(u32, u32, u32); int func_080E0D50(u32 *a) { func_08008E64(a[3], a[4], a[5]); return 0; }\n",
        "func_080E3610": "u8 func_080088CC(void *); int func_080E3610(u8 *a) { u8 v = func_080088CC(a - 8) & 2; return ((u32)-v) >> 31; }\n",
        "func_080E375C": "u8 func_080088CC(void *); int func_080E375C(u8 *a) { u8 v = func_080088CC(a - 8) & 2; return ((u32)-v) >> 31; }\n",
        "func_080E3A6C": "void func_080D0558(u32, u32, u32, u32); void func_080E3A6C(void *a, u32 b, u32 c, u32 d, u32 e) { func_080D0558(b, c, d, e); }\n",
        "func_080E3B60": f"void func_080D02EC(void); void func_08094268(void *, void *); void func_080E3B60(u32 *a, void *b) {{ *a = 0x{read_pc_lit(insns[3]) if n>3 else 0:08X}; func_080D02EC(); func_08094268(a, b); }}\n",
        "func_080E4190": f"void func_08000608(void *); void func_080E4190(u32 *a, int b) {{ *a = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E44B8": f"void func_080AC85C(void *, int); void func_08000608(void *); void func_080E44B8(u32 *a, int b) {{ func_080AC85C(a + 1, 2); *a = 0x{read_pc_lit(insns[6]) if n>6 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E4544": f"void func_08000608(void *); void func_080E4544(u32 *a, int b) {{ *a = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E5418": f"void func_080CA6F4(u32); void func_080E5418(void) {{ func_080CA6F4(**(u32 ***)0x{read_pc_lit(insns[1]) if n>1 else 0:08X}); }}\n",
        "func_080E581C": f"void func_08000608(void *); void func_080E581C(u32 *a, int b) {{ a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; *(u32 *)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} = a[0]; if (b & 1) func_08000608(a); }}\n",
        "func_080E5844": f"void func_08000608(void *); void func_080E5844(u32 *a, int b) {{ a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; *(u32 *)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} = a[0]; if (b & 1) func_08000608(a); }}\n",
    }
    if name in exact_map:
        return exact_map[name]

    def read_pc_lit(ins_obj):
        base = (ins_obj.address + 4) & ~3
        m_imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins_obj.op_str)
        disp = int(m_imm.group(1), 0) if m_imm else 0
        pool_addr = base + disp
        rom_off = pool_addr - 0x08000000
        return int.from_bytes(rom[rom_off:rom_off+4], 'little')

    # --- P14: Setter con offset grande (adds r0, #off; movs r1, #val; str/strh/strb r1, [r0]; bx lr) ---
    if n == 4 and ops[0][0] in ('adds', 'add') and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[1][1][0] == 'r1' and ops[2][0] in ('str', 'strh', 'strb') and ops[3][0] == 'bx':
        if ops[2][1] == ['r1', '[r0]']:
            off_val = int(ops[0][1][1].lstrip('#'), 0)
            val = int(ops[1][1][1].lstrip('#'), 0)
            st_mnem = ops[2][0]
            tp = 'u32' if st_mnem == 'str' else ('u16' if st_mnem == 'strh' else 'u8')
            return f"void {name}(u8 *arg0) {{\n    *({tp} *)(arg0 + {off_val}) = {val};\n}}\n"

    # --- P15: Signed getter con registro offset (movs r1, #off; ldrsh/ldrsb r0, [r0, r1]; bx lr) ---
    if n == 3 and ops[0][0] == 'movs' and ops[0][1][0] == 'r1' and ops[1][0] in ('ldrsh', 'ldrsb', 'ldsh', 'ldsb') and ops[2][0] == 'bx':
        off_val = int(ops[0][1][1].lstrip('#'), 0)
        tp = 's16' if 'h' in ops[1][0] else 's8'
        return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + {off_val});\n}}\n"

    # --- P16: Pointer member + offset (ldr r0, [r0, #off1]; adds r0, #off2; bx lr) ---
    if n == 3 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] in ('adds', 'add') and ops[1][1][0] == 'r0' and ops[2][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off1 = int(m_off.group(1), 0) if m_off.group(1) else 0
            off2 = int(ops[1][1][1].lstrip('#'), 0)
            return f"u8 *{name}(u8 *arg0) {{\n    return *(u8 **)(arg0 + {off1}) + {off2};\n}}\n"

    # --- P17: Word/Halfword Bitfield Getter (ldr/ldrh r0, [r0...]; lsls r0, r0, #s1; lsrs/asrs r0, r0, #s2; bx lr) ---
    if n == 4 and ops[0][0] in ('ldr', 'ldrh') and ops[0][1][0] == 'r0' and ops[1][0] == 'lsls' and ops[2][0] in ('lsrs', 'asrs') and ops[3][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            s1 = int(ops[1][1][2].lstrip('#'), 0)
            s2 = int(ops[2][1][2].lstrip('#'), 0)
            cast_tp = 'u32' if ops[2][0] == 'lsrs' else 's32'
            mem_tp = 'u32' if ops[0][0] == 'ldr' else 'u16'
            access = f"*({mem_tp} *)(arg0 + {off_val})" if off_val else f"*({mem_tp} *)arg0"
            return f"{cast_tp} {name}(u8 *arg0) {{\n    return (({cast_tp}){access} << {s1}) >> {s2};\n}}\n"

    # --- P18: Table lookup via global symbol (ldr r0, [pc, #imm]; lsls r1, r1, #1/#2; adds r1, r1, r0; ldrh/ldr r0, [r1]; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and '[pc' in ops[0][1][1] and ops[1][0] == 'lsls' and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldrh', 'ldr', 'ldrb') and ops[4][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        ld_m = ops[3][0]
        tp = 'u16' if ld_m == 'ldrh' else ('u32' if ld_m == 'ldr' else 'u8')
        return f"extern const {tp} g_{lit_val:08X}[];\n{tp} {name}(void *arg0, u32 arg1) {{\n    return g_{lit_val:08X}[arg1];\n}}\n"

    # --- P19a: Pointer member + literal offset deref (ldr r0, [r0, #off]; ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb/ldrh/ldr r0, [r0]; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'ldr' and ops[1][1][0] == 'r1' and '[pc' in ops[1][1][1] and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldrb', 'ldrh', 'ldr') and ops[4][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off and ops[3][1] == ['r0', '[r0]']:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            lit_val = read_pc_lit(insns[1])
            ld_m = ops[3][0]
            tp = 'u8' if ld_m == 'ldrb' else ('u16' if ld_m == 'ldrh' else 'u32')
            idx = off_val // 4
            return f"{tp} {name}(u32 *arg0) {{\n    return *({tp} *)(arg0[{idx}] + 0x{lit_val:X});\n}}\n"

    # --- P19b: Pointer member + literal offset (ldr r0, [r0, #off]; ldr r1, [pc, #imm]; adds r0, r0, r1; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'ldr' and ops[1][1][0] == 'r1' and '[pc' in ops[1][1][1] and ops[2][0] in ('adds', 'add') and ops[3][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            lit_val = read_pc_lit(insns[1])
            idx = off_val // 4
            return f"u32 {name}(u32 *arg0) {{\n    return arg0[{idx}] + 0x{lit_val:X};\n}}\n"

    # --- P20: Mul + add literal (ldr r0, [pc, #imm]; muls r0, r1, r0; adds r0, #off; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1][0] == 'muls' and ops[2][0] in ('adds', 'add') and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        off_val = int(ops[2][1][1].lstrip('#'), 0)
        return f"u32 {name}(u32 arg0, u32 arg1) {{\n    u32 c;\n    asm(\"ldr %0, =0x{lit_val:X}\" : \"=r\"(c));\n    return arg1 * c + {off_val};\n}}\n"

    # --- P21: Global word shift (ldr r0, [pc, #imm]; ldr r0, [r0]; lsrs r0, r0, #s; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1] == ('ldr', ['r0', '[r0]']) and ops[2][0] == 'lsrs' and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        sh = int(ops[2][1][2].lstrip('#'), 0)
        return f"u32 {name}(void) {{\n    return *(u32 *)0x{lit_val:08X} >> {sh};\n}}\n"

    # --- P22a: Atomic swap word through double pointer (ldr r2, [r0]; ldr r0, [r2]; str r1, [r2]; bx lr) ---
    if n == 4 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1] == ('ldr', ['r0', '[r2]']) and ops[2] == ('str', ['r1', '[r2]']) and ops[3][0] == 'bx':
        return f"u32 {name}(u32 **arg0, u32 arg1) {{\n    u32 *p = *arg0;\n    u32 old = *p;\n    *p = arg1;\n    return old;\n}}\n"

    # --- P22b: Atomic swap s16 through double pointer (ldr r2, [r0]; ldrh r0, [r2, #off]; strh r1, [r2, #off]; lsls; asrs; bx lr) ---
    if n == 6 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1][0] == 'ldrh' and ops[2][0] == 'strh' and ops[3][0] == 'lsls' and ops[4][0] == 'asrs' and ops[5][0] == 'bx':
        m_off = re.search(r'\[r2(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[1][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            idx = off_val // 2
            return f"s16 {name}(s16 **arg0, s16 arg1) {{\n    s16 *p = *arg0;\n    s16 old = p[{idx}];\n    p[{idx}] = arg1;\n    return old;\n}}\n"

    # --- P23: 1-case switch (push {lr}; cmp r1, #c; beq L; movs r0, #0; b Lend; movs r0, #hi; lsls r0, r0, #sh; pop {r1}; bx r1) ---
    if n == 9 and ops[0][0] == 'push' and ops[1][0] == 'cmp' and ops[2][0] == 'beq' and ops[3][0] == 'movs' and ops[4][0] == 'b' and ops[5][0] == 'movs' and ops[6][0] == 'lsls' and ops[7][0] == 'pop' and ops[8][0] == 'bx':
        cmp_reg = ops[1][1][0]
        c_val = int(ops[1][1][1].lstrip('#'), 0)
        def_val = int(ops[3][1][1].lstrip('#'), 0)
        hi_val = int(ops[5][1][1].lstrip('#'), 0)
        sh_val = int(ops[6][1][2].lstrip('#'), 0)
        case_ret = hi_val << sh_val
        arg_expr = "arg1" if cmp_reg == "r1" else "arg0"
        return f"int {name}(int arg0, int arg1) {{\n    switch ({arg_expr}) {{\n    case {c_val}: return {case_ret};\n    default: return {def_val};\n    }}\n}}\n"

    # --- P24: 2-case switch con case 0 == default (push {lr}; cmp r0, #0; beq L1; cmp r0, #1; beq L2; movs r0, #v0; b Lend; movs r0, #v1; pop {r1}; bx r1) ---
    if n == 9 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#0']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r0', '#1']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(int arg0) {{\n    switch (arg0) {{\n    case 0: return {v0};\n    case 1: return {v1};\n    default: return {v0};\n    }}\n}}\n"
    if n == 10 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#0']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r0', '#1']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop' and ops[9][0] == 'bx':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(int arg0) {{\n    switch (arg0) {{\n    case 0: return {v0};\n    case 1: return {v1};\n    default: return {v0};\n    }}\n}}\n"
    # Variante u32 bls (#1):
    if n == 10 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r0', '#1']) and ops[2][0] == 'bls' and ops[3] == ('cmp', ['r0', '#2']) and ops[4][0] == 'beq' and ops[5][0] == 'movs' and ops[6][0] == 'b' and ops[7][0] == 'movs' and ops[8][0] == 'pop' and ops[9][0] == 'bx':
        v0 = int(ops[5][1][1].lstrip('#'), 0)
        v1 = int(ops[7][1][1].lstrip('#'), 0)
        return f"int {name}(u32 arg0) {{\n    switch (arg0) {{\n    case 0:\n    case 1: return {v0};\n    case 2: return {v1};\n    default: return {v0};\n    }}\n}}\n"

    # --- P25: Self-relative pointer offset (ldr r1, [r0]; adds r1, #off; adds r0, r0, r1; bx lr) ---
    if n == 4 and ops[0] == ('ldr', ['r1', '[r0]']) and ops[1][0] in ('adds', 'add') and ops[1][1][0] == 'r1' and ops[2] in (('adds', ['r0', 'r0', 'r1']), ('add', ['r0', 'r0', 'r1'])) and ops[3][0] == 'bx':
        off_val = int(ops[1][1][1].lstrip('#'), 0)
        return f"u8 *{name}(u32 *arg0) {{\n    return (u8 *)arg0 + (*arg0 + {off_val});\n}}\n"

    # --- P26: Pair copy (ldr r2, [r1, #4]; ldr r1, [r1]; str r1, [r0, #off1]; str r2, [r0, #off2]; bx lr) ---
    if n == 5 and ops[0] == ('ldr', ['r2', '[r1, #4]']) and ops[1] == ('ldr', ['r1', '[r1]']) and ops[2][0] == 'str' and ops[3][0] == 'str' and ops[4][0] == 'bx':
        m1 = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[2][1][1])
        m2 = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[3][1][1])
        if m1 and m2:
            o1 = int(m1.group(1), 0) if m1.group(1) else 0
            o2 = int(m2.group(1), 0) if m2.group(1) else 0
            return f"void {name}(u8 *arg0, u32 *arg1) {{\n    u32 b = arg1[1];\n    u32 a = arg1[0];\n    *(u32 *)(arg0 + {o1}) = a;\n    *(u32 *)(arg0 + {o2}) = b;\n}}\n"

    # --- P27: Shifted offset getter/setter (movs r1/r2, #v; lsls r1/r2, #s; adds r0, r0, r1/r2; ldr/ldrb/strh/strb ...; bx lr) ---
    if n == 5 and ops[0][0] == 'movs' and ops[1][0] == 'lsls' and ops[2][0] in ('adds', 'add') and ops[3][0] in ('ldr', 'ldrh', 'ldrb') and ops[4][0] == 'bx':
        if ops[0][1][0] == 'r1' and ops[2][1] == ['r0', 'r0', 'r1'] and ops[3][1] == ['r0', '[r0]']:
            v = int(ops[0][1][1].lstrip('#'), 0)
            s = int(ops[1][1][2].lstrip('#'), 0)
            tp = 'u32' if ops[3][0] == 'ldr' else ('u16' if ops[3][0] == 'ldrh' else 'u8')
            return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + ({v} << {s}));\n}}\n"
    if n == 6 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[2][0] == 'lsls' and ops[3][0] in ('adds', 'add') and ops[4][0] in ('ldr', 'ldrh', 'ldrb', 'str', 'strh', 'strb') and ops[5][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            v = int(ops[1][1][1].lstrip('#'), 0)
            s = int(ops[2][1][2].lstrip('#'), 0)
            mn = ops[4][0]
            if mn.startswith('ldr'):
                tp = 'u32' if mn == 'ldr' else ('u16' if mn == 'ldrh' else 'u8')
                return f"{tp} {name}(u8 **arg0) {{\n    return *({tp} *)(arg0[{idx}] + ({v} << {s}));\n}}\n"
            else:
                tp = 'u32' if mn == 'str' else ('u16' if mn == 'strh' else 'u8')
                return f"void {name}(u8 **arg0, {tp} arg1) {{\n    *({tp} *)(arg0[{idx}] + ({v} << {s})) = arg1;\n}}\n"
    if n == 7 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r0' and ops[1][0] == 'movs' and ops[2][0] == 'lsls' and ops[3][0] in ('adds', 'add') and ops[4] == ('movs', ['r1', '#0']) and ops[5][0] in ('ldrsh', 'ldrsb') and ops[6][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            v = int(ops[1][1][1].lstrip('#'), 0)
            s = int(ops[2][1][2].lstrip('#'), 0)
            tp = 's16' if 'h' in ops[5][0] else 's8'
            return f"{tp} {name}(u8 **arg0) {{\n    return *({tp} *)(arg0[{idx}] + ({v} << {s}));\n}}\n"

    # --- P28: Literal offset byte/half/word getter (ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb/ldrh/ldr r0, [r0]; bx lr) ---
    if n == 4 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r0', 'r0', 'r1']) and ops[2][0] in ('ldrb', 'ldrh', 'ldr') and ops[3][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        tp = 'u8' if ops[2][0] == 'ldrb' else ('u16' if ops[2][0] == 'ldrh' else 'u32')
        return f"{tp} {name}(u8 *arg0) {{\n    return *({tp} *)(arg0 + 0x{lit_val:X});\n}}\n"

    # --- P29: Literal offset bitfield getter (ldr r1, [pc, #imm]; adds r0, r0, r1; ldrb r0, [r0]; lsls r0, r0, #s1; lsrs r0, r0, #s2; bx lr) ---
    if n == 6 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r0', 'r0', 'r1']) and ops[2] == ('ldrb', ['r0', '[r0]']) and ops[3][0] == 'lsls' and ops[4][0] == 'lsrs' and ops[5][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        s1 = int(ops[3][1][2].lstrip('#'), 0)
        s2 = int(ops[4][1][2].lstrip('#'), 0)
        return f"u32 {name}(u8 *arg0) {{\n    return ((u32)arg0[0x{lit_val:X}] << {s1}) >> {s2};\n}}\n"

    # --- P30: Double literal offset clear (ldr r2, [pc]; adds r1, r0, r2; movs r2, #0; strb r2, [r1]; ldr r1, [pc]; adds r0, r0, r1; strb r2, [r0]; bx lr) ---
    if n == 8 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[2] == ('movs', ['r2', '#0']) and ops[3] == ('strb', ['r2', '[r1]']) and ops[4][0] == 'ldr' and '[pc' in ops[4][1][1] and ops[6] == ('strb', ['r2', '[r0]']) and ops[7][0] == 'bx':
        l1 = read_pc_lit(insns[0])
        l2 = read_pc_lit(insns[4])
        return f"void {name}(u8 *arg0) {{\n    arg0[0x{l1:X}] = 0;\n    arg0[0x{l2:X}] = 0;\n}}\n"

    # --- P31: Non-zero check (ldr r1, [r0, #off]; rsbs r0, r1, #0; orrs r0, r1; lsrs r0, r0, #31; bx lr) ---
    if n == 5 and ops[0][0] == 'ldr' and ops[0][1][0] == 'r1' and ops[1] == ('rsbs', ['r0', 'r1', '#0']) and ops[2] == ('orrs', ['r0', 'r1']) and ops[3] == ('lsrs', ['r0', 'r0', '#0x1f']) and ops[4][0] == 'bx':
        m_off = re.search(r'\[r0(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[0][1][1])
        if m_off:
            idx = (int(m_off.group(1), 0) if m_off.group(1) else 0) // 4
            return f"u32 {name}(int *arg0) {{\n    int v = arg0[{idx}];\n    return ((u32)(-v | v)) >> 31;\n}}\n"

    # --- P32: Double pointer byte swap to const (ldr r2, [r0]; ldrb r0, [r2, #off]; movs r1, #val; strb r1, [r2, #off]; bx lr) ---
    if n == 5 and ops[0] == ('ldr', ['r2', '[r0]']) and ops[1][0] == 'ldrb' and ops[2][0] == 'movs' and ops[3][0] == 'strb' and ops[4][0] == 'bx':
        m_off = re.search(r'\[r2(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', ops[1][1][1])
        if m_off:
            off_val = int(m_off.group(1), 0) if m_off.group(1) else 0
            val = int(ops[2][1][1].lstrip('#'), 0)
            return f"u8 {name}(u8 **arg0) {{\n    u8 *p = *arg0;\n    u8 r = p[{off_val}];\n    p[{off_val}] = {val};\n    return r;\n}}\n"

    # --- P33: Move & clear pointer via literal offset (ldr r2, [pc]; adds r1, r1, r2; ldr r3, [r1]; movs r2, #0; str r2, [r1]; str r3, [r0]; bx lr) ---
    if n == 7 and ops[0][0] == 'ldr' and '[pc' in ops[0][1][1] and ops[1] == ('adds', ['r1', 'r1', 'r2']) and ops[2] == ('ldr', ['r3', '[r1]']) and ops[3] == ('movs', ['r2', '#0']) and ops[4] == ('str', ['r2', '[r1]']) and ops[5] == ('str', ['r3', '[r0]']) and ops[6][0] == 'bx':
        lit_val = read_pc_lit(insns[0])
        return f"void {name}(u32 *arg0, u8 *arg1) {{\n    u32 *p = (u32 *)(arg1 + 0x{lit_val:X});\n    u32 v = *p;\n    *p = 0;\n    *arg0 = v;\n}}\n"

    # --- P34: Tagged union setters (func_0809C0A0/AC/BC/C8) ---
    if n == 5 and ops[0] == ('ldr', ['r1', '[r1]']) and ops[1] == ('str', ['r1', '[r0, #0x10]']) and ops[2][0] == 'movs' and ops[3] == ('str', ['r1', '[r0, #0xc]']) and ops[4][0] == 'bx':
        tag = int(ops[2][1][1].lstrip('#'), 0)
        return f"void {name}(u32 *arg0, u32 *arg1) {{\n    arg0[4] = arg1[0];\n    arg0[3] = {tag};\n}}\n"
    if n == 7 and ops[0] == ('ldr', ['r2', '[r1, #4]']) and ops[1] == ('ldr', ['r1', '[r1]']) and ops[2] == ('str', ['r1', '[r0, #0x10]']) and ops[3] == ('str', ['r2', '[r0, #0x14]']) and ops[4][0] == 'movs' and ops[5] == ('str', ['r1', '[r0, #0xc]']) and ops[6][0] == 'bx':
        tag = int(ops[4][1][1].lstrip('#'), 0)
        return f"void {name}(u32 *arg0, u32 *arg1) {{\n    u32 y = arg1[1], x = arg1[0];\n    arg0[4] = x;\n    arg0[5] = y;\n    arg0[3] = {tag};\n}}\n"

    # --- P35: 3-case pointer offset switch (func_080A05A8/C4/AD8/AF4) ---
    if n == 14 and ops[0][0] == 'push' and ops[1] == ('cmp', ['r1', '#1']) and ops[2][0] == 'beq' and ops[3] == ('cmp', ['r1', '#1']) and ops[4][0] == 'blo' and ops[5] == ('cmp', ['r1', '#2']) and ops[6][0] == 'beq' and ops[7][0] == 'adds' and ops[8][0] == 'b' and ops[9][0] == 'adds' and ops[10][0] == 'b' and ops[11][0] == 'adds':
        o0 = int(ops[7][1][1].lstrip('#'), 0)
        o1 = int(ops[9][1][1].lstrip('#'), 0)
        o2 = int(ops[11][1][1].lstrip('#'), 0)
        return f"u8 *{name}(u8 *arg0, u32 arg1) {{\n    switch (arg1) {{\n    default:\n    case 0: return arg0 + {o0};\n    case 1: return arg0 + {o1};\n    case 2: return arg0 + {o2};\n    }}\n}}\n"

    # --- P36: Struct bitfield + 3 fields copy (func_080DD410..func_080DE05C) ---
    if n == 17 and ops[0] == ('ldrb', ['r3', '[r1]']) and ops[1] == ('movs', ['r2', '#0x10']) and ops[2] == ('rsbs', ['r2', 'r2', '#0']) and ops[4][0] == 'movs' and ops[7] == ('ldr', ['r2', '[r0, #0x50]']) and ops[16][0] == 'bx':
        bf_val = int(ops[4][1][1].lstrip('#'), 0)
        return f"struct B {{ u8 f:4; u32 x; u16 y, z; }};\nvoid {name}(u8 *arg0, struct B *arg1) {{\n    arg1->f = {bf_val};\n    arg1->x = *(u32 *)(arg0 + 0x50);\n    arg1->y = *(u16 *)(arg0 + 0x54);\n    arg1->z = *(u16 *)(arg0 + 0x56);\n}}\n"

    # --- P37: 8-arg call wrapper to func_08039F90 (func_080DD3A8..func_080DE080) ---
    if n in (21, 22) and ops[0][0] == 'push' and ops[1] == ('sub', ['sp', '#0x10']) and ops[3] == ('adds', ['r4', '#0x54']) and any(op[0] == 'bl' and '8039f90' in op[1][0] for op in ops):
        if n == 21:
            v6 = int(ops[12][1][1].lstrip('#'), 0)
            v7 = int(ops[14][1][1].lstrip('#'), 0)
            return f"void func_08039F90(u8 *, u32, u32, u32, int, int, int, int);\nvoid {name}(u8 *a, u32 b, u32 c, u32 d) {{\n    func_08039F90(a, b, c, d, *(s16 *)(a + 0x54), *(s16 *)(a + 0x56), {v6}, {v7});\n}}\n"
        elif n == 22:
            v7 = int(ops[15][1][1].lstrip('#'), 0)
            return f"void func_08039F90(u8 *, u32, u32, u32, int, int, int, int);\nvoid {name}(u8 *a, u32 b, u32 c, u32 d) {{\n    func_08039F90(a, b, c, d, *(s16 *)(a + 0x54), *(s16 *)(a + 0x56), *(int *)(a + 0x68) >> 16, {v7});\n}}\n"

    # --- P38: Casos exactos verificados del barrido <= 48B ---
    exact_map = {
        "func_08008CD0": "u32 func_08008CD0(u32 **a) { return ((*a)[1] >> 31) ^ 1; }\n",
        "func_08008D3C": f"struct S {{ u32 a; u8 b; }}; extern struct S g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[]; void func_08008B54(u32 *, u8); u32 func_08008D3C(u16 i) {{ u32 x; func_08008B54(&x, g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[i].b); return x; }}\n",
        "func_0800934C": f"struct S {{ u32 p0; s16 a; u32 b; u8 c; u16 d; }}; void func_0800934C(struct S **p, s16 a, u32 b, int c) {{ struct S *s = *p; register int v asm(\"r0\") = a; u8 f; if (v < 0) v = -v; v = -v; f = ((u32)(-c | c)) >> 31; s->a = v; s->b = b; s->c = f; s->d = 0x{read_pc_lit(insns[15]) if n>15 else 0:X}; }}\n",
        "func_080142F0": f"void func_080142F0(u8 **a) {{ (*(u8 **)(a[1] + 0x8c))[0x{read_pc_lit(insns[3]) if n>3 else 0:X}] = 1; }}\n",
        "func_08014304": f"void func_08014304(u8 **a) {{ (*(u8 **)(a[1] + 0x8c))[0x{read_pc_lit(insns[3]) if n>3 else 0:X}] = 0; }}\n",
        "func_08016D80": f"struct S {{ u8 a; u32 b; }}; void func_08016D80(void) {{ struct S *p = (struct S *)(*(u8 **)0x{read_pc_lit(insns[0]):08X} + (0xdb << 2)); p->a = 0; p->b = 0x8d << 2; }}\n",
        "func_08016D9C": f"u32 func_08016D9C(void) {{ u32 *p = (u32 *)(*(u8 **)0x{read_pc_lit(insns[0]):08X} + (0xdb << 2)); return p[1]; }}\n",
        "func_0801A8C0": "int func_0801A8C0(void *a, u32 b) { if (b <= 5) return 3; if (b <= 11) return 0; if (b > 17) return 2; return 1; }\n",
        "func_08021F88": f"extern u16 g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[][7]; int func_0809BC10(u32); u16 func_08021F88(u32 *a, int b) {{ return g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[func_0809BC10(a[13])][b]; }}\n",
        "func_080220D4": "int func_080220D4(u8 **a) { u8 *p = a[13]; switch (*(int *)(p + 0x20)) { default: return 0; case 0: return p[0x26]; case 1: return 2; case 2: return 1; } }\n",
        "func_08022950": "struct S { u8 pad[0x24]; int m; u8 pad2[2]; u8 b:7; }; int func_08022950(struct S **a) { struct S *p = a[13]; switch (p->m) { case 0: return *(u8 *)((u8 *)p + 0x2a); case 1: return p->b != 0 ? 4 : 1; default: return 0; } }\n",
        "func_08022980": f"extern u16 g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[][5]; int func_0809BCAC(u32); u16 func_08022980(u32 *a, int b) {{ return g_{read_pc_lit(insns[2]) if n>2 else 0:08X}[func_0809BCAC(a[13])][b]; }}\n",
        "func_08023804": "int func_08023804(u32 a) { switch (a) { case 0: return 9; case 1: return 11; case 2: return 12; default: return 9; } }\n",
        "func_08024C88": "void func_08024C88(u8 *a) { a[0x3c] = 8; a[0x3d] = 0xff; }\n",
        "func_08025AFC": "int func_08025AFC(u16 *a) { register int v asm(\"r0\") = a[2]; asm(\"\" : \"+r\"(v)); if (v <= 8) return 1; else return 0; }\n",
        "func_08032A64": "int func_08032A64(u8 *a) { u8 *p = a + 0x30; int r = 0; if (*(u16 *)(p + 0xe) != 0) r = ((u32)(-(*(s16 *)(p + 0x10)) | *(s16 *)(p + 0x10))) >> 31; return r; }\n",
        "func_08034248": f"extern const u16 g_{read_pc_lit(insns[0]):08X}[][5]; u16 func_08034248(u8 *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a[0x30]][b]; }}\n",
        "func_080380EC": "void func_080380EC(u8 *a, u8 b) { a[0x24] = b; *(u32 *)(a + 0x1c) = 0xa8 << 13; *(u32 *)(a + 0x20) = 0xc0 << 10; a[0x25] = 1; }\n",
        "func_08038E90": "void func_08038E90(u8 **a) { u8 *p = a[3]; *(u32 *)(p + 0x4c) = 0x90 << 17; p[0x50] = 1; }\n",
        "func_08039D98": "int func_08039D98(u8 *a) { return *(u32 *)(*(u32 *)(a + 0x34) + 0xC) != 4; }\n",
        "func_0803A320": f"extern const s16 g_{read_pc_lit(insns[0]):08X}[]; s16 func_0803A320(void *a, s16 b) {{ return g_{read_pc_lit(insns[0]):08X}[b]; }}\n",
        "func_0803A334": f"extern const s16 g_{read_pc_lit(insns[0]):08X}[]; s16 func_0803A334(void *a, s16 b) {{ return g_{read_pc_lit(insns[0]):08X}[(b + 0x40) & 0xff]; }}\n",
        "func_0803A820": "int func_0803A820(u8 *a) { u8 *p = a + 0x30; int r = 0; if (*(u16 *)(p + 0xe) != 0) r = ((u32)(-(*(s16 *)(p + 0x10)) | *(s16 *)(p + 0x10))) >> 31; return r; }\n",
        "func_0803BDE4": "void func_0803BDE4(u16 *a, u16 b, u16 c) { a[0] = b; a[1] = c; }\n",
        "func_0803BDEC": "void func_0803BDEC(u16 *a, int b, int c) { a[0] += b; a[1] += c; }\n",
        "func_0803BE9C": "struct S { u8 pad[11]; u16 x:7; u16 y:8; }; int func_0803BE9C(struct S **a) { return (*a)->y; }\n",
        "func_0803BEEC": "s16 func_0803BEEC(s16 **a) { return (*a)[0]; }\n",
        "func_0803BEF4": "s16 func_0803BEF4(s16 **a) { return (*a)[1]; }\n",
        "func_0803BFF0": "u32 func_0803C028(u32, u32, u32, u32, u32, u32, u32); u32 func_0803BFF0(u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) { return func_0803C028(a, b, c, d, e, f, 0); }\n",
        "func_0803C00C": "u32 func_0803C028(u32, u32, u32, u32, u32, u32, u32); u32 func_0803C00C(u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { return func_0803C028(a, b, c, d, e, f, g); }\n",
        "func_0804EE9C": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804EE30(u32, u32, u16, u16, u32); int func_0804EE9C(struct S *s) { func_0804EE30(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEBC": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804EDB4(u32, u32, u16, u16, u32); int func_0804EEBC(struct S *s) { func_0804EDB4(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEDC": "struct S { u32 p0, p1, p2, a, b; u16 c, d; u32 e; }; void func_0804ED28(u32, u32, u16, u16, u32); int func_0804EEDC(struct S *s) { func_0804ED28(s->a, s->b, s->c, s->d, s->e); return 0; }\n",
        "func_0804EEFC": "struct S { u32 p0, p1, p2, a; u16 e, b; u32 c, d, f; }; void func_0804E9F4(u32, u16, u32, u32, u16, u32); int func_0804EEFC(struct S *s) { func_0804E9F4(s->a, s->b, s->c, s->d, s->e, s->f); return 0; }\n",
        "func_08050B3C": "struct S { u8 pad[0x1dc]; u8 b0:1; }; void func_08050B3C(struct S *a) { a->b0 = 0; }\n",
        "func_08050C18": "struct S { u8 pad[0x1f0]; u8 b0:1; }; void func_08050C18(struct S *a) { a->b0 = 0; }\n",
        "func_08050C64": "void func_08050C64(u8 *a) { a[0x500] = 0; }\n",
        "func_08050D3C": "u32 func_0804F7A4(u32, u32, u32, u32, u32, u32, u32); u32 func_08050D3C(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { return func_0804F7A4(*a, b, c, d, e, f, g); }\n",
        "func_08050E0C": "void func_08050478(u32, u32, u32, u32, u32, u32, u32, u32); void func_08050E0C(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g, u32 h) { func_08050478(*a, b, c, d, e, f, g, h); }\n",
        "func_08050E30": "void func_08050664(u32, u32, u32, u32, u32, u32, u32); void func_08050E30(u32 *a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g) { func_08050664(*a, b, c, d, e, f, g); }\n",
        "func_080512B8": "int func_080512B8(u8 *a, int b) { int v = b + a[0x18]; if (v > 2) v -= 3; return v; }\n",
        "func_080522D8": "struct S { u8 a; u16 b; }; void func_080522D8(struct S *p, struct S *q, int i) { struct S *s = &p[i]; q->a = s->a; q->b = s->b; }\n",
        "func_080522E8": "struct S { u8 a; u16 b; }; void func_080522E8(struct S *p, struct S *q, int i) { struct S *s = &p[i]; s->a = q->a; s->b = q->b; }\n",
        "func_08075678": "void func_08075334(u32, u32, u32, u32, u32); void func_08075678(u32 a, u32 b, u32 c, u32 *d) { func_08075334(a, b, c, d[2], d[4]); }\n",
        "func_08075690": f"struct S {{ u32 x, y; }}; extern struct S g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[]; void func_08075334(u32, u32, u32, u32, u32); void func_08075690(u32 a, u32 b, u32 c, int d) {{ struct S *p = &g_{read_pc_lit(insns[3]) if n>3 else 0:08X}[d]; func_08075334(a, b, c, p->x, p->y); }}\n",
        "func_08075AE8": "void func_080E2BB4(u32, u32, u32, u32, u32); void func_08075AE8(u32 *a, u32 b, u32 c, u32 d, u32 e) { func_080E2BB4(*a, b, c, d, e); }\n",
        "func_08075E00": "void func_08008E64(u32, u32, u32); int func_08075E00(u32 *a) { func_08008E64(a[3], a[4], a[5]); if (a[7] != 0) func_08008E64(a[6], a[7], a[8]); return 0; }\n",
        "func_08093BFC": "int func_080088CC(void *); int func_08093BFC(void *a) { if (func_080088CC(a) & 2) return 1; return 0; }\n",
        "func_08093D4C": "int func_080088CC(void *); int func_08093D4C(void *a) { if (func_080088CC(a) & 2) return 1; return 0; }\n",
        "func_0809424C": f"void func_0809424C(u32 *a) {{ a[0] = 0x{read_pc_lit(insns[0]):08X}; a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; a[2] = 0; ((u8 *)a)[0xd] = 1; }}\n",
        "func_0809C318": "int func_0809C22C(void *); u8 func_0809C318(u8 *a) { register u8 *p asm(\"r4\") = a; int i = func_0809C22C(p); p += 6; p += i; return *p; }\n",
        "func_0809C694": "int func_0809C694(u16 *a, u16 b) { return a[6] == b; }\n",
        "func_0809C6B0": "void func_0809C6B0(u16 *a) { u32 v; asm(\"ldr %0, =0xFFFF\" : \"=r\"(v)); a[6] = v; }\n",
        "func_0809CE1C": "u32 func_0809CE1C(u8 *a, int b) { return *(u32 *)(a + (b << 3)); }\n",
        "func_0809CE24": "u32 func_0809CE24(u8 *a, int b) { b <<= 3; a += 4; return *(u32 *)(a + b); }\n",
        "func_0809E988": "struct S { u8 x[8]; }; void func_0809E988(struct S *a, int b, struct S *c) { a[b] = *c; }\n",
        "func_0809EAE0": "struct S { u8 pad[0x26]; u8 b:1; }; int func_0809EAE0(struct S *a) { return a->b; }\n",
        "func_0809EAEC": "struct S { u8 pad[0x26]; u8 b:1; }; void func_0809EAEC(struct S *a) { a->b = 1; }\n",
        "func_0809EB70": "struct S { u8 pad[0x14]; u8 a:4; u8 b:3; }; int func_0809EB70(struct S *s) { return (s->a << 28) != 0 && s->b == 0; }\n",
        "func_0809EBD4": "struct S { u8 pad[0x14]; u8 a:4; u8 b:4; u8 c:1; u8 d:1; }; void func_0809EBD4(struct S *s) { s->a = 0; s->c = 0; }\n",
        "func_0809ECE0": "struct S { u8 pad[0x14]; u16 a:6; u16 b:3; }; int func_0809ECE0(struct S *s) { return (s->a << 26) != 0 && s->b == 0; }\n",
        "func_0809EE20": "struct S { u8 pad[0x14]; u16 a:6; u16 b:3; }; void func_0809EE20(struct S *s, u32 x, u32 y) { s->a = x; s->b = y; }\n",
        "func_0809EE8C": "void func_0809E2D4(void *); void *func_0809EE8C(u8 *a) { func_0809E2D4(a); { register u32 z1 asm(\"r1\") = 0; register u32 z0 asm(\"r0\") = 0; asm(\"\" : \"+r\"(z1), \"+r\"(z0)); *(u16 *)(a + 0x14) = z0; a[0x16] = z1; } return a; }\n",
        "func_0809EEA4": "int func_0809EEA4(u8 *a, u32 b) { u32 m = 1 << b; if (b < a[0x16] && (*(u16 *)(a + 0x14) & m) == 0) return 1; return 0; }\n",
        "func_0809EED0": "int func_0809EED0(u8 *a) { if (a[0x16] != 10) { a[0x16]++; return 1; } return 0; }\n",
        "func_080A03A4": "struct S { u8 p[3]; u8 a:2; u8 b:3; }; void func_080A03A4(struct S *p, u32 v) { p->b = v; }\n",
        "func_080A1478": "void func_080A1478(u32 *a, u32 *b) { a[11] = *b; }\n",
        "func_080A4698": f"struct S {{ u8 x[40]; }}; extern struct S g_{read_pc_lit(insns[4]) if n>4 else 0:08X}[]; struct S *func_080A4698(int a) {{ return &g_{read_pc_lit(insns[4]) if n>4 else 0:08X}[a]; }}\n",
        "func_080A6640": "void func_080A5760(void *); void func_080A6640(u8 *a) { register u8 *p asm(\"r4\") = a; func_080A5760(p); { register u8 *q asm(\"r1\") = p + 0xb4; register u8 z asm(\"r0\") = 0; q[0] = z; q[1] = z; p += 0xb8; p[0] = z; p[1] = z; } }\n",
        "func_080AAF28": f"extern u16 g_{read_pc_lit(insns[1]) if n>1 else 0:08X}[][2]; u16 func_080AAF28(int a, u8 b) {{ return g_{read_pc_lit(insns[1]) if n>1 else 0:08X}[a][b]; }}\n",
        "func_080AB788": "u32 func_080D11E4(void); u32 func_080AB788(u32 a) { return ((func_080D11E4() & 0xFFFF) * a) >> 16; }\n",
        "func_080ADD08": "struct S { u32 x[8]; }; struct S *func_080ADD08(struct S *a, struct S **b) { *a = **b; return a; }\n",
        "func_080ADD44": "struct S { u32 a; u16 b, c; u32 d, e, f; u8 g; }; void func_080ADD44(struct S *p) { p->a = 0; p->b = 0x100; p->c = 0; p->d = 0; p->e = 0; p->f = 0; p->g = 0; }\n",
        "func_080ADD5C": "struct S { u32 a; u16 b, c; u32 d, e, f; u8 g; }; void func_080ADD5C(struct S *p, int x, u32 y) { p->d = x; p->e = y; p->f = 0; p->g = 0; p->a = ((u32)(-x | x)) >> 31; p->c = 0; }\n",
        "func_080B3990": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B3990(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})] + *(u32 *)(a + (0x93 << 4)) * 0x54; }}\n",
        "func_080B39BC": f"struct S {{ u8 pad[0x87 << 4]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39BC(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B39D8": f"struct S {{ u8 pad[0x{read_pc_lit(insns[2]) if n>2 else 0:X}]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39D8(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B39F4": f"struct S {{ u8 pad[0x{read_pc_lit(insns[2]) if n>2 else 0:X}]; u32 arr[16]; }}; extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B39F4(struct S *a, int b) {{ return g_{read_pc_lit(insns[0]):08X}[a->arr[b]]; }}\n",
        "func_080B3A10": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080B3A10(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})]; }}\n",
        "func_080B9F0C": "struct Elem { u32 p0, a, p2, b; u32 rest[12]; }; struct S { u8 pad[0x68]; struct Elem e[4]; }; u32 func_080D11E4(void); void func_080B9F0C(struct S *s, u8 i) { u32 v; s->e[i].a = 2; v = (func_080D11E4() & 0xFFFF) >> 14; s->e[i].b = v; }\n",
        "func_080B9F38": "struct Elem { u32 p0, a, p2, b; u32 rest[12]; }; struct S { u8 pad[0x68]; struct Elem e[4]; }; u32 func_080D11E4(void); void func_080B9F38(struct S *s, u8 i) { u32 v; s->e[i].a = 4; v = (func_080D11E4() & 0xFFFF) >> 14; s->e[i].b = v; }\n",
        "func_080C0B58": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C0B58(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + (0xc3 << 3))]; }}\n",
        "func_080C7B38": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C7B38(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})] + *(u32 *)(a + (0x98 << 4)) * 0x54; }}\n",
        "func_080C7B64": f"extern u16 g_{read_pc_lit(insns[0]):08X}[]; u16 func_080C7B64(u8 *a) {{ return g_{read_pc_lit(insns[0]):08X}[*(u32 *)(a + 0x{read_pc_lit(insns[1]) if n>1 else 0:X})]; }}\n",
        "func_080CADA0": "void func_080CADA0(u32 *a, u32 b, u32 c, u32 d) { a[1] = b; a[2] = c; a[0] = d; }\n",
        "func_080CC134": f"void func_080CC134(u32 *a, void *b, int c) {{ *a = ((u32 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X})[c]; }}\n",
        "func_080CC144": f"void func_080CC144(u32 *a) {{ *a = *(u32 *)0x{read_pc_lit(insns[0]):08X}; }}\n",
        "func_080CC720": "u8 *func_080CC720(u8 *a) { return a + (0xa0 << 2); }\n",
        "func_080CD534": f"struct S {{ u32 a:8; u32 b:24; }}; void func_080CD534(struct S *out, void *b, int c) {{ struct S v = ((struct S *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X})[c]; v.a += 0x78; *out = v; }}\n",
        "func_080CD558": f"struct S {{ u32 a:8; u32 b:24; }}; void func_080CD558(struct S *out) {{ struct S v = *(struct S *)0x{read_pc_lit(insns[0]):08X}; v.a += 0x78; *out = v; }}\n",
        "func_080D01E0": f"void func_080D01E0(u32 *a, u32 b) {{ *(u32 **)0x{read_pc_lit(insns[0]):08X} = a; a[0] = b - 16; a[1] = 0; a[2] = 0; a[3] = 0; }}\n",
        "func_080D0444": f"void func_080D0444(u32 a, u32 b) {{ u32 *p = *(u32 **)0x{read_pc_lit(insns[0]):08X}; p[1] = a; p[2] = b; }}\n",
        "func_080D06D0": f"u32 func_080D06D0(void) {{ return (*(u32 **)0x{read_pc_lit(insns[0]):08X})[6]; }}\n",
        "func_080D0A54": f"void func_080D0A54(u32 a) {{ **(u32 **)0x{read_pc_lit(insns[0]):08X} = 0; *(u32 *)(*(u8 **)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} + (0xc0 << 1)) = a; }}\n",
        "func_080D0A74": f"void func_080D0A74(void) {{ **(u32 **)0x{read_pc_lit(insns[0]):08X} = 0; *(u32 *)(*(u8 **)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} + (0xc0 << 1)) = 0; }}\n",
        "func_080D0ABC": f"void func_080D0ABC(void) {{ u16 v = *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X}; *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X} = 0; *(volatile u16 *)0x{read_pc_lit(insns[5]) if n>5 else 0:08X} |= 0x80; *(volatile u16 *)0x{read_pc_lit(insns[1]) if n>1 else 0:08X} = v; }}\n",
        "func_080D0B88": f"void func_080D0B88(void) {{ u32 *p = *(u32 **)0x{read_pc_lit(insns[0]):08X}; p[13] = 0; p[14] = 0; *(u32 **)0x{read_pc_lit(insns[5]) if n>5 else 0:08X} = &p[15]; p[15] = 0; }}\n",
        "func_080D6E98": "struct S { u8 a, b; u32 c, d; }; void func_080D6E98(struct S *p) { p->c = -1; p->d = -1; p->a = 1; p->b = 0; }\n",
        "func_080D6F0C": "struct S { u8 a, b; u32 c, d; }; void func_080D6F0C(struct S *p) { p->d = 0; p->c = 0; p->a = 0; p->b = 1; }\n",
        "func_080E0D50": "void func_08008E64(u32, u32, u32); int func_080E0D50(u32 *a) { func_08008E64(a[3], a[4], a[5]); return 0; }\n",
        "func_080E3610": "u8 func_080088CC(void *); int func_080E3610(u8 *a) { u8 v = func_080088CC(a - 8) & 2; return ((u32)-v) >> 31; }\n",
        "func_080E375C": "u8 func_080088CC(void *); int func_080E375C(u8 *a) { u8 v = func_080088CC(a - 8) & 2; return ((u32)-v) >> 31; }\n",
        "func_080E3A6C": "void func_080D0558(u32, u32, u32, u32); void func_080E3A6C(void *a, u32 b, u32 c, u32 d, u32 e) { func_080D0558(b, c, d, e); }\n",
        "func_080E3B60": f"void func_080D02EC(void); void func_08094268(void *, void *); void func_080E3B60(u32 *a, void *b) {{ *a = 0x{read_pc_lit(insns[3]) if n>3 else 0:08X}; func_080D02EC(); func_08094268(a, b); }}\n",
        "func_080E4190": f"void func_08000608(void *); void func_080E4190(u32 *a, int b) {{ *a = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E44B8": f"void func_080AC85C(void *, int); void func_08000608(void *); void func_080E44B8(u32 *a, int b) {{ func_080AC85C(a + 1, 2); *a = 0x{read_pc_lit(insns[6]) if n>6 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E4544": f"void func_08000608(void *); void func_080E4544(u32 *a, int b) {{ *a = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; if (b & 1) func_08000608(a); }}\n",
        "func_080E5418": f"void func_080CA6F4(u32); void func_080E5418(void) {{ func_080CA6F4(**(u32 ***)0x{read_pc_lit(insns[1]) if n>1 else 0:08X}); }}\n",
        "func_080E581C": f"void func_08000608(void *); void func_080E581C(u32 *a, int b) {{ a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; *(u32 *)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} = a[0]; if (b & 1) func_08000608(a); }}\n",
        "func_080E5844": f"void func_08000608(void *); void func_080E5844(u32 *a, int b) {{ a[1] = 0x{read_pc_lit(insns[2]) if n>2 else 0:08X}; *(u32 *)0x{read_pc_lit(insns[4]) if n>4 else 0:08X} = a[0]; if (b & 1) func_08000608(a); }}\n",
    }
    if name in exact_map:
        return exact_map[name]

    return None


def verify_candidate(e, code, manifest, rom, presets=('agbcc_O2', 'agbcp_O2', 'agbcc_O1', 'agbcp_O1', 'old_agbcc_O2', 'agbcc_Os')):
    target = common.rom_bytes(rom, e['addr'], e['size'])
    name = e['name']
    
    tmp_c = ROOT / f"scratch_{name}.c"
    tmp_o = ROOT / f"scratch_{name}.o"
    tmp_bin = ROOT / f"scratch_{name}.bin"
    
    full_code = PRELUDE + "\n" + code
    tmp_c.write_text(full_code, encoding='utf-8')
    
    matched = False
    winning_preset = None
    
    for preset in presets:
        r = common.cc_compile(tmp_c, tmp_o, 'THUMB', preset, exclude_name=name)
        if r.returncode == 0 and tmp_o.exists():
            subprocess.run([common.find_tool('objcopy'), '-O', 'binary', '-j', '.text', str(tmp_o), str(tmp_bin)], capture_output=True)
            if tmp_bin.exists():
                got = tmp_bin.read_bytes()
                # Comparar con target considerando padding
                exact = False
                if got == target:
                    exact = True
                elif len(got) <= len(target) and got == target[:len(got)]:
                    # Comprobar si el resto es padding (0x0000 o 0x46C0)
                    rem = target[len(got):]
                    stripped = rem.replace(b'\x00', b'').replace(b'\xc0\x46', b'').replace(b'\xff', b'')
                    if len(stripped) == 0:
                        exact = True
                
                if not exact and ('func_' in code or 'g_' in code or 'C_' in code or 'delete' in code):
                    # Enlace local rapido para resolver ramas bl, vtables C_XXXXXXXX y simbolos globales g_XXXXXXXX
                    calls = re.findall(r'func_([0-9A-Fa-f]{8})', code)
                    gsyms = re.findall(r'g_([0-9A-Fa-f]{8})', code)
                    vtsyms = re.findall(r'\bC_([0-9A-Fa-f]{8})\b', code)
                    sym_defs = [f"func_{c} = 0x{int(c, 16) & ~1:08X};" for c in set(calls) if f"func_{c}" != name]
                    sym_defs += [f"g_{g} = 0x{int(g, 16):08X};" for g in set(gsyms)]
                    sym_defs += [f"__vt_10C_{v} = 0x{int(v, 16):08X};" for v in set(vtsyms)]
                    sym_defs += ["__builtin_delete = 0x08000608;", "__builtin_new = 0x080005D4;"]
                    ld_txt = f"SECTIONS {{\n  . = 0x{e['addr']:08X};\n  .text : {{ *(.text) }}\n}}\n" + "\n".join(sym_defs) + "\n"
                    tmp_ld = ROOT / f"scratch_{name}.ld"
                    tmp_elf = ROOT / f"scratch_{name}.elf"
                    tmp_ld.write_text(ld_txt, encoding='utf-8')
                    lr = subprocess.run([common.find_tool('ld'), '-T', str(tmp_ld), '-o', str(tmp_elf), str(tmp_o)], capture_output=True)
                    if lr.returncode == 0:
                        subprocess.run([common.find_tool('objcopy'), '-O', 'binary', str(tmp_elf), str(tmp_bin)], capture_output=True)
                        if tmp_bin.exists():
                            got = tmp_bin.read_bytes()
                            if got == target or (len(got) <= len(target) and got == target[:len(got)] and not target[len(got):].replace(b'\x00', b'').replace(b'\xc0\x46', b'')):
                                exact = True
                    tmp_ld.unlink(missing_ok=True)
                    tmp_elf.unlink(missing_ok=True)

                if exact:
                    matched = True
                    winning_preset = preset
                    break

    # Limpieza
    for f in (tmp_c, tmp_o, tmp_bin):
        f.unlink(missing_ok=True)
        
    return matched, winning_preset


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scan', action='store_true', help='Escanear patrones reconocibles')
    ap.add_argument('--run', action='store_true', help='Ejecutar y aplicar matches exactos a src_sweep')
    args = ap.parse_args()
    
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()
    
    pending = [e for e in manifest if state.get(e['name'], {}).get('status') != 'matched']
    print(f"[*] Escaneando {len(pending)} funciones pendientes...")
    
    recognized = []
    
    for e in pending:
        clean_ins = get_clean_insns(rom, e['addr'], e['size'])
        if not clean_ins:
            continue

        c_code = synthesize_candidate(e, clean_ins, rom)
        if c_code:
            recognized.append((e, c_code))

    print(f"[+] Total funciones con patron analitico sintetizable: {len(recognized)}")
    
    if args.scan or not args.run:
        print("\nMuestra de candidatos algebraicos:")
        for e, code in recognized[:15]:
            print(f"--- {e['name']} ({e['size']}B) ---")
            print(code.strip())
        print("\nPara ejecutar la sintesis y aplicar los matches, ejecuta con: --run")
        return

    # Modo RUN: Evaluar y aplicar matches exactos
    print("\n[*] Iniciando compilacion y verificacion binaria 0-diff...")
    t0 = time.time()
    
    matches = []
    for e, code in recognized:
        ok, preset = verify_candidate(e, code, manifest, rom)
        if ok:
            matches.append((e, code, preset))
            print(f"  [MATCH EXACTO] {e['name']} ({e['size']}B) con {preset}")

    print(f"\n[+] Sintesis finalizada en {time.time() - t0:.1f}s:")
    print(f"    - Candidatos probados: {len(recognized)}")
    print(f"    - MATCHES 100% ZERO-DIFF LOGRADOS: {len(matches)}")
    print(f"    - Total bytes ganados: {sum(e['size'] for e, _, _ in matches)} bytes")

    if matches:
        print("\n[*] Aplicando matches a src_sweep...")
        for e, code, preset in matches:
            c_file = common.TREE_DIR / e['file']
            c_file.write_text(PRELUDE + "\n" + code, encoding='utf-8')
            state[e['name']]['status'] = 'matched'
            state[e['name']]['preset'] = preset
            state[e['name']]['best'] = 1.0
            state[e['name']]['how'] = 'algebraic-lifter'
            state[e['name']]['size'] = e['size']
            
        common.save_state(state)
        print(f"[+] state.json actualizado exitosamente. Nuevo total matched: {sum(1 for v in state.values() if v.get('status') == 'matched')}/{len(manifest)}")


if __name__ == '__main__':
    main()
