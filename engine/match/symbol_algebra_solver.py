"""Solucionador Algebraico de Simbolos para FoMT GBA (100% CPU, 0 Tokens).

Realiza un diff simbolico contra refs/stanhash_fomt/ (fomt.elf + fomt.map) y aplica
algebra de herencia de vtables C++, grafo de llamadas (callers/callees), interpolacion
por unidad de traduccion y analisis semantico de instrucciones Thumb/BIOS/IO para
despejar y nombrar las 3,454 funciones de Harvest Moon: FoMT sin alterar el 0-Diff.

Artefactos generados:
  - src_sweep/symbol_map.json
  - J:/Laboratorio/FIO-DECOMP-HMFOMT/src_zero_diff/symbol_map.json
  - J:/Laboratorio/FIO-DECOMP-HMFOMT/include/fomt_symbols.h
  - J:/Laboratorio/FIO-DECOMP-HMFOMT/SYMBOL_REPORT.md
"""
import argparse
import collections
import csv
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))

import algebraic_lifter as al
import common
import fsm_lifter as fl

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

STAN_DIR = ROOT / "refs" / "stanhash_fomt"
STUDIO_REF_DIR = ROOT / "refs" / "fomt_studio"
FIO_DIR = Path(r"J:\Laboratorio\FIO-DECOMP-HMFOMT")

STUDIO_TABLE_RANGES = [
    (0x080F89D4, 0x080F9E98, "ScriptVM"),
    (0x080FB200, 0x080FB900, "IntroSequence"),
    (0x08104100, 0x08104400, "NpcSystem"),
    (0x08106A00, 0x08107000, "MapEngine"),
    (0x081116A8, 0x08111B90, "ToolData"),
    (0x08111B90, 0x08112200, "FoodData"),
    (0x080EAB0C, 0x080EAED0, "ToolData"),
    (0x080EDCD8, 0x080EE788, "FoodData"),
    (0x080EFED4, 0x080F0348, "ItemData"),
    (0x0852D980, 0x0858B900, "PortraitEngine"),
    (0x0858BA00, 0x08670000, "SpriteAnimEngine"),
    (0x020025D8, 0x02004200, "SaveGameState"),
]

WEAK_DOMAINS = {
    "code_0803EE94",
    "code_809E804",
    "code_linkonce",
    "code_entities_08034CEC",
    "code_0803A8A4",
    "code_actor_0809BFE8",
    "code_0800BC58",
    "code_entities_080320DC",
}

BIOS_SWI = {
    0x00: "BIOS_SoftReset",
    0x01: "BIOS_RegisterRamReset",
    0x02: "BIOS_Halt",
    0x03: "BIOS_Stop",
    0x04: "BIOS_IntrWait",
    0x05: "BIOS_VBlankIntrWait",
    0x06: "BIOS_Div",
    0x07: "BIOS_DivArm",
    0x08: "BIOS_Sqrt",
    0x09: "BIOS_ArcTan",
    0x0A: "BIOS_ArcTan2",
    0x0B: "BIOS_CpuSet",
    0x0C: "BIOS_CpuFastSet",
    0x0D: "BIOS_GetBiosChecksum",
    0x0E: "BIOS_BgAffineSet",
    0x0F: "BIOS_ObjAffineSet",
    0x10: "BIOS_BitUnPack",
    0x11: "BIOS_LZ77UnCompWram",
    0x12: "BIOS_LZ77UnCompVram",
    0x13: "BIOS_HuffUnComp",
    0x14: "BIOS_RLUnCompWram",
    0x15: "BIOS_RLUnCompVram",
    0x16: "BIOS_Diff8bitUnFilterWram",
    0x17: "BIOS_Diff8bitUnFilterVram",
    0x18: "BIOS_Diff16bitUnFilter",
    0x19: "BIOS_SoundBias",
    0x1A: "BIOS_SoundDriverInit",
    0x1B: "BIOS_SoundDriverMode",
    0x1C: "BIOS_SoundDriverMain",
    0x1D: "BIOS_SoundDriverVSync",
    0x1E: "BIOS_SoundChannelClear",
    0x1F: "BIOS_MidiKey2Freq",
    0x20: "BIOS_SoundWhatever0",
    0x25: "BIOS_MultiBoot",
    0x2A: "BIOS_SoundDriverVSyncOff",
    0x2B: "BIOS_SoundDriverVSyncOn",
}

RUNTIME_SYMS = {
    0x0800018C: ("CRT0", "AgbMain"),
    0x0800059C: ("Memory", "alloc"),
    0x080005D4: ("CppRuntime", "builtin_new"),
    0x080005E4: ("CppRuntime", "builtin_vec_new"),
    0x080005F0: ("CppRuntime", "op_new_nothrow"),
    0x080005FC: ("CppRuntime", "op_vec_new_nothrow"),
    0x08000608: ("CppRuntime", "builtin_delete"),
    0x08000614: ("CppRuntime", "builtin_vec_delete"),
    0x08000620: ("CppRuntime", "op_delete_nothrow"),
    0x0800062C: ("CppRuntime", "op_vec_delete_nothrow"),
    0x080D01F8: ("LibC", "malloc"),
    0x080D0260: ("LibC", "free"),
    0x080D0EC8: ("LibGcc", "divsi3"),
    0x080D0ED0: ("LibGcc", "modsi3"),
    0x080D0EDA: ("LibGcc", "udivsi3"),
    0x080D0F4E: ("LibGcc", "umodsi3"),
    0x080D102C: ("System", "UnpackData"),
    0x080D11E4: ("LibC", "rand"),
    0x080D390C: ("LibGcc", "call_via_r0"),
    0x080D3910: ("LibGcc", "call_via_r1"),
    0x080D3914: ("LibGcc", "call_via_r2"),
    0x080D3948: ("LibC", "memcmp"),
    0x080D3994: ("LibC", "memcpy"),
    0x080D39F8: ("LibC", "memmove"),
    0x080D3A84: ("LibC", "memset"),
    0x080D3ADC: ("LibC", "strcat"),
    0x080D3B28: ("LibC", "strcpy"),
    0x080D3B78: ("LibC", "strlen"),
}

GBA_IO_REGS = {
    0x04000000: "DISPCNT",
    0x04000004: "DISPSTAT",
    0x04000006: "VCOUNT",
    0x04000008: "BG0CNT",
    0x0400000A: "BG1CNT",
    0x0400000C: "BG2CNT",
    0x0400000E: "BG3CNT",
    0x04000010: "BG0HOFS",
    0x04000050: "BLDCNT",
    0x04000052: "BLDALPHA",
    0x04000054: "BLDY",
    0x040000B0: "DMA0SAD",
    0x040000BC: "DMA1SAD",
    0x040000C8: "DMA2SAD",
    0x040000D4: "DMA3SAD",
    0x04000100: "TM0CNT",
    0x04000130: "KEYINPUT",
    0x04000200: "IE",
    0x04000202: "IF",
    0x04000204: "WAITCNT",
    0x04000208: "IME",
}

BANK_DOMAINS = {
    0x08000000: "Core",
    0x08010000: "WorldState",
    0x08020000: "SceneFlow",
    0x08030000: "TownUI",
    0x08040000: "MenuDialog",
    0x08050000: "HudShop",
    0x08060000: "EventCutscene",
    0x08070000: "NpcBehavior",
    0x08080000: "FestivalMini",
    0x08090000: "SpriteRender",
    0x080A0000: "AnimEntity",
    0x080B0000: "ScriptVM",
    0x080C0000: "DialogueText",
    0x080D0000: "M4A_Runtime",
    0x080E0000: "VTable_Core",
}

GENERIC_NAME_RE = re.compile(r"^(?:func|sub|loc|unk|g|off|method|smethod|vfunc|AUnk|Entity)_[0-9A-Fa-f]{8}$")
STAN_GENERIC_METHOD_RE = re.compile(r"^(?:method|smethod|vfunc)_[0-9A-Fa-f]{8}$")


def sanitize_ident(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s or s[0].isdigit():
        s = "F_" + s
    return s


def demangle_gcc295(sym: str):
    """Demangler ligero GCC 2.95.2 (agbcp). Devuelve (cls_name, method_name, is_generic_name)."""
    sym = sym.strip()
    if sym.startswith("__vt_"):
        m = re.match(r"^__vt_(\d+)([A-Za-z_]\w*)$", sym)
        if m:
            ln = int(m.group(1))
            cls = m.group(2)[:ln] if len(m.group(2)) >= ln else m.group(2)
            return cls, "vtable", False
        return None, sym, True

    if sym.startswith("_._"):
        m = re.match(r"^_\._(\d+)([A-Za-z_]\w*)$", sym)
        if m:
            ln = int(m.group(1))
            cls = m.group(2)[:ln]
            return cls, "Dtor", False

    if "__" in sym and not sym.startswith("__"):
        idx = sym.find("__")
        meth = sym[:idx]
        rest = sym[idx + 2:]
        if rest.startswith("F"):
            return None, meth, bool(GENERIC_NAME_RE.match(meth))
        m_cls = re.match(r"^C?(?:Q\d+)?(\d+)(.+)$", rest)
        if m_cls:
            ln = int(m_cls.group(1))
            cls = m_cls.group(2)[:ln]
            is_gen = bool(STAN_GENERIC_METHOD_RE.match(meth))
            return cls, meth, is_gen

    if sym.startswith("__") and len(sym) > 4:
        m_ctor = re.match(r"^__(?:C?)(\d+)(.+)$", sym)
        if m_ctor:
            ln = int(m_ctor.group(1))
            cls = m_ctor.group(2)[:ln]
            return cls, "Ctor", False

    is_gen = bool(re.match(r"^(?:func|sub|loc|unk|g|off)_[0-9A-Fa-f]{8}$", sym))
    return None, sym, is_gen


def extract_stan_anchors():
    """Lee fomt.elf (nm -n) y fomt.map para extraer simbolos y modulos originales."""
    nm_bin = common.find_tool("nm")
    elf_path = STAN_DIR / "fomt.elf"
    map_path = STAN_DIR / "fomt.map"

    elf_funcs = {}
    elf_vts = {}
    if elf_path.exists():
        r = subprocess.run([nm_bin, "-n", str(elf_path)], capture_output=True, text=True, timeout=20)
        for line in r.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and len(parts[0]) == 8:
                try:
                    addr = int(parts[0], 16)
                except ValueError:
                    continue
                sym = parts[2].strip()
                if not (0x08000000 <= addr < 0x08160000):
                    continue
                if sym.startswith("__vt_"):
                    cls, _, _ = demangle_gcc295(sym)
                    elf_vts[addr] = cls or sym
                else:
                    elf_funcs[addr & ~1] = sym

    obj_domains = {}
    if map_path.exists():
        txt = map_path.read_text(encoding="utf-8", errors="ignore")
        cur_mod = None
        for line in txt.splitlines():
            m_obj = re.search(r"\b(?:src|asm)/([A-Za-z0-9_]+)\.o\b", line)
            if m_obj:
                cur_mod = m_obj.group(1)
            m_sec = re.search(r"\b(0x08[0-9a-fA-F]{6})\s+(0x[0-9a-fA-F]+)\s+(?:src|asm)/([A-Za-z0-9_]+)\.o", line)
            if m_sec:
                sa = int(m_sec.group(1), 16)
                sz = int(m_sec.group(2), 16)
                mod = m_sec.group(3)
                obj_domains[(sa, sa + sz)] = mod
            elif cur_mod:
                m_sym = re.match(r"^\s+(0x08[0-9a-fA-F]{6})\s+([A-Za-z_]\w*)\b", line)
                if m_sym:
                    sa = int(m_sym.group(1), 16) & ~1
                    if sa not in elf_funcs:
                        elf_funcs[sa] = m_sym.group(2)

    return elf_funcs, elf_vts, sorted(obj_domains.items())


def infer_semantic_behavior(e: dict, rom: bytes, insns: list, fsm: dict) -> str:
    """Infiere un verbo semantico conciso desde instrucciones Thumb (BIOS, IO, Get/SetField, ReturnConst)."""
    # 1. BIOS SWI
    for ins in insns:
        if ins.mnemonic == "svc":
            m_imm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", ins.op_str)
            swi = int(m_imm.group(1), 0) if m_imm else 0
            return BIOS_SWI.get(swi, f"BIOS_SWI_0x{swi:02X}")

    # 2. GBA Hardware IO registers
    pwords = [v for _, v in sorted(fsm["pool_words"].items())]
    for v in pwords:
        if v in GBA_IO_REGS:
            return f"HW_{GBA_IO_REGS[v]}"
        if 0x04000000 <= v < 0x04000400:
            return f"HW_IO_0x{v & 0x3FF:03X}"

    n = len(insns)
    if n == 0:
        return f"Sub_{e['addr']:08X}"

    # 3. NoOp / ReturnConst
    if n == 1 and insns[0].mnemonic == "bx" and insns[0].op_str == "lr":
        return "NoOp"
    if n == 2 and insns[0].mnemonic == "movs" and insns[0].op_str.startswith("r0, #") and insns[1].mnemonic == "bx":
        imm = int(insns[0].op_str.split("#")[1], 0)
        return f"Return_{imm}"

    # 4. Simple GetField / SetField without calls
    calls = [ins for ins in fsm["insns_at"].values() if ins.mnemonic == "bl"]
    if not calls and n <= 8:
        # Getter: ldr/ldrh/ldrb r0, [r0, #off] ... bx lr
        if insns[0].mnemonic in ("ldr", "ldrh", "ldrb") and "[r0" in insns[0].op_str and insns[-1].mnemonic == "bx":
            m_off = re.search(r"#(0x[0-9a-fA-F]+|\d+)", insns[0].op_str)
            off = int(m_off.group(1), 0) if m_off else 0
            return f"GetField_0x{off:02X}"
        # Setter: str/strh/strb ..., [r0, #off] ... bx lr
        for ins in insns:
            if ins.mnemonic in ("str", "strh", "strb") and "[r0" in ins.op_str:
                m_off = re.search(r"#(0x[0-9a-fA-F]+|\d+)", ins.op_str)
                off = int(m_off.group(1), 0) if m_off else 0
                return f"SetField_0x{off:02X}"

    return f"Sub_{e['addr']:08X}"


def read_vtable_slots(rom: bytes, vt_addr: int) -> list:
    """Lee slots Thumb validos de una vtable GCC 2.95.2 (-fvtable-thunks, header 8B)."""
    off = vt_addr - common.ROM_BASE
    if off < 0 or off + 16 > len(rom):
        return []
    slots = []
    # Header en +0 y +4 (normalmente 0, 0). Slots empiezan en +8 de 4 en 4.
    for slot_idx in range(48):
        pos = off + 8 + slot_idx * 4
        if pos + 4 > len(rom):
            break
        val = int.from_bytes(rom[pos:pos + 4], "little")
        if val == 0:
            break
        if (val & 1) == 1 and common.CODE_HORIZON_START <= (val & ~1) < common.CODE_HORIZON_END:
            slots.append((slot_idx, val & ~1))
        else:
            break
    return slots


def solve_symbols():
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()
    by_addr = {e["addr"]: e for e in manifest}
    by_name = {e["name"]: e for e in manifest}

    elf_funcs, elf_vts, obj_ranges = extract_stan_anchors()

    # Estructuras algebraicas por funcion
    insns_by_addr = {}
    fsm_by_addr = {}
    callees = collections.defaultdict(list)   # addr -> [callee_addr]
    callers = collections.defaultdict(set)    # addr -> {caller_addr}
    vt_refs = collections.defaultdict(list)   # addr -> [vt_addr]
    all_vt_addrs = set(elf_vts.keys())

    for e in manifest:
        addr, size = e["addr"], e["size"]
        insns = al.get_clean_insns(rom, addr, size)
        fsm = fl.parse_function_fsm(rom, addr, size)
        insns_by_addr[addr] = insns
        fsm_by_addr[addr] = fsm
        for pc, ins in sorted(fsm["insns_at"].items()):
            if ins.mnemonic == "bl":
                tgt = ins.operands[0].imm & ~1
                callees[addr].append(tgt)
                if tgt in by_addr:
                    callers[tgt].add(addr)
        for _, pw in sorted(fsm["pool_words"].items()):
            if 0x080E5000 <= pw < 0x080EA000:
                vt_refs[addr].append(pw)
                all_vt_addrs.add(pw)

    # Mapa de dominio por rango de .o en fomt.map
    def map_module_for_addr(addr: int):
        for (s, e_a), mod in obj_ranges:
            if s <= addr < e_a:
                return mod
        return None

    # Estado de resolucion:
    # domain[addr]: str o None
    # method[addr]: str o None (nombre especifico si se conoce)
    # source[addr]: 'stanhash_elf', 'runtime_bios', 'vtable_algebra', 'graph_algebra', 'tu_interp', 'semantic_bank'
    # confidence[addr]: 'EXACT', 'HIGH', 'MEDIUM', 'HEURISTIC'
    domain = {}
    method = {}
    source = {}
    confidence = {}

    # 1. Runtime & BIOS exactos
    for addr, (dom, meth) in RUNTIME_SYMS.items():
        if addr in by_addr:
            domain[addr] = dom
            method[addr] = meth
            source[addr] = "runtime_bios"
            confidence[addr] = "EXACT"

    # 2. StanHash ELF + Map anclas directas (Y_0)
    for addr, raw_sym in elf_funcs.items():
        if addr not in by_addr or addr in RUNTIME_SYMS:
            continue
        cls, meth, is_gen = demangle_gcc295(raw_sym)
        mod = map_module_for_addr(addr)
        if cls:
            domain[addr] = cls
            if not is_gen:
                method[addr] = meth
                source[addr] = "stanhash_elf"
                confidence[addr] = "EXACT"
            else:
                source[addr] = "stanhash_elf_class"
                confidence[addr] = "HIGH"
        elif not is_gen:
            domain[addr] = mod.title() if mod else "Core"
            method[addr] = meth
            source[addr] = "stanhash_elf"
            confidence[addr] = "EXACT"
        elif mod and not mod.startswith("bank_"):
            domain[addr] = mod
            source[addr] = "stanhash_map_tu"
            confidence[addr] = "HIGH"

    # Tambien detectar SWI BIOS directos
    for e in manifest:
        addr = e["addr"]
        if addr in method:
            continue
        insns = insns_by_addr[addr]
        if any(i.mnemonic == "svc" for i in insns):
            beh = infer_semantic_behavior(e, rom, insns, fsm_by_addr[addr])
            if beh.startswith("BIOS_"):
                domain[addr] = "BIOS"
                method[addr] = beh[5:]
                source[addr] = "runtime_bios"
                confidence[addr] = "EXACT"

    # 2b. FoMT Studio ScriptVM Dispatch Table (0x03F900 inside func_0803F8DC, 328 casos) + Fomt_Lib.csv
    if 0x0803F8DC in by_addr:
        domain[0x0803F8DC] = "ScriptVM"
        method[0x0803F8DC] = "ExecuteOpcode"
        source[0x0803F8DC] = "fomt_studio_dispatch"
        confidence[0x0803F8DC] = "EXACT"

    fomt_lib_path = STUDIO_REF_DIR / "Fomt_Lib.csv"
    if fomt_lib_path.exists():
        lib_map = {}
        with open(fomt_lib_path, "r", encoding="utf-8", errors="replace") as lf:
            rd = csv.reader(lf)
            next(rd, None)
            for row in rd:
                if len(row) >= 4:
                    try:
                        cid = int(row[2].strip())
                    except ValueError:
                        continue
                    lib_map[cid] = row[3].strip()

        md_vm = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md_vm.detail = True
        ptrs = [(cid, struct.unpack_from("<I", rom, 0x03F900 + cid * 4)[0] & ~1) for cid in range(328)]
        sorted_targets = sorted(set(p for _, p in ptrs if 0x0803F900 < p < 0x08045584))

        # Pasada 1: contar en cuantos casos aparece cada bl para filtrar helpers compartidos de lectura de args
        case_bls = {}
        callee_case_cnt = collections.Counter()
        for cid, p in ptrs:
            if p <= 0x0803F900 or cid not in lib_map:
                continue
            nx = next((t for t in sorted_targets if t > p), 0x08045584)
            off = p - common.ROM_BASE
            sz = min(max(nx - p, 0), 256)
            bls = [
                i.operands[0].imm & ~1
                for i in md_vm.disasm(rom[off:off + sz], p)
                if i.mnemonic == "bl" and (i.operands[0].imm & ~1) in by_addr
            ]
            case_bls[cid] = bls
            for tgt in set(bls):
                callee_case_cnt[tgt] += 1

        shared_helpers = {
            tgt for tgt, cnt in callee_case_cnt.items()
            if cnt > 6 and tgt not in RUNTIME_SYMS and confidence.get(tgt) != "EXACT"
        }
        for tgt in shared_helpers:
            if domain.get(tgt) is None or domain.get(tgt) in WEAK_DOMAINS:
                domain[tgt] = "ScriptVM"
            if tgt not in method:
                method[tgt] = f"VmHelper_{tgt:08X}"
                source[tgt] = "fomt_studio_dispatch"
                confidence[tgt] = "HIGH"

        # Pasada 2: mapear Fomt_Lib.csv -> ultimo bl no-helper de cada caso
        action_cids = collections.defaultdict(list)
        for cid, bls in case_bls.items():
            cand_bls = [t for t in bls if t not in shared_helpers and t not in RUNTIME_SYMS]
            if not cand_bls:
                continue
            tgt = cand_bls[-1]
            action_cids[tgt].append(cid)

        for tgt, cids in action_cids.items():
            if confidence.get(tgt) == "EXACT":
                continue
            # Elegir el primer nombre no generico de Fomt_Lib, o el primero disponible
            names = [lib_map[c] for c in cids]
            best_name = next((n for n in names if not re.match(r"^(?:Proc|Func)[0-9A-Fa-f]{3}$", n)), names[0])
            is_gen_lib = bool(re.match(r"^(?:Proc|Func)[0-9A-Fa-f]{3}$", best_name))
            if domain.get(tgt) is None or domain.get(tgt) in WEAK_DOMAINS:
                domain[tgt] = "ScriptVM"
            if tgt not in method or re.match(r"^(?:Proc|Func)[0-9A-Fa-f]{3}$", method.get(tgt, "")):
                method[tgt] = sanitize_ident(best_name)
                source[tgt] = "fomt_studio_dispatch"
                confidence[tgt] = "EXACT" if (len(cids) == 1 and not is_gen_lib) else "HIGH"

    # 2c. FoMT Studio ROM/RAM Table Ranges (sobreescriben None o WEAK_DOMAINS)
    for e in manifest:
        addr = e["addr"]
        cur_d = domain.get(addr)
        if cur_d is not None and cur_d not in WEAK_DOMAINS:
            continue
        pwords = [v for _, v in sorted(fsm_by_addr[addr]["pool_words"].items())]
        matched_dom = None
        for pw in pwords:
            for lo, hi, t_dom in STUDIO_TABLE_RANGES:
                if lo <= pw < hi:
                    matched_dom = t_dom
                    break
            if matched_dom:
                break
        if matched_dom:
            domain[addr] = matched_dom
            source[addr] = "fomt_studio_table"
            if confidence.get(addr) != "EXACT":
                confidence[addr] = "HIGH"

    # 3. Algebra de Vtables: herencia V_der -> V_base y metodos Ctor / Dtor / Create / VFunc
    vt_class = dict(elf_vts)  # vt_addr -> class_name
    vt_parent = {}            # vt_der -> vt_base

    for e in manifest:
        addr = e["addr"]
        vts = vt_refs.get(addr, [])
        cs = callees.get(addr, [])
        # Si referencia 2+ vtables y llama a __builtin_delete (0x08000608), vts[0] hereda de vts[-1]
        if len(vts) >= 2 and 0x08000608 in cs:
            v_der, v_base = vts[0], vts[1]
            if v_der != v_base:
                vt_parent[v_der] = v_base

    # Propagar nombres de clase base en vtables derivadas
    for _ in range(4):
        for v_der, v_base in vt_parent.items():
            if v_der not in vt_class and v_base in vt_class:
                base_cls = vt_class[v_base]
                vt_class[v_der] = f"{base_cls}_{v_der & 0xFFFF:04X}"
    for v_addr in all_vt_addrs:
        if v_addr not in vt_class:
            # Intentar tomar dominio fuerte de la funcion que referencia esta vtable
            ref_doms = [domain[a] for a, vlist in vt_refs.items() if v_addr in vlist and a in domain and domain[a] not in WEAK_DOMAINS]
            if not ref_doms:
                ref_doms = [domain[a] for a, vlist in vt_refs.items() if v_addr in vlist and a in domain]
            if ref_doms:
                base_d = collections.Counter(ref_doms).most_common(1)[0][0]
                vt_class[v_addr] = f"{base_d}_{v_addr & 0xFFFF:04X}"
            else:
                vt_class[v_addr] = f"Class_{v_addr:08X}"

    # Leer slots de cada vtable para descubrir metodos virtuales y heredar nombres de slot del padre
    vt_slots_map = {v: read_vtable_slots(rom, v) for v in all_vt_addrs}
    vt_slot_names = collections.defaultdict(dict)  # vt_addr -> {slot_idx: meth_name}
    for v, slots in vt_slots_map.items():
        for sidx, fn_addr in slots:
            if fn_addr in method:
                vt_slot_names[v][sidx] = method[fn_addr]

    # Asignar Ctor / Dtor / Create / VFunc por algebra de vtables
    for e in manifest:
        addr = e["addr"]
        vts = vt_refs.get(addr, [])
        cs = callees.get(addr, [])
        if not vts:
            continue
        v0 = vts[0]
        cls = vt_class.get(v0)
        if not cls:
            continue
        if addr not in domain or domain[addr] in WEAK_DOMAINS:
            domain[addr] = cls
            source[addr] = "vtable_algebra"
            confidence[addr] = "HIGH"
        if addr not in method:
            if 0x08000608 in cs:
                method[addr] = "Dtor"
                source[addr] = "vtable_algebra"
                confidence[addr] = "HIGH"
            elif 0x080005D4 in cs and 0x080D3914 in cs:
                method[addr] = "AutoPtrFactory"
                source[addr] = "vtable_algebra"
                confidence[addr] = "HIGH"
            elif 0x080005D4 in cs:
                method[addr] = "Create"
                source[addr] = "vtable_algebra"
                confidence[addr] = "HIGH"
            else:
                # Si escribe puntero vtable en [r0] o [rX], es Ctor
                method[addr] = "Ctor"
                source[addr] = "vtable_algebra"
                confidence[addr] = "HIGH"

    # Nombrar funciones apuntadas desde slots de vtable
    for v, slots in vt_slots_map.items():
        cls = vt_class.get(v)
        p_vt = vt_parent.get(v)
        for sidx, fn_addr in slots:
            if fn_addr not in by_addr:
                continue
            # Evitar renombrar __pure_virtual / nullsubs globales compartidas por muchas vtables
            if fn_addr not in domain or domain[fn_addr] in WEAK_DOMAINS:
                domain[fn_addr] = cls
                source[fn_addr] = "vtable_algebra"
                confidence[fn_addr] = "HIGH"
            if fn_addr not in method:
                inh = vt_slot_names.get(p_vt, {}).get(sidx) if p_vt else None
                method[fn_addr] = inh if inh else f"vfunc_{sidx * 4 + 8:02X}"
                source[fn_addr] = "vtable_algebra"
                confidence[fn_addr] = "HIGH"

    # 4. Propagacion Algebraica en Punto Fijo ("despejar X con Y")
    IGNORE_CALLERS = {0x0800018C}  # AgbMain llama a inicializadores globales de muchos subsistemas
    IGNORE_DOMAINS = {"Runtime", "CppRuntime", "LibC", "LibGcc", "BIOS", "Core", "System"} | WEAK_DOMAINS

    sorted_entries = sorted(manifest, key=lambda x: x["addr"])
    addr_order = [e["addr"] for e in sorted_entries]

    for rnd in range(12):
        changed = 0
        # Regla 1 & 2 & 3: Grafo de llamadas
        for e in sorted_entries:
            addr = e["addr"]
            cur_dom = domain.get(addr)
            if cur_dom and cur_dom not in WEAK_DOMAINS and addr in method:
                continue

            cs = [c for c in callees.get(addr, []) if c != addr and domain.get(c) not in IGNORE_DOMAINS]
            rs = [r for r in callers.get(addr, set()) if r not in IGNORE_CALLERS and domain.get(r) not in IGNORE_DOMAINS]

            # Wrapper 1-a-1 exacto: X no tiene metodo, tiene exactamente 1 callee no-runtime con metodo conocido y size <= 72B
            if addr not in method and e["size"] <= 72 and len(cs) == 1 and cs[0] in method:
                y = cs[0]
                if cur_dom is None or cur_dom in WEAK_DOMAINS:
                    domain[addr] = domain[y]
                prefix = "AutoPtrWrap" if 0x080D3914 in callees.get(addr, []) else "Wrap"
                method[addr] = f"{prefix}_{method[y]}"
                source[addr] = "graph_algebra"
                confidence[addr] = "MEDIUM"
                changed += 1
                continue

            if cur_dom is None or cur_dom in WEAK_DOMAINS:
                # Callees homogeneos en dominio fuerte
                c_doms = {domain[c] for c in cs if c in domain and domain[c] not in IGNORE_DOMAINS}
                if len(c_doms) == 1:
                    domain[addr] = next(iter(c_doms))
                    source[addr] = "graph_algebra"
                    confidence[addr] = "MEDIUM"
                    changed += 1
                    continue

                # Callers homogeneos en dominio fuerte
                r_doms = {domain[r] for r in rs if r in domain and domain[r] not in IGNORE_DOMAINS}
                if len(r_doms) == 1 and len(rs) >= 1:
                    domain[addr] = next(iter(r_doms))
                    source[addr] = "graph_algebra"
                    confidence[addr] = "MEDIUM"
                    changed += 1
                    continue

        # Regla 4: Interpolacion de Unidad de Traduccion (funciones contiguas del mismo .cc)
        for idx in range(1, len(addr_order) - 1):
            a_cur = addr_order[idx]
            cur_dom = domain.get(a_cur)
            if cur_dom and cur_dom not in WEAK_DOMAINS:
                continue
            # Buscar vecino izquierdo y derecho con dominio en una ventana de 6 funciones / 0x800 bytes
            left_dom, right_dom = None, None
            for k in range(idx - 1, max(-1, idx - 6), -1):
                ak = addr_order[k]
                if a_cur - ak > 0x800:
                    break
                if ak in domain and domain[ak] not in IGNORE_DOMAINS:
                    left_dom = domain[ak]
                    break
            for k in range(idx + 1, min(len(addr_order), idx + 6)):
                ak = addr_order[k]
                if ak - a_cur > 0x800:
                    break
                if ak in domain and domain[ak] not in IGNORE_DOMAINS:
                    right_dom = domain[ak]
                    break
            if left_dom and left_dom == right_dom:
                domain[a_cur] = left_dom
                source[a_cur] = "tu_interp"
                confidence[a_cur] = "MEDIUM"
                changed += 1

        if changed == 0:
            break

    # 5. Completado semantico y asignacion de nombres limpios sin colisiones
    used_clean_names = set()
    symbol_map = {}
    stats = collections.Counter()

    for e in sorted_entries:
        addr = e["addr"]
        orig_name = e["name"]
        st = state.get(orig_name, {})
        p = common.TREE_DIR / e["file"]
        raw_txt = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        is_pure = not (
            "__asm__" in raw_txt
            or "asm volatile" in raw_txt
            or bool(re.search(r"\basm\s*\(", raw_txt))
        )

        dom = domain.get(addr)
        meth = method.get(addr)
        src = source.get(addr)
        conf = confidence.get(addr)

        if not dom:
            bank_base = addr & 0xFFFF0000
            dom = BANK_DOMAINS.get(bank_base, f"Bank_{bank_base:08X}")
            src = "semantic_bank"
            conf = "HEURISTIC"

        if not meth:
            meth = infer_semantic_behavior(e, rom, insns_by_addr[addr], fsm_by_addr[addr])
            if src is None:
                src = "semantic_bank"
                conf = "HEURISTIC"

        clean_base = sanitize_ident(f"{dom}_{meth}")
        clean_name = clean_base
        if clean_name in used_clean_names:
            clean_name = f"{clean_base}_{addr & 0xFFFF:04X}"
        if clean_name in used_clean_names:
            clean_name = f"{clean_base}_{addr:08X}"
        used_clean_names.add(clean_name)

        stats[src] += 1
        stats[f"conf:{conf}"] += 1

        symbol_map[orig_name] = {
            "addr": f"0x{addr:08X}",
            "size": e["size"],
            "domain": dom,
            "method": meth,
            "clean_name": clean_name,
            "source": src,
            "confidence": conf,
            "pure_c_cpp": is_pure,
            "preset": st.get("preset", "unknown"),
        }

    # Exportar symbol_map.json a src_sweep y FIO-DECOMP-HMFOMT
    out_json = common.TREE_DIR / "symbol_map.json"
    out_json.write_text(json.dumps(symbol_map, indent=2), encoding="utf-8")

    if FIO_DIR.exists():
        (FIO_DIR / "src_zero_diff" / "symbol_map.json").write_text(
            json.dumps(symbol_map, indent=2), encoding="utf-8"
        )
        # Generar include/fomt_symbols.h
        h_lines = [
            "#ifndef FOMT_SYMBOLS_H",
            "#define FOMT_SYMBOLS_H",
            "",
            "/* Tabla algebraica de simbolos resuelta desde StanHash + VTables + Grafo de Llamadas */",
            "",
        ]
        for orig, info in symbol_map.items():
            h_lines.append(
                f"#define {info['clean_name']:<48} {orig} /* {info['addr']} [{info['confidence']} / {info['source']}] */"
            )
        h_lines.extend(["", "#endif /* FOMT_SYMBOLS_H */", ""])
        (FIO_DIR / "include" / "fomt_symbols.h").write_text("\n".join(h_lines), encoding="utf-8")

        # Generar SYMBOL_REPORT.md
        dom_counts = collections.Counter(v["domain"] for v in symbol_map.values())
        rep = [
            "# Reporte Algebraico de Simbolos — FIO-DECOMP-HMFOMT",
            "",
            f"- **Funciones analizadas:** {len(symbol_map)}",
            f"- **Anclas exactas StanHash ELF (`stanhash_elf`):** {stats['stanhash_elf']}",
            f"- **Despacho ScriptVM FoMT Studio (`fomt_studio_dispatch`):** {stats['fomt_studio_dispatch']}",
            f"- **Tablas ROM/RAM FoMT Studio (`fomt_studio_table`):** {stats['fomt_studio_table']}",
            f"- **Clases heredadas en mapa StanHash (`stanhash_elf_class` + `stanhash_map_tu`):** {stats['stanhash_elf_class'] + stats['stanhash_map_tu']}",
            f"- **Runtime / GBA BIOS (`runtime_bios`):** {stats['runtime_bios']}",
            f"- **Algebra de Vtables C++ (`vtable_algebra`):** {stats['vtable_algebra']}",
            f"- **Propagacion por Grafo de Llamadas (`graph_algebra`):** {stats['graph_algebra']}",
            f"- **Interpolacion de Unidad de Traduccion (`tu_interp`):** {stats['tu_interp']}",
            f"- **Clasificacion semantica por banco (`semantic_bank`):** {stats['semantic_bank']}",
            "",
            "## Distribucion por Confianza",
            f"- `EXACT`: {stats['conf:EXACT']}",
            f"- `HIGH`: {stats['conf:HIGH']}",
            f"- `MEDIUM`: {stats['conf:MEDIUM']}",
            f"- `HEURISTIC`: {stats['conf:HEURISTIC']}",
            "",
            "## Top 30 Dominios / Clases C++ Descubiertas",
            "",
            "| Dominio / Clase | Funciones |",
            "|---|---|",
        ]
        for d_name, cnt in dom_counts.most_common(30):
            rep.append(f"| `{d_name}` | {cnt} |")
        rep.append("")
        (FIO_DIR / "SYMBOL_REPORT.md").write_text("\n".join(rep), encoding="utf-8")

    print("=" * 70)
    print("SYMBOL ALGEBRA SOLVER :: Completado (100% CPU, 0 Tokens)")
    print("=" * 70)
    print(f"Total funciones: {len(symbol_map)}")
    print(f"  - StanHash ELF directo    : {stats['stanhash_elf']}")
    print(f"  - FoMT Studio Dispatch VM : {stats['fomt_studio_dispatch']}")
    print(f"  - FoMT Studio Tablas      : {stats['fomt_studio_table']}")
    print(f"  - StanHash Clase/TU map   : {stats['stanhash_elf_class'] + stats['stanhash_map_tu']}")
    print(f"  - Runtime / GBA BIOS      : {stats['runtime_bios']}")
    print(f"  - Algebra de Vtables C++  : {stats['vtable_algebra']}")
    print(f"  - Propagacion Grafo (X=Y) : {stats['graph_algebra']}")
    print(f"  - Interpolacion TU        : {stats['tu_interp']}")
    print(f"  - Semantica por Banco     : {stats['semantic_bank']}")
    print("-" * 70)
    print(f"Confianza -> EXACT: {stats['conf:EXACT']} | HIGH: {stats['conf:HIGH']} | MEDIUM: {stats['conf:MEDIUM']} | HEURISTIC: {stats['conf:HEURISTIC']}")
    print(f"Vtables descubiertas: {len(all_vt_addrs)} | Herencias V_der->V_base detectadas: {len(vt_parent)}")
    print(f"Artefactos: {out_json}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Solucionador algebraico de simbolos FoMT")
    ap.parse_args()
    solve_symbols()
