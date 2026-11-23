import re
import sys
from pathlib import Path
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))
import common

_THUMB_MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def extract_features(rom: bytes, e: dict):
    if e.get("mode") != "THUMB":
        return None
    addr = e["addr"]
    size = e["size"]
    bts = common.rom_bytes(rom, addr, size)
    ins_list = list(_THUMB_MD.disasm(bts, addr))
    if not ins_list:
        return None

    l0_ops = []
    l1_ops = []
    l2_ops = []
    l3_ops = []
    literals = []
    lit_addr_to_idx = {}
    calls = []
    max_branch = addr

    for i in ins_list:
        m, op = i.mnemonic, i.op_str
        is_branch = m.startswith("b") and m not in ("bl", "bx") and op.startswith("#0x")
        is_ldr_pc = m == "ldr" and "[pc" in op
        is_bl = m == "bl" and op.startswith("#0x")

        # Base L0
        if is_branch:
            try:
                tgt = int(op[1:], 16)
                if addr < tgt < addr + size:
                    max_branch = max(max_branch, tgt)
                rel_off = tgt - i.address
                l0 = f"{m} REL_{rel_off}"
                l3_b = f"{m} TGT"
            except ValueError:
                l0 = f"{m} {op}"
                l3_b = f"{m} TGT"
        elif is_ldr_pc:
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
            l0 = f"ldr {reg}, [LIT_{l_idx}]"
            l3_b = None
        elif is_bl:
            tgt = int(op[1:], 16)
            c_idx = len(calls)
            calls.append(f"func_{tgt:08X}")
            l0 = f"bl CALL_{c_idx}"
            l3_b = None
        else:
            l0 = f"{m} {op}"
            l3_b = None

        l0_ops.append(l0)

        # L1: ignorando inmediatos y direcciones de pool
        # Reemplazar numeros/hex por IMM salvo registros
        l1_op = re.sub(r"#(0x[0-9a-fA-F]+|\d+)", "#IMM", l0)
        l1_op = re.sub(r"LIT_\d+", "LIT", l1_op)
        l1_op = re.sub(r"CALL_\d+", "CALL", l1_op)
        l1_ops.append(l1_op)

        # L2: ignorando además los números de registro
        l2_op = re.sub(r"\br\d+\b", "rX", l1_op)
        l2_ops.append(l2_op)

        # L3: ignorando además offsets de ramas
        if is_branch:
            l3_ops.append(re.sub(r"\br\d+\b", "rX", l3_b))
        else:
            l3_ops.append(l2_op)

        is_ret = (m == "bx" and op in ("r0", "r1", "r2", "r3", "lr")) or (m == "pop" and "pc" in op)
        if is_ret and (i.address + i.size) > max_branch:
            break

    return {
        "l0": tuple(l0_ops),
        "l1": tuple(l1_ops),
        "l2": tuple(l2_ops),
        "l3": tuple(l3_ops),
        "literals": literals,
        "calls": calls,
    }

def main():
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    matched_feats = {"l0": defaultdict(list), "l1": defaultdict(list), "l2": defaultdict(list), "l3": defaultdict(list)}
    pending_entries = []

    matched_count = 0
    for e in manifest:
        st = state.get(e["name"], {})
        status = st.get("status", "wip")
        f = extract_features(rom, e)
        if not f:
            continue
        if status == "matched":
            matched_count += 1
            for lvl in ("l0", "l1", "l2", "l3"):
                matched_feats[lvl][f[lvl]].append(e["name"])
        else:
            pending_entries.append((e, f))

    print(f"Total matched analizados: {matched_count}")
    print(f"Total pendientes analizados: {len(pending_entries)}")
    print(f"Esqueletos unicos en matched: L0={len(matched_feats['l0'])}, L1={len(matched_feats['l1'])}, L2={len(matched_feats['l2'])}, L3={len(matched_feats['l3'])}")

    cov_l0 = sum(1 for e, f in pending_entries if f["l0"] in matched_feats["l0"])
    cov_l1 = sum(1 for e, f in pending_entries if f["l1"] in matched_feats["l1"])
    cov_l2 = sum(1 for e, f in pending_entries if f["l2"] in matched_feats["l2"])
    cov_l3 = sum(1 for e, f in pending_entries if f["l3"] in matched_feats["l3"])

    print("=" * 60)
    print("COBERTURA DE FUNCIONES PENDIENTES CON VECINO EN MATCHED:")
    print(f"  L0 (Esqueleto exacto actual): {cov_l0} funciones ({cov_l0 * 100 / len(pending_entries):.1f}%)")
    print(f"  L1 (Ignorando inmediatos):    {cov_l1} funciones ({cov_l1 * 100 / len(pending_entries):.1f}%)")
    print(f"  L2 (Ignorando registros):     {cov_l2} funciones ({cov_l2 * 100 / len(pending_entries):.1f}%)")
    print(f"  L3 (Ignorando ramas):         {cov_l3} funciones ({cov_l3 * 100 / len(pending_entries):.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    main()

