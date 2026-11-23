"""Verifica el C++ de StanHash/fomt contra la ROM, funcion por funcion, con agbcp (GCC 2.95 C++).

Pipeline por archivo src/*.cc de Stan (identico a su Makefile):
  arm-none-eabi-cpp (Windows)  ->  agbcp (WSL, -O2 -fno-rtti -fvtable-thunks ...)  ->  arm-none-eabi-as (Windows)
Despues, para cada simbolo func_XXXXXXXX del .o compara sus bytes con la ROM enmascarando
relocaciones (bl -> R_ARM_THM_CALL/PC22, palabras de pool -> R_ARM_ABS32). Es la comparacion
estandar 'modulo relocaciones': si coincide, el codigo generado es identico y solo faltan simbolos.

Uso:
  python tools/match/verify_stan_cc.py              # todos los .cc
  python tools/match/verify_stan_cc.py farmer.cc    # uno
Salida: logs/stan_cc_verify.json
"""
import json
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

ROOT = Path(__file__).resolve().parents[2]
STAN = ROOT / "refs" / "stanhash_fomt"
OUT_DIR = ROOT / "build_stan_cc"
REPORT = ROOT / "logs" / "stan_cc_verify.json"
ROM = (ROOT / "fomt virgen.gba").read_bytes()
ROM_BASE = 0x08000000
AGBCP_WSL = "/mnt/j/Laboratorio/FOMT-MATCH-ENGINE/UTILITYS/agbcc/linux/agbcp"
CXXFLAGS = ["-quiet", "-fno-exceptions", "-fno-rtti", "-fvtable-thunks", "-g", "-mthumb-interwork",
            "-Wimplicit", "-Wparentheses", "-O2", "-fhex-asm"]
INC = ["tools/agbcc/include", "tools/libagbc++", "tools/libsix/include"]


def tool(n):
    sys.path.insert(0, str(ROOT / "tools" / "match"))
    import common
    return common.find_tool(n)


def wsl_path(p: Path) -> str:
    s = str(p.resolve()).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def compile_cc(cc: Path):
    OUT_DIR.mkdir(exist_ok=True)
    i_file, s_file, o_file = (OUT_DIR / (cc.stem + x) for x in (".ii", ".s", ".o"))
    agbcc_inc = ROOT / "UTILITYS" / "agbcc" / "include"
    cpp = [tool("cpp"), "-nostdinc", "-undef", "-D__GNUC__=2", "-D__GNUC_MINOR__=95", "-D__thumb__",
           "-D__cplusplus", "-x", "c++",
           "-I", str(agbcc_inc)] + sum([["-I", str(STAN / d)] for d in INC[1:]], []) + \
          ["-iquote", str(STAN), "-iquote", str(STAN / "include"), "-Wno-trigraphs", str(cc), "-o", str(i_file)]
    r = subprocess.run(cpp, capture_output=True, text=True, cwd=str(STAN))
    if r.returncode:
        return None, "cpp: " + r.stderr[:400]
    r = subprocess.run(["wsl", "-d", "Ubuntu", "--", AGBCP_WSL] + CXXFLAGS +
                       [wsl_path(i_file), "-o", wsl_path(s_file)], capture_output=True, text=True)
    if r.returncode or not s_file.exists():
        return None, "agbcp: " + (r.stderr or r.stdout)[:600]
    r = subprocess.run([tool("as"), "-mcpu=arm7tdmi", "-I", str(STAN), "-I", str(STAN / "include"),
                        str(s_file), "-o", str(o_file)], capture_output=True, text=True)
    if r.returncode:
        return None, "as: " + r.stderr[:400]
    return o_file, ""


def compare_obj(o_file: Path):
    res = {}
    with open(o_file, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        relocs = {}
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                tgt = elf.get_section(sec["sh_info"]).name
                for rel in sec.iter_relocations():
                    relocs.setdefault(tgt, []).append((rel["r_offset"], rel["r_info_type"]))
        for sym in symtab.iter_symbols():
            n = sym.name
            if not n.startswith("func_") or sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] == "SHN_UNDEF":
                continue
            try:
                addr = int(n[5:13], 16)
            except ValueError:
                continue
            sec = elf.get_section(sym["st_shndx"])
            data = sec.data()
            start = sym["st_value"] & ~1
            size = sym["st_size"]
            if not size:
                continue
            # incluir pool: hasta el siguiente simbolo de funcion de la seccion o fin
            got = bytearray(data[start:start + size])
            tgt = bytearray(ROM[addr - ROM_BASE: addr - ROM_BASE + size])
            mask = bytearray(b"\xff" * size)
            for off, typ in relocs.get(sec.name, []):
                if start <= off < start + size:
                    w = 4
                    for k in range(w):
                        if off - start + k < size:
                            mask[off - start + k] = 0
            diff = sum(1 for g, t, m in zip(got, tgt, mask) if m and g != t)
            res[n] = {"addr": addr, "size": size, "diff_bytes": diff, "match": diff == 0}
    return res


def main():
    files = sorted((STAN / "src").glob("*.cc"))
    if len(sys.argv) > 1:
        files = [STAN / "src" / a for a in sys.argv[1:]]
    report, ok, total, errs = {}, 0, 0, {}
    for cc in files:
        o, err = compile_cc(cc)
        if not o:
            errs[cc.name] = err
            print(f"[!] {cc.name}: {err.splitlines()[0] if err else '?'}")
            continue
        r = compare_obj(o)
        m = sum(1 for v in r.values() if v["match"])
        ok += m
        total += len(r)
        report.update(r)
        print(f"[+] {cc.name:28s} {m:3d}/{len(r):3d} exactas (modulo relocaciones)")
    REPORT.write_text(json.dumps({"funcs": report, "errors": errs}, indent=1), encoding="utf-8")
    print(f"\nTOTAL: {ok}/{total} funciones exactas | archivos con error: {len(errs)}")
    print(f"Bytes exactos: {sum(v['size'] for v in report.values() if v['match'])}")


if __name__ == "__main__":
    main()

