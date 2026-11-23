"""Compila libgcc.a de agbcc usando las herramientas de Windows."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGBCC_SRC = ROOT / "refs" / "agbcc_cp"
LIBGCC_DIR = AGBCC_SRC / "libgcc"
OUT_DIR = ROOT / "refs" / "stanhash_fomt" / "tools" / "agbcc" / "lib"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CPP = "arm-none-eabi-cpp"
AS = "arm-none-eabi-as"
AR = "arm-none-eabi-ar"
OLD_AGBCC = str(ROOT / "UTILITYS" / "agbcc" / "bin" / "old_agbcc.exe")

LIB1ASMFUNCS = ["_udivsi3", "_divsi3", "_umodsi3", "_modsi3", "_dvmd_tls", "_call_via_rX"]
LIB2FUNCS = [
    "_muldi3", "_divdi3", "_moddi3", "_udivdi3", "_umoddi3", "_negdi2",
    "_lshrdi3", "_ashldi3", "_ashrdi3", "_ffsdi2",
    "_udiv_w_sdiv", "_udivmoddi4", "_cmpdi2", "_ucmpdi2", "_floatdidf", "_floatdisf",
    "_fixunsdfsi", "_fixunssfsi", "_fixunsdfdi", "_fixdfdi", "_fixunssfdi", "_fixsfdi"
]

objs = []

print("[*] Compilando libgcc1 (funciones en ensamblador Thumb)...")
for name in LIB1ASMFUNCS:
    s_file = LIBGCC_DIR / f"{name}.s"
    o_file = LIBGCC_DIR / f"{name}.o"
    r_cpp = subprocess.run([CPP, "-undef", "-nostdinc", f"-DL{name}", "-x", "assembler-with-cpp", "lib1thumb.asm", "-o", str(s_file)], cwd=str(LIBGCC_DIR))
    # append align
    with open(s_file, "a") as f:
        f.write("\n.text\n\t.align\t2, 0\n")
    subprocess.run([AS, "-mcpu=arm7tdmi", str(s_file), "-o", str(o_file)], cwd=str(LIBGCC_DIR))
    s_file.unlink(missing_ok=True)
    objs.append(str(o_file))

print("[*] Compilando libgcc2...")
for name in LIB2FUNCS:
    i_file = LIBGCC_DIR / f"{name}.i"
    s_file = LIBGCC_DIR / f"{name}.s"
    o_file = LIBGCC_DIR / f"{name}.o"
    subprocess.run([CPP, "-undef", "-I", "../ginclude", "-nostdinc", f"-DL{name}", "libgcc2.c", "-o", str(i_file)], cwd=str(LIBGCC_DIR))
    subprocess.run([OLD_AGBCC, "-O2", str(i_file), "-o", str(s_file)], cwd=str(LIBGCC_DIR))
    with open(s_file, "a") as f:
        f.write("\n.text\n\t.align\t2, 0\n")
    subprocess.run([AS, "-mcpu=arm7tdmi", str(s_file), "-o", str(o_file)], cwd=str(LIBGCC_DIR))
    i_file.unlink(missing_ok=True)
    s_file.unlink(missing_ok=True)
    objs.append(str(o_file))

print("[*] Compilando fp-bit y dp-bit...")
for base, flag in [("fp-bit", ["#define FLOAT\n", "#define FLOAT_BIT_ORDER_MISMATCH\n"]),
                   ("dp-bit", ["#define FLOAT_BIT_ORDER_MISMATCH\n", "#define FLOAT_WORD_ORDER_MISMATCH\n"])]:
    c_file = LIBGCC_DIR / f"{base}.c"
    with open(c_file, "w") as f:
        f.writelines(flag)
        f.write((LIBGCC_DIR / "fp-bit-base.c").read_text())
    i_file = LIBGCC_DIR / f"{base}.i"
    s_file = LIBGCC_DIR / f"{base}.s"
    o_file = LIBGCC_DIR / f"{base}.o"
    subprocess.run([CPP, "-undef", "-I", "../ginclude", "-nostdinc", str(c_file), "-o", str(i_file)], cwd=str(LIBGCC_DIR))
    subprocess.run([OLD_AGBCC, "-O2", str(i_file), "-o", str(s_file)], cwd=str(LIBGCC_DIR))
    with open(s_file, "a") as f:
        f.write("\n.text\n\t.align\t2, 0\n")
    subprocess.run([AS, "-mcpu=arm7tdmi", str(s_file), "-o", str(o_file)], cwd=str(LIBGCC_DIR))
    c_file.unlink(missing_ok=True)
    i_file.unlink(missing_ok=True)
    s_file.unlink(missing_ok=True)
    objs.append(str(o_file))

libgcc_a = OUT_DIR / "libgcc.a"
libgcc_a.unlink(missing_ok=True)
subprocess.run([AR, "-rc", str(libgcc_a)] + objs, cwd=str(LIBGCC_DIR))

# Limpiar .o
for o in objs:
    Path(o).unlink(missing_ok=True)

print(f"[+] libgcc.a generada exitosamente en {libgcc_a} ({libgcc_a.stat().st_size} bytes)")

