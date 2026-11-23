"""Compila libc.a de agbcc usando las herramientas de Windows."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGBCC_SRC = ROOT / "refs" / "agbcc_cp"
LIBC_DIR = AGBCC_SRC / "libc"
OUT_DIR = ROOT / "refs" / "stanhash_fomt" / "tools" / "agbcc" / "lib"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CPP = "arm-none-eabi-cpp"
AS = "arm-none-eabi-as"
AR = "arm-none-eabi-ar"
OLD_AGBCC = str(ROOT / "UTILITYS" / "agbcc" / "bin" / "old_agbcc.exe")

CPPFLAGS = [
    "-I", "../ginclude", "-I", "include", "-nostdinc", "-undef",
    "-DABORT_PROVIDED", "-DHAVE_GETTIMEOFDAY", "-D__thumb__", "-DARM_RDI_MONITOR",
    "-D__GNUC__", "-DINTERNAL_NEWLIB", "-D__USER_LABEL_PREFIX__="
]

objs = []

print("[*] Compilando libc C sources...")
c_files = [p for p in LIBC_DIR.rglob("*.c") if p.name != "mallocr.c"]

for c in c_files:
    i_file = c.with_suffix(".i")
    s_file = c.with_suffix(".s")
    o_file = c.with_suffix(".o")
    r1 = subprocess.run([CPP] + CPPFLAGS + [str(c), "-o", str(i_file)], cwd=str(LIBC_DIR), capture_output=True)
    if r1.returncode != 0:
        continue
    r2 = subprocess.run([OLD_AGBCC, "-O2", "-fno-builtin", str(i_file), "-o", str(s_file)], cwd=str(LIBC_DIR), capture_output=True)
    i_file.unlink(missing_ok=True)
    if r2.returncode != 0 or not s_file.exists():
        continue
    with open(s_file, "a") as f:
        f.write("\n.text\n\t.align\t2, 0\n")
    subprocess.run([AS, "-mcpu=arm7tdmi", str(s_file), "-o", str(o_file)], cwd=str(LIBC_DIR))
    s_file.unlink(missing_ok=True)
    if o_file.exists():
        objs.append(str(o_file))

# Variantes de malloc
mallocr_c = LIBC_DIR / "stdlib" / "mallocr.c"
malloc_defs = [
    ("mallocr", "-DDEFINE_MALLOC"),
    ("freer", "-DDEFINE_FREE"),
    ("reallocr", "-DDEFINE_REALLOC"),
    ("callocr", "-DDEFINE_CALLOC"),
    ("cfreer", "-DDEFINE_CFREE"),
    ("malignr", "-DDEFINE_MEMALIGN"),
    ("vallocr", "-DDEFINE_VALLOC"),
    ("pvallocr", "-DDEFINE_PVALLOC"),
    ("mallinfor", "-DDEFINE_MALLINFO"),
    ("mallstatsr", "-DDEFINE_MALLOC_STATS"),
    ("msizer", "-DDEFINE_MALLOC_USABLE_SIZE"),
    ("malloptr", "-DDEFINE_MALLOPT"),
]

for name, flag in malloc_defs:
    i_file = LIBC_DIR / "stdlib" / f"{name}.i"
    s_file = LIBC_DIR / "stdlib" / f"{name}.s"
    o_file = LIBC_DIR / "stdlib" / f"{name}.o"
    subprocess.run([CPP] + CPPFLAGS + [flag, str(mallocr_c), "-o", str(i_file)], cwd=str(LIBC_DIR))
    subprocess.run([OLD_AGBCC, "-O2", "-fno-builtin", str(i_file), "-o", str(s_file)], cwd=str(LIBC_DIR))
    i_file.unlink(missing_ok=True)
    with open(s_file, "a") as f:
        f.write("\n.text\n\t.align\t2, 0\n")
    subprocess.run([AS, "-mcpu=arm7tdmi", str(s_file), "-o", str(o_file)], cwd=str(LIBC_DIR))
    s_file.unlink(missing_ok=True)
    if o_file.exists():
        objs.append(str(o_file))

# Assembler sources
for s in [LIBC_DIR / "arm" / "setjmp.s", LIBC_DIR / "arm" / "trap.s"]:
    if s.exists():
        o = s.with_suffix(".o")
        subprocess.run([AS, "-mcpu=arm7tdmi", str(s), "-o", str(o)], cwd=str(LIBC_DIR))
        if o.exists():
            objs.append(str(o))

libc_a = OUT_DIR / "libc.a"
libc_a.unlink(missing_ok=True)
subprocess.run([AR, "-rc", str(libc_a)] + objs, cwd=str(LIBC_DIR))

# Limpiar .o
for o in objs:
    Path(o).unlink(missing_ok=True)

print(f"[+] libc.a generada exitosamente en {libc_a} ({libc_a.stat().st_size} bytes con {len(objs)} objetos)")

