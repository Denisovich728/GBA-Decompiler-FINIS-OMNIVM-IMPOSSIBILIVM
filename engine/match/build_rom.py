"""Fase 3: reconstruye la ROM completa y la compara contra 'fomt virgen.gba'.

Cada funcion con status 'matched' en state.json se enlaza desde su objeto compilado C/C++
(incluyendo los 42 modulos C++ de Stan compilados con agbcp y las funciones C89 de src_sweep
compiladas con agbcc/old_agbcc); el resto (y todo lo que no es codigo: graficos, audio, tablas)
se inserta como bytes originales con .incbin en UN SOLO archivo ensamblador (rapido). Asi la
ROM resultante es siempre 1:1 y el porcentaje de C/C++ real sube conforme se logran matches.

Verificacion: tras enlazar, cada funcion 'matched' se compara contra la ROM. Si alguna
difiere en el enlace final, se marca 'regressed' en state.json y lift.py la reintenta.

Uso: python tools/match/build_rom.py
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa


def thumb_bit(e):
    return 1 if e["mode"] == "THUMB" else 0


def write_symbols_ld(manifest, path, extra_code=""):
    lines = [f"PROVIDE({e['name']} = 0x{e['addr'] & ~1:08X});" for e in manifest]
    known = {e["name"] for e in manifest}
    for n in sorted(set(re.findall(r"\bfunc_([0-9A-F]{8})\b", extra_code))):
        if "func_" + n not in known:
            lines.append(f"PROVIDE(func_{n} = 0x{int(n, 16) & ~1:08X});")
    for gn in sorted(set(re.findall(r"\bg_([0-9A-Fa-f]{8})\b", extra_code))):
        gname = f"g_{gn}"
        if gname not in known:
            known.add(gname)
            lines.append(f"PROVIDE({gname} = 0x{int(gn, 16):08X});")
    for idx, rg in enumerate(["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "ip", "sp", "lr"]):
        lines.append(f"PROVIDE(_call_via_{rg} = 0x{0x080D390C + idx * 4:08X});")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_symdefs_ads(manifest, path, extra_code="", exclude_name=None):
    """Genera un archivo #<SYMDEFS># nativo para armlink.exe de ADS 1.2."""
    lines = ["#<SYMDEFS># ARM Linker, ADS1.2 [Build 805]:"]
    known = set()
    for e in manifest:
        if e["name"] == exclude_name:
            continue
        known.add(e["name"])
        sym_type = "T" if e["mode"] == "THUMB" else "A"
        lines.append(f"0x{e['addr'] & ~1:08x} {sym_type} {e['name']}")
    for n in sorted(set(re.findall(r"\bfunc_([0-9A-F]{8})\b", extra_code))):
        fn = "func_" + n
        if fn not in known and fn != exclude_name:
            lines.append(f"0x{int(n, 16) & ~1:08x} T {fn}")
    for gn in sorted(set(re.findall(r"\bg_([0-9A-Fa-f]{8})\b", extra_code))):
        gname = f"g_{gn}"
        if gname not in known:
            known.add(gname)
            lines.append(f"0x{int(gn, 16):08x} D {gname}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


PRELUDE_GUARD = """typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef u8 undefined;
typedef u8 undefined1;
typedef u16 undefined2;
typedef u32 undefined3;
typedef u32 undefined4;
typedef u64 undefined5;
typedef u64 undefined6;
typedef u64 undefined7;
typedef u64 undefined8;
typedef u8 byte;
typedef u16 ushort;
typedef u32 uint;
typedef u32 uint3;
typedef s32 int3;
typedef u32 bool;
typedef int (*code)();
#define true 1
#define false 0
"""


def compile_c(e, obj, preset):
    c_path = TREE_DIR / e["file"]
    if obj.exists() and c_path.exists() and obj.stat().st_mtime >= c_path.stat().st_mtime:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    txt = c_path.read_text(encoding="utf-8", errors="replace")
    if "typedef unsigned char u8;" not in txt:
        calls = set(re.findall(r"\bfunc_([0-9A-F]{8})\b", txt)) - {e["name"][5:]}
        head = txt.split("{")[0] if "{" in txt else ""
        fwds = "".join(f"int func_{c}();\n" for c in sorted(calls) if f"func_{c}" not in head)
        tmp_c = obj.with_suffix(".pre.c")
        tmp_c.write_text(PRELUDE_GUARD + fwds + txt + "\n", encoding="utf-8")
        return cc_compile(tmp_c, obj, e["mode"], preset, exclude_name=e["name"])
    return cc_compile(c_path, obj, e["mode"], preset, exclude_name=e["name"])


def load_stan_sections():
    """Carga las secciones ejecutables (.text y .gnu.linkonce.t.*) y de datos (NOLOAD) de Stan."""
    map_path = ROOT / "refs" / "stanhash_fomt" / "fomt.map"
    elf_path = ROOT / "refs" / "stanhash_fomt" / "fomt.elf"
    if not map_path.exists() or not elf_path.exists():
        return [], []
    map_text = map_path.read_text(encoding="utf-8", errors="ignore")
    sec_matches = re.findall(
        r"\n\s+(\.text|\.gnu\.linkonce\.t\.[^\s]+)\s*\n?\s+(0x08[0-9a-fA-F]{6})\s+(0x[0-9a-fA-F]+)\s+(src/[^\s]+\.o)",
        map_text,
    )
    stan_mods = []
    for sec, a, s, obj in sec_matches:
        start = int(a, 16)
        size = int(s, 16)
        p = ROOT / "refs" / "stanhash_fomt" / "build" / obj
        if p.exists() and size > 0:
            stan_mods.append((start, start + size, p, obj, sec))
    stan_mods.sort(key=lambda x: x[0])

    data_matches = re.findall(
        r"\n\s+(\.[a-zA-Z0-9_\.]+)\s*\n?\s+(0x0[238][0-9a-fA-F]{6})\s+(0x[0-9a-fA-F]+)\s+(src/[^\s]+\.o)",
        map_text,
    )
    noload_secs = []
    for sec, a, s, obj in data_matches:
        if sec == ".text" or sec.startswith(".gnu.linkonce.t.") or sec in (".rom", ".rom_header"):
            continue
        start = int(a, 16)
        size = int(s, 16)
        p = ROOT / "refs" / "stanhash_fomt" / "build" / obj
        if p.exists() and size > 0:
            noload_secs.append((start, p, sec))
    return stan_mods, noload_secs


def build_stan_syms_obj(manifest, out_dir):
    """Genera stan_syms.o con tipado STT_FUNC y bit Thumb explicito para evitar veneers en GNU ld."""
    elf_path = ROOT / "refs" / "stanhash_fomt" / "fomt.elf"
    sym_s_path = out_dir / "stan_syms.s"
    sym_o_path = out_dir / "stan_syms.o"
    readelf = find_tool("readelf")
    as_bin = find_tool("as")

    sym_asm = ["\t.code 16"]
    known_syms = set()

    if elf_path.exists():
        r_elf = subprocess.run([readelf, "-s", "-W", str(elf_path)], capture_output=True, text=True, check=True)
        for line in r_elf.stdout.splitlines():
            if "GLOBAL" not in line and "WEAK" not in line:
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            val_hex, sym_type, ndx, name = parts[1], parts[3], parts[6], parts[7]
            if ndx == "UND" or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or name in known_syms:
                continue
            known_syms.add(name)
            if name in ("__vt_15Entity_080E6554", "__vt_10ANpcEntity", "__vt_12ScriptEngine"):
                sym_asm.append(f"\t.global {name}")
            else:
                sym_asm.append(f"\t.weak {name}")
            if sym_type == "FUNC":
                sym_asm.append(f"\t.type {name}, function")
            sym_asm.append(f"\t.equ {name}, 0x{val_hex}")

    for e in manifest:
        name = e["name"]
        if name not in known_syms:
            known_syms.add(name)
            addr_val = (e["addr"] | 1) if e.get("mode") == "THUMB" else (e["addr"] & ~1)
            sym_asm.append(f"\t.weak {name}")
            sym_asm.append(f"\t.type {name}, function")
            sym_asm.append(f"\t.equ {name}, 0x{addr_val:08X}")

    for idx, rg in enumerate(["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "ip", "sp", "lr"]):
        name = f"_call_via_{rg}"
        if name not in known_syms:
            known_syms.add(name)
            sym_asm.append(f"\t.weak {name}")
            sym_asm.append(f"\t.type {name}, function")
            sym_asm.append(f"\t.equ {name}, 0x{(0x080D390C + idx * 4) | 1:08X}")

    sym_s_path.write_text("\n".join(sym_asm) + "\n", encoding="utf-8")
    r_as = subprocess.run([as_bin, "-mcpu=arm7tdmi", "-mthumb-interwork", str(sym_s_path), "-o", str(sym_o_path)], capture_output=True, text=True)
    if r_as.returncode != 0:
        print(r_as.stderr[:2000])
        sys.exit(1)
    return sym_o_path, known_syms


def build():
    rom = load_rom()
    manifest = load_manifest()
    state = load_state()
    BUILD_DIR.mkdir(exist_ok=True)
    (BUILD_DIR / "o").mkdir(exist_ok=True)
    gcc, ld, objcopy = find_tool("gcc"), find_tool("ld"), find_tool("objcopy")

    stan_mods, noload_secs = load_stan_sections()
    covered_by_stan = set()
    for s, e_addr, p, obj, sec in stan_mods:
        for entry in manifest:
            if s <= entry["addr"] < e_addr:
                covered_by_stan.add(entry["name"])

    sym_o_path, known_syms = build_stan_syms_obj(manifest, BUILD_DIR)

    extra = "".join(
        (TREE_DIR / e["file"]).read_text(encoding="utf-8", errors="replace")
        for e in manifest
        if state.get(e["name"], {}).get("status") == "matched" and e["name"] not in covered_by_stan
    )
    ld_lines = []
    for gn in sorted(set(re.findall(r"\bg_([0-9A-Fa-f]{8})\b", extra))):
        gname = f"g_{gn}"
        if gname not in known_syms:
            known_syms.add(gname)
            ld_lines.append(f"PROVIDE({gname} = 0x{int(gn, 16):08X});")
    (BUILD_DIR / "symbols.ld").write_text("\n".join(ld_lines) + "\n", encoding="utf-8")

    c_objs_set = {str(sym_o_path)}
    c_objs = [str(sym_o_path)]
    asm, script, matched = [], ['INCLUDE "symbols.ld"', "SECTIONS {"], []
    cursor, ngap = ROM_BASE, 0

    def add_obj(p_str):
        if p_str not in c_objs_set:
            c_objs_set.add(p_str)
            c_objs.append(p_str)

    def add_gap(start, end):
        nonlocal ngap
        if end > start:
            ngap += 1
            a = f"{start:08X}"
            asm.append(f'.section .seg_{a},"ax"\n.incbin "{ROM_PATH.as_posix()}", 0x{start - ROM_BASE:X}, 0x{end - start:X}\n')
            script.append(f"  . = 0x{a}; .t_{a} : {{ *(.seg_{a}) }}")

    items = []
    for s, e_addr, p, obj, sec in stan_mods:
        items.append(("STAN", s, e_addr, (p, sec)))
    for e in manifest:
        if e["name"] not in covered_by_stan:
            items.append(("FUNC", e["addr"], e["addr"] + e["size"], e))
    items.sort(key=lambda x: x[1])

    for kind, start, end, data in items:
        add_gap(cursor, start)
        cursor = max(cursor, end)
        a = f"{start:08X}"
        if kind == "STAN":
            p, sec = data
            add_obj(str(p))
            script.append(f'  . = 0x{a}; .t_{a} : {{ "{p.as_posix()}"({sec}) }}')
            for entry in manifest:
                if start <= entry["addr"] < end:
                    matched.append(entry)
        else:
            e = data
            st = state.get(e["name"], {})
            obj = BUILD_DIR / "o" / f"{e['name']}.o"
            use_c = False
            if st.get("status") in ("matched",):
                r = compile_c(e, obj, st.get("preset", "O2"))
                if r.returncode == 0:
                    use_c = True
                else:
                    print(f"[!] {e['name']}: fallo de compilacion, se usa fallback binario")
            if use_c:
                add_obj(str(obj))
                matched.append(e)
                script.append(f'  . = 0x{a}; .t_{a} : {{ "{obj.as_posix()}"(.text*) }}')
            else:
                off = e["addr"] - ROM_BASE
                asm.append(f'.section .seg_{a},"ax"\n.incbin "{ROM_PATH.as_posix()}", 0x{off:X}, 0x{e["size"]:X}\n')
                script.append(f"  . = 0x{a}; .t_{a} : {{ *(.seg_{a}) }}")

    add_gap(cursor, ROM_BASE + len(rom))
    for idx_nl, (nl_addr, nl_p, nl_sec) in enumerate(noload_secs):
        add_obj(str(nl_p))
        script.append(f'  .nl_{idx_nl} 0x{nl_addr:08X} (NOLOAD) : {{ "{nl_p.as_posix()}"({nl_sec}) }}')

    script.append("  /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.data*) *(.bss*) *(.rodata*) *(.debug*) *(.gnu.linkonce.*) }")
    script.append("}")
    (BUILD_DIR / "layout.ld").write_text("\n".join(script) + "\n", encoding="utf-8")
    (BUILD_DIR / "fallback.s").write_text("".join(asm), encoding="utf-8")
    r = run([gcc, "-c", str(BUILD_DIR / "fallback.s"), "-o", str(BUILD_DIR / "fallback.o")])
    if r.returncode != 0:
        print(r.stderr[:3000])
        sys.exit(1)

    elf, out = BUILD_DIR / "fomt.elf", BUILD_DIR / "fomt.gba"
    objs_rsp = BUILD_DIR / "objs.txt"
    objs_rsp.write_text(
        "\n".join(f'"{Path(p).as_posix()}"' for p in ([str(BUILD_DIR / "fallback.o")] + c_objs)) + "\n",
        encoding="utf-8",
    )
    r = run([ld, "-T", "layout.ld", "-o", str(elf), f"@{objs_rsp.name}"], cwd=str(BUILD_DIR))
    if r.returncode != 0:
        print(r.stderr[:4000])
        sys.exit(1)
    run([objcopy, "-O", "binary", str(elf), str(out)])
    built = out.read_bytes()

    # verificacion por funcion matched
    regressed = []
    for e in matched:
        o = e["addr"] - ROM_BASE
        if built[o:o + e["size"]] != rom[o:o + e["size"]]:
            regressed.append(e["name"])
            state[e["name"]] = {"status": "regressed"}
    if regressed:
        save_state(state)
        print(f"[!] {len(regressed)} funciones matched difieren en el enlace final (marcadas regressed): "
              f"{', '.join(regressed[:10])}")

    n = min(len(built), len(rom))
    diff = sum(1 for a, b in zip(built[:n], rom[:n]) if a != b) + abs(len(built) - len(rom))
    pct = 100.0 * (1 - diff / len(rom))
    total_fn_bytes = sum(e["size"] for e in manifest)
    bytes_c = sum(e["size"] for e in matched) - sum(e["size"] for e in manifest if e["name"] in regressed)
    print(f"[+] ROM: {out}  tamano={len(built)} / {len(rom)}")
    print(f"[+] Funciones desde C/C++: {len(matched) - len(regressed)}/{len(manifest)} "
          f"({100 * (len(matched) - len(regressed)) / len(manifest):.2f}% funciones | "
          f"{bytes_c:,}/{total_fn_bytes:,} B = {100 * bytes_c / total_fn_bytes:.2f}% de .text | "
          f"{100 * bytes_c / len(rom):.3f}% de la ROM)")
    print(f"[+] Diff vs ROM original: {diff} bytes distintos -> coincidencia {pct:.6f}%")
    if diff == 0:
        print("[+] MATCH 100% (byte a byte)")
    return diff


if __name__ == "__main__":
    sys.exit(0 if build() == 0 else 2)
