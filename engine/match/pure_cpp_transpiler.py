"""Transpilador Estructural Determinista ASM -> Pure C / C++ (Cero __asm__) para FoMT GBA.

Escanea las funciones de src_sweep/ que aun contienen bloques __asm__ y aplica sintesis
algebraica C89 (agbcc) y sintesis de clases/plantillas C++98 (agbcp / cc1plus: AutoPtr<T>,
destructores polimorficos ~AEntity(), constructores con vtable, despachadores virtuales
_call_via_rX, bitfields y bloques lineales) verificando cada candidato a 0-Diff contra la ROM.
"""
import concurrent.futures
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common
import algebraic_lifter as al
import fsm_lifter as fl


AUTOPTR_TEMPLATE = """class V0 { public: virtual ~V0(); };
class V1 : public V0 {};
template <class T>
struct AutoPtr {
    T *_M_ptr;
    explicit AutoPtr(T *p = 0) : _M_ptr(p) {}
    AutoPtr(AutoPtr &a) : _M_ptr(a.release()) {}
    ~AutoPtr() { delete _M_ptr; }
    T *release() {
        T *tmp = _M_ptr;
        _M_ptr = 0;
        return tmp;
    }
    struct Ref {
        void *s;
        T *p;
        Ref(void *s, T *p) : s(s), p(p) {}
    };
    template <class U>
    AutoPtr(AutoPtr<U> const &a) {
        Ref r((void *)&a, a._M_ptr);
        *(U **)r.s = 0;
        _M_ptr = r.p;
    }
};
"""

AUTOPTR_NV_TEMPLATE = """struct NV0 { int x; ~NV0() {} };
struct NV1 : public NV0 {};
template <class T>
struct AutoPtrNV {
    T *_M_ptr;
    explicit AutoPtrNV(T *p = 0) : _M_ptr(p) {}
    AutoPtrNV(AutoPtrNV &a);
    ~AutoPtrNV() { operator delete(_M_ptr); }
    struct Ref {
        void *s;
        T *p;
        Ref(void *s, T *p) : s(s), p(p) {}
    };
    template <class U>
    AutoPtrNV(AutoPtrNV<U> const &a) {
        Ref r((void *)&a, a._M_ptr);
        *(U **)r.s = 0;
        _M_ptr = r.p;
    }
};
"""


def read_pc_lit(rom, ins_obj):
    base = (ins_obj.address + 4) & ~3
    m_imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins_obj.op_str)
    disp = int(m_imm.group(1), 0) if m_imm else 0
    pool_addr = base + disp
    rom_off = pool_addr - 0x08000000
    return int.from_bytes(rom[rom_off:rom_off + 4], 'little')


def generate_pure_candidates(e, rom):
    """Genera lista de candidatos C / C++ 100% puros (sin __asm__ ni asm) para la funcion e."""
    name = e['name']
    size = e['size']
    addr = e['addr']
    candidates = []

    # 0. Si el archivo actual solo tiene barreras vacias asm("" : ...), probar eliminandolas
    c_path = common.TREE_DIR / e['file']
    if c_path.exists():
        txt = c_path.read_text(encoding='utf-8', errors='replace')
        cleaned = re.sub(r'(__asm__|asm)\s*(volatile)?\s*\(\s*""\s*:[^;]*\);?', '', txt)
        if '__asm__' not in cleaned and 'asm(' not in cleaned and 'asm volatile' not in cleaned:
            body = cleaned.split("#define NULL 0")[-1].strip() if "#define NULL 0" in cleaned else cleaned
            candidates.append(body + "\n")

    insns = al.get_clean_insns(rom, addr, size)
    n = len(insns)
    fsm = fl.parse_function_fsm(rom, addr, size)
    calls = [f"func_{ins.operands[0].imm:08X}" for pc, ins in sorted(fsm['insns_at'].items()) if ins.mnemonic == 'bl']
    vts = [f"{v:08X}" for k, v in sorted(fsm['pool_words'].items()) if 0x080E5000 <= v < 0x080EA000]
    pwords = [v for k, v in sorted(fsm['pool_words'].items())]

    # 1. AutoPtr<V0> 60B virtual delegate family
    if size == 60 and len(calls) == 2 and calls[1] == 'func_080D3914':
        callee = calls[0]
        candidates.append(AUTOPTR_TEMPLATE + f"""struct In {{ int f0; int f4; }};
extern "C" AutoPtr<V1> {callee}(int);
extern "C" AutoPtr<V0> {name}(In *in) {{
    return {callee}(in->f4);
}}
""")

    # 2. AutoPtrNV 48B non-virtual delegate family
    if size == 48 and len(calls) == 2 and calls[1] == 'func_08000608':
        callee = calls[0]
        candidates.append(AUTOPTR_NV_TEMPLATE + f"""struct In {{ int f0; int f4; }};
extern "C" AutoPtrNV<NV1> {callee}(int);
extern "C" AutoPtrNV<NV0> {name}(In *in) {{
    return {callee}(in->f4);
}}
""")

    # 3. AutoPtr Factory New (76B, 80B, 84B)
    if size in (76, 80, 84) and len(calls) == 2 and calls[0] == 'func_080005D4' and calls[1] == 'func_080D3914' and vts:
        vt = vts[0]
        if size == 76:
            candidates.append(AUTOPTR_TEMPLATE + f"""struct C_{vt} : public V0 {{
    AutoPtr<V0> f4;
    int f8;
    C_{vt}(AutoPtr<V0> a, int b) : f4(a), f8(b) {{}}
}};
struct In {{ int vtbl; AutoPtr<V0> f4; int f8; }};
extern "C" AutoPtr<V0> {name}(In *in) {{
    return AutoPtr<C_{vt}>(new C_{vt}(in->f4, in->f8));
}}
""")
        elif size == 80:
            candidates.append(AUTOPTR_TEMPLATE + f"""struct C_{vt} : public V0 {{
    AutoPtr<V0> f4;
    int f8;
    int fc;
    C_{vt}(AutoPtr<V0> a, int b, int c) : f4(a), f8(b), fc(c) {{}}
}};
struct In {{ int vtbl; AutoPtr<V0> f4; int f8; int fc; }};
extern "C" AutoPtr<V0> {name}(In *in) {{
    return AutoPtr<C_{vt}>(new C_{vt}(in->f4, in->f8, in->fc));
}}
""")
        elif size == 84:
            candidates.append(AUTOPTR_TEMPLATE + f"""struct C_{vt} : public V0 {{
    AutoPtr<V0> f4;
    int f8;
    int fc;
    u8 f10;
    C_{vt}(AutoPtr<V0> a, int b, int c, u8 d) : f4(a), f8(b), fc(c), f10(d) {{}}
}};
struct In {{ int vtbl; AutoPtr<V0> f4; int f8; int fc; u8 f10; }};
extern "C" AutoPtr<V0> {name}(In *in) {{
    return AutoPtr<C_{vt}>(new C_{vt}(in->f4, in->f8, in->fc, in->f10));
}}
""")

    # 4. AEntity Deleting Destructors (80B..108B)
    if size in (80, 84, 88, 108) and len(vts) >= 2 and 'func_08000608' in calls and 'func_080D3914' in calls:
        vt_der, vt_base = vts[0], vts[1]
        c1 = calls[0]
        c2 = calls[1] if len(calls) > 1 else calls[0]
        if size == 84:
            for off_pad, field_name in (("u8 pad2[0x1C];\n    ", "actor_34"), ("", "actor_18")):
                candidates.append(f"""struct Loc {{ u32 a, b; }};
extern "C" Loc {c1}(void const *);
extern "C" void {c2}(void *, Loc const &);
struct V4 {{ u32 f0; virtual ~V4(); }};
struct C_{vt_base} {{
    u8 pad[0x10];
    V4 *unk_10;
    virtual ~C_{vt_base}() {{ delete unk_10; }}
}};
struct C_{vt_der} : public C_{vt_base} {{
    {off_pad}void *{field_name};
    virtual ~C_{vt_der}();
}};
C_{vt_der}::~C_{vt_der}() {{
    {c2}({field_name}, {c1}(this));
}}
extern "C" void {name}() __attribute__((alias("_._10C_{vt_der}")));
""")
            candidates.append(f"""struct Loc {{ u32 a, b; }};
extern "C" Loc {c1}(void const *);
extern "C" void {c2}(void *, Loc const &, int);
struct V4 {{ u32 f0; virtual ~V4(); }};
struct C_{vt_base} {{
    u8 pad[0x10];
    V4 *unk_10;
    virtual ~C_{vt_base}() {{ delete unk_10; }}
}};
struct C_{vt_der} : public C_{vt_base} {{
    void *actor_18;
    virtual ~C_{vt_der}();
}};
C_{vt_der}::~C_{vt_der}() {{
    {c2}(actor_18, {c1}(this), 6);
}}
extern "C" void {name}() __attribute__((alias("_._10C_{vt_der}")));
""")
        elif size == 108:
            candidates.append(f"""struct Loc {{ u32 a, b; }};
extern "C" Loc {c1}(void const *);
extern "C" void {c2}(void *, Loc const &);
struct V4 {{ u32 f0; virtual ~V4(); }};
struct C_{vt_base} {{
    u8 pad[0x8];
    int x_q16;
    int y_q16;
    V4 *unk_10;
    virtual ~C_{vt_base}() {{ delete unk_10; }}
}};
struct C_{vt_der} : public C_{vt_base} {{
    u8 pad2[0x1C];
    void *actor_34;
    u8 pad3[0x4];
    s16 sx_3c;
    s16 sy_3e;
    u8 flag_40;
    virtual ~C_{vt_der}();
}};
C_{vt_der}::~C_{vt_der}() {{
    if (flag_40) {{
        x_q16 = sx_3c << 16;
        y_q16 = sy_3e << 16;
    }}
    {c2}(actor_34, {c1}(this));
}}
extern "C" void {name}() __attribute__((alias("_._10C_{vt_der}")));
""")
            candidates.append(f"""struct Loc {{ u32 a, b; }};
extern "C" Loc {c1}(void const *);
extern "C" void {c2}(void *, Loc const &);
struct V4 {{ u32 f0; virtual ~V4(); }};
struct C_{vt_base} {{
    u8 pad[0x8];
    int x_q16;
    int y_q16;
    V4 *unk_10;
    virtual ~C_{vt_base}() {{ delete unk_10; }}
}};
struct C_{vt_der} : public C_{vt_base} {{
    u8 pad2[0x1C];
    void *actor_34;
    s16 sx_38;
    s16 sy_3a;
    u8 pad3;
    u8 flag_3d;
    virtual ~C_{vt_der}();
}};
C_{vt_der}::~C_{vt_der}() {{
    if (flag_3d) {{
        x_q16 = sx_38 << 16;
        y_q16 = sy_3a << 16;
    }}
    {c2}(actor_34, {c1}(this));
}}
extern "C" void {name}() __attribute__((alias("_._10C_{vt_der}")));
""")

    # 5. Saturating sub byte (28B): func_0800DC8C, func_0800DF34, func_0800E0D4
    if size == 28 and n == 12 and insns[2].mnemonic == 'ldrb':
        m_off = re.search(r'#(\d+|0x[0-9a-fA-F]+)', insns[2].op_str)
        off = int(m_off.group(1), 0) if m_off else 1
        candidates.append(f"""void {name}(u8 *a, u32 b) {{
    u8 v = a[{off}];
    if (v != 0) {{
        if (v > b)
            a[{off}] = v - b;
        else
            a[{off}] = 0;
    }}
}}
""")

    # 6. Catalogo exacto de funciones C/C++ puras verificadas sin __asm__
    pure_catalog = {
        "func_080E41B0": """class V0 { public: virtual ~V0(); };
class V4 { public: int x; virtual ~V4(); };
struct S_080E41B0 { int f0; V4 *f4; V0 *f8; };
extern "C" void func_080007EC(void *, int);
extern "C" void func_080E41B0(S_080E41B0 *a, int b) {
    delete a->f8;
    delete a->f4;
    func_080007EC(a, b);
}
""",
        "func_080AAF10": "void func_080AAF10(u32 **a) { struct { u32 v; } s = { a[3][2] }; }\n",
        "func_080AAF1C": "void func_080AAF1C(u32 *a) { struct { u32 v; } s = { a[3] }; }\n",
        "func_080D100C": f"u32 func_080D100C(int i, u32 v) {{ u32 *p = &((u32 *)0x{pwords[0] if pwords else 0:08X})[i]; u32 old = *p; *p = v; return old; }}\n",
        "func_080D101C": f"u16 func_080D101C(int i, u16 v) {{ u16 *p = &((u16 *)0x{pwords[0] if pwords else 0:08X})[i]; u16 old = *p; *p = v; return old; }}\n",
        "func_08000714": "struct S { u32 a; u8 b:2; }; u32 func_080D100C(u32, u32); u32 func_08000714(struct S *s, u32 v) { return func_080D100C(s->b + 3, v); }\n",
        "func_08024C74": "void func_08024C74(u8 *a) { a[0x3c] = 0; a[0x3e] = 0; *(u16 *)(a + 0xa6) = 0; }\n",
        "func_08033914": "u32 func_08033914(u32 a) { return (((a + 1) * (0xc0 << 9)) >> 8) + (0x80 << 8); }\n",
        "func_0809D8D4": "struct E { u8 a:4; u8 b; }; struct R { u32 h; struct E e[28]; }; u32 func_0809D8D4(struct R *r, int x, int y) { return r[y].e[x].a; }\n",
        "func_080CC70C": "struct E { u32 a, b, c; }; struct S { u8 pad[0x86 << 2]; struct E e[1]; }; struct E *func_080CC70C(struct S *s, int i) { return &s->e[i]; }\n",
        "func_080CECD0": "void func_080CECD0(u8 *a) { a[0x84] = 0; a[0x68] = 0; *(u32 *)(a + 0x7c) = 0x12; *(u32 *)(a + 0x80) = 0; }\n",
        "func_08075DB8": "void func_08075C88(u16 *, s16); void func_08075DB8(u16 *a, s16 b) { a[3] = 0xFFFF; a[5] = -1; func_08075C88(a, b); }\n",
        "func_0809EB4C": "struct S { u8 pad[0x14]; u8 a; u8 b:1; }; void func_0809E2D4(void *); struct S *func_0809EB4C(struct S *s) { func_0809E2D4(s); s->a = 0; s->b = 0; return s; }\n",
        "func_0803B454": "struct S { u32 w[5]; }; void func_0803B474(struct S *, u32, u32); struct S *func_0803B454(struct S *a, struct S *b, u32 c, u32 d) { *a = *b; func_0803B474(a, c, d); return a; }\n",
        "func_080941A8": "void func_080941A8(u32 *a) { (*(void (**)(u32 *, u32, u32, u32, u32))(*a + 0x34))(a, a[6], a[7], a[8], a[9]); }\n",
        "func_08094648": "void func_08094648(u32 *a) { (*(void (**)(u32 *, u32, u32, u32, u32))(*a + 0x34))(a, a[8], a[9], a[10], a[11]); }\n",
        "func_0809444C": "void func_0809444C(u32 *a) { (*(void (**)(u32 *, u32, int, void *, int))(*a + 0x34))(a, a[5], 8, a + 6, 8); }\n",
        "func_0801238C": "void func_0801238C(u8 **a, u32 b, u32 c, u32 d) { u32 *p = *(u32 **)(a[1] + 0xa8); (*(void (**)(u32 *, u32, u32, u32))(*p + 0x24))(p, b, c, d); }\n",
        "func_08016EC4": "void func_08016EC4(u8 **a, u32 b, u32 c, u32 d, u32 e, u16 f) { u32 *p = *(u32 **)(a[1] + 0xa8); (*(void (**)(u32 *, u32, u32, u32, u32, u16))(*p + (0xb0 << 1)))(p, b, c, d, e, f); }\n",
        "func_08009300": "struct Node { u32 a; u16 b; u32 c; u8 d; u16 e; Node(u32 x) : a(x), b(0), c(0), d(0), e(0) {} }; extern \"C\" Node **func_08009300(Node **out, u32 x) { *out = new Node(x); return out; }\n",
        "func_08032B04": "void func_0805E860(void *); void func_08032B04(u8 *a) { func_0805E860(a + 0x30); a[0x44] = 1; a[0x46] = 0; a[0x47] = 1; }\n",
        "func_080390DC": "void func_0805E860(void *); void func_080390DC(u8 *a) { func_0805E860(a + 0x30); a[0x44] = 1; a[0x46] = 0; a[0x47] = 1; }\n",
        "func_0804E9D0": "void func_080D374C(void *, u32, u32); void func_0804E9D0(u32 a, u32 b, void *c) { func_080D374C(c, b, ((((u32)(u16)a * (a >> 16)) << 5) >> 2) & 0x1FFFFF); }\n",
        "func_08050DF0": "u32 func_08050DF0(u8 **a) { u8 *p = *a; if (*(u32 *)(p + 8) == 6) return 0; return *(u32 *)(p + (0xac << 1)); }\n",
        "func_08085EEC": f"u32 func_08085EEC(u8 *a) {{ u32 v = *(u32 *)(a + 0x{pwords[0] if pwords else 0:X}); if (v > 1) return 0x{pwords[1] if len(pwords)>1 else 0:X}; return v; }}\n",
        "func_0800C25C": "struct S { u8 a:2; u8 pad[3]; u8 b:6; u8 c:1; }; void func_0800C25C(struct S *s) { if (s->a > 1 && !s->c) s->c = 1; }\n",
        "func_08011588": "u32 func_08011588(u8 *a, u32 n) { u32 s = 0; if (a != 0 && n != 0) { do { s += *a++; n--; } while (n != 0); } return s; }\n",
        "func_0809B018": "struct E { u32 a, b; }; struct S { u32 p0, p1, n; struct E e[1]; }; struct E *func_0809B018(struct S *s, u32 i) { if (i < s->n) return &s->e[s->n - (i + 1)]; return s->e; }\n",
        "func_0809B038": "struct E { u32 a, b; }; struct S { u8 pad[0xfc]; u32 n; struct E e[1]; }; struct E *func_0809B038(struct S *s, u32 i) { if (i < s->n) return &s->e[s->n - (i + 1)]; return s->e; }\n",
        "func_08016784": "int func_08008CD0(void *); void func_08008BF8(void *, int); int func_08016784(u8 **a) { u8 *p = a[1] + 0xbc; if ((u8)func_08008CD0(p)) { func_08008BF8(p, 5); return 1; } return 0; }\n",
        "func_08024CA0": "int func_08024CA0(u8 *a) { if ((*(u8 (**)(u8 *))(*(u32 *)(a + 0x14) + 0x28))(a)) return 0; if ((s8)a[0x3c] <= 0x2a && (s8)a[0x3c] >= 0x24) return 1; return 0; }\n",
        "func_08050E98": "struct S { u8 pad[0xaa << 3]; u8 bf:6; }; void func_08050E98(struct S **a, u32 b) { (*a)->bf &= ~b; }\n",
        "func_08050EBC": "struct S { u8 pad[0xaa << 3]; u8 bf:6; }; void func_08050EBC(struct S **a, u32 b) { (*a)->bf |= b; }\n",
        "func_08057F24": "struct S { u8 pad[0x2c]; u8 bf:2; }; void func_08057F64(void *); void func_08057F24(struct S *s) { s->bf++; func_08057F64(s); }\n",
        "func_080D0A94": f"void func_080D0A54(u32); void func_080D0A94(u32 a) {{ u8 **p = (u8 **)0x{pwords[0] if pwords else 0:08X}; *(u32 *)(*p + (0xbe << 1)) = 1; func_080D0A54(a); *(u32 *)(*p + (0xbe << 1)) = 0; }}\n",
        "func_080D0678": f"u32 func_080D0678(void) {{ u8 *p = **(u8 ***)0x{pwords[0] if pwords else 0:08X}; return p[0x2c] | (p[0x2d] << 8) | (p[0x2e] << 16) | (p[0x2f] << 24); }}\n",
        "func_080E2094": "struct P { u32 a, b; }; struct S { struct P p[6]; }; struct S *func_080E2094(struct S *s) { struct { u32 x, y, z; } pad; s->p[0].a = 0; s->p[0].b = 0; s->p[1].b = 0; s->p[2].a = 0; s->p[2].b = 0; s->p[3].b = 0; s->p[4].a = 0; s->p[4].b = 0; s->p[5].b = 0; return s; }\n",
    }
    if name in pure_catalog:
        candidates.append(pure_catalog[name])

    return candidates


def try_transpile_one(e, rom, manifest):
    cands = generate_pure_candidates(e, rom)
    for code in cands:
        if '__asm__' in code or 'asm(' in code or 'asm volatile' in code:
            continue
        ok, preset = al.verify_candidate(e, code, manifest, rom)
        if ok:
            return (e, code, preset)
    return (e, None, None)


def main():
    rom = common.load_rom()
    manifest = common.load_manifest()
    state = common.load_state()

    asm_funcs = []
    for e in manifest:
        p = common.TREE_DIR / e['file']
        txt = p.read_text(encoding='utf-8', errors='replace') if p.exists() else ''
        if '__asm__' in txt or 'asm(' in txt or 'asm volatile' in txt:
            asm_funcs.append(e)

    print(f"[*] Escaneando {len(asm_funcs)} funciones con inline ASM para transpilacion a Pure C/C++...")
    t0 = time.time()

    with_cands = [e for e in asm_funcs if generate_pure_candidates(e, rom)]
    print(f"[*] Probando {len(with_cands)} funciones con candidatos C/C++ puros (8 workers)...")

    converted = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(try_transpile_one, e, rom, manifest): e for e in with_cands}
        for fut in concurrent.futures.as_completed(futs):
            e, code, preset = fut.result()
            if code:
                converted.append((e, code, preset))
                print(f"  [PURE C/C++ 0-DIFF] {e['name']} ({e['size']}B) -> {preset}")

    print(f"\n[+] Transpilacion completada en {time.time() - t0:.1f}s: {len(converted)}/{len(with_cands)} funciones convertidas a Pure C/C++ (cero __asm__)!")
    if converted:
        for e, code, preset in converted:
            c_file = common.TREE_DIR / e['file']
            c_file.write_text(al.PRELUDE + "\n" + code, encoding='utf-8')
            state[e['name']]['preset'] = preset
            state[e['name']]['how'] = 'pure-cpp-transpiler'
        common.save_state(state)


if __name__ == '__main__':
    main()
