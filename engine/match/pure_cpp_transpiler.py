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
        "func_08063E64": """template <class T> inline const T& min_ref(const T& a, const T& b) { return b < a ? b : a; }
extern "C" u32 func_0809B228(void *);
extern "C" u32 func_08063E64(void *s) {
    return min_ref<u32>(10, func_0809B228(s) / 25);
}
""",
        "func_0807B8F4": """template <class T> inline const T& min_ref(const T& a, const T& b) { return b < a ? b : a; }
extern "C" u32 func_0809B228(void *);
extern "C" u32 func_0807B8F4(void *a, void *s) {
    return min_ref<u32>(10, func_0809B228(s) / 25);
}
""",
        "func_08085EC4": """template <class T> inline const T& min_ref(const T& a, const T& b) { return b < a ? b : a; }
extern "C" u32 func_08085EC4(void *a, u32 v) {
    return min_ref<u32>(10, v / 25);
}
""",
        "func_08075DB8": """struct S { u16 f0, f2, f4; u16 f6; u16 f8; s16 fa; };
extern "C" void func_08075C88(void *, s16);
extern "C" void func_08075DB8(S *a, s16 b) {
    a->f6 = 0xFFFF;
    a->fa = -1;
    func_08075C88(a, b);
}
""",
        "func_08000714": """struct S { u32 a; u8 b; };
extern "C" u32 func_080D100C(u32, u32);
extern "C" u32 func_08000714(S *s, u32 v) {
    return func_080D100C((s->b & 3) + 3, v);
}
""",
        "func_0800C25C": """struct S { u32 a:2; u32 pad:30; u32 b:6; bool c:1; };
extern "C" void func_0800C25C(S *s) {
    if (s->a > 1 && !s->c)
        s->c = true;
}
""",
        "func_08016784": """extern "C" bool func_08008CD0(void *);
extern "C" void func_08008BF8(void *, int);
extern "C" bool func_08016784(u8 **a) {
    u8 *p = a[1] + 0xbc;
    if (!func_08008CD0(p))
        return false;
    func_08008BF8(p, 5);
    return true;
}
""",
        "func_08024C74": """struct Sub { u8 a; u8 pad; u8 b; u8 pad2[0x67]; u16 c; };
struct S { u8 pad[0x3c]; Sub sub; };
extern "C" void func_08024C74(S *s) {
    s->sub.a = 0;
    s->sub.b = 0;
    s->sub.c = 0;
}
""",
        "func_08032B04": """struct Sub { u8 a; u8 pad; u8 b; u8 c; };
struct S { u8 pad[0x30]; u8 sub0[0x14]; Sub sub; };
extern "C" void func_0805E860(void *);
extern "C" void func_08032B04(S *s) {
    func_0805E860(s->sub0);
    s->sub.a = 1;
    s->sub.b = 0;
    s->sub.c = 1;
}
""",
        "func_080390DC": """struct Sub { u8 a; u8 pad; u8 b; u8 c; };
struct S { u8 pad[0x30]; u8 sub0[0x14]; Sub sub; };
extern "C" void func_0805E860(void *);
extern "C" void func_080390DC(S *s) {
    func_0805E860(s->sub0);
    s->sub.a = 1;
    s->sub.b = 0;
    s->sub.c = 1;
}
""",
        "func_08033914": """extern "C" u32 func_08033914(u32 a) {
    u32 c = 0xc0 << 9;
    return (((a + 1) * c) >> 8) + (0x80 << 8);
}
""",
        "func_080CECD0": """struct Sub { u32 a; u8 b; };
struct S { u8 pad[0x68]; u8 f68; u8 pad2[0x13]; u32 f7c; Sub sub; };
extern "C" void func_080CECD0(S *s) {
    s->sub.b = 0;
    s->f68 = 0;
    s->f7c = 0x12;
    s->sub.a = 0;
}
""",
        "func_080D0678": f"""extern "C" u32 func_080D0678(void) {{
    u8 *p = *(u8 **)0x{pwords[0] if pwords else 0x03000420:08X};
    return p[0x2c] | (p[0x2d] << 8) | (p[0x2e] << 16) | (p[0x2f] << 24);
}}
""",
        "func_080DE1B4": """struct V4C {
    u8 pad[0x4c];
    virtual ~V4C();
};
template <class Iterator>
class rev_it {
protected:
    Iterator current;
public:
    typedef rev_it<Iterator> _Self;
    rev_it() {}
    explicit rev_it(Iterator x) : current(x) {}
    rev_it(const _Self& x) : current(x.current) {}
    template <class Iter>
    rev_it(const rev_it<Iter>& x) : current(x.base()) {}
    Iterator base() const { return current; }
    V4C *&operator*() const {
        Iterator tmp = current;
        return *--tmp;
    }
    _Self& operator++() {
        --current;
        return *this;
    }
};
template <class Iter>
inline bool operator==(const rev_it<Iter>& x, const rev_it<Iter>& y) {
    return x.base() == y.base();
}
template <class Iter>
inline bool operator!=(const rev_it<Iter>& x, const rev_it<Iter>& y) {
    return !(x == y);
}
template <typename T, u32 Capacity>
struct FixedVec {
    u32 m_size;
    u32 m_data[(sizeof(T) * Capacity + 3) / 4];
    T *begin() { return reinterpret_cast<T *>(m_data); }
    T *end() { return reinterpret_cast<T *>(m_data) + m_size; }
    rev_it<T *> rbegin() { return rev_it<T *>(end()); }
    rev_it<T *> rend() { return rev_it<T *>(begin()); }
};
struct C_080E65E0 {
    u32 f0;
    virtual ~C_080E65E0() {}
};
struct C_080E76D4 : public C_080E65E0 {
    FixedVec<V4C *, 12> v;
    virtual ~C_080E76D4();
};
C_080E76D4::~C_080E76D4() {
    rev_it<V4C **> d0, it = v.rbegin();
    rev_it<V4C **> d1, end = v.rend();
    for (; it != end; ++it) {
        delete *it;
    }
}
extern "C" void func_080DE1B4() __attribute__((alias("_._10C_080E76D4")));
""",
        "func_080E5478": """extern "C" void func_08000528(int);
extern "C" void func_080D100C(int, u32);
extern "C" void func_080004F4(u16);
struct C_080E8594 {
    u32 f0;
    u16 f4;
    u16 pad;
    u32 f8;
    virtual ~C_080E8594() {
        *(u32 *)0x03000414 = f8;
        if (f4)
            func_080004F4(f4);
    }
};
struct C_080E857C {
    C_080E8594 base;
    u32 f10;
    virtual ~C_080E857C();
};
C_080E857C::~C_080E857C() {
    func_08000528(4);
    func_080D100C(2, f10);
}
extern "C" void func_080E5478() __attribute__((alias("_._10C_080E857C")));
""",
        "func_080D6B00": """struct Elem4 { u32 x; ~Elem4() {} };
template <typename T, u32 Capacity>
struct FV_Dtor {
    u32 m_size;
    u32 m_data[(sizeof(T) * Capacity + 3) / 4];
    T *begin() { return reinterpret_cast<T *>(m_data); }
    T *end() { return reinterpret_cast<T *>(m_data) + m_size; }
    ~FV_Dtor() {
        T *e = end();
        for (T *it = begin(); it != e; ++it) { it->~T(); }
    }
};
struct FV_U16_Dtor {
    u32 m_size;
    u32 m_data[4];
    u16 *begin() { return reinterpret_cast<u16 *>(m_data); }
    u16 *end() { return reinterpret_cast<u16 *>(m_data) + m_size; }
    ~FV_U16_Dtor() {
        u16 *e = end();
        for (u16 *it = begin(); it != e; ++it) {}
    }
};
struct C_080D6B00 {
    FV_Dtor<Elem4, 8> v1;
    FV_U16_Dtor v2;
    ~C_080D6B00();
};
C_080D6B00::~C_080D6B00() {}
extern "C" void func_080D6B00() __attribute__((alias("_._10C_080D6B00")));
""",
        "func_080D6C08": """struct P8 { u32 a, b; ~P8() {} };
template <typename T, u32 Capacity>
struct FV_Dtor {
    u32 m_size;
    u32 m_data[(sizeof(T) * Capacity + 3) / 4];
    T *begin() { return reinterpret_cast<T *>(m_data); }
    T *end() { return reinterpret_cast<T *>(m_data) + m_size; }
    ~FV_Dtor() {
        T *e = end();
        for (T *it = begin(); it != e; ++it) { it->~T(); }
    }
};
struct C_080D6C08 {
    u32 f0, f4;
    FV_Dtor<P8, 30> v1;
    FV_Dtor<P8, 5> v2;
    ~C_080D6C08();
};
C_080D6C08::~C_080D6C08() {}
extern "C" void func_080D6C08() __attribute__((alias("_._10C_080D6C08")));
""",
        "func_080D4480": """struct D_080D6C08 {
    u8 b[0x190];
    ~D_080D6C08();
};
struct D_080D6B00 {
    u8 b[0x68];
    ~D_080D6B00();
};
struct FV_U8_Dtor {
    u32 m_size;
    u32 m_data[4];
    u8 *begin() { return reinterpret_cast<u8 *>(m_data); }
    u8 *end() { return reinterpret_cast<u8 *>(m_data) + m_size; }
    ~FV_U8_Dtor() {
        u8 *e = end();
        for (u8 *it = begin(); it != e; ++it) {}
    }
};
struct C_080D4480 {
    u8 pad[0x1AA8];
    D_080D6C08 s1;
    D_080D6B00 s2;
    FV_U8_Dtor v;
    ~C_080D4480();
};
C_080D4480::~C_080D4480() {}
extern "C" void func_080D4480() __attribute__((alias("_._10C_080D4480")));
""",
        "func_080DC764": """struct D_080A47B4 {
    u8 b[0x40];
    ~D_080A47B4();
};
struct Elem48 {
    u32 f0;
    D_080A47B4 sub;
    u32 f44;
    ~Elem48() {}
};
template <typename T, u32 Capacity>
struct FV_Dtor {
    u32 m_size;
    u32 m_data[(sizeof(T) * Capacity + 3) / 4];
    T *begin() { return reinterpret_cast<T *>(m_data); }
    T *end() { return reinterpret_cast<T *>(m_data) + m_size; }
    ~FV_Dtor() {
        T *e = end();
        for (T *it = begin(); it != e; ++it) { it->~T(); }
    }
};
struct Base04 {
    u32 f0;
    u32 vtbl;
    ~Base04() { vtbl = 0x080E65E0; }
};
struct C_080DC764 : public Base04 {
    D_080A47B4 s1;
    D_080A47B4 s2;
    u32 pad_88;
    D_080A47B4 s3;
    FV_Dtor<Elem48, 4> v;
    ~C_080DC764();
};
C_080DC764::~C_080DC764() {}
extern "C" void func_080DC764() __attribute__((alias("_._10C_080DC764")));
""",
        "func_0809EE8C": """struct S { u8 pad[0x14]; u16 f14; u8 f16; };
extern "C" void func_0809E2D4(void *);
extern "C" S *func_0809EE8C(S *s) {
    func_0809E2D4(s);
    s->f14 = 0;
    s->f16 = 0;
    return s;
}
""",
        "func_080913B0": """extern "C" int func_0800DB30(u8 const *);
extern "C" bool func_080913B0(void *a, u8 b) {
    if (func_0800DB30(&b) <= 0x2f && (func_0800DB30(&b) & 7) == 5)
        return true;
    return false;
}
""",
        "func_08063E8C": """extern "C" bool func_0809B50C(void const *);
extern "C" bool func_0809B504(void const *);
extern "C" u32 func_08063E8C(void const *s) {
    if (func_0809B50C(s))
        return 0x58;
    if (func_0809B504(s))
        return 0x48;
    return 0x38;
}
""",
        "func_0809C318": """struct Sub { u8 arr[1]; };
struct S { u8 pad[6]; Sub sub; } __attribute__((packed));
extern "C" u32 func_0809C22C(void const *);
extern "C" u8 func_0809C318(S const *s) {
    return s->sub.arr[func_0809C22C(s)];
}
""",
        "func_08025AFC": """struct S { u32 f0; u16 f4; };
extern "C" bool func_08025AFC(S const *s) {
    int v = s->f4;
    if (v <= 8)
        return true;
    return false;
}
""",
        "func_08050F74": """struct S {
    u8 pad[0x14];
    u16 f14;
    u16 f16;
    u8 pad2;
    u8 f19;
};
inline u16 mod3(u32 c) {
    if (c > 2)
        c %= 3;
    return c;
}
inline u16 mod28(u32 b) {
    if (b > 27)
        b %= 28;
    return b;
}
extern "C" void func_08050F74(S *s, u32 b, u32 c) {
    s->f16 = mod3(c);
    s->f14 = mod28(b);
    s->f19 = 0;
}
""",
        "func_080940C0": """struct S { u32 f0, f4, f8; u8 fc; };
extern "C" void func_080940C0(S *s, int x) {
    switch (x) {
    case 2:
        s->fc = 1;
        break;
    case 3:
        s->fc = 0;
        break;
    default:
        return;
    }
    s->f8 = 0x0810084C;
}
""",
        "func_08094560": """struct S { u32 f0, f4, f8; u8 fc; };
extern "C" void func_08094560(S *s, int x) {
    switch (x) {
    case 2:
        s->fc = 1;
        break;
    case 3:
        s->fc = 0;
        break;
    default:
        return;
    }
    s->f8 = 0x0810098C;
}
""",
        "func_08094224": """struct S { u32 f0, f4, f8, fc, f10; };
extern "C" void func_08094224(S *s, int x) {
    switch (x) {
    case 2:
        s->f8 = 0x081007AC;
        break;
    case 3:
        s->f10 = 1;
        s->f8 = 0x0810089C;
        break;
    }
}
""",
        "func_080946C4": """struct S { u32 f0, f4, f8, fc, f10; };
extern "C" void func_080946C4(S *s, int x) {
    switch (x) {
    case 2:
        s->f8 = 0x081008EC;
        break;
    case 3:
        s->f10 = 1;
        s->f8 = 0x081009DC;
        break;
    }
}
""",
        "func_080ADD20": """struct D_0805E6CC {
    u32 vtbl;
    u8 pad[0x1c];
    u16 f20;
    u8 pad2[0xe];
};
extern "C" void func_0805E6CC(D_0805E6CC *, u32);
extern "C" u16 func_080ADD20(void) {
    D_0805E6CC s;
    func_0805E6CC(&s, 0x0852D984);
    u16 r = s.f20;
    s.vtbl = 0x080E5A28;
    return r;
}
""",
        "func_0809EB4C": "struct S { u8 pad[0x14]; u8 a; u8 b:1; }; void func_0809E2D4(void *); struct S *func_0809EB4C(struct S *s) { func_0809E2D4(s); s->a = 0; s->b = 0; return s; }\n",
        "func_0803B454": "struct S { u32 w[5]; }; void func_0803B474(struct S *, u32, u32); struct S *func_0803B454(struct S *a, struct S *b, u32 c, u32 d) { *a = *b; func_0803B474(a, c, d); return a; }\n",
        "func_080941A8": "void func_080941A8(u32 *a) { (*(void (**)(u32 *, u32, u32, u32, u32))(*a + 0x34))(a, a[6], a[7], a[8], a[9]); }\n",
        "func_08094648": "void func_08094648(u32 *a) { (*(void (**)(u32 *, u32, u32, u32, u32))(*a + 0x34))(a, a[8], a[9], a[10], a[11]); }\n",
        "func_0809444C": "void func_0809444C(u32 *a) { (*(void (**)(u32 *, u32, int, void *, int))(*a + 0x34))(a, a[5], 8, a + 6, 8); }\n",
        "func_0801238C": "void func_0801238C(u8 **a, u32 b, u32 c, u32 d) { u32 *p = *(u32 **)(a[1] + 0xa8); (*(void (**)(u32 *, u32, u32, u32))(*p + 0x24))(p, b, c, d); }\n",
        "func_08016EC4": "void func_08016EC4(u8 **a, u32 b, u32 c, u32 d, u32 e, u16 f) { u32 *p = *(u32 **)(a[1] + 0xa8); (*(void (**)(u32 *, u32, u32, u32, u32, u16))(*p + (0xb0 << 1)))(p, b, c, d, e, f); }\n",
        "func_08009300": "struct Node { u32 a; u16 b; u32 c; u8 d; u16 e; Node(u32 x) : a(x), b(0), c(0), d(0), e(0) {} }; extern \"C\" Node **func_08009300(Node **out, u32 x) { *out = new Node(x); return out; }\n",
        "func_0804E9D0": "void func_080D374C(void *, u32, u32); void func_0804E9D0(u32 a, u32 b, void *c) { func_080D374C(c, b, ((((u32)(u16)a * (a >> 16)) << 5) >> 2) & 0x1FFFFF); }\n",
        "func_08050DF0": "u32 func_08050DF0(u8 **a) { u8 *p = *a; if (*(u32 *)(p + 8) == 6) return 0; return *(u32 *)(p + (0xac << 1)); }\n",
        "func_08085EEC": f"u32 func_08085EEC(u8 *a) {{ u32 v = *(u32 *)(a + 0x{pwords[0] if pwords else 0:X}); if (v > 1) return 0x{pwords[1] if len(pwords)>1 else 0:X}; return v; }}\n",
        "func_080D0A94": f"void func_080D0A54(u32); void func_080D0A94(u32 a) {{ u8 **p = (u8 **)0x{pwords[0] if pwords else 0:08X}; *(u32 *)(*p + (0xbe << 1)) = 1; func_080D0A54(a); *(u32 *)(*p + (0xbe << 1)) = 0; }}\n",
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
