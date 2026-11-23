"""Fusion de StanHash/fomt con el manifest del motor (semantizacion + cobertura + seeds C++).

Cruza por direccion:
  - Stan: asm/*.s (funciones sin decompilar, con limites exactos) y src/*.cc (decompiladas, C++).
  - Nosotros: src_sweep/manifest.json + state.json.

Produce (NO modifica manifest.json ni state.json; todo va a archivos aparte):
  src_sweep/fusion/semantic_map.json     addr -> modulo, clase, nombre Stan, origen, tamanos
  src_sweep/fusion/manifest_additions.json  funciones de Stan que no existen en nuestro manifest
  src_sweep/fusion/conflicts.json        limites distintos (fusionadas/partidas/tamano distinto)
  src_sweep/fusion/stan_cc/<func>.cc     C++ verificado de Stan por funcion (seed de maxima calidad)
  src_sweep/fusion/REPORT.md             resumen

Uso:
  python tools/match/fuse_stan.py
"""
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "match"))
import stan_import as S  # noqa: E402
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM  # noqa: E402

STAN = ROOT / "refs" / "stanhash_fomt"
OUT = ROOT / "src_sweep" / "fusion"
ROM_BASE = 0x08000000
TMD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
AMD = Cs(CS_ARCH_ARM, CS_MODE_ARM)

CC_DEF = re.compile(
    r"^(?:EC\s+)?(?P<ret>[\w:<>\s\*&,]+?)\s+(?P<name>func_(?P<addr>[0-9A-Fa-f]{8}))\s*\((?P<args>[^)]*)\)\s*(?:const)?\s*$"
)
CLASS_IN_ARGS = re.compile(r"\b([A-Z]\w+)\s+const\s*&|\b([A-Z]\w+)\s*\*|\b([A-Z]\w+)\s*&")


def asm_size(f, rom):
    """(codigo+pools, blob). 'blob' = bytes crudos '.byte' tras el codigo: en Stan son funciones
    aun sin desensamblar embebidas en la funcion previa."""
    off = f["addr"] - ROM_BASE
    pos = off
    md = TMD if f["mode"] == "THUMB" else AMD
    code_end = None
    for s in f["ins"]:
        if s == "@align":
            if (f["addr"] + pos - off) % 4:
                pos += 2
            continue
        if s.startswith("@blob"):
            if code_end is None:
                code_end = pos
            pos += int(s[5:])
            continue
        if s.startswith("@pool"):
            pos += int(s[5:])
            continue
        ci = next(md.disasm(rom[pos:pos + 4], f["addr"] + pos - off), None)
        pos += ci.size if ci else 2
    if code_end is None:
        return pos - off, 0
    return code_end - off, pos - code_end


def parse_cc():
    """Funciones decompiladas en src/*.cc: addr -> {file, ret, args, class, body}."""
    out = {}
    for p in sorted((STAN / "src").glob("*.cc")):
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        i = 0
        while i < len(lines):
            m = CC_DEF.match(lines[i])
            if m and i + 1 < len(lines) and lines[i + 1].strip().startswith("{"):
                depth, j = 0, i + 1
                while j < len(lines):
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
                    if depth == 0:
                        break
                cm = CLASS_IN_ARGS.search(m.group("args"))
                cls = next((g for g in cm.groups() if g), None) if cm else None
                out[int(m.group("addr"), 16)] = {
                    "file": p.name, "ret": m.group("ret").strip(), "args": m.group("args").strip(),
                    "class": cls, "body": "\n".join(lines[i:j]), "name": m.group("name"),
                }
                i = j
                continue
            i += 1
    return out


def module_of(fname):
    n = fname.rsplit(".", 1)[0]
    return re.sub(r"^code_", "", n)


def main():
    rom = (ROOT / "fomt virgen.gba").read_bytes()
    manifest = json.loads((ROOT / "src_sweep" / "manifest.json").read_text(encoding="utf-8"))
    state = json.loads((ROOT / "src_sweep" / "state.json").read_text(encoding="utf-8"))
    ours = sorted(manifest, key=lambda e: e["addr"])
    by_addr = {e["addr"]: e for e in ours}
    starts = [e["addr"] for e in ours]

    import bisect

    def containing(a):
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0 and ours[i]["addr"] <= a < ours[i]["addr"] + ours[i]["size"]:
            return ours[i]
        return None

    stan_asm = S.build_index()
    cc = parse_cc()

    funcs = {}  # addr -> info
    for f in stan_asm:
        csz, blob = asm_size(f, rom)
        funcs[f["addr"]] = {"addr": f["addr"], "stan_name": f["name"], "origin": "asm",
                            "module": module_of(f["file"]), "class": None,
                            "stan_size": csz, "blob_size": blob, "mode": f["mode"]}
    for a, c in cc.items():
        sz = None
        e = by_addr.get(a)
        if e:
            sz = e["size"]
        funcs.setdefault(a, {"addr": a, "stan_name": c["name"], "mode": "THUMB", "stan_size": sz})
        funcs[a].update({"origin": "cc", "module": module_of(c["file"]), "class": c["class"],
                         "signature": f"{c['ret']} {c['name']}({c['args']})"})

    sem, adds, conflicts = {}, [], []
    cnt = collections.Counter()
    for a, f in sorted(funcs.items()):
        e = by_addr.get(a)
        rec = dict(f)
        rec["addr"] = f"0x{a:08X}"
        if e:
            rec["our_name"] = e["name"]
            rec["our_size"] = e["size"]
            rec["our_status"] = state.get(e["name"], {}).get("status")
            if f.get("stan_size") and f["stan_size"] != e["size"]:
                cnt["size_diff"] += 1
                conflicts.append({"addr": rec["addr"], "kind": "size_diff", "stan": f["stan_size"], "ours": e["size"],
                                  "origin": f["origin"]})
            else:
                cnt["same_bounds"] += 1
        else:
            host = containing(a)
            if host:
                cnt["merged_in_ours"] += 1
                rec["our_host"] = host["name"]
                conflicts.append({"addr": rec["addr"], "kind": "merged_in_ours", "host": host["name"],
                                  "host_size": host["size"], "stan_size": f.get("stan_size")})
            else:
                cnt["only_stan"] += 1
                adds.append({"name": f"func_{a:08X}", "addr": a, "mode": f["mode"],
                             "size": f.get("stan_size"), "origin": f["origin"], "module": f.get("module")})
        sem[f"{a:08X}"] = rec

    stan_addrs = set(funcs)
    only_ours = [e for e in ours if e["addr"] not in stan_addrs]
    # clasificar las nuestras que Stan no lista: dentro de un blob '.byte' (Stan aun no las desensambla),
    # dentro del codigo de otra funcion de Stan (nosotros partimos de mas) o fuera de todo.
    blobs = sorted((a + f["stan_size"], a + f["stan_size"] + f["blob_size"]) for a, f in funcs.items()
                   if f.get("blob_size"))
    bstarts = [b for b, _ in blobs]
    stan_iv = sorted((a, a + f["stan_size"]) for a, f in funcs.items() if f.get("stan_size"))
    sstarts = [a for a, _ in stan_iv]
    where = collections.Counter()
    in_blob_bytes = 0
    split_ours = []
    for e in only_ours:
        j = bisect.bisect_right(bstarts, e["addr"]) - 1
        i = bisect.bisect_right(sstarts, e["addr"]) - 1
        if j >= 0 and blobs[j][0] <= e["addr"] < blobs[j][1]:
            where["en_blob_de_stan"] += 1
            in_blob_bytes += e["size"]
        elif i >= 0 and stan_iv[i][0] <= e["addr"] < stan_iv[i][1]:
            where["dentro_de_funcion_stan"] += 1
            split_ours.append(e["name"])
        else:
            where["fuera_de_todo"] += 1
    cnt["only_ours"] = len(only_ours)
    cnt["ours_split_inside_stan"] = len(split_ours)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "stan_cc").mkdir(exist_ok=True)
    (OUT / "semantic_map.json").write_text(json.dumps(sem, indent=1), encoding="utf-8")
    (OUT / "manifest_additions.json").write_text(json.dumps(adds, indent=1), encoding="utf-8")
    (OUT / "conflicts.json").write_text(json.dumps(conflicts, indent=1), encoding="utf-8")
    for a, c in cc.items():
        hh = (STAN / "include" / (c["file"].rsplit(".", 1)[0] + ".hh"))
        head = f"// Stan fomt: {c['file']}  addr 0x{a:08X}  (C++ para agbcp, verificado por Stan)\n"
        if hh.exists():
            head += f'// requiere include/{hh.name}\n'
        (OUT / "stan_cc" / f"func_{a:08X}.cc").write_text(head + c["body"] + "\n", encoding="utf-8")

    add_bytes = sum(x["size"] or 0 for x in adds)
    mods = collections.Counter(f["module"] for f in funcs.values())
    cls = collections.Counter(f["class"] for f in funcs.values() if f.get("class"))
    st = collections.Counter(r.get("our_status") for r in sem.values() if r.get("our_status"))
    rep = [
        "# Fusion Stan <-> FOMT-MATCH-ENGINE", "",
        f"- Funciones de Stan: {len(funcs)} (asm {len(stan_asm)}, cc {len(cc)})",
        f"- Nuestro manifest: {len(ours)}",
        f"- Mismos limites: {cnt['same_bounds']} | tamano distinto: {cnt['size_diff']} | "
        f"Stan dentro de una nuestra (fusionada): {cnt['merged_in_ours']}",
        f"- Solo en Stan (no estan en nuestro manifest): {cnt['only_stan']} funciones, {add_bytes} bytes",
        f"- Solo nuestras (no existen en Stan): {cnt['only_ours']} -> {dict(where)} "
        f"(en blobs .byte de Stan: {in_blob_bytes} bytes que Stan aun no desensambla y nosotros si)",
        f"- Blobs .byte de Stan (codigo sin desensamblar): {sum(f.get('blob_size', 0) for f in funcs.values())} bytes",
        f"- Estado nuestro de las funciones comunes: {dict(st)}",
        f"- Modulos Stan (top): {dict(mods.most_common(12))}",
        f"- Clases detectadas en .cc: {dict(cls.most_common(12))}",
    ]
    (OUT / "REPORT.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
