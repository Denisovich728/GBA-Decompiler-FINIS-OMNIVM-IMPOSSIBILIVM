"""Fase 2: motor de matching con IA local (Ollama / qwen2.5-coder:7b) + ADS 1.2 + permutador.

Por cada funcion:
  1. Contexto: desensamblado real, literales anotados (registros GBA, entropia de tablas/graficos),
     llamadas BL, fragmentos de proyectos de referencia y pseudocodigo Ghidra (solo referencia).
  2. Qwen escribe C; se compila con TODOS los presets de ADS, se enlaza en la direccion exacta y se
     puntua contra la ROM (similitud de instrucciones + bytes). Hasta --tries intentos con feedback.
  3. Los mejores candidatos pasan por el permutador (busqueda local sobre el codigo) buscando diff 0.
  4. Estados: matched (identidad exacta, entra a la ROM), approx (>= --approx de paridad, se guarda en
     approx/ sin entrar a la ROM), wip. Todo reanudable en state.json.

Uso:
  python tools/match/lift.py --limit 20
  python tools/match/lift.py --func func_08000240 --tries 30 --permute 600
  python tools/match/lift.py --retry-wip
"""
import argparse
import difflib
import hashlib
import itertools
import json
import random
import re
import sys
import threading
import time
from pathlib import Path

_THREAD_STEM_COUNTER = itertools.count()

import psutil
import requests
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa
from build_rom import write_symbols_ld, write_symdefs_ads
from refs import describe_function
from control import Control, install_tee
import permuter
import ai_gateway
ctrl = Control()

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434/api/chat")
MODEL = os.environ.get("FOMT_MODEL", "deepseek-coder-v2:latest")
HALF_THREADS = int(os.environ.get("FOMT_THREADS", "8"))
THROTTLE_PAUSE = float(os.environ.get("FOMT_COOLDOWN", "1.5"))


def enforce_half_power_hardware():
    """Aplica al instante la configuracion electrica y de hilos de engine_config.json a Python y Ollama."""
    global HALF_THREADS, THROTTLE_PAUSE
    cfg = load_engine_config()
    HALF_THREADS = max(1, min(16, int(cfg.get("threads", HALF_THREADS))))
    THROTTLE_PAUSE = max(0.0, float(cfg.get("cooldown", THROTTLE_PAUSE)))
    prio_str = cfg.get("priority", "below_normal")
    prio_map = {
        "idle": getattr(psutil, "IDLE_PRIORITY_CLASS", 0x00000040),
        "below_normal": getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", 0x00004000),
        "normal": getattr(psutil, "NORMAL_PRIORITY_CLASS", 0x00000020),
    }
    target_prio = prio_map.get(prio_str, prio_map["below_normal"])
    half_mask = list(range(min(HALF_THREADS, os.cpu_count() or 8)))
    try:
        me = psutil.Process(os.getpid())
        me.cpu_affinity(half_mask)
        if os.name == "nt":
            me.nice(target_prio)
    except Exception:
        pass
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            pname = (proc.info.get("name") or "").lower()
            if "ollama" in pname or "llama" in pname:
                try:
                    proc.cpu_affinity(half_mask)
                    if os.name == "nt":
                        proc.nice(target_prio)
                except Exception:
                    pass
    except Exception:
        pass
    return cfg


SYSTEM = (
    "ERES UN COMPILADOR INVERSO ESTRICTO QUE TRADUCE FUNCIONES DE GAME BOY ADVANCE A CODIGO C89 PURO PARA ARM ADS 1.2 (tcc.exe / armcc.exe).\n"
    "NO ERES UN ASISTENTE CONVERSACIONAL. PROHIBIDO DAR EXPLICACIONES, SALUDOS, COMENTARIOS O TEXTO FUERA DEL CODIGO.\n"
    "TU UNICA SALIDA PERMITIDA ES UN BLOQUE ```c ... ``` CON UNA UNICA FUNCION EN C89 ESTANDAR COMPILABLE.\n\n"
    "REGLAS INQUEBRANTABLES DE SINTAXIS C89:\n"
    "1. CERO ENSAMBLADOR (PROHIBICION ABSOLUTA): Jamas escribas `asm`, `__asm`, ni mnemonicos como "
    "`push`, `pop`, `sub sp`, `add sp`, `mov`, `movs`, `add`, `adds`, `sub`, `subs`, `lsl`, `lsls`, `lsr`, `lsrs`, "
    "`asr`, `asrs`, `ldr`, `ldrh`, `ldrb`, `str`, `strh`, `strb`, `cmp`, `bne`, `beq`, `b`, `bl`, `bx`.\n"
    "2. CERO NOMBRES DE REGISTROS: Prohibido usar `sp`, `lr`, `pc`, `r0`, `r1`, `r2`, `r3`, `r4`, `r5`, `r6`, `r7` como variables.\n"
    "3. DECLARACIONES AL INICIO (C89 ESTRICTO): En ADS 1.2 tcc.exe es OBLIGATORIO declarar TODAS las variables locales "
    "en las primeras lineas inmediatamente despues de `{`, ANTES de cualquier `if`, llamada a funcion o asignacion. "
    "Prohibido declarar variables en medio de la funcion o dentro de `for (int i = 0; ...)`.\n"
    "4. TRADUCCION DE PATRONES THUMB A C89:\n"
    "   - `lsls reg, reg, #16` + `lsrs reg, reg, #16` -> cast `(u16)x` o variable tipo `u16`.\n"
    "   - `lsls reg, reg, #24` + `lsrs reg, reg, #24` -> cast `(u8)x` o variable tipo `u8`.\n"
    "   - `lsls reg, reg, #16` + `asrs reg, reg, #16` -> cast `(s16)x` o variable tipo `s16`.\n"
    "   - `lsls reg, reg, #24` + `asrs reg, reg, #24` -> cast `(s8)x` o variable tipo `s8`.\n"
    "   - `sub sp, #0xNN` y accesos `[sp, #0x..]` -> arreglo o variables locales en la pila, ej: `u8 buf[0x20]; u32 var1; u32 var2;`.\n"
    "   - `bl #0x08XXXXXX` -> llamada a funcion C `func_08XXXXXX(arg1, arg2)`.\n"
    "   - `push {...}` y `pop {...}; bx ...` -> prologo y `return` automaticos del compilador C (NO se escriben en C).\n"
    "5. TIPOS DISPONIBLES: `u8`, `u16`, `u32`, `s8`, `s16`, `s32`, `BOOL`, `void*`. Prohibido `#include`.\n"
    "6. CERO PSEUDOCODIGO O NOMBRES BASURA DE GHIDRA: Prohibido usar `CONCAT44`, `undefined4`, `undefined2`, `undefined1`, `in_lr`, `unaff_`, `extraout_`, "
    "y prohibido dejar nombres crudos de Ghidra (`puVar1`, `uVar1`, `iVar1`, `cVar1`, `uStack_10`, `param_1`, `LAB_...`). "
    "Usa SIEMPRE nombres de variables C89 limpios y legibles (`status_ptr`, `local_val`, `result`, `arg0`, `idx`) e indentacion limpia.\n"
)

PRELUDE = """typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
typedef signed char s8; typedef signed short s16; typedef signed int s32;
typedef volatile unsigned char vu8; typedef volatile unsigned short vu16; typedef volatile unsigned int vu32;
typedef volatile signed char vs8; typedef volatile signed short vs16; typedef volatile signed int vs32;
typedef unsigned char uint8_t; typedef unsigned short uint16_t; typedef unsigned int uint32_t;
typedef signed char int8_t; typedef signed short int16_t; typedef signed int int32_t;
typedef unsigned int uintptr_t; typedef int intptr_t; typedef unsigned int size_t;
typedef unsigned char uchar; typedef unsigned short ushort; typedef unsigned int uint; typedef unsigned long ulong;
typedef unsigned int uint3; typedef unsigned int undefined3; typedef int int3;
typedef unsigned int undefined5; typedef unsigned int undefined6; typedef unsigned int undefined7;
typedef int (*code)();
typedef int BOOL; typedef int bool;
#define TRUE 1
#define FALSE 0
#define true 1
#define false 0
#define NULL ((void *)0)
#define CONCAT11(a, b) ((u16)(((u16)(u8)(a) << 8) | (u8)(b)))
#define CONCAT12(a, b) ((u32)(((u32)(u8)(a) << 16) | (u16)(b)))
#define CONCAT13(a, b) ((u32)(((u32)(u8)(a) << 24) | ((u32)(b) & 0xFFFFFFu)))
#define CONCAT21(a, b) ((u32)(((u32)(u16)(a) << 8) | (u8)(b)))
#define CONCAT22(a, b) ((u32)(((u32)(u16)(a) << 16) | (u16)(b)))
#define CONCAT31(a, b) ((u32)(((u32)(a) << 8) | (u8)(b)))
#define CONCAT44(a, b) ((u32)(b))
#define SUB41(a, b) ((u8)((u32)(a) >> ((b) * 8)))
#define SUB42(a, b) ((u16)((u32)(a) >> ((b) * 8)))
#define SUB84(a, b) ((u32)(a))
#define ZEXT14(a) ((u32)(u8)(a))
#define ZEXT24(a) ((u32)(u16)(a))
#define ZEXT48(a) ((u32)(a))
#define SEXT14(a) ((s32)(s8)(a))
#define SEXT24(a) ((s32)(s16)(a))
#define SEXT48(a) ((s32)(a))
#define CARRY4(a, b) ((u32)(a) > (0xFFFFFFFFu - (u32)(b)))
#define SCARRY4(a, b) (((s32)((u32)(a) + (u32)(b)) < 0) != ((s32)(a) < 0) && ((s32)(a) < 0) == ((s32)(b) < 0))
#define SBORROW4(a, b) (((s32)((u32)(a) - (u32)(b)) < 0) != ((s32)(a) < 0) && ((s32)(a) < 0) != ((s32)(b) < 0))
#define BADSPACEBASE 0
"""
COMPILER_PROFILES = {
    "THUMB": {
        "bin": "agbcc.exe (Nintendo GBA SDK C89 Compiler) + tcc.exe (ADS 1.2)",
        "rules": (
            "- Compilador Primario: UTILITYS/agbcc/bin/agbcc.exe (-O2 -mthumb-interwork -fhex-asm, C89 estricto).\n"
            "- Declara TODAS las variables locales al inicio exacto del bloque `{ }` antes de cualquier sentencia.\n"
            "- Si el epilogo termina en `pop {r0}; bx r0`, la funcion retorna `void`. Si termina en `lsls r0, r0, #16; lsrs r0, r0, #16; pop {r1}; bx r1`, retorna `u16`.\n"
            "- Si el ensamblador reserva stack (`add sp, #-0xNN` o `sub sp, #0xNN`), declara un buffer o variables locales al inicio de la funcion (`u8 stack_buf[0x20]; u32 local_a;`) y pasa `&stack_buf[0]` o `&local_a` a las funciones llamadas.\n"
            "- Prohibido escribir instrucciones ASM o usar `sp`/`lr`/`pc` como variables.\n"
        ),
    },
    "ARM": {
        "bin": "armcc.exe (ARM ADS 1.2 ARM 32-bit C Compiler)",
        "rules": (
            "- Compilador: UTILITYS/ADSv1_2/Bin/armcc.exe (C89 estricto).\n"
            "- Declara TODAS las variables locales al inicio exacto del bloque `{ }` antes de cualquier sentencia.\n"
            "- Prohibido escribir instrucciones ASM o usar `sp`/`lr`/`pc` como variables.\n"
        ),
    },
}


def _infer_thumb_epilogue(rom: bytes, e: dict):
    """Infiere el tipo de retorno exacto emitido por agbcc inspeccionando el epilogo Thumb real en la ROM."""
    if not rom or not e or e.get("mode") != "THUMB":
        return None
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    ins = list(md.disasm(rom_bytes(rom, e["addr"], e["size"]), e["addr"]))
    for idx, i in enumerate(ins):
        if i.mnemonic == "bx" and i.op_str in ("r0", "r1", "r2", "r3"):
            if i.op_str == "r0":
                return "void"
            # bx r1/r2/r3 preserva r0 -> la funcion devuelve un valor en r0
            window = [(x.mnemonic, x.op_str.replace(" ", "")) for x in ins[max(0, idx - 4):idx]]
            for k in range(len(window) - 1):
                m1, o1 = window[k]
                m2, o2 = window[k + 1]
                if m1 in ("lsl", "lsls") and o1 == "r0,r0,#0x10":
                    if m2 in ("lsr", "lsrs") and o2 == "r0,r0,#0x10":
                        return "u16"
                    if m2 in ("asr", "asrs") and o2 == "r0,r0,#0x10":
                        return "s16"
                if m1 in ("lsl", "lsls") and o1 == "r0,r0,#0x18":
                    if m2 in ("lsr", "lsrs") and o2 == "r0,r0,#0x18":
                        return "u8"
                    if m2 in ("asr", "asrs") and o2 == "r0,r0,#0x18":
                        return "s8"
            return "u32"
    return None


def clean_ghidra_ref(raw_text: str, rom: bytes = None, e: dict = None) -> str:
    """Limpia el pseudocodigo de Ghidra y resuelve literales _DAT_08XXXXXX desde la ROM para que compile en C89."""
    # 1. Erradicar aliases de stack para in_lr (ej. uStack_4 = in_lr; ... return uStack_4;)
    m_lr_alias = re.search(r"\b([A-Za-z_]\w*)\s*=\s*in_lr\s*;", raw_text)
    if m_lr_alias:
        alias = m_lr_alias.group(1)
        raw_text = re.sub(rf"^\s*\w+\s+{re.escape(alias)}\s*;\s*\n", "", raw_text, flags=re.M)
        raw_text = re.sub(rf"^\s*{re.escape(alias)}\s*=\s*in_lr\s*;\s*\n", "", raw_text, flags=re.M)
        raw_text = re.sub(rf"\breturn\s+{re.escape(alias)}\s*;", "return in_lr;", raw_text)
        # Tambien limpiar el alias si aparece dentro de un CONCAT44(alias, ...)
        raw_text = re.sub(rf"\bCONCAT44\s*\(\s*{re.escape(alias)}\s*,\s*", "CONCAT44(in_lr, ", raw_text)

    # 2. Erradicar variables temporales de stack residuales de in_lr
    raw_text = re.sub(r"^\s*(?:undefined\d*|u32|int)\s+[A-Za-z_]\w*Stack_\w*\s*=\s*in_lr\s*;\s*\n", "", raw_text, flags=re.M)
    raw_text = re.sub(r"^\s*[A-Za-z_]\w*Stack_\w*\s*=\s*in_lr\s*;\s*\n", "", raw_text, flags=re.M)

    has_return_in_lr = bool(re.search(r"\breturn\s+in_lr\s*;", raw_text))
    epilogue_ret = _infer_thumb_epilogue(rom, e)
    lines = []
    for ln in raw_text.splitlines():
        s = ln.strip()
        if s.startswith("/*") and s.endswith("*/"):
            continue
        if "in_lr" in s and ("undefined" in s or "u32" in s) and "return" not in s:
            continue
        lines.append(ln)
    txt = "\n".join(lines)
    txt = re.sub(r"\)\s*\n+\s*\{", ") {", txt)

    # 3. Erradicacion segura de macros pseudo-Ghidra de concatenacion (preservando parentesis anidados)
    txt = re.sub(r"\b(\w+)\s*=\s*CONCAT22\s*\(\s*\1\._2_2_\s*,\s*([^;]+)\)\s*;", r"*(u16 *)&\1 = (u16)(\2);", txt)
    txt = re.sub(r"\b(\w+)\s*=\s*CONCAT22\s*\(\s*([^,]+)\s*,\s*\1\._0_2_\s*\)\s*;", r"*((u16 *)&\1 + 1) = (u16)(\2);", txt)
    txt = re.sub(r"\breturn\s+CONCAT44\s*\(\s*in_lr\s*,\s*([^;]+)\)\s*;", r"return (\1);", txt)
    txt = re.sub(r"\bCONCAT44\s*\(\s*[^,()]+\s*,\s*([^,()]+)\)", r"(\1)", txt)
    txt = re.sub(r"\bCONCAT31\s*\(\s*[^,()]+\s*,\s*([^,()]+)\)", r"(\1)", txt)
    txt = re.sub(r"\bCONCAT22\s*\(\s*[^,()]+\s*,\s*([^,()]+)\)", r"((u16)(\1))", txt)
    txt = re.sub(r"\bCONCAT13\s*\(\s*[^,()]+\s*,\s*([^,()]+)\)", r"(\1)", txt)
    txt = re.sub(r"\bCONCAT11\s*\(\s*[^,()]+\s*,\s*([^,()]+)\)", r"((u8)(\1))", txt)

    # 4. Normalizacion estricta de tipos Ghidra a C89
    txt = re.sub(r"\bundefined8\b", "u32", txt)
    txt = re.sub(r"\bundefined[567]\b", "u32", txt)
    txt = re.sub(r"\bundefined4\b", "u32", txt)
    txt = re.sub(r"\bundefined3\b", "u32", txt)
    txt = re.sub(r"\bundefined2\b", "u16", txt)
    txt = re.sub(r"\bundefined1?\b", "u8", txt)
    txt = re.sub(r"\bulonglong\b", "u32", txt)
    txt = re.sub(r"\blonglong\b", "s32", txt)
    txt = re.sub(r"\buint3\b", "u32", txt)
    txt = re.sub(r"\bint3\b", "s32", txt)
    txt = re.sub(r"\bbyte\b", "u8", txt)
    txt = re.sub(r"\bsbyte\b", "s8", txt)
    txt = re.sub(r"\bushort\b", "u16", txt)
    txt = re.sub(r"\buint\b", "u32", txt)
    txt = re.sub(r"\b_?func_(?:0x)?08([0-9a-fA-F]{5})\b", lambda m: "func_080" + m.group(1).upper(), txt)
    txt = re.sub(r"\b_?func_(?:0x)?8([0-9a-fA-F]{6})\b", lambda m: "func_08" + m.group(1).upper(), txt)
    txt = re.sub(r"\b_?func_(?:0x)?([0-9a-fA-F]{8})\b", lambda m: "func_" + m.group(1).upper(), txt)
    txt = re.sub(r"\bUNK_([0-9a-fA-F]{8})\b", lambda m: "0x" + m.group(1).upper(), txt)
    # Limpiar notacion de subpieza Ghidra: var._offset_size_ -> (*(u8/u16/u32 *)((u8 *)&var + offset))
    def _subpiece_repl(m):
        var_n, off_s, sz_s = m.group(1), int(m.group(2)), int(m.group(3))
        tp = "u8" if sz_s == 1 else ("u16" if sz_s == 2 else "u32")
        if re.match(r"^(?:PTR_)?_?(?:DAT|LAB)_08[0-9a-fA-F]{6}$", var_n):
            if off_s == 0:
                return f"(*({tp} *){var_n})"
            return f"(*({tp} *)((u8 *){var_n} + {off_s}))"
        if off_s == 0:
            return f"(*({tp} *)&{var_n})"
        return f"(*({tp} *)((u8 *)&{var_n} + {off_s}))"
    txt = re.sub(r"\b([A-Za-z_]\w*)\._(\d+)_(\d+)_", _subpiece_repl, txt)
    # Limpiar stack0x... y register0x... residuales de Ghidra
    txt = re.sub(r"^\s*(?:u8|u16|u32|s8|s16|s32|int|short|char|undefined\d*)\s+\*?\s*register0x[0-9a-fA-F]+\s*;\s*\n", "", txt, flags=re.M)
    txt = re.sub(r"^\s*register0x[0-9a-fA-F]+\s*=[^;]+;\s*\n", "", txt, flags=re.M)
    txt = re.sub(r"&\s*stack0x[0-9a-fA-F]+", "0", txt)
    txt = re.sub(r"\bstack0x[0-9a-fA-F]+\b", "0", txt)
    txt = re.sub(r"\bregister0x[0-9a-fA-F]+\b", "0", txt)
    # Normalizar (-X | X >> 0x1f) -> ((u32)(-X | X)) >> 0x1f
    txt = re.sub(r"\(\s*-(\w+)\s*\|\s*\1\s*>>\s*(?:0x1f|31)\s*\)", r"(((u32)(-\1 | \1)) >> 0x1f)", txt)
    txt = re.sub(r"\s*&\s*0xffffffff0000ffff\b", "", txt)
    txt = re.sub(r"\s*&\s*0xffffffff\b", "", txt)
    if has_return_in_lr or re.search(r"\breturn(?:\s+in_lr)?\s*;", txt):
        if epilogue_ret and epilogue_ret != "void":
            # El epilogo es pop {r1}; bx r1 -> preserva r0 de la ultima llamada
            txt = re.sub(
                r"\b(func_[0-9A-F]{8}\s*\([^;\n{}]*\))\s*;\s*\n\s*return(?:\s+in_lr)?\s*;",
                r"return \1;",
                txt,
            )
        txt = re.sub(
            r"^\s*(?:void|u32|u16|u8|s32|s16|s8|int|uint32_t|uint16_t|uint8_t|BOOL)\s+(func_[0-9A-F]{8}\s*\()",
            f"{epilogue_ret or 'void'} \\1",
            txt,
            count=1,
            flags=re.M,
        )
        if not epilogue_ret or epilogue_ret == "void":
            txt = re.sub(r"\n\s*return\s+in_lr\s*;\s*(?=\n\s*\})", "", txt)
            txt = re.sub(r"\breturn\s+in_lr\s*;", "return;", txt)
    elif epilogue_ret:
        txt = re.sub(
            r"^\s*(?:void|u32|u16|u8|s32|s16|s8|int|uint32_t|uint16_t|uint8_t|BOOL)\s+(func_[0-9A-F]{8}\s*\()",
            f"{epilogue_ret} \\1",
            txt,
            count=1,
            flags=re.M,
        )
    if rom is not None:
        def _resolve_rom_val(hex6: str) -> str:
            addr = int("08" + hex6, 16)
            off = addr - ROM_BASE
            if 0 <= off <= len(rom) - 4:
                val = int.from_bytes(rom[off:off + 4], "little")
                return f"0x{val:08X}"
            return f"0x{addr:08X}"

        txt = re.sub(
            r"\*\s*(?:PTR_)?_?DAT_08([0-9a-fA-F]{6})\s*=\s*(?:PTR_)?_?DAT_08([0-9a-fA-F]{6})\b",
            lambda m: f"*(u32 *){_resolve_rom_val(m.group(1))} = {_resolve_rom_val(m.group(2))}",
            txt,
        )
        txt = re.sub(
            r"\*\s*(?:PTR_)?_?DAT_08([0-9a-fA-F]{6})\b",
            lambda m: f"*(u16 *){_resolve_rom_val(m.group(1))}",
            txt,
        )
        txt = re.sub(
            r"\b(?:PTR_)?_?DAT_08([0-9a-fA-F]{6})\b",
            lambda m: _resolve_rom_val(m.group(1)),
            txt,
        )
        txt = re.sub(
            r"\bPTR_(?:case|LAB)_[0-9a-fA-F]+_08([0-9a-fA-F]{6})\b",
            lambda m: _resolve_rom_val(m.group(1)),
            txt,
        )
        # Resolver _LAB_08XXXXXX SOLO cuando es referencia a literal pool (con guion bajo inicial, NO precedido por goto ni seguido de ':')
        txt = re.sub(
            r"(?<!goto\s)(?<!goto\s\s)\b_LAB_08([0-9a-fA-F]{6})\b(?!\s*:)",
            lambda m: _resolve_rom_val(m.group(1)),
            txt,
        )
    # Normalizar etiquetas con guion bajo en goto y definiciones de etiqueta, y asegurar sentencia nula antes de '}'
    txt = re.sub(r"\bgoto\s+_?(LAB_08[0-9a-fA-F]{6})\b", r"goto \1", txt)
    txt = re.sub(r"^(\s*)_(LAB_08[0-9a-fA-F]{6}\s*:)", r"\1\2", txt, flags=re.M)
    txt = re.sub(r"(\b(?:LAB_08[0-9a-fA-F]{6}|case_08[0-9a-fA-F]{6}|switchD_[0-9a-fA-F_]+)\s*:)\s*(?=\n\s*\})", r"\1 ;", txt)
    # Limpiar cualquier in_lr residual en expresiones
    txt = re.sub(r"\breturn\s+in_lr\s*;", "return;" if (not epilogue_ret or epilogue_ret == "void") else "return 0;", txt)
    txt = re.sub(r"\bin_lr\b", "0", txt)
    txt = re.sub(r"\bREG_DISPCNT\b", "(*(vu16 *)0x04000000)", txt)
    txt = re.sub(r"\bREG_SOUNDCNT_X(?:\._0_1_)?\b", "(*(vu16 *)0x04000084)", txt)
    txt = re.sub(r"\bREG_IME\b", "(*(vu16 *)0x04000208)", txt)
    txt = re.sub(r"\bREG_IE\b", "(*(vu16 *)0x04000200)", txt)
    txt = re.sub(r"\bREG_IF\b", "(*(vu16 *)0x04000202)", txt)
    txt = re.sub(r"\bREG_DISPSTAT\b", "(*(vu16 *)0x04000004)", txt)
    txt = re.sub(r"\bREG_VCOUNT\b", "(*(vu16 *)0x04000006)", txt)
    txt = re.sub(r"\(\(\s*([A-Za-z_]\w*\s*\*+)\s*\)\s*(0x[0-9A-Fa-f]+)\)", r"(\1)\2", txt)
    return txt.strip()


def disasm(rom, e):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if e["mode"] == "THUMB" else CS_MODE_ARM)
    code = rom_bytes(rom, e["addr"], e["size"])
    out = []
    for idx_ins, i in enumerate(md.disasm(code, e["addr"])):
        if idx_ins >= 90:
            out.append("  /* ... resto de instrucciones omitido por brevedad ... */")
            break
        m, op = i.mnemonic, i.op_str
        hint = ""
        if m in ("push", "stmfd", "stmia") and "lr" in op:
            hint = " ; prologo C"
        elif m in ("pop", "ldmfd", "ldmia") and ("pc" in op or "r" in op):
            hint = " ; return C"
        elif m == "bx":
            hint = " ; return C"
        elif m == "bl" and op.startswith("#0x"):
            addr_val = int(op[1:], 16)
            hint = f" ; -> func_{addr_val:08X}()"
        elif m in ("sub", "add") and "sp" in op:
            hint = " ; stack local"
        out.append(f"  {i.address:08x}: {m} {op}{hint}")
    return "\n".join(out)


def externs(manifest, code):
    used = sorted(set(re.findall(r"\bfunc_[0-9A-F]{8}\b", code)))
    out = []
    for n in used:
        # No declarar si ya tiene definicion con cuerpo { o si ya tiene prototipo explicito en el codigo
        if re.search(rf"\b{n}\s*\([^)]*\)\s*\{{", code):
            continue
        if re.search(rf"(?:extern\s+)?(?:\w+\s+)+\*?{n}\s*\(", code):
            continue
        out.append(f"extern u32 {n}();\n")
    return "".join(out)


def condense(text, n=900):
    """Une las lineas partidas de ADS/ld en un solo mensaje corto sin comer el texto entre rutas."""
    t = re.sub(r"\s+", " ", text).strip()
    t = re.sub(r"\"[^\"\n]*?[\\/]([^\\/\"\n]+)\"", r'"\1"', t)
    return t[:n]


_DECL_INIT_RE = re.compile(
    r"^(\s*)((?:volatile\s+)?(?:(?:unsigned|signed)\s+)?(?:u8|u16|u32|s8|s16|s32|vu8|vu16|vu32|vs8|vs16|vs32|"
    r"uint8_t|uint16_t|uint32_t|int8_t|int16_t|int32_t|uintptr_t|intptr_t|size_t|uchar|ushort|uint|ulong|"
    r"int|short|char|long|BOOL|bool|void)(?:\s*\*+|\s+)+)([A-Za-z_]\w*)\s*=\s*(.+?);\s*$"
)
_DECL_ONLY_RE = re.compile(
    r"^(\s*)((?:volatile\s+)?(?:(?:unsigned|signed)\s+)?(?:u8|u16|u32|s8|s16|s32|vu8|vu16|vu32|vs8|vs16|vs32|"
    r"uint8_t|uint16_t|uint32_t|int8_t|int16_t|int32_t|uintptr_t|intptr_t|size_t|uchar|ushort|uint|ulong|"
    r"int|short|char|long|BOOL|bool)(?:\s*\*+|\s+)+)([A-Za-z_]\w*)(\s*\[[^\]]+\])?\s*;\s*$"
)
_FOR_DECL_RE = re.compile(
    r"\bfor\s*\(\s*((?:unsigned\s+|signed\s+)?(?:u8|u16|u32|s8|s16|s32|int|uint|short|char|size_t|uintptr_t))\s+([A-Za-z_]\w*)\s*="
)


def normalize_c89(code: str, rom: bytes = None, e: dict = None) -> str:
    """Convierte automaticamente modismos C99 (declaraciones a mitad de bloque o en for) a C89 estricto."""
    code = clean_ghidra_ref(code, rom=rom, e=e)
    hoisted = []
    declared_names = set()

    def _for_repl(m):
        tp, var = m.group(1).strip(), m.group(2).strip()
        if var not in declared_names:
            hoisted.append(f"    {tp} {var};")
            declared_names.add(var)
        return f"for ({var} ="

    code = _FOR_DECL_RE.sub(_for_repl, code)
    lines = code.splitlines()
    brace_idx = next((i for i, l in enumerate(lines) if "{" in l), None)
    if brace_idx is None:
        return code

    # Recolectar declaraciones que ya estan al principio del bloque
    idx = brace_idx + 1
    while idx < len(lines):
        s = lines[idx].strip()
        if not s:
            idx += 1
            continue
        m_init = _DECL_INIT_RE.match(lines[idx])
        m_only = _DECL_ONLY_RE.match(lines[idx])
        if m_init:
            declared_names.add(m_init.group(3))
            idx += 1
        elif m_only:
            declared_names.add(m_only.group(3))
            idx += 1
        else:
            break

    # Escanear el resto de la funcion (despues de la primera sentencia ejecutable) y elevar declaraciones C99
    new_tail = []
    for ln in lines[idx:]:
        m_init = _DECL_INIT_RE.match(ln)
        if m_init and not ln.strip().startswith("return "):
            indent, tp, var, expr = m_init.group(1), m_init.group(2).strip(), m_init.group(3), m_init.group(4)
            if var not in declared_names:
                hoisted.append(f"    {tp} {var};")
                declared_names.add(var)
            new_tail.append(f"{indent}{var} = {expr};")
            continue
        m_only = _DECL_ONLY_RE.match(ln)
        if m_only and not ln.strip().startswith("return "):
            tp, var, arr = m_only.group(2).strip(), m_only.group(3), m_only.group(4) or ""
            if var not in declared_names:
                hoisted.append(f"    {tp} {var}{arr};")
                declared_names.add(var)
            continue
        new_tail.append(ln)

    res_lines = lines[:brace_idx + 1] + hoisted + lines[brace_idx + 1:idx] + new_tail
    return "\n".join(res_lines)


def extract_c(text, rom: bytes = None, e: dict = None):
    m = re.search(r"```(?:c|C)?\s*\n(.*?)```", text, re.S)
    code = (m.group(1) if m else text)
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"\)\s*\n+\s*\{", ") {", code)
    if "{" in code and "}" in code:
        lines_raw = code.splitlines()
        # Preservar declaraciones struct, static inline o extern g_08XXXXXX previas a la funcion
        fn_brace_idx = None
        target_fn_name = e["name"] if e and "name" in e else None
        if target_fn_name:
            for i, l in enumerate(lines_raw):
                if target_fn_name in l and "(" in l:
                    for fwd in range(i, min(len(lines_raw), i + 5)):
                        if "{" in lines_raw[fwd]:
                            fn_brace_idx = fwd
                            break
                    if fn_brace_idx is not None:
                        break
        if fn_brace_idx is None:
            for i, l in enumerate(lines_raw):
                if "{" in l and not re.match(r"^\s*(?:struct|static\s+inline)\b", l):
                    fn_brace_idx = i
                    break
        if fn_brace_idx is None:
            fn_brace_idx = next((i for i, l in enumerate(lines_raw) if "{" in l), 0)
        sig_start = fn_brace_idx
        for back in range(1, min(5, fn_brace_idx + 1)):
            if "(" in lines_raw[fn_brace_idx - back]:
                sig_start = fn_brace_idx - back
                break
        # Si hay bloques struct, static inline o extern const ... g_08XXXXXX antes de sig_start, conservarlos
        pre_lines = []
        in_block = 0
        for l in lines_raw[:sig_start]:
            s = l.strip()
            if (s.startswith("struct ") or s.startswith("static inline ")) and "{" in s:
                in_block += s.count("{") - s.count("}")
                pre_lines.append(l)
            elif in_block > 0:
                in_block += s.count("{") - s.count("}")
                pre_lines.append(l)
            elif re.match(r"^\s*extern\b.*\bg_[0-9A-Fa-f]{8}\b", s):
                pre_lines.append(l)
            elif re.match(r"^\s*(?:extern\s+)?(?:\w+\s+)+\*?func_[0-9A-Fa-f]{8}\s*\(.*?\);", s):
                pre_lines.append(l)
        last_brace = max((i for i, l in enumerate(lines_raw) if "}" in l), default=len(lines_raw) - 1)
        code = "\n".join(pre_lines + lines_raw[sig_start:last_brace + 1])
    keep = []
    for ln in code.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#include") or re.match(r"^extern\s+(?:u32|int)\s+func_[0-9A-F]{8}\(\);", s):
            continue
        if re.match(r"typedef\s+(?:unsigned\s+|signed\s+)?\w+\s+(?:u|s)(?:8|16|32|_?int\w*|_t)\s*;", s) or \
           re.match(r"typedef\s+(?:u)?int(?:8|16|32)_t\s+\w+\s*;", s):
            continue
        keep.append(ln)
    cleaned = "\n".join(keep).strip()
    if cleaned:
        cleaned = normalize_c89(cleaned, rom=rom, e=e)
    return cleaned + "\n"


ASM_STREAM_LINE_RE = re.compile(
    r"^\s*(?:__asm|asm\b|push\s*\{|pop\s*\{|"
    r"(?:lsls?|lsrs?|asrs?|rors?|movs?|adds?|subs?|ldr|ldrh|ldrb|ldmia|ldmfd|str|strh|strb|stmia|stmfd|"
    r"cmp|cmn|tst|bne|beq|bhi|bhs|blo|bls|blt|bge|bgt|ble|bx|bl)\s+(?:r[0-9]|sp\b|lr\b|pc\b|#0x|0x|func_))",
    re.IGNORECASE,
)


EXTRA_CTX_BUMP = 0


FEW_SHOT_PROMPT = (
    "### EJEMPLOS VERIFICADOS 100% BYTE-PERFECT (THUMB / agbcc -O2):\n\n"
    "--- Ejemplo 1: Acceso a MMIO y llamado a subrutina (28 bytes) ---\n"
    "Disassembly ARM:\n"
    "  push {lr}\n"
    "  lsls r0, r0, #16\n"
    "  lsrs r0, r0, #16\n"
    "  ldr r1, =0x04000202\n"
    "  strh r0, [r1]\n"
    "  bl func_080004F4\n"
    "  pop {r1}\n"
    "  bx r1\n"
    "Codigo C89 Exacto (Zero-Diff):\n"
    "```c\n"
    "u16 func_0800050C(u16 arg0) {\n"
    "    u32 val;\n"
    "    *(u16 *)0x04000202 = arg0;\n"
    "    val = func_080004F4(arg0);\n"
    "    return val;\n"
    "}\n"
    "```\n\n"
    "--- Ejemplo 2: Buffer de stack, condicional y llamada (36 bytes) ---\n"
    "Disassembly ARM:\n"
    "  push {lr}\n"
    "  sub sp, #4\n"
    "  ldrb r0, [r1, #1]\n"
    "  cmp r0, #0\n"
    "  bne _else\n"
    "  mov r0, sp\n"
    "  movs r1, #0x5f\n"
    "  bl func_0800DF50\n"
    "  mov r0, sp\n"
    "  ldrb r0, [r0]\n"
    "  b _end\n"
    "_else:\n"
    "  ldrb r0, [r1]\n"
    "_end:\n"
    "  add sp, #4\n"
    "  pop {r1}\n"
    "  bx r1\n"
    "Codigo C89 Exacto (Zero-Diff):\n"
    "```c\n"
    "u32 func_0800E058(const u8 *param_1) {\n"
    "    u8 buf[4];\n"
    "    u8 res;\n"
    "    if (param_1[1] == 0) {\n"
    "        func_0800DF50(buf, 0x5f);\n"
    "        res = buf[0];\n"
    "    } else {\n"
    "        res = param_1[0];\n"
    "    }\n"
    "    return res;\n"
    "}\n"
    "```\n\n"
)


def ask(messages, model, temperature=0.1, quiet=False, seed=None):
    """Llama al proveedor configurado (Ollama, OpenAI, Anthropic, Google Gemini o Custom REST) con limite electrico y control."""
    global EXTRA_CTX_BUMP
    cfg = enforce_half_power_hardware()
    patched_msgs = [dict(m) for m in messages]
    if patched_msgs and patched_msgs[-1]["role"] == "user":
        patched_msgs[-1]["content"] += (
            "\n\nENTREGA UNICAMENTE UN BLOQUE ```c ... ``` CON CODIGO C89 VALIDO PARA ADS 1.2 (tcc.exe). "
            "DECLARA TODAS LAS VARIABLES AL INICIO DE `{ }`. "
            "PROHIBIDO ESCRIBIR ENSAMBLADOR (push, pop, sub sp, mov, add, ldr, str, cmp, bne, bl, bx)."
        )
    total_chars = sum(len(m.get("content", "")) for m in patched_msgs)
    est_prompt_tokens = int(total_chars / 2.5) + 300
    n_ctx = min(8192, max(2048, est_prompt_tokens + 600)) + EXTRA_CTX_BUMP

    provider = cfg.get("ai_provider", "ollama").lower()
    active_model = cfg.get("ai_model", model)

    pwr = estimate_power(HALF_THREADS, THROTTLE_PAUSE, cfg.get("duty_cycle", 85), cfg.get("priority", "below_normal"))
    if not quiet:
        print(f"  --- [{provider.upper()}] {active_model} [{HALF_THREADS}t | ~{pwr['total_avg_w']}W avg / {pwr['total_peak_w']}W pk | T={temperature:.2f}] ---", flush=True)

    try:
        raw_resp = ai_gateway.call_unified_llm(
            messages=patched_msgs,
            provider=provider,
            model=active_model,
            temperature=temperature,
            max_tokens=2048,
            quiet=quiet,
            num_ctx=n_ctx,
            threads=HALF_THREADS,
        )
        if not quiet:
            for ch in raw_resp:
                sys.stdout.write(ch)
            sys.stdout.flush()
            print("\n  ------------", flush=True)
        if THROTTLE_PAUSE > 0:
            time.sleep(THROTTLE_PAUSE)
        return raw_resp
    except Exception as ex:
        if not quiet:
            print(f"\n  [AI GATEWAY ERROR: {ex}] Fallback a Ollama...", flush=True)
        # Fallback a Ollama en caso de error de API de terceros
        opts = {
            "temperature": temperature,
            "top_p": 0.80,
            "top_k": 20,
            "num_ctx": n_ctx,
            "num_predict": 700,
            "repeat_penalty": 1.03,
            "num_thread": HALF_THREADS,
            "stop": ["\nExplicación", "\nExplanation", "\nEn este", "\nNota:", "\n###"],
        }
        if seed is not None:
            opts["seed"] = seed
        r = requests.post(
            OLLAMA,
            json={"model": model, "messages": patched_msgs, "stream": False, "options": opts, "keep_alive": "15m"},
            timeout=90,
        )
        r.raise_for_status()
        out = r.json().get("message", {}).get("content", "")
        if not quiet:
            sys.stdout.write(out)
            sys.stdout.flush()
            print("\n  ------------", flush=True)
        if THROTTLE_PAUSE > 0:
            time.sleep(THROTTLE_PAUSE)
        return out


def _safe_remove(p: Path) -> bool:
    """Elimina un archivo con reintentos ante bloqueos transitorios de Windows (WinError 32)."""
    for _ in range(5):
        try:
            if p.exists():
                p.unlink()
            return True
        except OSError:
            time.sleep(0.08)
    return not p.exists()


def try_candidate(e, c_code, manifest, preset, tag=None):
    """Compila, enlaza y extrae binario usando agbcc/old_agbcc (GBA SDK) + GNU ld o ARM ADS 1.2 (tcc/armcc + armlink + fromelf)."""
    if not c_code or not c_code.strip() or e["name"] not in c_code or "{" not in c_code or "}" not in c_code:
        return False, None, f"Codigo vacio o incompleto para {e['name']}."
    if c_code.count("{") != c_code.count("}"):
        return False, None, f"Llaves desbalanceadas (generacion truncada) en {e['name']}."
    wd = BUILD_DIR / "lift"
    wd.mkdir(parents=True, exist_ok=True)
    c_seq = next(_THREAD_STEM_COUNTER)
    stem = f"{e['name']}_{os.getpid()}_{threading.get_ident()}_{c_seq}"
    src = wd / f"{stem}.c"
    obj = wd / f"{stem}.o"
    axf = wd / f"{stem}.axf"
    binf = wd / f"{stem}.bin"
    symdefs = wd / f"symdefs_{os.getpid()}_{threading.get_ident()}_{c_seq}.txt"

    full = PRELUDE + externs(manifest, c_code) + c_code
    try:
        src.write_text(full, encoding="utf-8")
        if preset not in AGBCC_PRESETS or e["mode"] != "THUMB":
            write_symdefs_ads(manifest, symdefs, c_code, exclude_name=e["name"])
    except OSError as io_err:
        return False, None, f"Error temporal de E/S preparando archivos: {io_err}"

    r = cc_compile(src, obj, e["mode"], preset, c_code=c_code, exclude_name=e["name"])
    if r.returncode != 0 or not obj.exists():
        return False, None, condense(r.stderr + r.stdout)

    try:
        if preset in AGBCC_PRESETS and e["mode"] == "THUMB":
            ld_bin = find_tool("ld")
            objcopy_bin = find_tool("objcopy")
            r_link = subprocess.run(
                [ld_bin, "-Ttext", f"0x{e['addr']:08X}", str(obj), "-o", str(axf)],
                cwd=str(wd),
                capture_output=True,
                text=True,
                timeout=8,
            )
            if r_link.returncode != 0 or not axf.exists():
                return False, None, condense(r_link.stderr + r_link.stdout)
            r_bin = subprocess.run(
                [objcopy_bin, "-O", "binary", "-j", ".text", str(axf), str(binf)],
                cwd=str(wd),
                capture_output=True,
                text=True,
                timeout=8,
            )
        else:
            r_link = subprocess.run(
                [
                    str(ADS_ARMLINK),
                    "-ro-base", f"0x{e['addr']:08X}",
                    "-first", f"{obj.name}(.text)",
                    str(obj),
                    str(symdefs),
                    "-o", str(axf),
                ],
                cwd=str(wd),
                capture_output=True,
                text=True,
                env=ads_env(),
                timeout=8,
            )
            if r_link.returncode != 0 or not axf.exists():
                return False, None, condense(r_link.stderr + r_link.stdout)

            r_bin = subprocess.run(
                [str(ADS_FROMELF), "-bin", "-output", str(binf), str(axf)],
                cwd=str(wd),
                capture_output=True,
                text=True,
                env=ads_env(),
                timeout=8,
            )
    except subprocess.TimeoutExpired:
        for f_tmp in (src, obj, axf, binf, symdefs):
            _safe_remove(f_tmp)
        return False, None, f"Timeout enlazando {e['name']}"
    if r_bin.returncode != 0 or not binf.exists():
        for f_tmp in (src, obj, axf, binf, symdefs):
            _safe_remove(f_tmp)
        return False, None, condense(r_bin.stderr + r_bin.stdout or "No se genero binario")
    try:
        bts = binf.read_bytes()
    except OSError as io_err:
        return False, None, f"Error leyendo binario: {io_err}"
    finally:
        for f_tmp in (src, obj, axf, binf, symdefs):
            _safe_remove(f_tmp)
    if not bts:
        return False, None, "El binario compilado tiene 0 bytes"
    return True, bts, ""



def _dis_lines(bts, e):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if e["mode"] == "THUMB" else CS_MODE_ARM)
    return [f"{i.mnemonic} {i.op_str}" for i in md.disasm(bts, e["addr"])]



def _is_padding(tail: bytes) -> bool:
    if not tail:
        return True
    # Relleno comun entre funciones en GBA / ADS 1.2: 0x00, 0xFF o NOP Thumb (0x46C0)
    stripped = tail.replace(b"\xc0\x46", b"").replace(b"\x00", b"").replace(b"\xff", b"")
    return len(stripped) == 0


def score(e, target, got):
    """(exacto, puntaje 0..1). Gradiente granular: instrucciones, registros normalizados, opcodes y tamano."""
    if not got:
        return False, 0.0
    exact = (
        len(got) <= len(target)
        and got == target[:len(got)]
        and _is_padding(target[len(got):])
    )
    if exact:
        return True, 1.0
    # Compara contra la ventana util si got es mas corto que el bloque barrido
    ref = target[:max(len(got), min(len(target), len(got) + 8))]
    t_lines = _dis_lines(ref, e)
    g_lines = _dis_lines(got, e)
    ops = lambda L: [x.split()[0] for x in L]
    nreg = lambda L: [re.sub(r"\br\d+\b", "rX", x) for x in L]
    sm = lambda a, b: difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    size_ratio = min(len(got), len(target)) / max(len(got), len(target)) if max(len(got), len(target)) > 0 else 0.0
    sc = 0.35 * sm(t_lines, g_lines) + 0.30 * sm(nreg(t_lines), nreg(g_lines)) + 0.25 * sm(ops(t_lines), ops(g_lines)) + 0.10 * size_ratio
    return False, sc


def feedback(e, target, got):
    exp_ins = _dis_lines(target, e)
    got_ins = _dis_lines(got, e)
    diff = list(difflib.unified_diff(exp_ins, got_ins, "ROM_objetivo", "tu_C_compilado", lineterm="", n=1))[:28]
    commented_diff = "\n".join(f"  {ln}" for ln in diff)
    size_msg = f"Tamano compilado: {len(got)} bytes vs Objetivo ROM: {len(target)} bytes."
    return (
        f"{size_msg}\n"
        f"Diferencias en el ensamblador emitido por tcc.exe (SOLO LECTURA, PROHIBIDO COPIAR MNEMONICOS AL C):\n"
        f"{commented_diff}\n"
        f"Ajusta UNICAMENTE las expresiones C89 (tipos u8/u16/u32, casts, cantidad/orden de variables locales al inicio de '{{ }}', "
        f"o estructura if/else) para que el compilador ADS 1.2 emita el tamano e instrucciones objetivo."
    )


def evaluate(e, code, manifest, target, presets):
    """Prueba todos los presets. Devuelve (mejor_score, preset, got, exact, err)."""
    best, err = (-1.0, None, None, False), None
    for p in presets:
        ok, got, log = try_candidate(e, code, manifest, p)
        if not ok:
            err = log
            if p == presets[0]:
                break  # error de sintaxis/enlace: no depende del preset
            continue
        exact, sc = score(e, target, got)
        if sc > best[0]:
            best = (sc, p, got, exact)
        if exact:
            break
    return best + (err,)


def _write_atomic(dest: Path, text: str):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dest)


def _log_collection_event(event: dict):
    try:
        col_dir = TREE_DIR / "collection"
        col_dir.mkdir(parents=True, exist_ok=True)
        event["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(col_dir / "history.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass


_GHIDRA_DIRTY_RE = re.compile(
    r"\b(?:p?[uicsb]Var\d+|u?Stack_[0-9a-fA-F]+|auStack_[0-9a-fA-F]+|local_[0-9a-fA-F]+|param_\d+|LAB_[0-9a-fA-F]+)\b"
)


def _deterministic_clean_identifiers(code: str) -> str:
    """Reemplaza nombres residuales de Ghidra (puVar1, uStack_10, param_1, LAB_...) por identificadores C89 limpios sin alterar el bytecode."""
    out = code
    for idx, m in enumerate(sorted(set(re.findall(r"\bparam_(\d+)\b", out)), key=int)):
        out = re.sub(rf"\bparam_{m}\b", f"arg{int(m) - 1}", out)
    for idx, m in enumerate(sorted(set(re.findall(r"\bp[uicsb]Var(\d+)\b", out)), key=int), 1):
        sfx = "" if idx == 1 else str(idx)
        out = re.sub(rf"\bp[uicsb]Var{m}\b", f"mem_ptr{sfx}", out)
    for idx, m in enumerate(sorted(set(re.findall(r"\b[uicsb]Var(\d+)\b", out)), key=int), 1):
        sfx = "" if idx == 1 else str(idx)
        out = re.sub(rf"\b[uicsb]Var{m}\b", f"val{sfx}", out)
    for idx, m in enumerate(sorted(set(re.findall(r"\bu?Stack_([0-9a-fA-F]+)\b", out))), 1):
        sfx = "" if idx == 1 else str(idx)
        out = re.sub(rf"\bu?Stack_{m}\b", f"local_buf{sfx}", out)
    for idx, m in enumerate(sorted(set(re.findall(r"\bLAB_([0-9a-fA-F]+)\b", out))), 1):
        sfx = "" if idx == 1 else f"_{idx}"
        out = re.sub(rf"\bLAB_{m}\b", f"exit_label{sfx}", out)
    return out


def llm_beautify_matched_c(e, code, p, manifest, target, rom, model=MODEL):
    """Pide a DeepSeek limpiar y refactorizar una funcion C89 que ya logro 100% match, verificando que conserve 0 bytes de diff."""
    if not _GHIDRA_DIRTY_RE.search(code):
        return code, "llm-clean"
    prompt_clean = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"La siguiente funcion C89 para `{e['name']}` (0x{e['addr']:08X}) YA COMPILA AL 100.0% EXACTO byte a byte con `{p}`:\n"
            f"```c\n{code.strip()}\n```\n\n"
            "TAREA DE LIMPIEZA SEMANTICA C89:\n"
            "1. Renombra TODAS las variables y parametros crudos de Ghidra (`param_1`, `puVar1`, `uVar1`, `iVar1`, `cVar1`, `uStack_...`, `LAB_...`) "
            "por nombres descriptivos y legibles en C89 (ej. `slot`, `io_reg`, `status_ptr`, `zero_val`, `result`, `idx`).\n"
            "2. Manten EXACTAMENTE los mismos tipos de datos (`u8`, `u16`, `u32`, `void`), el mismo orden de declaracion de variables al inicio de `{ }`, "
            "las mismas direcciones hexadecimales y las mismas llamadas a `func_08XXXXXX` para conservar el 100% de identidad binaria.\n"
            "3. Entrega UNICAMENTE el bloque ```c ... ``` con la funcion limpia."
        )},
    ]
    try:
        print(f"  [limpieza DeepSeek] Refactorizando identificadores de Ghidra en {e['name']} manteniendo match 100%...")
        txt = ask(prompt_clean, model, temperature=0.05, quiet=False)
        cand = extract_c(txt, rom=rom, e=e)
        if cand.strip() and e["name"] in cand and not ASM_RE.search(cand):
            if _GHIDRA_DIRTY_RE.search(cand):
                cand = _deterministic_clean_identifiers(cand)
            ok, got, _ = try_candidate(e, cand, manifest, p)
            if ok and score(e, target, got)[0]:
                print(f"  [limpieza DeepSeek] Verificado 100.0% byte a byte tras limpieza LLM.")
                return cand, "deepseek-clean"
    except Exception:
        pass
    det_clean = _deterministic_clean_identifiers(code)
    ok, got, _ = try_candidate(e, det_clean, manifest, p)
    if ok and score(e, target, got)[0]:
        return det_clean, "clean-c89"
    return code, "raw-c89"


def save_matched(e, code, p, manifest, state, tries, how, target=None, rom=None, model=MODEL, use_llm_clean=False, phase_num=1, semantic_name=None):
    if target is None:
        if rom is None:
            rom = load_rom()
        target = rom_bytes(rom, e["addr"], e["size"])

    # Verificacion estricta e inmutable de integridad 100% Zero-Diff bit a bit antes de persistir
    ok_v, got_v, err_v = try_candidate(e, code, manifest, p)
    if not ok_v or got_v != target or len(got_v) != e["size"]:
        err_msg = (
            f"[FATAL INTEGRIDAD] save_matched rechazo el guardado de {e['name']}: "
            f"el binario no coincide 100% con la ROM virgen (ok={ok_v}, got_len={len(got_v) if got_v else 0}, "
            f"target_len={len(target)}). Detalle: {err_v[:120] if err_v else 'bytes divergentes'}"
        )
        print(err_msg)
        raise ValueError(err_msg)

    if use_llm_clean:
        code, clean_tag = llm_beautify_matched_c(e, code, p, manifest, target, rom, model=model)
        how = f"{how}+{clean_tag}"
    elif _GHIDRA_DIRTY_RE.search(code):
        det_clean = _deterministic_clean_identifiers(code)
        ok_d, got_d, _ = try_candidate(e, det_clean, manifest, p)
        if ok_d and score(e, target, got_d)[0]:
            code = det_clean
            how = f"{how}+clean-c89"
    path = TREE_DIR / e["file"]
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not path.with_suffix(".ghidra.txt").exists():
        _write_atomic(path.with_suffix(".ghidra.txt"), raw)
    sem_header = ""
    if semantic_name:
        sem_header = f"/* Nombre semantico (Fase 3): {semantic_name} (@ 0x{e['addr']:08X}) */\n#define {semantic_name} {e['name']}\n"
    full_c = PRELUDE + externs(manifest, code) + sem_header + code
    _write_atomic(path, full_c)
    _write_atomic(TREE_DIR / "collection" / "matched" / f"{e['name']}.c", full_c)
    prev_st = state.get(e["name"], {})
    is_named = bool(semantic_name or prev_st.get("named", False))
    sem_final = semantic_name or prev_st.get("semantic_name", "")
    state[e["name"]] = {
        "status": "matched",
        "best": 1.0,
        "preset": p,
        "tries": tries,
        "how": how,
        "phase": phase_num,
        "named": is_named,
        "semantic_name": sem_final,
        "addr": e["addr"],
        "size": e["size"],
    }
    save_state(state)
    _log_collection_event({
        "func": e["name"],
        "addr": f"0x{e['addr']:08X}",
        "status": "matched",
        "score": 1.0,
        "preset": p,
        "via": how,
        "tries": tries,
        "phase": phase_num,
        "semantic_name": sem_final,
    })
    ctrl.publish(
        force=True,
        phase=f"MATCHED {e['name']} (100% via {how})",
        func=e["name"],
        addr=e["addr"],
        size=e["size"],
        mode=e["mode"],
        try_num=tries,
        max_tries=tries,
        best_score=1.0,
        last_score=1.0,
    )
    print(f"  [MATCH] {e['name']} preset={p} via={how}" + (f" -> {sem_final}()" if sem_final else ""))


def process_phase3_naming(e, rom, manifest, state, args):
    """Fase 3: Nombra semanticamente la funcion y sus variables con DeepSeek conservando el 100.0% de match binario."""
    st = state.get(e["name"], {})
    if st.get("status") != "matched" or st.get("named", False):
        return
    target = rom_bytes(rom, e["addr"], e["size"])
    path = TREE_DIR / e["file"]
    raw_c = path.read_text(encoding="utf-8", errors="replace")
    base_c = extract_c(raw_c, rom=rom, e=e)
    preset = st.get("preset", "agbcc_O2")
    ctx = describe_function(rom, e, manifest)
    ctrl.publish(
        force=True,
        phase=f"FASE 3 [NOMBRADO] {e['name']}",
        func=e["name"],
        addr=e["addr"],
        size=e["size"],
        mode=e["mode"],
        try_num=1,
        max_tries=1,
        best_score=1.0,
        model=args.model,
        threads=HALF_THREADS,
    )
    prompt_name = [
        {
            "role": "system",
            "content": (
                "ERES UN INGENIERO DE REVERSA DE GAME BOY ADVANCE (Harvest Moon: Friends of Mineral Town).\n"
                "Recibiras una funcion C89 que YA COMPILA AL 100.0% EXACTO byte a byte contra la ROM.\n"
                "Tu tarea en esta FASE 3 (Nombrado Semantico) es:\n"
                "1. Proponer en la primera linea un comentario exacto: `/* SEMANTIC_NAME: nombre_descriptivo_snake_case */` "
                "(ej. `sram_verify_header`, `dma3_clear_buffer`, `irq_enable_mask`, `rtc_read_status`).\n"
                "2. Dentro del bloque ```c ... ```, mantener el nombre del simbolo de enlace `func_08XXXXXX` en la firma para no romper el linker, "
                "pero renombrar TODOS los parametros y variables locales (`arg0`, `val1`, `mem_ptr`, `local_buf`, `puVar1`, `uStack_...`) "
                "con nombres semanticos claros del dominio GBA.\n"
                "3. NO alteres los tipos (`u8`, `u16`, `u32`, `void`), ni el orden de declaracion de variables al inicio de `{ }`, "
                "ni las operaciones ni literales hexadecimales, para conservar el 100.0% de identidad binaria."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Funcion `{e['name']}` @ 0x{e['addr']:08X} ({e['size']} B, preset `{preset}`):\n"
                f"```c\n{base_c.strip()}\n```\n\n{ctx}\n"
                "Responde con `/* SEMANTIC_NAME: ... */` seguido del bloque ```c ... ```."
            ),
        },
    ]
    sem_name = f"sub_{e['addr']:08x}"
    final_c = _deterministic_clean_identifiers(base_c)
    try:
        txt = ask(prompt_name, args.model, temperature=0.05, quiet=False)
        m_sem = re.search(r"SEMANTIC_NAME\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)", txt)
        if m_sem:
            cand_name = m_sem.group(1).strip()
            if not cand_name.lower().startswith("func_08"):
                sem_name = cand_name
        cand_c = extract_c(txt, rom=rom, e=e)
        if cand_c.strip() and e["name"] in cand_c and not ASM_RE.search(cand_c):
            cand_c = _deterministic_clean_identifiers(cand_c)
            ok, got, _ = try_candidate(e, cand_c, manifest, preset)
            if ok and score(e, target, got)[0]:
                final_c = cand_c
                print(f"  [Fase 3] Verificado 100.0% byte a byte -> alias semantico: {sem_name}()")
            else:
                print(f"  [Fase 3] Re-escritura altero bytes; se conserva estructura C89 limpia con alias: {sem_name}()")
    except Exception as ex:
        print(f"  [Fase 3 aviso] {ex}")

    names_file = TREE_DIR / "collection" / "function_names.json"
    names_file.parent.mkdir(parents=True, exist_ok=True)
    names_map = {}
    if names_file.exists():
        try:
            names_map = json.loads(names_file.read_text(encoding="utf-8"))
        except Exception:
            names_map = {}
    names_map[e["name"]] = {"addr": f"0x{e['addr']:08X}", "semantic_name": sem_name, "preset": preset, "size": e["size"]}
    _write_atomic(names_file, json.dumps(names_map, indent=2))
    save_matched(e, final_c, preset, manifest, state, st.get("tries", 0), st.get("how", "cpu") + "+named", phase_num=3, semantic_name=sem_name)



def run_permuter(e, code, p, sc, manifest, target, iters, rng, label):
    """Hill-climbing multi-preset con pase estructural determinista inicial. Devuelve (score, code, exact)."""
    cur_code, cur_sc, best_code, best_sc, best_p = code, sc, code, sc, p
    all_presets = list(CFLAG_PRESETS)

    # Pase 0: probar transformaciones estructurales deterministas (_m_sink_zero, _m_cond_assign, _m_split_decl_init), paso de param_1 y tipos de parametro/retorno en todos los presets
    det_candidates = []
    if "param_1" in best_code:
        c_p1 = re.sub(r"\b(func_[0-9A-F]{8})\s*\(\s*\)", r"\1(param_1)", best_code, count=1)
        if c_p1 != best_code:
            det_candidates.append(("passthrough_param1", c_p1))
    for p_idx in (1, 2, 3, 4):
        pname = f"param_{p_idx}"
        if re.search(rf"\(\s*{pname}\s*&\s*0xff\s*\)", best_code, re.I):
            c_u8 = re.sub(rf"\b(?:u32|uint|int|s32)\s+{pname}\b", f"u8 {pname}", best_code)
            c_u8 = re.sub(rf"\(\s*{pname}\s*&\s*0xff\s*\)", pname, c_u8, flags=re.I)
            det_candidates.append((f"{pname}_u8", c_u8))
        if re.search(rf"\(\s*{pname}\s*&\s*0xffff\s*\)", best_code, re.I):
            c_u16 = re.sub(rf"\b(?:u32|uint|int|s32)\s+{pname}\b", f"u16 {pname}", best_code)
            c_u16 = re.sub(rf"\(\s*{pname}\s*&\s*0xffff\s*\)", pname, c_u16, flags=re.I)
            det_candidates.append((f"{pname}_u16", c_u16))
    for tag_d, cand_d in det_candidates:
        s_eval, p_eval, _, ex_eval, _ = evaluate(e, cand_d, manifest, target, all_presets)
        if ex_eval:
            print(f"  [perm {label}] EXACTO en pase determinista ({tag_d}, preset {p_eval})")
            return 1.0, cand_d, True
        if s_eval > best_sc:
            best_sc, best_code, best_p = s_eval, cand_d, p_eval
            cur_sc, cur_code = s_eval, cand_d
            print(f"  [perm {label}] {tag_d}: {best_sc * 100:.1f}% (preset {best_p})")

    for rt_probe in ("u16", "u32", "u8", "s16", "s8"):
        cand_rt = re.sub(
            r"^(\s*)(?:u32|u16|u8|s32|s16|s8|int)\s+(func_[0-9A-F]{8}\s*\()",
            rf"\1{rt_probe} \2",
            best_code,
            count=1,
            flags=re.M,
        )
        if cand_rt != best_code:
            s_eval, p_eval, _, ex_eval, _ = evaluate(e, cand_rt, manifest, target, all_presets)
            if ex_eval:
                print(f"  [perm {label}] EXACTO en pase de tipo de retorno ({rt_probe}, preset {p_eval})")
                return 1.0, cand_rt, True
            if s_eval > best_sc:
                best_sc, best_code, best_p = s_eval, cand_rt, p_eval
                cur_sc, cur_code = s_eval, cand_rt
                print(f"  [perm {label}] ret_type {rt_probe}: {best_sc * 100:.1f}% (preset {best_p})")

    for fn_struct in (permuter._m_sink_zero, permuter._m_cond_assign, permuter._m_split_decl_init):
        lns = best_code.splitlines()
        if fn_struct(lns, rng):
            cand_s = "\n".join(lns) + "\n"
            s_eval, p_eval, _, ex_eval, _ = evaluate(e, cand_s, manifest, target, all_presets)
            if ex_eval:
                print(f"  [perm {label}] EXACTO en pase estructural ({fn_struct.__name__}, preset {p_eval})")
                return 1.0, cand_s, True
            if s_eval > best_sc:
                best_sc, best_code, best_p = s_eval, cand_s, p_eval
                cur_sc, cur_code = s_eval, cand_s
                print(f"  [perm {label}] struct {fn_struct.__name__}: {best_sc * 100:.1f}% (preset {best_p})")

    alt_presets = [k for k in CFLAG_PRESETS if k != best_p]
    stagnant = 0
    for i in range(iters):
        cand = permuter.mutate(cur_code, rng)
        if not cand:
            continue
        ok, got, _ = try_candidate(e, cand, manifest, best_p)
        if not ok:
            continue
        exact, s = score(e, target, got)
        if exact:
            print(f"  [perm {label}] EXACTO en iteracion {i + 1} (preset {best_p})")
            return 1.0, cand, True
        # Si mejora o cada 25 iteraciones, sondear presets alternativos (ej. O1_nocse / O2_nocse)
        if s > best_sc or (i % 25 == 0 and s >= best_sc - 0.02):
            for ap in alt_presets:
                ok_a, got_a, _ = try_candidate(e, cand, manifest, ap)
                if ok_a:
                    ex_a, s_a = score(e, target, got_a)
                    if ex_a:
                        print(f"  [perm {label}] EXACTO en iteracion {i + 1} (preset {ap})")
                        return 1.0, cand, True
                    if s_a > s:
                        s, best_p = s_a, ap
        if s >= cur_sc:
            cur_code, cur_sc = cand, s
            if s > best_sc:
                best_code, best_sc = cand, s
                stagnant = 0
                print(f"  [perm {label}] it {i + 1}: {s * 100:.1f}% (preset {best_p})")
            else:
                stagnant += 1
        else:
            stagnant += 1
            if stagnant >= 30 or rng.random() < 0.05:
                cur_code, cur_sc = best_code, best_sc
                stagnant = 0
    return best_sc, best_code, False


ASM_RE = re.compile(
    r"\b(__asm|__asm__|asm)\b|\b__builtin_|"
    r"\b(push|pop)\s*\{|"
    r"\b(ldr|ldrh|ldrb|ldmia|ldmfd|str|strh|strb|stmia|stmfd|movs?|adds?|subs?|cmp|cmn|tst|ands?|orrs?|eors?|lsls?|lsrs?|asrs?|b|bl|bx)\s+(?:r[0-9]|sp\b|lr\b|pc\b|#[0-9])",
    re.MULTILINE | re.IGNORECASE
)

STRATEGIES = [
    "Declara TODAS las variables locales al inicio exacto de `{ }` y traduce cada operacion a expresiones C89 puras (casts u16/s16/u8, operadores +, -, &, |, >>, <<).",
    "Revisa las llamadas a funciones `func_XXXXXXXX(...)` y aplica casts C89 exactos `(u16)`, `(u8)` o `(s16)` a sus argumentos y al `return`.",
    "Usa punteros tipados (`u8*`, `u16*`, `u32*`) con desreferencia directa (`*ptr`, `ptr[offset]`) para los accesos a memoria del literal pool.",
    "Si la funcion reserva espacio en la pila, declara un arreglo local o variables (`u8 buf[0x20]; u32 val1; u32 val2;`) al inicio de `{ }` y pasa sus direcciones `&val1`.",
    "Simplifica las condiciones `if / else` o usa expresion ternaria C89 en el `return` eliminando variables temporales redundantes.",
    "Ajusta el orden de declaracion de las variables locales al inicio de `{ }` y sus tipos (`u16` vs `u32`) para que `tcc.exe` asigne los mismos registros.",
]


def process(e, rom, manifest, state, args):
    phase_num = int(getattr(args, "phase", 1))
    if phase_num == 3:
        process_phase3_naming(e, rom, manifest, state, args)
        return
    target = rom_bytes(rom, e["addr"], e["size"])
    path = TREE_DIR / e["file"]
    raw = path.read_text(encoding="utf-8", errors="replace")
    ghidra = path.with_suffix(".ghidra.txt")
    if ghidra.exists():
        raw = ghidra.read_text(encoding="utf-8", errors="replace")
    if state.get(e["name"], {}).get("status") == "matched":
        return
    rng = random.Random(int(e["addr"]))
    presets = list(CFLAG_PRESETS)
    ctx = describe_function(rom, e, manifest)
    prev = path.with_suffix(".wip.c")
    use_llm_clean = (phase_num >= 2)

    cleaned_ref = clean_ghidra_ref(raw, rom=rom, e=e)
    prof = COMPILER_PROFILES.get(e["mode"], COMPILER_PROFILES["THUMB"])
    cc_bin = e.get("cc", prof["bin"])
    disasm_txt = disasm(rom, e)

    hist, seen = [], set()
    best = (0.0, None, None)  # (score, code, preset)
    candidate_paths = [
        TREE_DIR / "approx" / f"{e['name']}.c",
        TREE_DIR / "collection" / "approx" / f"{e['name']}.c",
        TREE_DIR / "permute" / "code" / f"{e['name']}.c",
        prev,
        TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c",
    ]
    for cp in candidate_paths:
        if cp.exists():
            c_cand = extract_c(cp.read_text(encoding="utf-8", errors="replace"), rom=rom, e=e)
            if e["name"] in c_cand and "{" in c_cand and not ASM_RE.search(c_cand):
                sc_c, p_c, got_c, ex_c, _ = evaluate(e, c_cand, manifest, target, presets)
                if p_c is not None:
                    if ex_c:
                        save_matched(e, c_cand, p_c, manifest, state, 0, f"exact:{cp.parent.name}", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
                        return
                    if sc_c > best[0]:
                        best = (sc_c, c_cand, p_c)
    repeats, asm_strikes, t_start = 0, 0, time.time()
    ctrl.current = e["name"]
    ctrl.publish(
        phase=f"FASE {phase_num} [{'CPU DIFF+PERM' if phase_num == 1 else 'DEEPSEEK ORPHAN/WIP'}] {e['name']}",
        func=e["name"],
        addr=e["addr"],
        size=e["size"],
        mode=e["mode"],
        try_num=0,
        max_tries=0 if phase_num == 1 else args.tries,
        best_score=round(best[0], 4),
        model="CPU-ONLY (agbcc+permuter)" if phase_num == 1 else args.model,
        threads=HALF_THREADS,
    )

    # Semilla determinista (Try 0): evalua el esqueleto C89 limpio antes de invocar al LLM
    seed_c = extract_c(cleaned_ref, rom=rom, e=e)
    if e["name"] in seed_c and "{" in seed_c and not ASM_RE.search(seed_c):
        sc0, p0, got0, exact0, _ = evaluate(e, seed_c, manifest, target, presets)
        if p0 is not None:
            seen.add(hashlib.md5(re.sub(r"\s+", "", seed_c).encode()).hexdigest())
            print(f"  [semilla C89] preset {p0}: puntaje {sc0 * 100:.1f}% ({len(got0)}/{e['size']} B)")
            if exact0:
                save_matched(e, seed_c, p0, manifest, state, 0, "seed-c89", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
                return
            if sc0 >= best[0]:
                best = (sc0, seed_c, p0)
                _write_atomic(prev, seed_c)
                _write_atomic(TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c", seed_c)
            if sc0 >= args.perm_threshold and args.permute_quick:
                psc, pc, pex = run_permuter(e, best[1], best[2], best[0], manifest, target, args.permute_quick, rng, "seed")
                if pex:
                    save_matched(e, pc, best[2], manifest, state, 0, "permuter-seed", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
                    return
                if psc > best[0]:
                    _, p_best, got_best, _, _ = evaluate(e, pc, manifest, target, presets)
                    best = (psc, pc, p_best or best[2])
                    seen.add(hashlib.md5(re.sub(r"\s+", "", pc).encode()).hexdigest())
                    if got_best is not None:
                        got0 = got_best
                    _write_atomic(prev, pc)
                    _write_atomic(TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c", pc)
            hist = [
                {"role": "assistant", "content": f"```c\n{best[1].strip()}\n```"},
                {"role": "user", "content": (
                    f"Compilo correctamente ({best[0] * 100:.1f}%).\n{feedback(e, target, got0)}\n"
                    f"PROHIBIDO repetir el mismo codigo anterior: cambia el orden/tipo de variables locales al inicio de `{{ }}` o la forma de acceder a punteros/condiciones."
                )}
            ]

    t = 0
    trunc_strikes = 0
    degrade_strikes = 0
    max_tries = (0 if phase_num == 1 else args.tries) + ctrl.extra_for.pop(e["name"], 0)
    while t < max_tries:
        try:
            # 1. Chequeo de interrupcion por consola
            ctrl.wait_if_paused()
            if ctrl.extra_now > 0:
                max_tries += ctrl.extra_now
                ctrl.extra_now = 0
            if ctrl.minutes is not None:
                args.max_minutes = ctrl.minutes
                ctrl.minutes = None
            if ctrl.interrupted():
                if ctrl.reset_all:
                    print("  [control] Reinicio total detectado: abortando funcion actual y rebobinando al inicio de la ROM.")
                    return
                if ctrl.retry:
                    ctrl.retry = False
                    state.clear()
                    state.update(load_state())
                    t = 0
                    hist, seen, repeats, asm_strikes, trunc_strikes = [], set(), 0, 0, 0
                    print("  [control] Reiniciando intentos de la funcion actual (estado recargado).")
                    continue
                print("  [control] Saltando al permutador final por orden manual de consola.")
                ctrl.skip = False
                break

            # 2. Publicar estado rico para el HUD
            ctrl.publish(
                phase=f"LLM Try {t+1}/{max_tries} para {e['name']}",
                func=e["name"],
                addr=e["addr"],
                size=e["size"],
                mode=e["mode"],
                try_num=t + 1,
                max_tries=max_tries,
                best_score=round(best[0], 4),
                model=args.model,
                threads=HALF_THREADS,
            )

            # Solo cortar por tiempo si el usuario lo pidio explicitamente con 'minutes N' (> 0)
            if args.max_minutes and args.max_minutes > 0 and (time.time() - t_start > args.max_minutes * 60):
                print(f"  [limite manual] {args.max_minutes} min alcanzado -> pasando al permutador")
                break
            if repeats >= 4:
                print("  [agotado] 4 candidatos C89 repetidos (sin nuevas variantes desde ASM) -> saltando al permutador final")
                break
            cfg_live = load_engine_config()
            t_base = float(cfg_live.get("temp_base", 0.08))
            t_max = min(0.28, float(cfg_live.get("temp_max", 0.25)))
            temp = min(t_max, t_base + (0.03 * t) + (0.04 * repeats))
            strat = STRATEGIES[(t + repeats + asm_strikes + trunc_strikes) % len(STRATEGIES)]

            ref_code_block = (best[1].strip() if best[1] else cleaned_ref[:1800])
            if best[0] >= 0.80 and best[1]:
                # Para funciones de alta paridad, enviar el C89 actual y el diff exacto de ensamblador, evitando volcar ASM crudo
                _, _, got_curr, _, _ = evaluate(e, best[1], manifest, target, presets)
                diff_hint = feedback(e, target, got_curr) if got_curr else ""
                user_head_txt = (
                    f"Funcion `{e['name']}` @ 0x{e['addr']:08X} | Modo: {e['mode']} | Compilador: {cc_bin} | Tamano objetivo: {e['size']} bytes.\n\n"
                    f"### Codigo C89 base a mejorar ({best[0]*100:.1f}%)\n```c\n{ref_code_block}\n```\n\n"
                    f"### Diferencia de ensamblador generada por tu codigo C compilado vs ROM objetivo:\n{diff_hint}\n\n"
                    f"ESTRATEGIA C89: {strat}\n"
                    f"INSTRUCCIONES CRITICAS:\n"
                    f"1. Escribe UNICAMENTE codigo en C89 puro dentro de un bloque ```c ... ```.\n"
                    f"2. Esta TERMINANTEMENTE PROHIBIDO escribir instrucciones en ensamblador (push, pop, ldr, str, add, sub, mov, etc.).\n"
                    f"3. Ajusta UNICAMENTE las variables locales en C, sus tipos (u8, u16, u32), casts o el orden de asignaciones para que agbcc emita las instrucciones deseadas.\n"
                    f"4. Declara todas las variables al principio de `{{ }}`."
                )
            else:
                user_head_txt = (
                    f"Funcion `{e['name']}` @ 0x{e['addr']:08X} | Modo: {e['mode']} | Compilador: {cc_bin} | Tamano objetivo: {e['size']} bytes.\n\n"
                    f"{FEW_SHOT_PROMPT}"
                    f"### Reglas obligatorias de {cc_bin}\n{prof['rules']}\n"
                    f"### Referencia de instrucciones de la ROM (SOLO LECTURA - NO COPIAR MNEMONICOS AL CODIGO C)\n{disasm_txt}\n\n{ctx}"
                    f"### Codigo C89 base a mejorar ({best[0]*100:.1f}%)\n```c\n{ref_code_block}\n```\n\n"
                    f"ESTRATEGIA C89 ACTIVA: {strat}\n"
                    f"Escribe UNICAMENTE la funcion C89 `{e['name']}` dentro de ```c ... ```. "
                    f"Declara todas las variables locales al principio de `{{ }}`. Prohibido escribir ensamblador."
                )
            current_head = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_head_txt}]

            msgs = current_head + hist[-2:]
            text = ask(msgs, args.model, temp, seed=rng.randrange(1 << 30))
            c = extract_c(text, rom=rom)
            h = hashlib.md5(re.sub(r"\s+", "", c).encode()).hexdigest()
            if ASM_RE.search(c):
                asm_strikes += 1
                seen.add(h)
                anchor_c = best[1].strip() if best[1] else cleaned_ref[:1500]
                hist = [
                    {"role": "assistant", "content": "```c\n/* intento invalido con mnemonicos ASM */\n```"},
                    {"role": "user", "content": (
                        "[RECHAZO FATAL]: Tu respuesta incluyo instrucciones de ensamblador (push/pop/mov/ldr/str/cmp/bl/bx/sub sp). "
                        "Esta ESTRICTAMENTE PROHIBIDO escribir ensamblador. "
                        "Reescribe la logica usando UNICAMENTE sintaxis C89 pura (variables locales declaradas al inicio de `{ }`, "
                        "`if (...)`, asignaciones `=`, punteros y llamadas `func_XXXXXXXX(...)`) basandote en este esqueleto C:\n"
                        f"```c\n{anchor_c}\n```"
                    )},
                ]
                print(f"  [t{t + 1}] rechazado: contiene mnemonicos ASM -> forzando anclaje C89 (strike {asm_strikes})")
                if asm_strikes >= 2:
                    t += 1
                continue

            if not c.strip() or e["name"] not in c or c.count("{") == 0 or c.count("{") != c.count("}"):
                trunc_strikes += 1
                hist = []
                print(f"  [t{t + 1}] respuesta incompleta/truncada ({trunc_strikes}/3) -> compactando historial y regenerando...")
                if trunc_strikes >= 3:
                    print("  [limite] 3 respuestas truncadas consecutivas -> pasando al permutador final con el mejor candidato.")
                    break
                t += 1
                continue

            if h in seen:
                repeats += 1
                hist = [
                    {"role": "assistant", "content": f"```c\n{c.strip()}\n```"},
                    {"role": "user", "content": (
                        f"Ese codigo C89 es identico a un intento anterior. "
                        f"Cambia la estructura C89 aplicando esta estrategia: {STRATEGIES[(t + repeats) % len(STRATEGIES)]}"
                    )},
                ]
                print(f"  [t{t + 1}] candidato repetido ({repeats}/4), se fuerza otra estrategia C89")
                t += 1
                continue
            repeats = 0
            trunc_strikes = 0
            seen.add(h)
            sc, p, got, exact, err = evaluate(e, c, manifest, target, presets)
            if p is None:
                print(f"  [t{t + 1}] no compila: {(err or '?')[:150]}")
                ctrl.publish(force=True, last_score=0.0, last_err=(err or "")[:120])
                fb = f"El compilador ADS 1.2 (`{cc_bin}`) reporto error en tu codigo C:\n{err}"
                if err and any(code in err for code in ["C2292E", "C2284E", "C2323E", "C2143E", "C2304E", "C2285E"]):
                    fb += (
                        "\n[CAUSA]: En C89 de ADS 1.2 todas las declaraciones de variables locales (`u32 x;`, `u16 y;`) "
                        "DEBEN ir en las primeras lineas inmediatamente despues de `{`, antes de cualquier llamada o `if`."
                    )
                hist = [
                    {"role": "assistant", "content": f"```c\n{c.strip()}\n```"},
                    {"role": "user", "content": fb + "\nCorrige SOLO el error de compilacion C89 manteniendo todo en C puro. Entrega solo el bloque ```c."}
                ]
            else:
                print(f"  [t{t + 1}] mejor preset {p}: puntaje {sc * 100:.1f}% ({len(got)}/{e['size']} B)")
                if exact:
                    save_matched(e, c, p, manifest, state, t + 1, "llm", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
                    return
                if sc > best[0]:
                    best = (sc, c, p)
                    degrade_strikes = 0
                    _write_atomic(prev, c)
                    _write_atomic(TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c", c)
                    state[e["name"]] = {"status": "wip", "best": round(best[0], 4), "preset": p, "phase": phase_num, "addr": e["addr"], "size": e["size"]}
                    save_state(state)
                    fb = f"Compilo correctamente ({sc * 100:.1f}%).\n{feedback(e, target, got)}"
                    hist = [
                        {"role": "assistant", "content": f"```c\n{c.strip()}\n```"},
                        {"role": "user", "content": fb}
                    ]
                else:
                    degrade_strikes += 1
                    hist = []  # No contaminar la conversacion con codigo degradado
                    print(f"  [retroceso] intento con paridad inferior ({sc*100:.1f}% vs base {best[0]*100:.1f}%) -> descartado (strike {degrade_strikes}/2)")
                    if degrade_strikes >= 2:
                        print(f"  [limite] 2 strikes sin mejora respecto a {best[0]*100:.1f}% -> cerrando intentos LLM para esta funcion")
                        break

                ctrl.publish(force=True, best_score=round(best[0], 4), last_score=round(sc, 4), last_err="")
                if sc >= args.perm_threshold and args.permute_quick:
                    ctrl.publish(force=True, phase=f"Permuter Quick ({args.permute_quick} it) en {e['name']}")
                    psc, pc, pex = run_permuter(e, c, p, sc, manifest, target, args.permute_quick, rng, f"t{t + 1}")
                    if pex:
                        save_matched(e, pc, p, manifest, state, t + 1, "permuter", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
                        return
                    if psc > best[0]:
                        best = (psc, pc, p)
                        degrade_strikes = 0
                        _write_atomic(prev, pc)
                        _write_atomic(TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c", pc)
                        state[e["name"]] = {"status": "wip", "best": round(best[0], 4), "preset": p, "phase": phase_num, "addr": e["addr"], "size": e["size"]}
                        save_state(state)
            t += 1
        except KeyboardInterrupt:
            raise
        except Exception as try_ex:
            print(f"  [aviso t{t + 1}] fallo transitorio de E/S o subproceso ({try_ex}) -> reintentando sin saltar de funcion...")
            time.sleep(1.5)
            continue

    if phase_num >= 2 and best[1] and (args.permute or ctrl.permute_now > 0) and not ctrl.stop:
        p_iters = args.permute + ctrl.permute_now
        ctrl.permute_now = 0
        ctrl.publish(force=True, phase=f"Permuter Final ({p_iters} it) en {e['name']}", best_score=round(best[0], 4))
        print(f"  [perm final] {p_iters} iteraciones sobre el mejor ({best[0] * 100:.1f}%)")
        psc, pc, pex = run_permuter(e, best[1], best[2], best[0], manifest, target, p_iters, rng, "final")
        if pex:
            save_matched(e, pc, best[2], manifest, state, max_tries, "permuter-final", target=target, rom=rom, model=args.model, use_llm_clean=use_llm_clean, phase_num=phase_num)
            return
        if psc > best[0]:
            best = (psc, pc, best[2])
    if best[1]:
        _write_atomic(prev, best[1])
        _write_atomic(TREE_DIR / "collection" / "wip" / f"{e['name']}.wip.c", best[1])
    if (best[0] >= args.approx or ctrl.accept) and best[1]:
        ctrl.accept = False
        ad = TREE_DIR / "approx"
        ad.mkdir(exist_ok=True)
        approx_txt = f"/* paridad {best[0] * 100:.1f}% preset {best[2]} */\n" + best[1]
        _write_atomic(ad / f"{e['name']}.c", approx_txt)
        _write_atomic(TREE_DIR / "collection" / "approx" / f"{e['name']}.c", approx_txt)
        state[e["name"]] = {"status": "approx", "best": round(best[0], 4), "preset": best[2], "phase": phase_num, "addr": e["addr"], "size": e["size"]}
        save_state(state)
        _log_collection_event({"func": e["name"], "addr": f"0x{e['addr']:08X}", "status": "approx", "score": round(best[0], 4), "preset": best[2], "phase": phase_num})
        print(f"  [approx] {e['name']} paridad={best[0] * 100:.1f}% (guardado en approx/ y collection/approx/)")
    elif best[0] <= 0.0:
        state[e["name"]] = {"status": "orphan", "best": 0.0, "preset": None, "phase": phase_num, "addr": e["addr"], "size": e["size"]}
        save_state(state)
        _log_collection_event({"func": e["name"], "addr": f"0x{e['addr']:08X}", "status": "orphan", "score": 0.0, "preset": None, "phase": phase_num})
        print(f"  [orphan] {e['name']} (0.0% no compilable directo -> cola Fase 2 DeepSeek)")
    else:
        state[e["name"]] = {"status": "wip", "best": round(best[0], 4), "preset": best[2], "phase": phase_num, "addr": e["addr"], "size": e["size"]}
        save_state(state)
        _log_collection_event({"func": e["name"], "addr": f"0x{e['addr']:08X}", "status": "wip", "score": round(best[0], 4), "preset": best[2], "phase": phase_num})
        print(f"  [wip] {e['name']} mejor={best[0] * 100:.1f}% (cola Fase 2 DeepSeek)")


def _select_todo_for_phase(manifest, state, args):
    phase = int(getattr(args, "phase", 1))
    if args.func:
        return [e for e in manifest if e["name"] == args.func]
    base = [e for e in manifest if args.min_size <= e["size"] <= args.max_size]
    if phase == 1:
        # Fase 1 (CPU Diff + Permutador): solo funciones que aun no han sido evaluadas por CPU
        todo = [e for e in base if e["name"] not in state]
        todo.sort(key=lambda e: e["addr"])
        return todo
    if phase == 2:
        # Fase 2 (LLM Coder): candidatos ordenados por paridad descendente (las mas cercanas primero)
        # Incluye 'approx' (>=90%), 'wip' (50-89%) y 'orphan' (0%)
        # Permite filtrar por rango si min_score o max_score fueron especificados
        min_sc = getattr(args, "min_score", 0.0)
        max_sc = getattr(args, "max_score", 1.0)
        
        todo = []
        for e in base:
            st = state.get(e["name"], {})
            status = st.get("status", "orphan")
            if status not in ("approx", "wip", "orphan"):
                continue
            sc = float(st.get("best", 0.0) or 0.0)
            if min_sc <= sc <= max_sc:
                todo.append(e)

        # Ordenar por menor numero de pasadas fallidas (attempts) y luego mayor paridad (99% -> 0%)
        # Esto evita que al reiniciar el motor vuelva a atascarse siempre en la misma primera funcion.
        todo.sort(key=lambda e: (
            int(state.get(e["name"], {}).get("attempts", 0) or 0),
            -float(state.get(e["name"], {}).get("best", 0.0) or 0.0),
            e["size"],
            e["addr"],
        ))
        return todo
    if phase == 3:
        # Fase 3 (Nombrado Semantico con DeepSeek): funciones matched que aun no tienen nombre semantico
        todo = [
            e for e in base
            if state.get(e["name"], {}).get("status") == "matched"
            and not state.get(e["name"], {}).get("named", False)
        ]
        todo.sort(key=lambda e: e["addr"])
        return todo
    skip = ("matched",) if args.retry_wip else ("matched", "wip", "approx", "orphan")
    todo = [e for e in base if state.get(e["name"], {}).get("status") not in skip]
    todo.sort(key=(lambda e: e["addr"]) if args.order == "addr" else (lambda e: e["size"]))
    return todo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", type=int, choices=[1, 2, 3], default=1, help="1=CPU Diff/Perm, 2=DeepSeek Orphans/WIP, 3=Semantic Naming")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--func")
    ap.add_argument("--tries", type=int, default=30, help="intentos de LLM por funcion")
    ap.add_argument("--permute", type=int, default=800, help="iteraciones del permutador final")
    ap.add_argument("--permute-quick", type=int, default=40, help="iteraciones por candidato prometedor")
    ap.add_argument("--perm-threshold", type=float, default=0.55)
    ap.add_argument("--approx", type=float, default=0.90, help="paridad para marcar approx")
    ap.add_argument("--max-minutes", type=float, default=0, help="tope de tiempo por funcion (0 = sin limite)")
    ap.add_argument("--max-size", type=int, default=256, help="bytes; salta funciones mas grandes")
    ap.add_argument("--min-size", type=int, default=2)
    ap.add_argument("--retry-wip", action="store_true", help="reintenta funciones wip/approx")
    ap.add_argument("--min-score", type=float, default=0.0, help="filtro de puntaje minimo (0.0 a 1.0)")
    ap.add_argument("--max-score", type=float, default=1.0, help="filtro de puntaje maximo (0.0 a 1.0)")
    ap.add_argument("--order", choices=["size", "addr", "score"], default="score")
    args = ap.parse_args()

    cfg = enforce_half_power_hardware()
    ads_info = verify_ads_compilers()
    install_tee()
    rom, manifest, state = load_rom(), load_manifest(), load_state()
    sync_collection(state)
    todo = _select_todo_for_phase(manifest, state, args)
    cnt = lambda s: sum(1 for v in state.values() if v.get("status") == s)
    named_cnt = sum(1 for v in state.values() if v.get("status") == "matched" and v.get("named"))
    pwr = estimate_power(HALF_THREADS, THROTTLE_PAUSE, cfg.get("duty_cycle", 85), cfg.get("priority", "below_normal"))
    phase_labels = {
        1: "FASE 1/3 :: BARRIDO PURO POR CPU (Semilla C89 + Permutador | CERO LLM)",
        2: "FASE 2/3 :: BARRIDO DEEPSEEK + PERMUTADOR (Solo Huerfanas y WIP)",
        3: "FASE 3/3 :: PASADA SEMANTICA (Nombrado y Limpieza de Funciones Matched)",
    }
    print(f"[*] {phase_labels.get(args.phase, 'FASE ACTIVA')}")
    print(f"[*] Compiladores Verificados: THUMB={Path(ads_info.get('agbcc') or ads_info['tcc']).name} + {Path(ads_info['tcc']).name} | ARM={Path(ads_info['armcc']).name}")
    print(f"[*] Estado Global: {cnt('matched')} matched ({named_cnt} nombradas), {cnt('approx')} approx, {cnt('wip')} wip, {cnt('orphan')} orphan; "
          f"{len(todo)} pendientes en Fase {args.phase}")

    try:
        idx = 0
        limit_list = list(todo[: args.limit])
        by_name = {e["name"]: e for e in manifest}
        while idx < len(limit_list):
            if ctrl.stop:
                print("[!] Detenido de forma segura por consola (stop).")
                break
            if ctrl.reset_all:
                ctrl.reset_all = False
                state.clear()
                state.update(load_state())
                todo = _select_todo_for_phase(manifest, state, args)
                limit_list = list(todo[: args.limit])
                idx = 0
                print(f"[*] Lote rebobinado desde 0 -> iniciando en {limit_list[0]['name'] if limit_list else 'N/A'}")
                continue
            while ctrl.priority:
                p_name = ctrl.priority.pop(0)
                if p_name in by_name:
                    limit_list.insert(idx, by_name[p_name])
            e = limit_list[idx]
            idx += 1
            if e["name"] in ctrl.skip_names:
                ctrl.skip_names.discard(e["name"])
                continue
            t0 = time.time()
            print(f"[*] [F{args.phase}] {e['name']} ({e['mode']}, {e['size']} B)")
            try:
                process(e, rom, manifest, state, args)
            except KeyboardInterrupt:
                raise
            except Exception as ex:  # noqa
                print(f"  [err] {e['name']}: {ex}")
            if not ctrl.reset_all:
                save_state(state)  # checkpoint atomico tras cada funcion
            print(f"  {time.time() - t0:.1f}s")
    except KeyboardInterrupt:
        print("[!] Interrumpido; progreso previo guardado, relanza el mismo comando para continuar.")
    finally:
        ctrl.publish(force=True, phase=f"IDLE (Fase {args.phase} en espera)")
        save_state(state)
    print(f"[+] Resumen F{args.phase}: matched={cnt('matched')} ({named_cnt} nombradas) approx={cnt('approx')} wip={cnt('wip')} orphan={cnt('orphan')} de {len(manifest)}")



if __name__ == "__main__":
    main()
