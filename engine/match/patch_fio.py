"""Parchea FinisOmnivmOrchestrator.java con opciones optimizadas de descompilador y sanitizador C89."""
from pathlib import Path

FIO_JAVA = Path(r"J:\Laboratorio\GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM\core\FinisOmnivmOrchestrator.java")

def main():
    if not FIO_JAVA.exists():
        print(f"Error: {FIO_JAVA} no existe")
        return 1

    content = FIO_JAVA.read_text(encoding="utf-8")

    # 1. Nuevas opciones de DecompileOptions
    old_opts = "        dOpts.setEliminateUnreachable(true); // Elimina bloques inalcanzables silenciosamente\n        decomp.setOptions(dOpts);"
    old_opts_crlf = "        dOpts.setEliminateUnreachable(true); // Elimina bloques inalcanzables silenciosamente\r\n        decomp.setOptions(dOpts);"

    new_opts = """        dOpts.setEliminateUnreachable(true); // Elimina bloques inalcanzables silenciosamente
        dOpts.setInferConstantPointers(true); // Infiere punteros a constantes de memoria y literales
        dOpts.setAnalyzeForLoops(true);       // Convierte bucles while/goto a for C estructurados
        dOpts.setSplitStructures(false);      // NO descompone structs en variables sueltas (evita piStack_2c)
        dOpts.setSplitPointers(false);        // NO separa punteros en offsets de pila individuales
        dOpts.setSimplifyDoublePrecision(true);
        dOpts.setIgnoreUnimplemented(true);
        dOpts.setConventionPrint(false);      // Limpia ruido de convencion en firmas
        decomp.setOptions(dOpts);"""

    if old_opts_crlf in content:
        content = content.replace(old_opts_crlf, new_opts.replace("\n", "\r\n"))
        print("[+] DecompileOptions actualizadas (CRLF)")
    elif old_opts in content:
        content = content.replace(old_opts, new_opts)
        print("[+] DecompileOptions actualizadas (LF)")
    else:
        print("[!] No se encontro el bloque de DecompileOptions (quizas ya estaba parcheado)")

    # 2. Reemplazar la limpieza basica por sanitizeGhidraC
    old_clean = """                // Limpieza estética rigurosa: eliminar cualquier bloque residual de comentarios WARNING
                code = code.replaceAll("(?m)^\\\\s*/\\\\*\\\\s*WARNING:.*?\\\\*/\\\\r?\\\\n?", "");
                code = code.replaceAll("(\\\\r?\\\\n){3,}", "\\n\\n").trim();"""
    old_clean_crlf = old_clean.replace("\n", "\r\n")

    new_clean = """                // Limpieza y sanitizacion rigurosa C89 (reprimenda a Ghidra)
                code = sanitizeGhidraC(code, fn);"""

    if old_clean_crlf in content:
        content = content.replace(old_clean_crlf, new_clean.replace("\n", "\r\n"))
        print("[+] Llamada a sanitizeGhidraC inyectada (CRLF)")
    elif old_clean in content:
        content = content.replace(old_clean, new_clean)
        print("[+] Llamada a sanitizeGhidraC inyectada (LF)")
    else:
        print("[!] Bloque de limpieza anterior no encontrado")

    # 3. Metodo sanitizeGhidraC
    target_entry = "    // --------------------------------------------------------------------------\n    //  ENTRYPOINT PRINCIPAL DE GHIDRA SCRIPT"
    target_entry_crlf = "    // --------------------------------------------------------------------------\r\n    //  ENTRYPOINT PRINCIPAL DE GHIDRA SCRIPT"

    sanitizer_method = '''    // --------------------------------------------------------------------------
    //  SANITIZADOR C89 RIGUROSO (REPRIMENDA A GHIDRA)
    // --------------------------------------------------------------------------
    private String sanitizeGhidraC(String code, Function fn) {
        if (code == null) return "";

        // 1. Eliminar advertencias y comentarios internos de Ghidra
        code = code.replaceAll("(?m)^\\\\s*/\\\\*\\\\s*WARNING:.*?\\\\*/\\\\r?\\\\n?", "");

        // 2. Erradicar variables espurias: in_lr, unaff_rX, extraout_rX
        code = code.replaceAll("(?m)^\\\\s*(undefined\\\\d*|int|u\\\\d+|s\\\\d+|void\\\\s*\\\\*?)\\\\s+in_lr\\\\s*;\\\\r?\\\\n?", "");
        code = code.replaceAll("(?m)^\\\\s*(undefined\\\\d*|int|u\\\\d+|s\\\\d+|void\\\\s*\\\\*?)\\\\s+unaff_r\\\\w+\\\\s*;\\\\r?\\\\n?", "");
        code = code.replaceAll("(?m)^\\\\s*(undefined\\\\d*|int|u\\\\d+|s\\\\d+|void\\\\s*\\\\*?)\\\\s+extraout_\\\\w+\\\\s*;\\\\r?\\\\n?", "");

        // 3. Normalizar retornos con in_lr y usos de registros no preservados
        code = code.replaceAll("\\\\breturn\\\\s+in_lr\\\\s*;", "return 0;");
        code = code.replaceAll("\\\\bin_lr\\\\b", "0");
        code = code.replaceAll("\\\\bunaff_r\\\\w+\\\\b", "0");
        code = code.replaceAll("\\\\bextraout_\\\\w+\\\\b", "0");

        // 4. Normalizar tipos Ghidra a C89 estandar GBA
        code = code.replaceAll("\\\\bundefined4\\\\b", "u32");
        code = code.replaceAll("\\\\bundefined2\\\\b", "u16");
        code = code.replaceAll("\\\\bundefined1\\\\b", "u8");
        code = code.replaceAll("\\\\bundefined\\\\b", "u8");
        code = code.replaceAll("\\\\bbyte\\\\b", "u8");
        code = code.replaceAll("\\\\bushort\\\\b", "u16");
        code = code.replaceAll("\\\\buint\\\\b", "u32");
        code = code.replaceAll("\\\\bulong\\\\b", "u32");
        code = code.replaceAll("\\\\blonglong\\\\b", "s64");
        code = code.replaceAll("\\\\bulonglong\\\\b", "u64");

        // 5. Normalizar llamadas de funciones y simbolos (func_0x08 -> func_08)
        code = code.replaceAll("\\\\bfunc_0x([0-9a-fA-F]{8})\\\\b", "func_$1");
        code = code.replaceAll("\\\\bfunc_0x([0-9a-fA-F]+)\\\\b", "func_$1");
        code = code.replaceAll("\\\\bFUN_([0-9a-fA-F]{8})\\\\b", "func_$1");
        code = code.replaceAll("\\\\bDAT_0x([0-9a-fA-F]+)\\\\b", "DAT_$1");

        // 6. Eliminar artefactos y trampas intrusivas
        code = code.replaceAll("(?m)^\\\\s*halt_baddata\\\\(\\\\)\\\\s*;\\\\r?\\\\n?", "");
        code = code.replaceAll("(?m)^\\\\s*trap\\\\(\\\\d+\\\\)\\\\s*;\\\\r?\\\\n?", "");

        // 7. Colapsar lineas en blanco consecutivas
        code = code.replaceAll("(\\\\r?\\\\n){3,}", "\\n\\n").trim();
        return code;
    }

'''

    if "sanitizeGhidraC" not in content:
        if target_entry_crlf in content:
            content = content.replace(target_entry_crlf, sanitizer_method.replace("\n", "\r\n") + target_entry_crlf)
            print("[+] Metodo sanitizeGhidraC inyectado (CRLF)")
        elif target_entry in content:
            content = content.replace(target_entry, sanitizer_method + target_entry)
            print("[+] Metodo sanitizeGhidraC inyectado (LF)")
        else:
            print("[!] No se encontro el punto de insercion para sanitizeGhidraC")
    else:
        print("[*] sanitizeGhidraC ya existe en el archivo")

    FIO_JAVA.write_text(content, encoding="utf-8")
    print("[+] Archivo FinisOmnivmOrchestrator.java guardado exitosamente!")
    return 0

if __name__ == "__main__":
    main()

