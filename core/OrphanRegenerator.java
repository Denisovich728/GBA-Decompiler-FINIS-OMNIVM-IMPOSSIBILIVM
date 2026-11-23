import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.*;

public class OrphanRegenerator extends GhidraScript {

    private String sanitizeGhidraC(String code, Function fn) {
        if (code == null) return "";

        // 1. Eliminar advertencias y comentarios internos
        code = code.replaceAll("(?m)^\\s*/\\*\\s*WARNING:.*?\\*/\\r?\\n?", "");

        // 2. Erradicar variables espurias: in_lr, unaff_rX, extraout_rX
        code = code.replaceAll("(?m)^\\s*(undefined\\d*|int|u\\d+|s\\d+|void\\s*\\*?)\\s+in_lr\\s*;\\r?\\n?", "");
        code = code.replaceAll("(?m)^\\s*(undefined\\d*|int|u\\d+|s\\d+|void\\s*\\*?)\\s+unaff_r\\w+\\s*;\\r?\\n?", "");
        code = code.replaceAll("(?m)^\\s*(undefined\\d*|int|u\\d+|s\\d+|void\\s*\\*?)\\s+extraout_\\w+\\s*;\\r?\\n?", "");

        // 3. Normalizar retornos con in_lr y usos de registros no preservados
        code = code.replaceAll("\\breturn\\s+CONCAT44\\s*\\([^,]+,\\s*([^)]+)\\)\\s*;", "return (void *)$1;");
        code = code.replaceAll("\\bCONCAT44\\s*\\([^,]+,\\s*([^)]+)\\)", "$1");
        code = code.replaceAll("\\breturn\\s+in_lr\\s*;", "return 0;");
        code = code.replaceAll("\\bin_lr\\b", "0");
        code = code.replaceAll("\\bunaff_r\\w+\\b", "0");
        code = code.replaceAll("\\bextraout_\\w+\\b", "0");

        // 4. Normalizar tipos Ghidra a C89 estandar GBA
        code = code.replaceAll("\\bundefined8\\b", "void *");
        code = code.replaceAll("\\bundefined[4-7]\\b", "u32");
        code = code.replaceAll("\\bundefined3\\b", "u32");
        code = code.replaceAll("\\bundefined2\\b", "u16");
        code = code.replaceAll("\\bundefined1\\b", "u8");
        code = code.replaceAll("\\bundefined\\b", "u8");
        code = code.replaceAll("\\buint3\\b", "u32");
        code = code.replaceAll("\\bint3\\b", "s32");
        code = code.replaceAll("\\bbyte\\b", "u8");
        code = code.replaceAll("\\bushort\\b", "u16");
        code = code.replaceAll("\\buint\\b", "u32");
        code = code.replaceAll("\\bulong\\b", "u32");
        code = code.replaceAll("\\blonglong\\b", "s64");
        code = code.replaceAll("\\bulonglong\\b", "u64");
        code = code.replaceAll("\\bcode\\s*\\*", "void *");

        // 5. Normalizar llamadas de funciones y simbolos (func_0x08 -> func_08)
        code = code.replaceAll("\\bfunc_0x([0-9a-fA-F]{8})\\b", "func_$1");
        code = code.replaceAll("\\bfunc_0x([0-9a-fA-F]+)\\b", "func_$1");
        code = code.replaceAll("\\bFUN_([0-9a-fA-F]{8})\\b", "func_$1");
        code = code.replaceAll("\\bDAT_0x([0-9a-fA-F]+)\\b", "DAT_$1");

        // 6. Eliminar artefactos y trampas intrusivas
        code = code.replaceAll("(?m)^\\s*halt_baddata\\(\\)\\s*;\\r?\\n?", "");
        code = code.replaceAll("(?m)^\\s*trap\\(\\d+\\)\\s*;\\r?\\n?", "");
        code = code.replaceAll("(?m)^\\s*\\(\\w+\\s*\\*?\\)\\s*0x[0-9a-fA-F]+\\s*;\\r?\\n?", "");

        // 7. Colapsar lineas en blanco consecutivas
        code = code.replaceAll("(\\r?\\n){3,}", "\n\n").trim();
        return code;
    }

    @Override
    public void run() throws Exception {
        println("==============================================================================");
        println(" FIO DECOMP :: ORPHAN REGENERATOR (RESCATE C89 DIRECTO EN GHIDRA)");
        println("==============================================================================");

        File jsonFile = new File("J:/Laboratorio/FOMT-MATCH-ENGINE/src_sweep/control/orphans_to_regenerate.json");
        if (!jsonFile.exists()) {
            println("[ERROR] No se encontro orphans_to_regenerate.json en " + jsonFile.getAbsolutePath());
            return;
        }

        File outFile = new File("J:/Laboratorio/FOMT-MATCH-ENGINE/src_sweep/regenerated_orphans.c");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outFile));
        writer.write("// ==============================================================================\n");
        writer.write("//  FOMT REGENERATED ORPHANS (C89 PURE / GHIDRA FRESH REGEN)\n");
        writer.write("// ==============================================================================\n\n");

        DecompInterface decomp = new DecompInterface();
        DecompileOptions dOpts = new DecompileOptions();
        dOpts.grabFromProgram(currentProgram);
        dOpts.setWARNCommentIncluded(false);
        dOpts.setMaxJumpTableEntries(4096);
        dOpts.setMaxInstructions(250000);
        dOpts.setMaxPayloadMBytes(200);
        dOpts.setEliminateUnreachable(true);
        dOpts.setInferConstantPointers(true);
        dOpts.setAnalyzeForLoops(true);
        dOpts.setSplitStructures(false);
        dOpts.setSplitPointers(false);
        dOpts.setSimplifyDoublePrecision(true);
        dOpts.setIgnoreUnimplemented(true);
        dOpts.setConventionPrint(false);
        decomp.setOptions(dOpts);
        decomp.toggleSyntaxTree(true);

        if (!decomp.openProgram(currentProgram)) {
            println("[ERROR] No se pudo inicializar la interfaz del descompilador Ghidra.");
            writer.close();
            return;
        }

        // Leer JSON con regex robusta
        String jsonText = "";
        try (BufferedReader br = new BufferedReader(new FileReader(jsonFile))) {
            StringBuilder sb = new StringBuilder();
            String l;
            while ((l = br.readLine()) != null) sb.append(l).append("\n");
            jsonText = sb.toString();
        }

        Pattern p = Pattern.compile("\\{\\s*\"name\":\\s*\"([^\"]+)\",\\s*\"addr\":\\s*(\\d+),\\s*\"size\":\\s*(\\d+)(?:,\\s*\"mode\":\\s*\"([^\"]+)\")?\\s*\\}");
        Matcher m = p.matcher(jsonText);

        Register tMode = currentProgram.getRegister("TMode");
        int count = 0;
        int success = 0;

        while (m.find()) {
            if (monitor.isCancelled()) break;
            count++;

            String fnName = m.group(1);
            long addr = Long.parseLong(m.group(2));
            long size = Long.parseLong(m.group(3));
            String mode = m.group(4) != null ? m.group(4) : "THUMB";

            Address start = toAddr(addr);
            Address end = toAddr(addr + size - 1);
            AddressSet body = new AddressSet(start, end);

            // Asegurar modo Thumb o ARM
            try {
                if ("THUMB".equalsIgnoreCase(mode)) {
                    currentProgram.getProgramContext().setValue(tMode, start, end, BigInteger.ONE);
                } else {
                    currentProgram.getProgramContext().setValue(tMode, start, end, BigInteger.ZERO);
                }
            } catch (Exception ignored) {}

            // Forzar desensamblado si faltaba
            Instruction ins = getInstructionAt(start);
            if (ins == null) {
                DisassembleCommand disCmd = new DisassembleCommand(start, body, true);
                disCmd.applyTo(currentProgram, monitor);
            }

            // Obtener o crear funcion
            Function func = getFunctionAt(start);
            if (func == null) {
                CreateFunctionCmd cmd = new CreateFunctionCmd(fnName, start, body, SourceType.USER_DEFINED);
                cmd.applyTo(currentProgram, monitor);
                func = getFunctionAt(start);
            }

            if (func != null) {
                try {
                    DecompileResults res = decomp.decompileFunction(func, 60, monitor);
                    if (res != null && res.decompileCompleted()) {
                        DecompiledFunction decFunc = res.getDecompiledFunction();
                        if (decFunc != null) {
                            String cCode = decFunc.getC();
                            cCode = sanitizeGhidraC(cCode, func);

                            String hexAddr = String.format("%08X", addr);
                            writer.write("\n// --- " + fnName + " @ " + hexAddr + " [" + mode + "/REGEN] ---\n");
                            writer.write(cCode);
                            writer.write("\n");
                            success++;
                            println(String.format("  [OK] %-20s @ 0x%08X (%d bytes) => C89 Regen OK", fnName, addr, size));
                        }
                    } else {
                        println(String.format("  [WARN] %-20s @ 0x%08X => Decompile error: %s", fnName, addr, (res != null ? res.getErrorMessage() : "null")));
                    }
                } catch (Exception ex) {
                    println(String.format("  [EX] %-20s @ 0x%08X => %s", fnName, addr, ex.getMessage()));
                }
            } else {
                println(String.format("  [FAIL] %-20s @ 0x%08X => No se pudo instanciar funcion", fnName, addr));
            }

            if (count % 20 == 0) {
                writer.flush();
            }
        }

        writer.flush();
        writer.close();
        decomp.dispose();

        println("\n==============================================================================");
        println(String.format(" REGENERACION FINALIZADA: %d / %d funciones decompiladas a C89", success, count));
        println(" Archivo generado en: " + outFile.getAbsolutePath());
        println("==============================================================================\n");
    }
}

