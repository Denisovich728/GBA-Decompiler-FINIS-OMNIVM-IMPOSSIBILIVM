import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.*;
import java.util.*;

public class TargetedDecompiler extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== TARGETED DECOMPILER - MAP HANDLERS DECOMPILATION ===");

        File outFile = new File("J:/Laboratorio/GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM/output/fomt_virgen/targeted_map_routines.c");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outFile));
        writer.write("// ==============================================================================\n");
        writer.write("//  FIO TARGETED DECOMPILATION - MAP & FURNITURE CORE ROUTINES\n");
        writer.write("// ==============================================================================\n\n");

        DecompInterface decomp = new DecompInterface();
        DecompileOptions dOpts = new DecompileOptions();
        dOpts.grabFromProgram(currentProgram);
        dOpts.setWARNCommentIncluded(false);
        dOpts.setMaxJumpTableEntries(4096);
        dOpts.setMaxInstructions(250000);
        dOpts.setMaxPayloadMBytes(200);
        dOpts.setEliminateUnreachable(true);
        decomp.setOptions(dOpts);
        decomp.toggleSyntaxTree(true);

        if (!decomp.openProgram(currentProgram)) {
            println("[ERROR] No se pudo abrir el programa en DecompInterface.");
            writer.close();
            return;
        }

        long[][] handlers = new long[][]{
            {0x080A6C18L, 0x080A6D76L, 0L}, // Map 00: Farm Normal
            {0x080A6D78L, 0x080A6EE2L, 1L}, // Map 01: Farm Winter
            {0x080A6EE4L, 0x080A6F9EL, 41L}, // Map 41: House LV1
            {0x080A6FA0L, 0x080A70DAL, 42L}, // Map 42: House LV2
            {0x080A70DCL, 0x080A725EL, 43L}, // Map 43: House LV3
            {0x080A7260L, 0x080A72B0L, 36L}, // Map 36: Chicken Coop 1 Inside
            {0x080A72B2L, 0x080A733AL, 37L}, // Map 37: Chicken Coop 2 Inside
            {0x080A733CL, 0x080A7394L, 38L}, // Map 38: Barn 1 Inside
            {0x080A7396L, 0x080A73F0L, 39L}  // Map 39: Barn 2 Inside
        };

        for (long[] h : handlers) {
            long sAddr = h[0];
            long eAddr = h[1];
            long mapId = h[2];
            String name = String.format("HandleMap_%02d_0x%08X", mapId, sAddr);

            Address start = toAddr(sAddr);
            Address end   = toAddr(eAddr);
            AddressSet body = new AddressSet(start, end);

            println("[*] Procesando " + name + " (0x" + Long.toHexString(sAddr).toUpperCase() + " .. 0x" + Long.toHexString(eAddr).toUpperCase() + ")...");

            Function oldFunc = getFunctionAt(start);
            if (oldFunc != null) {
                removeFunction(oldFunc);
            }

            DisassembleCommand disCmd = new DisassembleCommand(start, body, true);
            disCmd.applyTo(currentProgram, monitor);

            CreateFunctionCmd cmd = new CreateFunctionCmd(name, start, body, SourceType.USER_DEFINED);
            cmd.applyTo(currentProgram, monitor);
            Function func = getFunctionAt(start);

            if (func != null) {
                DecompileResults res = decomp.decompileFunction(func, 60, monitor);
                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction decFunc = res.getDecompiledFunction();
                    if (decFunc != null) {
                        String cCode = decFunc.getC();
                        writer.write("// ------------------------------------------------------------------------------\n");
                        writer.write("// " + name + "\n");
                        writer.write("// ------------------------------------------------------------------------------\n");
                        writer.write(cCode);
                        writer.write("\n\n");
                        println("  [OK] " + name + " decompilada (" + cCode.length() + " chars).");
                    }
                } else {
                    println("  [WARN] Fallo: " + (res != null ? res.getErrorMessage() : "null"));
                }
            } else {
                println("  [ERROR] No se pudo crear funcion para " + name);
            }
        }

        writer.close();
        println("[+] Finalizado exitosamente. Salida en: " + outFile.getAbsolutePath());
    }
}
