import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.*;
import java.util.*;

public class DeepRoutineDecompiler extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== DEEP ROUTINE DECOMPILER - FURNITURE & BLITTER ENGINE ===");

        File outFile = new File("J:/Laboratorio/GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM/output/fomt_virgen/deep_furniture_blitter_routines.c");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outFile));
        writer.write("// ==============================================================================\n");
        writer.write("//  FIO DECOMPILATION - FURNITURE & BLITTER CORE ENGINE\n");
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

        Object[][] targets = new Object[][]{
            {"ApplyMapPatch_Blitter_080A5BD8", 0x080A5BD8L, 0x080A5CB4L},
            {"GetMapRuntime_080A4698", 0x080A4698L, 0x080A4700L},
            {"HandleHouseFeature_080AA850", 0x080AA850L, 0x080AA8D0L},
            {"FinalizeMap_080AACB8", 0x080AACB8L, 0x080AAD20L},
            {"SaveGet_FarmHouseLevel_0800BF14", 0x0800BF14L, 0x0800BF1CL},
            {"SaveGet_Refrigerator_0800BF1C", 0x0800BF1CL, 0x0800BF34L},
            {"SaveGet_Cabinet_0800BF34", 0x0800BF34L, 0x0800BF50L},
            {"SaveGet_HasRecordPlayer_0800BF50", 0x0800BF50L, 0x0800BF70L},
            {"SaveGet_HasFireplaceLit_0800BF84", 0x0800BF84L, 0x0800BF8CL},
            {"SaveGet_HasFireplace_0800BF8C", 0x0800BF8CL, 0x0800BF94L},
            {"SaveGet_HasCarpetDiningTable_0800BF94", 0x0800BF94L, 0x0800BF9CL},
            {"SaveGet_HasMirror_0800BF9C", 0x0800BF9CL, 0x0800BFA4L},
            {"SaveGet_HasClock_0800BFAC", 0x0800BFACL, 0x0800BFB4L},
            {"SaveGet_HasLargeShelf_0800BFB4", 0x0800BFB4L, 0x0800BFC0L},
            {"SaveGet_HasKitchen_0800BFCC", 0x0800BFCCL, 0x0800BFDCL},
            {"SaveGet_RecordPlayerDisc_0800BB74", 0x0800BB74L, 0x0800BB90L}
        };

        for (Object[] target : targets) {
            String name = (String) target[0];
            long sAddr = (Long) target[1];
            long eAddr = (Long) target[2];

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
