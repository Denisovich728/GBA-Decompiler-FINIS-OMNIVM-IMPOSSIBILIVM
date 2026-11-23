import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.*;

public class MapLoaderDecompiler extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== MAP LOADER & PALETTE SYSTEM DECOMPILER ===");

        File outFile = new File("J:/Laboratorio/GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM/output/fomt_virgen/map_loader_palette_routines.c");
        BufferedWriter writer = new BufferedWriter(new FileWriter(outFile));
        writer.write("// ==============================================================================\n");
        writer.write("//  FIO DECOMPILATION - MAP LOADER & PALETTE SUBSYSTEM\n");
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
            println("[ERROR] No se pudo abrir el programa.");
            writer.close();
            return;
        }

        Object[][] targets = new Object[][]{
            {"MapInit_080A5770", 0x080A5770L, 0x080A58F0L},
            {"MapLoadGfx_080A58F0", 0x080A58F0L, 0x080A5A50L},
            {"MapSetup_080A5CC0", 0x080A5CC0L, 0x080A5DC0L},
            {"MapPaletteLoad_080AA2B0", 0x080AA2B0L, 0x080AA400L},
            {"MapSeasonPalette_080AA540", 0x080AA540L, 0x080AA650L},
            {"MapPalette_080AA6C0", 0x080AA6C0L, 0x080AA7A0L}
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
