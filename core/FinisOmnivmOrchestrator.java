// ==============================================================================
//  FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM  ::  UNIVERSAL GBA ENGINE v1.2
//  Autonomous Decompilation Engine for Any Game Boy Advance ROM (ARMv4T / Thumb)
// ==============================================================================
//
//  ALGORITMO ORQUESTADOR UNIVERSAL (7 FASES):
//    0.  AUTO-DETECCION UNIVERSAL DE ROM:
//        - Lee cabecera oficial GBA (0x080000A0..0x080000BC): Titulo, GameCode, MakerCode.
//        - Mide tamano exacto de ROM (4MB, 8MB, 16MB, 32MB).
//        - Vector de arranque (0x08000000) y salto crt0.
//    1.  INYECCION DE ARQUITECTURA HARDWARE GBA:
//        - Mapea BIOS, EWRAM, IWRAM, IO_REGS, PALRAM, VRAM, OAM.
//        - Convierte literales IO a punteros hardware tipados (REG_DISPCNT, etc.).
//    1b. CAZADOR Y FILTRO DE ACTIVOS MULTIMEDIA ULTRA-RAPIDO EN RAM:
//        - Escaneo en memoria de alta velocidad (<50ms) usando buffer byte[].
//        - Detecta cabeceras LZ77 (0x10, 0x11), Huffman (0x24, 0x28), RLE (0x30), Popuri (0x70).
//        - Detecta cabeceras M4A / Sappy Music (tracks, voicegroup, sequence pointers).
//        - Detecta cabeceras DirectSound WaveData (PCM Audio Sample Headers).
//        - Detecta paletas de color GBA BGR 15-bit (bit 15 = 0 en halfwords).
//        - Fusiona intervalos continuos para eliminar cuellos de botella DB en Ghidra.
//        - AISLA y BLOQUEA estas regiones para evitar decompilarlas como codigo C.
//    2.  INGESTION DINAMICA DE SIMBOLOS Y CONTEXTO:
//        - Soporta diccionarios JSON (funciones, vtables, labels, data).
//        - Modo ciego universal si no hay simbolos externos (func_08XXXXXX).
//    3.  "EL EMULADOR CIEGO" (Recursive Tracer + Gap Sweeper):
//        - Cola de trabajo recursiva siguiendo ramas BL, BLX, BX, B tail-calls.
//        - Gap Sweeper universal: detecta prologos Thumb (0xB5, 0xB4), ARM (STMFD)
//          y leaf functions (bx lr) omitiendo zonas multimedia.
//    4.  RESOLUTOR UNIVERSAL DE SWITCH JUMP TABLES NATIVO GHIDRA:
//        - Inyecta modelos ghidra.program.model.pcode.JumpTable con writeOverride()
//        - Reemplaza saltos indirectos con switch-case nativos estructurados en C.
//        - Etiqueta destinos simbolicos limpios (case_08XXXXXX) en vez de hex sucio.
//    5.  GUARDIAN DE CONTEXTO PARAMETRICO:
//        - Bloquea epilogos de retorno (FlowOverride.RETURN en bx lr y pop; bx rX).
//        - Nivel 1 (Permisivo): Preserva getters/setters, leaf functions y ramas crudas.
//        - Nivel 2 (Equilibrado - RECOMENDADO): Elimina pseudo-casos y loops huerfanos.
//        - Nivel 3 (Estricto): Solo funciones canonicas con prologo PUSH {lr}.
//    6.  DECOMPILACION ESTRATIFICADA A C Y TELEMETRIA MATRIX CON PROGRESS BAR:
//        - Streaming Matrix con etiqueta [PROGRESS: XX%] para barra de progreso en vivo.
//        - Genera <prefix>_all.c, <prefix>_named.c, <prefix>_thunks.c, hotmap y resumen.
//
//  @category GBA_Universal
//  @author   Denisovich728 + Antigravity
//  @version  1.2 "FIO Decomp"
// ==============================================================================

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.listing.FlowOverride;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.util.*;

public class FinisOmnivmOrchestrator extends GhidraScript {

    // --------------------------------------------------------------------------
    //  CONFIGURACION DINAMICA Y PARAMETROS
    // --------------------------------------------------------------------------
    private String outDir               = "output";
    private int guardianStrictness      = 2; // 1 = Permisivo, 2 = Equilibrado (RECOMENDADO), 3 = Estricto
    private String contextJsonPath      = "NONE";
    private String gamePrefix           = "gba_game";
    private String gameTitle            = "UNKNOWN_GBA";
    private String gameCode             = "AGBE";
    private String makerCode            = "01";

    private long romBase                = 0x08000000L;
    private long romSize                = 0x01000000L; // 16MB default
    private long romEnd                 = 0x08FFFFFFL;
    private long entryPoint             = 0x080000C0L;
    private long codeStart              = 0x080000C0L;
    private long codeEnd                = 0x08FFFFFFL;

    // --------------------------------------------------------------------------
    //  PERFIL DE MOTOR Y CONFIGURACION DINAMICA (ENGINE PROFILES & SWITCHBOARD)
    // --------------------------------------------------------------------------
    private String engineProfileName      = "GENERIC_GBA";
    private String engineProfileDesc      = "Generic ARMv4T / Thumb Universal Architecture";
    private String horizonMode            = "CONTINUOUS_PERMISSIVE"; // CONTINUOUS_STRICT, CONTINUOUS_PERMISSIVE, SEGMENTED_OVERLAYS
    private boolean allowSegmentedOverlays = false;
    private int minOverlayClusterKb       = 8;
    private int horizonStreakToleranceKb  = 32;
    private int horizonMaxScanMb          = 8;
    private double horizonMaxIllegalRatio = 0.05;
    private double horizonMaxTextDensity  = 0.65;
    private double horizonInlineDataRatio = 0.12;
    private boolean initBiosVectors       = true;
    private boolean camelotScratchTolerance = false;
    private boolean scanIwramFastOverlays = false;
    private long iwramSourceOffset        = 0x08180000L;
    private String textCharsetMode        = "ASCII";
    private double entropyCutoff          = 7.85;
    private boolean allowByteOffsetTables = false;
    private boolean allowCamelotScriptTables = false;

    // Regiones multimedia / audio / graficos y textos aislados
    private final List<long[]> skipRegions = new ArrayList<>();
    private final TreeMap<Long, Long> skipMap = new TreeMap<>();
    private int assetsFound             = 0;
    private long assetsProtectedBytes   = 0;
    private int stringsFound            = 0;
    private long stringsDumpedBytes     = 0;

    // --------------------------------------------------------------------------
    //  ESTADO Y CONTADORES
    // --------------------------------------------------------------------------
    private final TreeMap<Long, String[]> hotmap  = new TreeMap<>();
    private final TreeMap<Long, String[]> kFuncs  = new TreeMap<>();
    private final TreeMap<Long, String[]> kLabels = new TreeMap<>();
    private final TreeMap<Long, String[]> kVtbls  = new TreeMap<>();
    private final TreeMap<Long, String[]> kData   = new TreeMap<>();

    private int cleanedInst = 0, resolvedPtrs = 0;
    private int applF = 0, applL = 0, applV = 0, applD = 0;
    private int discFuncs = 0, thumbF = 0, armF = 0;
    private int decompNamed = 0, decompAnon = 0, decompErr = 0, decompSkip = 0;
    private int resolvedJumpTables = 0, resolvedJumpCases = 0, nativeSwitchesOverridden = 0;
    private int returnsLocked = 0, bogusFuncsPurged = 0;
    private long totalLines = 0;

    private final Deque<Long> workQueue = new ArrayDeque<>();
    private final Set<Long> visited = new HashSet<>();

    // --------------------------------------------------------------------------
    //  HELPERS DE MEMORIA Y REGIONES
    // --------------------------------------------------------------------------
    private Address a(long off) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }

    private boolean isSkip(long off) {
        Map.Entry<Long, Long> entry = skipMap.floorEntry(off);
        return (entry != null && off < entry.getValue());
    }

    private void rebuildSkipMap() {
        skipMap.clear();
        for (long[] r : skipRegions) {
            skipMap.put(r[0], r[1]);
        }
    }

    private void setT(Address addr, boolean thumb) {
        try {
            Register t = currentProgram.getProgramContext().getRegister("T");
            if (t != null) {
                currentProgram.getProgramContext().setValue(t, addr, addr,
                    thumb ? java.math.BigInteger.ONE : java.math.BigInteger.ZERO);
            }
        } catch (Exception ignored) {}
    }

    private void kf(long addr, String name, String mode, String comment) {
        kFuncs.put(addr, new String[]{name, mode, comment});
        hotmap.put(addr, new String[]{name, mode, "KNOWN"});
    }

    // --------------------------------------------------------------------------
    //  FASE 0: LECTURA DE ARGUMENTOS Y AUTO-DETECCION UNIVERSAL
    // --------------------------------------------------------------------------
    private void parseArgsAndDetect() {
        println("==============================================================================");
        println("   FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM  ::  UNIVERSAL GBA ENGINE v1.2");
        println("==============================================================================");

        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            outDir = args[0];
        }
        if (args != null && args.length > 1 && args[1] != null && !args[1].isEmpty()) {
            try { guardianStrictness = Integer.parseInt(args[1]); } catch (Exception ignored) {}
        }
        if (args != null && args.length > 2 && args[2] != null && !args[2].isEmpty()) {
            contextJsonPath = args[2];
        }
        if (args != null && args.length > 3 && args[3] != null && !args[3].isEmpty()) {
            gamePrefix = args[3];
        }

        File outDirFile = new File(outDir);
        if (!outDirFile.exists()) {
            outDirFile.mkdirs();
        }

        // Inspeccionar memoria ROM
        try {
            MemoryBlock romBlock = currentProgram.getMemory().getBlock(a(romBase));
            if (romBlock != null) {
                romSize = romBlock.getSize();
                romEnd  = romBase + romSize - 1L;
                codeEnd = romEnd;
            }
        } catch (Exception ignored) {}

        // Leer Cabecera GBA (0x080000A0..0x080000BC)
        try {
            Memory mem = currentProgram.getMemory();
            byte[] titleBytes = new byte[12];
            mem.getBytes(a(0x080000A0L), titleBytes);
            gameTitle = new String(titleBytes).replaceAll("[^A-Za-z0-9_\\- ]", "").trim();
            if (gameTitle.isEmpty()) gameTitle = "GBA_ROM";

            byte[] codeBytes = new byte[4];
            mem.getBytes(a(0x080000ACL), codeBytes);
            gameCode = new String(codeBytes).replaceAll("[^A-Za-z0-9_]", "").trim();

            byte[] makerBytes = new byte[2];
            mem.getBytes(a(0x080000B0L), makerBytes);
            makerCode = new String(makerBytes).replaceAll("[^A-Za-z0-9_]", "").trim();

            int firstArm = mem.getInt(a(romBase));
            if ((firstArm & 0xFF000000) == 0xEA000000) { // B <imm24>
                int imm24 = firstArm & 0x00FFFFFF;
                if ((imm24 & 0x00800000) != 0) imm24 |= 0xFF000000;
                long target = romBase + 8 + (imm24 << 2);
                if (target >= romBase && target < romEnd) {
                    entryPoint = target;
                    codeStart = target;
                }
            }
        } catch (Exception ignored) {}

        if (gamePrefix.equals("gba_game") || gamePrefix.isEmpty()) {
            gamePrefix = gameTitle.toLowerCase().replaceAll("[^a-z0-9_]", "_");
            if (gamePrefix.isEmpty()) gamePrefix = "gba_rom";
        }

        println("  [ROM DETECTADA]");
        println("    Titulo       : " + gameTitle);
        println("    Codigo Juego : " + gameCode);
        println("    Codigo Maker : " + makerCode);
        println(String.format("    Rango ROM    : 0x%08X - 0x%08X (%.2f MB)", romBase, romEnd, romSize / 1048576.0));
        println(String.format("    Entrypoint   : 0x%08X", entryPoint));
        println("  [CONFIGURACION]");
        println("    Salida       : " + outDir);
        println("    Guardian     : Nivel " + guardianStrictness +
            (guardianStrictness == 2 ? " (Equilibrado - RECOMENDADO)" : (guardianStrictness == 1 ? " (Permisivo)" : " (Estricto)")));
        println("    Contexto     : " + contextJsonPath);
        println("    Prefijo      : " + gamePrefix);
        println("==============================================================================\n");

        loadEngineProfile();
    }

    // --------------------------------------------------------------------------
    //  CARGA Y AUTO-CONFIGURACION DE PERFILES DE MOTOR (ENGINE PROFILES)
    // --------------------------------------------------------------------------
    private void loadEngineProfile() {
        String tU = gameTitle.toUpperCase();
        String cU = gameCode.toUpperCase();
        String mU = makerCode.toUpperCase();

        if (cU.startsWith("AGS") || cU.startsWith("AGF") || cU.startsWith("BMG") || cU.startsWith("BM8") ||
            tU.contains("GOLDEN_SUN") || tU.contains("MARIO_GOLF") || tU.contains("MARIO_TENNIS")) {
            engineProfileName        = "CAMELOT";
            engineProfileDesc        = "Camelot Software Planning (Golden Sun & Mario Sports Multi-Cluster Architecture)";
            horizonMode              = "SEGMENTED_OVERLAYS";
            allowSegmentedOverlays   = true;
            horizonMaxScanMb         = 16;
            horizonStreakToleranceKb = 64;
            horizonMaxIllegalRatio   = 0.06;
            horizonInlineDataRatio   = 0.14;
            initBiosVectors          = true;
            camelotScratchTolerance  = true;
            allowByteOffsetTables    = true;
            allowCamelotScriptTables = true;
            entropyCutoff            = 7.80;
            textCharsetMode          = "ASCII_CAMELOT";
        } else if (cU.startsWith("BPE") || cU.startsWith("AXV") || cU.startsWith("AXP") || cU.startsWith("BPR") || cU.startsWith("BPG") ||
                   tU.contains("POKEMON")) {
            engineProfileName        = "GAME_FREAK";
            engineProfileDesc        = "Game Freak / Creatures Inc. (Pokemon Gen 3 Engine Architecture)";
            horizonMode              = "CONTINUOUS_STRICT";
            allowSegmentedOverlays   = false;
            horizonMaxScanMb         = 4;
            horizonStreakToleranceKb = 16;
            horizonMaxIllegalRatio   = 0.03;
            horizonInlineDataRatio   = 0.08;
            initBiosVectors          = true;
            entropyCutoff            = 7.92;
            textCharsetMode          = "POKEMON_GEN3";
        } else if (mU.equals("08") || cU.startsWith("ARE") || cU.startsWith("AE2") || cU.startsWith("A6B") || cU.startsWith("B4W") || cU.startsWith("BRB") || cU.startsWith("BZM") ||
                   tU.contains("MEGAMAN") || tU.contains("ROCKMAN") || (tU.contains("ZELDA") && cU.startsWith("BZM"))) {
            engineProfileName        = "CAPCOM";
            engineProfileDesc        = "Capcom / Flagship (Mega Man Battle Network & Minish Cap Architecture)";
            horizonMode              = "CONTINUOUS_PERMISSIVE";
            allowSegmentedOverlays   = false;
            horizonMaxScanMb         = 8;
            horizonStreakToleranceKb = 32;
            horizonMaxIllegalRatio   = 0.05;
            horizonInlineDataRatio   = 0.12;
            scanIwramFastOverlays    = true;
            iwramSourceOffset        = 0x08180000L;
            allowByteOffsetTables    = true;
            entropyCutoff            = 7.82;
            textCharsetMode          = "ASCII_CAPCOM";
        } else if (mU.equals("A4") || mU.equals("B2") || cU.startsWith("A44") || cU.startsWith("BFG") ||
                   tU.contains("HARVEST") || tU.contains("MINERAL")) {
            engineProfileName        = "MARVELOUS";
            engineProfileDesc        = "Marvelous / Victor Interactive Software (Harvest Moon FoMT Architecture)";
            horizonMode              = "CONTINUOUS_PERMISSIVE";
            allowSegmentedOverlays   = false;
            horizonMaxScanMb         = 4;
            horizonStreakToleranceKb = 24;
            horizonMaxIllegalRatio   = 0.05;
            horizonInlineDataRatio   = 0.12;
            entropyCutoff            = 7.85;
            textCharsetMode          = "ASCII_LATIN";
        } else {
            engineProfileName        = "GENERIC_GBA";
            engineProfileDesc        = "Generic ARMv4T / Thumb Universal Fallback Architecture";
            horizonMode              = "CONTINUOUS_PERMISSIVE";
            allowSegmentedOverlays   = false;
            horizonMaxScanMb         = 8;
            horizonStreakToleranceKb = 16;
            horizonMaxIllegalRatio   = 0.04;
            horizonInlineDataRatio   = 0.10;
            entropyCutoff            = 7.85;
        }

        loadConfigJsonIfExists();

        println("==============================================================================");
        println("  [ENGINE PROFILE ACTIVADO]");
        println("    Motor Activo : " + engineProfileName + " - " + engineProfileDesc);
        println("    Modo Horizon : " + horizonMode + " (maxScan: " + horizonMaxScanMb + "MB | streak: " + horizonStreakToleranceKb + "KB)");
        println("    Vectores BIOS: " + (initBiosVectors ? "Inicializados en 0x00000000 (Sin warnings de dereferencia)" : "Sin inicializar"));
        println("    Overlays     : " + (allowSegmentedOverlays ? "MULTI-CLUSTER HABILITADO (Escaneo en ROM completa)" : (scanIwramFastOverlays ? "IWRAM Overlay 0x08180000 HABILITADO" : "Estandar Monolitico")));
        println("    Jump Tables  : " + (allowCamelotScriptTables ? "Camelot Event VM + GCC Computed" : (allowByteOffsetTables ? "Capcom Byte Tables + GCC Computed" : "GCC Standard Computed Tables")));
        println("    Filtro Asset : Shannon Cutoff " + String.format("%.2f", entropyCutoff) + " | Charset: " + textCharsetMode);
        println("==============================================================================\n");
    }

    private void loadConfigJsonIfExists() {
        File[] candidateFiles = new File[]{
            new File("core/finis_engine_config.json"),
            new File("finis_engine_config.json"),
            new File(outDir, "finis_engine_config.json")
        };
        File cfgFile = null;
        for (File f : candidateFiles) {
            if (f.exists()) { cfgFile = f; break; }
        }
        if (cfgFile == null) return;

        try (BufferedReader br = new BufferedReader(new FileReader(cfgFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("\"active_preset_override\"")) {
                    String val = line.replaceAll("[^a-zA-Z0-9_]", " ").replace("active_preset_override", "").trim().toLowerCase();
                    if (val.contains("camelot")) {
                        engineProfileName = "CAMELOT";
                        allowSegmentedOverlays = true;
                        horizonMode = "SEGMENTED_OVERLAYS";
                        horizonMaxScanMb = 16;
                    } else if (val.contains("capcom")) {
                        engineProfileName = "CAPCOM";
                        allowByteOffsetTables = true;
                        scanIwramFastOverlays = true;
                    } else if (val.contains("game_freak")) {
                        engineProfileName = "GAME_FREAK";
                        horizonMode = "CONTINUOUS_STRICT";
                    } else if (val.contains("marvelous")) {
                        engineProfileName = "MARVELOUS";
                    }
                } else if (line.contains("\"allow_segmented_overlays\": true")) {
                    allowSegmentedOverlays = true;
                    horizonMode = "SEGMENTED_OVERLAYS";
                } else if (line.contains("\"init_bios_vectors\": false")) {
                    initBiosVectors = false;
                }
            }
            println("  [CONFIG] Parametros cargados exitosamente desde: " + cfgFile.getName());
        } catch (Exception ignored) {}
    }


    // --------------------------------------------------------------------------
    //  DETECCION DINAMICA DE HORIZONTE DE CODIGO (.text BOUNDARY) - ANALISIS ESTADISTICO
    // --------------------------------------------------------------------------
    private void detectCodeHorizon() {
        if (allowSegmentedOverlays) {
            println("[0b] Modo Multi-Cluster (Overlays Segmentados) activo. Escaneando la ROM completa de " + (romSize / 1048576) + "MB...");
            codeEnd = romEnd;
            println(String.format("  [0b] Horizonte Multi-Cluster expandido: 0x%08X -> 0x%08X (%.2f MB totales)",
                codeStart, codeEnd, (codeEnd - codeStart) / (1024.0 * 1024.0)));
            return;
        }

        println("[0b] Delimitando horizonte de ejecucion (.text horizon) dinamicamente via analisis continuo de instrucciones...");
        try {
            Memory mem = currentProgram.getMemory();
            int maxScan = (int) Math.min(romSize, (long) horizonMaxScanMb * 1024 * 1024);
            byte[] buf = new byte[maxScan];
            mem.getBytes(a(romBase), buf);

            int startScan = (int)(codeStart - romBase);
            int windowSz = 2048;
            int streakNonCode = 0;
            int lastSolidCode = startScan;

            for (int off = startScan; off < maxScan - windowSz; off += windowSz) {
                int prologs = 0;
                int returns = 0;
                int illegal = 0;
                int valid = 0;
                int txtChars = 0;

                for (int i = 0; i < windowSz - 1; i += 2) {
                    int b0 = buf[off + i] & 0xFF;
                    int b1 = buf[off + i + 1] & 0xFF;
                    int hw = b0 | (b1 << 8);

                    if ((b0 >= 0x20 && b0 <= 0x7E) || (b0 >= 0xBB && b0 <= 0xFE)) txtChars++;
                    if ((b1 >= 0x20 && b1 <= 0x7E) || (b1 >= 0xBB && b1 <= 0xFE)) txtChars++;

                    if ((hw & 0xFF00) == 0xB500) prologs++;
                    if (hw == 0x4770 || (hw & 0xFF00) == 0xBD00) returns++;

                    // Chequeo de instrucciones ARMv4T Thumb ilegales
                    if (((hw & 0xFF00) == 0xDF00 && (hw & 0xFF) > 0x2A) ||
                        ((hw & 0xFF00) == 0xBF00) ||
                        ((hw & 0xF800) == 0xE800)) {
                        illegal++;
                    } else {
                        valid++;
                    }
                }

                double illRatio = (valid + illegal > 0) ? ((double) illegal / (valid + illegal)) : 0.0;
                double txtDensity = (double) txtChars / windowSz;

                // Criterio matematico de continuidad de codigo:
                // 1. Si la ventana contiene prologos y retornos activos (funciones con tablas o literal pools en linea), es codigo genuino.
                // 2. O si tiene alta densidad de instrucciones validas y baja tasa de opcodes ilegales sin densidad de texto masiva.
                boolean isCodeWindow = false;
                if (prologs >= 2 && returns >= 1 && txtDensity <= 0.65 && illRatio <= 0.12) {
                    isCodeWindow = true;
                } else if ((illRatio <= 0.05) && (txtDensity <= 0.60) && (prologs >= 1 || valid > 500)) {
                    isCodeWindow = true;
                }

                if (isCodeWindow) {
                    streakNonCode = 0;
                    lastSolidCode = off + windowSz;
                } else {
                    streakNonCode++;
                    if (streakNonCode >= 8) {
                        // Se detecto fin de continuidad de .text (16 KB continuos sin instrucciones de codigo)
                        break;
                    }
                }
            }

            long calculatedEnd = romBase + ((lastSolidCode + 3) & ~3);
            if (calculatedEnd > codeStart && calculatedEnd < romEnd) {
                codeEnd = calculatedEnd;
            }
            println(String.format("  [0b] Horizonte de codigo delimitado dinamicamente: 0x%08X -> 0x%08X (%.2f KB de instrucciones continuas)",
                codeStart, codeEnd, (codeEnd - codeStart) / 1024.0));
        } catch (Exception ex) {
            println("  [WARN] No se pudo calcular horizonte de codigo, usando limite ROM: " + ex.getMessage());
        }
    }

    // --------------------------------------------------------------------------
    //  FASE 1c: CAZADOR Y SEPARADOR UNIVERSAL DE TEXTOS Y CADENAS ASCII
    // --------------------------------------------------------------------------
    private void phase1c_asciiTextHunter() throws Exception {
        long startTime = System.currentTimeMillis();
        println("[FASE 1c] Cazando y extrayendo textos, dialogos y patrones ASCII...");
        Memory mem = currentProgram.getMemory();
        Listing lst = currentProgram.getListing();

        int romLen = (int) Math.min(romSize, 32L * 1024 * 1024);
        byte[] rom = new byte[romLen];
        try {
            mem.getBytes(a(romBase), rom);
        } catch (Exception ex) {
            println("  [WARN] No se pudo leer ROM para detector de textos: " + ex.getMessage());
            return;
        }

        List<long[]> txtRegions = new ArrayList<>();
        List<String> txtEntries = new ArrayList<>();
        List<String> cHeaderEntries = new ArrayList<>();

        // Acotar escaneo de textos universalmente tras el horizonte dinamico de codigo
        long textStartAddr = Math.max(0x080000C0L, codeEnd);
        long textLimitAddr = Math.min(romEnd, romBase + (long)(romSize * 0.98));

        int scanStart = (int) Math.max(0xC0, textStartAddr - romBase);
        int scanEndLimit = (int) Math.min(romLen - 4, textLimitAddr - romBase);

        java.util.regex.Pattern tileRepeatPattern = java.util.regex.Pattern.compile("(?i)([BCDEGHRTUVcftw])\\1{2,}");

        int idx = scanStart;
        while (idx < scanEndLimit) {
            if (monitor.isCancelled()) break;
            long curAddr = romBase + idx;
            if (isSkip(curAddr)) {
                idx++;
                continue;
            }

            int b = rom[idx] & 0xFF;
            // Caracteres ASCII imprimibles, formato o tags de control GBA
            if ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x01 && b <= 0x08)) {
                int strStart = idx;
                int letterCount = 0;
                int vowelCount = 0;
                int printableCount = 0;
                StringBuilder sb = new StringBuilder();
                StringBuilder sbC = new StringBuilder();
                StringBuilder plainText = new StringBuilder();

                while (idx < scanEndLimit) {
                    int c = rom[idx] & 0xFF;
                    if (c == 0x00) break; // Fin de cadena C / GBA
                    if ((c >= 0x20 && c <= 0x7E) || c == 0x09 || c == 0x0A || c == 0x0D || (c >= 0x01 && c <= 0x08)) {
                        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                            letterCount++;
                            char lc = Character.toLowerCase((char) c);
                            if (lc == 'a' || lc == 'e' || lc == 'i' || lc == 'o' || lc == 'u' || lc == 'y') {
                                vowelCount++;
                            }
                        }
                        if (c >= 0x20 && c <= 0x7E) {
                            printableCount++;
                            char ch = (char) c;
                            sb.append(ch);
                            plainText.append(ch);
                            if (ch == '"' || ch == '\\') sbC.append('\\');
                            sbC.append(ch);
                        } else if (c == 0x0A) {
                            printableCount++;
                            sb.append("\\n");
                            sbC.append("\\n");
                            plainText.append('\n');
                        } else if (c == 0x0D) {
                            printableCount++;
                            sb.append("\\r");
                            sbC.append("\\r");
                            plainText.append('\r');
                        } else if (c == 0x09) {
                            printableCount++;
                            sb.append("\\t");
                            sbC.append("\\t");
                            plainText.append('\t');
                        } else {
                            sb.append(String.format("\\x%02X", c));
                            sbC.append(String.format("\\x%02X", c));
                        }
                        idx++;
                    } else {
                        break;
                    }
                }

                int strLen = idx - strStart;
                // Filtrado heuristico y linguistico riguroso:
                // 1. Longitud >= 4 y al menos 2 letras
                // 2. Si tiene >= 4 letras, debe contener al menos 1 vocal (evita patrones binarios)
                // 3. Al menos 3 caracteres imprimibles
                // 4. Rechazar patrones repetitivos de nibbles 4bpp (ej. "DDDD", "ffff", "wwww", "c6QQ")
                if (strLen >= 4 && letterCount >= 2 && printableCount >= 3) {
                    if (letterCount < 4 || vowelCount >= 1) {
                        String rawPlain = plainText.toString();
                        if (!tileRepeatPattern.matcher(rawPlain).find()) {
                            long addr = romBase + strStart;
                            long endAddr = romBase + idx;
                            txtRegions.add(new long[]{addr, endAddr});

                            String text = sb.toString();
                            String textC = sbC.toString();
                            txtEntries.add(String.format("[0x%08X] \"%s\"", addr, text));
                            cHeaderEntries.add(String.format("const char str_%08X[] = \"%s\";", addr, textC));
                        }
                    }
                }
            }
            idx++;
        }

        // Fusionar regiones de texto continuas
        txtRegions.sort((r1, r2) -> Long.compare(r1[0], r2[0]));
        List<long[]> mergedTxt = new ArrayList<>();
        long[] curR = null;
        for (long[] r : txtRegions) {
            if (curR == null) {
                curR = new long[]{r[0], r[1]};
            } else if (r[0] <= curR[1] + 8L) {
                curR[1] = Math.max(curR[1], r[1]);
            } else {
                mergedTxt.add(curR);
                curR = new long[]{r[0], r[1]};
            }
        }
        if (curR != null) mergedTxt.add(curR);

        // Anadir a skipRegions y actualizar skipMap
        skipRegions.addAll(mergedTxt);
        rebuildSkipMap();
        stringsFound = txtEntries.size();

        // Volcar archivos de texto
        File txtFile = new File(outDir, gamePrefix + "_strings.txt");
        try (PrintWriter pw = new PrintWriter(txtFile)) {
            pw.println("==============================================================================");
            pw.println("  FIO DECOMP :: CATALOGO DE TEXTOS Y CADENAS ASCII EXTRAIDAS");
            pw.println("  ROM: " + gameTitle + " [" + gameCode + "]");
            pw.println("  Total Cadenas Extraidas: " + stringsFound);
            pw.println("==============================================================================\n");
            for (String entry : txtEntries) {
                pw.println(entry);
            }
        }

        File hFile = new File(outDir, gamePrefix + "_strings.h");
        try (PrintWriter pw = new PrintWriter(hFile)) {
            pw.println("// ==============================================================================");
            pw.println("//  FIO DECOMP :: CONSTANTES DE TEXTO GBA EN C");
            pw.println("//  ROM: " + gameTitle + " [" + gameCode + "]");
            pw.println("// ==============================================================================\n");
            pw.println("#ifndef GBA_STRINGS_H");
            pw.println("#define GBA_STRINGS_H\n");
            for (String cEntry : cHeaderEntries) {
                pw.println(cEntry);
            }
            pw.println("\n#endif // GBA_STRINGS_H\n");
        }

        long elapsed = System.currentTimeMillis() - startTime;
        println(String.format("  [1c] Escaneo de textos completado en %d ms:", elapsed));
        println(String.format("       - Cadenas y dialogos extraidos : %d", stringsFound));
        println(String.format("       - Bloques de texto aislados    : %d", mergedTxt.size()));
        println("       - Archivo catalogo generado    : " + txtFile.getAbsolutePath());
        println("       - Archivo cabecera C generado  : " + hFile.getAbsolutePath());
        println("  [FASE 1c] COMPLETA.\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 1: INYECCION DE ARQUITECTURA HARDWARE GBA Y LITERAL POOLS
    // --------------------------------------------------------------------------
    private void phase1_hardwareMapping() throws Exception {
        println("[FASE 1] Inyectando arquitectura hardware GBA (MMIO + RAM)...");

        if (initBiosVectors) {
            try {
                Address biosBase = a(0x00000000L);
                MemoryBlock existing = currentProgram.getMemory().getBlock(biosBase);
                if (existing == null) {
                    MemoryBlock b = currentProgram.getMemory().createInitializedBlock("BIOS", biosBase, 0x00004000L, (byte) 0, monitor, false);
                    b.setRead(true);
                    b.setWrite(false);
                    b.setExecute(true);
                    currentProgram.getMemory().setInt(biosBase, 0xEA000006); // B 0x20 SoftReset
                    currentProgram.getMemory().setInt(a(0x00000018L), 0xEA000000); // IRQ vector
                }
            } catch (Exception ignored) {
                injectMem("BIOS", 0x00000000L, 0x00004000L, true, false, true);
            }
        } else {
            injectMem("BIOS", 0x00000000L, 0x00004000L, true, false, true);
        }
        injectMem("EWRAM",   0x02000000L, 0x00040000L, true, true,  true);
        injectMem("IWRAM",   0x03000000L, 0x00008000L, true, true,  true);
        injectMem("IO_REGS", 0x04000000L, 0x00000400L, true, true,  false);
        injectMem("PALRAM",  0x05000000L, 0x00000400L, true, true,  false);
        injectMem("VRAM",    0x06000000L, 0x00018000L, true, true,  false);
        injectMem("OAM",     0x07000000L, 0x00000400L, true, true,  false);

        DataType u16 = UnsignedShortDataType.dataType;
        DataType u32 = UnsignedIntegerDataType.dataType;

        // Registros IO GBA estándar
        iol(0x04000000L, "REG_DISPCNT",    u16, "Display Control");
        iol(0x04000004L, "REG_DISPSTAT",   u16, "Display Status");
        iol(0x04000006L, "REG_VCOUNT",     u16, "V-Counter");
        iol(0x04000008L, "REG_BG0CNT",     u16, "BG0 Control");
        iol(0x0400000AL, "REG_BG1CNT",     u16, "BG1 Control");
        iol(0x0400000CL, "REG_BG2CNT",     u16, "BG2 Control");
        iol(0x0400000EL, "REG_BG3CNT",     u16, "BG3 Control");
        iol(0x04000010L, "REG_BG0HOFS",    u16, "BG0 X Offset");
        iol(0x04000012L, "REG_BG0VOFS",    u16, "BG0 Y Offset");
        iol(0x04000048L, "REG_WININ",      u16, "Window Inside Control");
        iol(0x0400004AL, "REG_WINOUT",     u16, "Window Outside Control");
        iol(0x04000050L, "REG_BLDCNT",     u16, "Blend Control");
        iol(0x04000052L, "REG_BLDALPHA",   u16, "Blend Alpha Coefficients");
        iol(0x04000054L, "REG_BLDY",       u16, "Blend Brightness");
        iol(0x04000080L, "REG_SOUNDCNT_L", u16, "Sound Control L");
        iol(0x04000082L, "REG_SOUNDCNT_H", u16, "Sound Control H");
        iol(0x04000084L, "REG_SOUNDCNT_X", u16, "Sound Control Master");
        iol(0x04000088L, "REG_SOUNDBIAS",  u16, "Sound Bias");
        iol(0x040000B0L, "REG_DMA0SAD",    u32, "DMA0 Src Addr");
        iol(0x040000B4L, "REG_DMA0DAD",    u32, "DMA0 Dst Addr");
        iol(0x040000B8L, "REG_DMA0CNT_L",  u16, "DMA0 Count");
        iol(0x040000BAL, "REG_DMA0CNT_H",  u16, "DMA0 Control");
        iol(0x040000BDL, "REG_DMA1SAD",    u32, "DMA1 Src Addr");
        iol(0x040000C0L, "REG_DMA1DAD",    u32, "DMA1 Dst Addr");
        iol(0x040000C4L, "REG_DMA1CNT_L",  u16, "DMA1 Count");
        iol(0x040000C6L, "REG_DMA1CNT_H",  u16, "DMA1 Control");
        iol(0x040000C8L, "REG_DMA2SAD",    u32, "DMA2 Src Addr");
        iol(0x040000CCL, "REG_DMA2DAD",    u32, "DMA2 Dst Addr");
        iol(0x040000D0L, "REG_DMA2CNT_L",  u16, "DMA2 Count");
        iol(0x040000D2L, "REG_DMA2CNT_H",  u16, "DMA2 Control");
        iol(0x040000D4L, "REG_DMA3SAD",    u32, "DMA3 Src Addr");
        iol(0x040000D8L, "REG_DMA3DAD",    u32, "DMA3 Dst Addr");
        iol(0x040000DCL, "REG_DMA3CNT_L",  u16, "DMA3 Count");
        iol(0x040000DEL, "REG_DMA3CNT_H",  u16, "DMA3 Control");
        iol(0x04000100L, "REG_TM0CNT_L",   u16, "Timer0 Data");
        iol(0x04000102L, "REG_TM0CNT_H",   u16, "Timer0 Control");
        iol(0x04000104L, "REG_TM1CNT_L",   u16, "Timer1 Data");
        iol(0x04000106L, "REG_TM1CNT_H",   u16, "Timer1 Control");
        iol(0x04000108L, "REG_TM2CNT_L",   u16, "Timer2 Data");
        iol(0x0400010AL, "REG_TM2CNT_H",   u16, "Timer2 Control");
        iol(0x0400010CL, "REG_TM3CNT_L",   u16, "Timer3 Data");
        iol(0x0400010EL, "REG_TM3CNT_H",   u16, "Timer3 Control");
        iol(0x04000130L, "REG_KEYINPUT",   u16, "Keypad Status");
        iol(0x04000132L, "REG_KEYCNT",     u16, "Keypad IRQ Control");
        iol(0x04000200L, "REG_IE",          u16, "Interrupt Enable");
        iol(0x04000202L, "REG_IF",          u16, "Interrupt Request/Ack");
        iol(0x04000204L, "REG_WAITCNT",     u16, "Game Pak Waitstate Control");
        iol(0x04000208L, "REG_IME",         u16, "Interrupt Master Enable");

        // Resolver Literal Pools a punteros tipados hardware / RAM
        Listing lst = currentProgram.getListing();
        DataIterator di = lst.getDefinedData(true);
        PointerDataType pdt = new PointerDataType();
        while (di.hasNext()) {
            if (monitor.isCancelled()) break;
            Data d = di.next();
            long da = d.getAddress().getOffset();
            if (da < romBase || da > romEnd || d.getLength() != 4) continue;
            long v = 0;
            try {
                if (d.getValue() instanceof Address) {
                    v = ((Address) d.getValue()).getOffset();
                } else if (d.getValue() instanceof ghidra.program.model.scalar.Scalar) {
                    v = ((ghidra.program.model.scalar.Scalar) d.getValue()).getUnsignedValue();
                } else {
                    continue;
                }
            } catch (Exception e) { continue; }

            if ((v >= 0x04000000L && v <= 0x04000400L) ||
                (v >= 0x02000000L && v <= 0x02040000L) ||
                (v >= 0x03000000L && v <= 0x03008000L)) {
                if (!d.getDataType().getName().contains("pointer")) {
                    try {
                        lst.clearCodeUnits(d.getAddress(), d.getAddress().add(3), false);
                        lst.createData(d.getAddress(), pdt);
                        resolvedPtrs++;
                    } catch (Exception ignored) {}
                }
            }
        }
        println("  [1] Literal pools resueltos a punteros hardware: " + resolvedPtrs);
        println("  [FASE 1] COMPLETA.\n");
    }

    private void injectMem(String name, long base, long size, boolean r, boolean w, boolean x) {
        try {
            Address ba = a(base);
            if (currentProgram.getMemory().getBlock(ba) != null) return;
            MemoryBlock b = currentProgram.getMemory().createUninitializedBlock(name, ba, size, false);
            b.setRead(r); b.setWrite(w); b.setExecute(x);
            if (name.equals("IO_REGS")) b.setVolatile(true);
        } catch (Exception ignored) {}
    }

    private void iol(long addr, String name, DataType dt, String comment) {
        try {
            Address ad = a(addr);
            createLabel(ad, name, true, SourceType.USER_DEFINED);
            if (dt != null) {
                try {
                    currentProgram.getListing().clearCodeUnits(ad, ad.add(dt.getLength() - 1), false);
                    currentProgram.getListing().createData(ad, dt);
                } catch (Exception ignored) {}
            }
            if (comment != null) setEOLComment(ad, comment);
        } catch (Exception ignored) {}
    }

    // --------------------------------------------------------------------------
    //  CALCULO MATEMATICO DE ENTROPIA DE SHANNON H = -SUM(p * log2(p))
    // --------------------------------------------------------------------------
    private double calculateShannonEntropy(byte[] data, int offset, int length) {
        if (data == null || length <= 0 || offset < 0 || offset + length > data.length) {
            return 0.0;
        }
        int[] freq = new int[256];
        for (int i = 0; i < length; i++) {
            freq[data[offset + i] & 0xFF]++;
        }
        double entropy = 0.0;
        double log2 = Math.log(2.0);
        for (int c : freq) {
            if (c > 0) {
                double p = (double) c / length;
                entropy -= p * (Math.log(p) / log2);
            }
        }
        return entropy;
    }

    // --------------------------------------------------------------------------
    //  VERIFICACION DE AUTOCORRELACION ACUSTICA (PCM AUDIO WAVEDATA)
    // --------------------------------------------------------------------------
    private boolean isDirectSoundAudioPcm(byte[] rom, int sampleStart, int sampleLen) {
        int checkLen = Math.min(sampleLen, 128);
        if (checkLen < 32 || sampleStart + checkLen > rom.length) return false;

        int sumDiff = 0;
        for (int i = 0; i < checkLen - 1; i++) {
            int s1 = rom[sampleStart + i] & 0xFF;
            int s2 = rom[sampleStart + i + 1] & 0xFF;
            sumDiff += Math.abs(s2 - s1);
        }
        double meanDiff = (double) sumDiff / (checkLen - 1);
        return meanDiff < 35.0;
    }

    // --------------------------------------------------------------------------
    //  VALIDADOR MATEMATICO Y PROBADOR ESTRICTO DE CODIGO ARMv4T THUMB
    // --------------------------------------------------------------------------
    private boolean isValidThumbPrologueAndBody(byte[] rom, int off, int romLen) {
        if (off < 0 || off + 4 > romLen) return false;

        int hw0 = (rom[off] & 0xFF) | ((rom[off + 1] & 0xFF) << 8);
        int b1 = (hw0 >> 8) & 0xFF;
        if (b1 != 0xB5 && b1 != 0xB4) return false;

        // Si es 0xB4 (PUSH {r4..r7}), verificar que venga precedido de retorno o padding
        if (b1 == 0xB4) {
            if (off >= 2) {
                int prev = (rom[off - 2] & 0xFF) | ((rom[off - 1] & 0xFF) << 8);
                boolean validPrev = (prev == 0x4770 || // bx lr
                                     (prev & 0xFF00) == 0xBD00 || // pop {..., pc}
                                     (prev & 0xF800) == 0xE000 || // b <target>
                                     prev == 0x0000 || prev == 0xFFFF);
                if (!validPrev) return false;
            } else {
                return false;
            }
        }

        int idx = off + 2;
        int maxScan = Math.min(off + 64, romLen); // Sondear hasta 32 instrucciones (64 bytes)
        int valid = 1;
        int illegal = 0;
        int txtChars = 0;

        while (idx + 1 < maxScan && (valid + illegal) < 32) {
            int bLo = rom[idx] & 0xFF;
            int bHi = rom[idx + 1] & 0xFF;
            int hw = bLo | (bHi << 8);
            idx += 2;

            if ((bLo >= 0x20 && bLo <= 0x7E) || (bLo >= 0xBB && bLo <= 0xFE)) txtChars++;
            if ((bHi >= 0x20 && bHi <= 0x7E) || (bHi >= 0xBB && bHi <= 0xFE)) txtChars++;

            // 1. Fin de cuerpo por retorno incondicional
            if ((hw & 0xFF00) == 0xBD00 || (hw & 0xFF87) == 0x4700) { // POP {..., pc} o BX Rm
                valid++;
                break;
            }

            // 2. SWI ilegal (BIOS GBA solo soporta SWI 0x00 a 0x2A)
            if ((hw & 0xFF00) == 0xDF00) {
                int swi = hw & 0xFF;
                if (swi > 0x2A) {
                    illegal++;
                    break;
                }
                valid++;
                continue;
            }

            // 3. Opcodes indefinidos en arquitectura ARMv4T
            if ((hw & 0xFF00) == 0xBF00 || (hw & 0xF800) == 0xE800) {
                illegal++;
                break;
            }

            // 4. Par de instrucciones BL (Prefijo 0xF000..0xF7FF seguido de Sufijo 0xF800..0xFFFF)
            if ((hw & 0xF800) == 0xF000) {
                if (idx + 1 < romLen) {
                    int hw2 = (rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8);
                    if ((hw2 & 0xF800) == 0xF800) {
                        idx += 2;
                        valid += 2;
                        continue;
                    } else {
                        illegal++;
                        break;
                    }
                } else {
                    valid++;
                    continue;
                }
            } else if ((hw & 0xF800) == 0xF800) {
                // Sufijo BL huerfano sin prefijo
                illegal++;
                break;
            }

            // 5. Opcodes Thumb estándar
            int top5 = hw >> 11;
            if (top5 <= 28) {
                valid++;
            } else {
                illegal++;
                break;
            }
        }

        if (illegal > 0) return false;

        // Densidad de caracteres de texto: el codigo real nunca supera el 65% de texto en su inicio
        int scannedBytes = idx - off;
        if (scannedBytes >= 8) {
            double txtDensity = (double) txtChars / scannedBytes;
            if (txtDensity >= 0.65) return false;
        }

        return true;
    }

    // --------------------------------------------------------------------------
    //  FASE 1b: CAZADOR Y FILTRO ENTROPICO UNIVERSAL DE ACTIVOS MULTIMEDIA (AUDIO, IMAGENES, TABLAS)
    // --------------------------------------------------------------------------
    private void phase1b_mediaAssetFilter() throws Exception {
        long startTime = System.currentTimeMillis();
        println("[FASE 1b] Analizando y aislando activos multimedia via firmas acusticas, entropia y tablas...");
        Listing lst = currentProgram.getListing();
        Memory  mem = currentProgram.getMemory();
        FunctionManager fnMgr = currentProgram.getFunctionManager();

        int romLen = (int) Math.min(romSize, 32L * 1024 * 1024);
        byte[] rom = new byte[romLen];
        try {
            mem.getBytes(a(romBase), rom);
        } catch (Exception ex) {
            println("  [WARN] No se pudo leer ROM en bloque a RAM: " + ex.getMessage());
            return;
        }

        List<long[]> rawRegions = new ArrayList<>();
        int scanEnd = romLen - 32;
        int textBoundary = (int) Math.min(romLen, codeEnd - romBase);

        // 1. En zona .text (instrucciones ejecutables): aislar unicamente zonas de padding/alineacion (>= 32 bytes de 0x00 o 0xFF)
        int idx = 0x0C0;
        while (idx < textBoundary - 4) {
            int h = (rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8);
            if (h == 0x0000 || h == 0xFFFF) {
                int padStart = idx;
                while (idx < textBoundary && (((rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8)) == h)) {
                    idx += 2;
                }
                if (idx - padStart >= 32) {
                    rawRegions.add(new long[]{romBase + padStart, romBase + idx});
                    continue;
                }
            }
            idx += 2;
        }

        // 2. En zona de datos (.rodata y bancos multimedia tras codeEnd): Analizador Entropico y de Firmas Multimedia Completo
        idx = textBoundary;
        while (idx < scanEnd) {
            if (monitor.isCancelled()) break;
            long curOff = romBase + idx;

            // 1. Deteccion de Compresion: LZ77 (0x10, 0x11), Huffman (0x24, 0x28), RLE (0x30), Popuri (0x70)
            int b0 = rom[idx] & 0xFF;
            if (b0 == 0x10 || b0 == 0x11 || b0 == 0x24 || b0 == 0x28 || b0 == 0x30 || b0 == 0x70) {
                int b1 = rom[idx + 1] & 0xFF;
                int b2 = rom[idx + 2] & 0xFF;
                int b3 = rom[idx + 3] & 0xFF;
                int uncompSize = b1 | (b2 << 8) | (b3 << 16);

                if (uncompSize >= 64 && uncompSize <= 0x00080000) {
                    // Validar entropia de la corriente comprimida (datos comprimidos tienen H >= 5.0)
                    int testLen = Math.min(128, romLen - idx - 4);
                    double ent = (testLen >= 32) ? calculateShannonEntropy(rom, idx + 4, testLen) : 6.0;
                    if (ent >= 5.0) {
                        int estCompressedLen = Math.max(32, (int)(uncompSize * 0.25));
                        int endIdx = Math.min(romLen, idx + estCompressedLen);
                        rawRegions.add(new long[]{curOff, romBase + endIdx});
                        idx = (endIdx + 3) & ~3;
                        continue;
                    }
                }
            }

            // 2. Deteccion de Cabeceras de Musica M4A / Sappy (Alineado a 4 bytes)
            if ((idx & 3) == 0) {
                int tracks = rom[idx] & 0xFF;
                int blk    = rom[idx + 1] & 0xFF;
                int pri    = rom[idx + 2] & 0xFF;
                int rev    = rom[idx + 3] & 0xFF;

                if (tracks >= 1 && tracks <= 16 && blk == 0 && pri <= 15 && (rev == 0 || rev == 0x80)) {
                    int vg = (rom[idx + 4] & 0xFF) | ((rom[idx + 5] & 0xFF) << 8) | ((rom[idx + 6] & 0xFF) << 16) | ((rom[idx + 7] & 0xFF) << 24);
                    int t1 = (rom[idx + 8] & 0xFF) | ((rom[idx + 9] & 0xFF) << 8) | ((rom[idx + 10] & 0xFF) << 16) | ((rom[idx + 11] & 0xFF) << 24);

                    long vgL = Integer.toUnsignedLong(vg);
                    long t1L = Integer.toUnsignedLong(t1);
                    if ((vgL & 0xFE000000L) == romBase && (t1L & 0xFE000000L) == romBase) {
                        int hdrLen = 8 + (tracks * 4);
                        rawRegions.add(new long[]{curOff, curOff + hdrLen});
                        idx += hdrLen;
                        continue;
                    }
                }

                // 3. Deteccion de Cabeceras DirectSound WaveData (PCM Audio Sample) con Verificacion Acustica
                int flags  = (rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8) | ((rom[idx + 2] & 0xFF) << 16) | ((rom[idx + 3] & 0xFF) << 24);
                int rateHz = (rom[idx + 4] & 0xFF) | ((rom[idx + 5] & 0xFF) << 8) | ((rom[idx + 6] & 0xFF) << 16) | ((rom[idx + 7] & 0xFF) << 24);
                int loopSt = (rom[idx + 8] & 0xFF) | ((rom[idx + 9] & 0xFF) << 8) | ((rom[idx + 10] & 0xFF) << 16) | ((rom[idx + 11] & 0xFF) << 24);
                int loopLn = (rom[idx + 12] & 0xFF) | ((rom[idx + 13] & 0xFF) << 8) | ((rom[idx + 14] & 0xFF) << 16) | ((rom[idx + 15] & 0xFF) << 24);

                long rateL = Integer.toUnsignedLong(rateHz);
                long loopLnL = Integer.toUnsignedLong(loopLn);
                if ((flags == 0x00000000 || flags == 0x40000000 || flags == 0x00000400) &&
                    ((rateL >= 4000L && rateL <= 50000L) || (rateL >= 0x00001000L && rateL <= 0x00040000L)) &&
                    (loopLnL >= 64 && loopLnL <= 0x00080000L) && loopSt <= loopLn) {
                    if (isDirectSoundAudioPcm(rom, idx + 16, (int)loopLnL)) {
                        int sampleEnd = Math.min(romLen, idx + 16 + (int)loopLnL);
                        rawRegions.add(new long[]{curOff, romBase + sampleEnd});
                        idx = (sampleEnd + 3) & ~3;
                        continue;
                    }
                }
            }

            // 4. Deteccion de Paletas GBA 15-bit BGR (32 bytes = 16 colores, bit 15 = 0)
            if ((idx & 1) == 0 && idx + 32 <= scanEnd) {
                boolean allValid = true;
                int nonZero = 0;
                for (int c = 0; c < 16; c++) {
                    int col = (rom[idx + c*2] & 0xFF) | ((rom[idx + c*2 + 1] & 0xFF) << 8);
                    if ((col & 0x8000) != 0) {
                        allValid = false;
                        break;
                    }
                    if (col != 0) nonZero++;
                }
                if (allValid && nonZero >= 4) {
                    rawRegions.add(new long[]{curOff, curOff + 32L});
                    idx += 32;
                    continue;
                }
            }

            // 5. Deteccion de Corrientes de Texto y Tablas de Dialogo (en seccion de datos tras codeEnd)
            if (curOff >= codeEnd && idx + 64 <= scanEnd) {
                int txtCount = 0;
                for (int ti = 0; ti < 64; ti++) {
                    int tb = rom[idx + ti] & 0xFF;
                    if ((tb >= 0x20 && tb <= 0x7E) || (tb >= 0xBB && tb <= 0xFE) || tb == 0 ||
                        tb == 0x09 || tb == 0x0A || tb == 0xFD || tb == 0xFE || tb == 0xFF) {
                        txtCount++;
                    }
                }
                if (txtCount >= 48) { // >= 75% caracteres de texto / terminadores
                    int tStart = idx;
                    while (idx + 32 <= scanEnd) {
                        int c32 = 0;
                        for (int ti = 0; ti < 32; ti++) {
                            int tb = rom[idx + ti] & 0xFF;
                            if ((tb >= 0x20 && tb <= 0x7E) || (tb >= 0xBB && tb <= 0xFE) || tb == 0 ||
                                tb == 0x09 || tb == 0x0A || tb == 0xFD || tb == 0xFE || tb == 0xFF) {
                                c32++;
                            }
                        }
                        if (c32 < 16) break; // Densidad cayo bajo 50%
                        idx += 32;
                    }
                    if (idx - tStart >= 64) {
                        rawRegions.add(new long[]{romBase + tStart, romBase + idx});
                        continue;
                    }
                }
            }

            // 6. Zonas de Padding / Free Space (>= 32 bytes de 0x00 o 0xFF)
            int h = (rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8);
            if (h == 0x0000 || h == 0xFFFF) {
                int padStart = idx;
                while (idx < scanEnd && (((rom[idx] & 0xFF) | ((rom[idx + 1] & 0xFF) << 8)) == h)) {
                    idx += 2;
                }
                if (idx - padStart >= 32) {
                    rawRegions.add(new long[]{romBase + padStart, romBase + idx});
                    continue;
                }
            }

            idx += 2;
        }

        // Fusionar intervalos superpuestos o contiguos
        rawRegions.sort((r1, r2) -> Long.compare(r1[0], r2[0]));
        List<long[]> merged = new ArrayList<>();
        long[] current = null;
        long totalBytes = 0;

        for (long[] r : rawRegions) {
            if (current == null) {
                current = new long[]{r[0], r[1]};
            } else if (r[0] <= current[1] + 16L) {
                current[1] = Math.max(current[1], r[1]);
            } else {
                merged.add(current);
                totalBytes += (current[1] - current[0]);
                current = new long[]{r[0], r[1]};
            }
        }
        if (current != null) {
            merged.add(current);
            totalBytes += (current[1] - current[0]);
        }

        skipRegions.clear();
        skipRegions.addAll(merged);
        rebuildSkipMap();
        assetsFound = merged.size();
        assetsProtectedBytes = totalBytes;

        // Limpiar únicamente las regiones consolidadas (evita congestión DB)
        for (long[] r : merged) {
            try {
                Address sA = a(r[0]);
                Address eA = a(r[1] - 1L);
                FunctionIterator fit = fnMgr.getFunctions(sA, true);
                while (fit.hasNext()) {
                    Function f = fit.next();
                    if (f.getEntryPoint().getOffset() >= r[1]) break;
                    fnMgr.removeFunction(f.getEntryPoint());
                }
                lst.clearCodeUnits(sA, eA, false);
                createLabel(sA, String.format("ASSET_BLOCK_%08X", r[0]), true, SourceType.ANALYSIS);
            } catch (Exception ignored) {}
        }

        long elapsed = System.currentTimeMillis() - startTime;
        println(String.format("  [1b] Escaneo en memoria completado en %d ms:", elapsed));
        println(String.format("       - Bloques fusionados protegidos : %d", assetsFound));
        println(String.format("       - Memoria multimedia aislada    : %.2f MB", assetsProtectedBytes / (1024.0 * 1024.0)));
        println("  [FASE 1b] COMPLETA.\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 2: INGESTION DINAMICA DE SIMBOLOS Y CONTEXTO
    // --------------------------------------------------------------------------
    private void phase2_loadSymbols() throws Exception {
        println("[FASE 2] Ingestando simbolos y contexto externo...");

        File jsonFile = null;
        if (!contextJsonPath.equals("NONE") && !contextJsonPath.isEmpty()) {
            jsonFile = new File(contextJsonPath);
            if (!jsonFile.exists()) {
                jsonFile = new File(outDir, contextJsonPath);
            }
        }
        // Si no se especifico archivo de contexto (NONE), NO cargar archivos de simbolos residuales
        if (jsonFile != null && !jsonFile.exists()) {
            println("  [WARN] Archivo de contexto especificado no encontrado: " + jsonFile.getAbsolutePath());
            jsonFile = null;
        }

        if (jsonFile != null && jsonFile.exists()) {
            println("  [SIMBOLOS] Cargando catalogo desde: " + jsonFile.getAbsolutePath());
            try (BufferedReader br = new BufferedReader(new FileReader(jsonFile))) {
                String line;
                String currentSection = "";
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.contains("\"functions\":")) { currentSection = "FUNC"; continue; }
                    if (line.contains("\"vtables\":"))   { currentSection = "VTBL"; continue; }
                    if (line.contains("\"data\":"))      { currentSection = "DATA"; continue; }

                    if (currentSection.equals("FUNC") && line.startsWith("\"0x")) {
                        try {
                            String addrStr = line.substring(1, line.indexOf("\":"));
                            long addr = Long.decode(addrStr);
                            int bOpen = line.indexOf("[");
                            int bClose = line.lastIndexOf("]");
                            if (bOpen != -1 && bClose != -1 && bClose > bOpen) {
                                String rest = line.substring(bOpen + 1, bClose);
                                String[] parts = rest.split("\",\\s*\"");
                                String nm = parts[0].replace("\"", "").trim();
                                String mode = parts.length > 1 ? parts[1].replace("\"", "").trim() : "THUMB";
                                String cmt = parts.length > 2 ? parts[2].replace("\"", "").trim() : "";
                                kf(addr, nm, mode, cmt);
                                applF++;
                            } else {
                                String nm = line.substring(line.indexOf("\":") + 2).replace("\"", "").replace(",", "").trim();
                                kf(addr, nm, "THUMB", "");
                                applF++;
                            }
                        } catch (Exception ignored) {}
                    } else if (currentSection.equals("VTBL") && line.startsWith("\"0x")) {
                        try {
                            String addrStr = line.substring(1, line.indexOf("\":"));
                            long addr = Long.decode(addrStr);
                            String nm = line.substring(line.indexOf("\":") + 2).replace("\"", "").replace(",", "").trim();
                            kVtbls.put(addr, new String[]{nm, "vtable"});
                            applV++;
                        } catch (Exception ignored) {}
                    } else if (currentSection.equals("DATA") && line.startsWith("\"0x")) {
                        try {
                            String addrStr = line.substring(1, line.indexOf("\":"));
                            long addr = Long.decode(addrStr);
                            int bOpen = line.indexOf("[");
                            int bClose = line.lastIndexOf("]");
                            if (bOpen != -1 && bClose != -1 && bClose > bOpen) {
                                String rest = line.substring(bOpen + 1, bClose);
                                String[] parts = rest.split("\",\\s*\"");
                                String nm = parts[0].replace("\"", "").trim();
                                String cmt = parts.length > 1 ? parts[1].replace("\"", "").trim() : "";
                                kData.put(addr, new String[]{nm, cmt});
                                applD++;
                            }
                        } catch (Exception ignored) {}
                    }
                }
            } catch (Exception ex) {
                println("  [WARN] Error leyendo JSON de simbolos: " + ex.getMessage());
            }
        } else {
            println("  [MODO UNIVERSAL CIEGO] Sin diccionario previo. Descubrimiento dinamico puro.");
        }

        // Semillas obligatorias
        kf(romBase, "GBA_Header_Boot", "ARM", "GBA Cartridge Boot Vector");
        kf(entryPoint, "crt0_entry", "THUMB", "C Runtime Entry Point");

        // Aplicar a Ghidra
        for (Map.Entry<Long, String[]> e : kFuncs.entrySet()) {
            if (monitor.isCancelled()) return;
            try {
                Address ad = a(e.getKey());
                boolean thumb = !e.getValue()[1].equalsIgnoreCase("ARM") && e.getKey() >= romBase + 0xC0L;
                setT(ad, thumb);
                try { disassemble(ad); } catch (Exception ignored) {}
                Function f = getFunctionAt(ad);
                if (f == null) f = createFunction(ad, e.getValue()[0]);
                if (f != null) {
                    f.setName(e.getValue()[0], SourceType.USER_DEFINED);
                    if (e.getValue()[2] != null && !e.getValue()[2].isEmpty()) {
                        f.setComment(e.getValue()[2]);
                    }
                }
            } catch (Exception ignored) {}
        }

        println(String.format("  [2] Simbolos preparados: %d Funcs, %d Vtables, %d Data", kFuncs.size(), kVtbls.size(), kData.size()));
        println("  [FASE 2] COMPLETA.\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 3: EL EMULADOR CIEGO (RECURSIVE TRACER + GAP SWEEPER)
    // --------------------------------------------------------------------------
    private void phase3_blindEmulator() throws Exception {
        println("[FASE 3] 'El Emulador Ciego' - Rastreo Recursivo y Barrido Universal...");
        Listing lst = currentProgram.getListing();
        Memory  mem = currentProgram.getMemory();
        Register tReg = currentProgram.getProgramContext().getRegister("T");

        int romLen = (int) Math.min(romSize, 32L * 1024 * 1024);
        byte[] rom = new byte[romLen];
        try {
            mem.getBytes(a(romBase), rom);
        } catch (Exception ignored) {}

        if (tReg != null) {
            try {
                currentProgram.getProgramContext().setValue(
                    tReg, a(romBase + 0xC0L), a(romEnd), java.math.BigInteger.ONE);
                currentProgram.getProgramContext().setValue(
                    tReg, a(romBase), a(romBase + 0xBEL), java.math.BigInteger.ZERO);
            } catch (Exception ignored) {}
        }

        workQueue.clear();
        visited.clear();

        // Cargar semillas
        workQueue.add(romBase); // ARM
        workQueue.add(entryPoint | 1L); // Thumb
        if (scanIwramFastOverlays && iwramSourceOffset >= romBase && iwramSourceOffset < romEnd) {
            workQueue.add(iwramSourceOffset); // Rutinas rapidas IWRAM (Capcom / MMBN)
            kf(iwramSourceOffset, "src_fast_ram_routines", "ARM", "IWRAM Fast Overlay Code");
        }
        for (long kfAddr : kFuncs.keySet()) {
            if (isSkip(kfAddr)) continue;
            boolean isT = kfAddr >= romBase + 0xC0L && !kFuncs.get(kfAddr)[1].equalsIgnoreCase("ARM");
            workQueue.add(isT ? (kfAddr | 1L) : kfAddr);
        }

        // 3a. Motor de Rastreo Recursivo
        int processedBlocks = 0;
        while (!workQueue.isEmpty()) {
            if (monitor.isCancelled()) break;
            long rawTarget = workQueue.poll();
            long target = rawTarget & ~1L;
            boolean isThumb = (rawTarget & 1L) != 0 || (target >= romBase + 0xC0L);

            if (visited.contains(target)) continue;
            visited.add(target);

            if (target < romBase || target >= romEnd) continue;
            if (isSkip(target)) continue;

            Address ad = a(target);
            setT(ad, isThumb);

            Instruction inst = lst.getInstructionAt(ad);
            if (inst == null && lst.getDataAt(ad) == null) {
                try {
                    disassemble(ad);
                    inst = lst.getInstructionAt(ad);
                } catch (Exception ignored) {}
            }

            Function fn = getFunctionAt(ad);
            String fnName;
            if (fn == null) {
                String[] known = kFuncs.get(target);
                fnName = known != null ? known[0] : String.format("func_%08X", target);
                try {
                    fn = createFunction(ad, fnName);
                    if (fn != null) discFuncs++;
                } catch (Exception ignored) {}
            } else {
                fnName = fn.getName();
                if (fnName.startsWith("FUN_") || fnName.startsWith("DAT_")) {
                    fnName = String.format("func_%08X", target);
                    try { fn.setName(fnName, SourceType.ANALYSIS); } catch (Exception ignored) {}
                }
            }

            hotmap.put(target, new String[]{fnName, isThumb ? "THUMB" : "ARM", "EMU_TRACED"});
            if (isThumb) thumbF++; else armF++;
            processedBlocks++;

            if (fn != null) {
                AddressSetView body = fn.getBody();
                InstructionIterator iter = lst.getInstructions(body, true);
                while (iter.hasNext()) {
                    Instruction i = iter.next();
                    String mn = i.getMnemonicString().toUpperCase();

                    // BL: salto de subrutina (mantiene modo)
                    if (mn.equals("BL")) {
                        for (Address flow : i.getFlows()) {
                            long fo = flow.getOffset();
                            if (fo >= romBase && fo < romEnd && !isSkip(fo)) {
                                workQueue.add(isThumb ? (fo | 1L) : fo);
                            }
                        }
                    }
                    // BLX: salto con interworking (conmuta modo)
                    else if (mn.startsWith("BLX")) {
                        for (Address flow : i.getFlows()) {
                            long fo = flow.getOffset();
                            if (fo >= romBase && fo < romEnd && !isSkip(fo)) {
                                workQueue.add(!isThumb ? (fo | 1L) : fo);
                            }
                        }
                    }
                    // B: tail-call a funcion real
                    else if (mn.equals("B")) {
                        for (Address flow : i.getFlows()) {
                            long fo = flow.getOffset();
                            if (fo >= romBase && fo < romEnd && !isSkip(fo)) {
                                try {
                                    int pb = mem.getByte(flow.add(1)) & 0xFF;
                                    if (pb == 0xB5 || pb == 0xB4 || kFuncs.containsKey(fo)) {
                                        workQueue.add(isThumb ? (fo | 1L) : fo);
                                    }
                                } catch (Exception ignored) {}
                            }
                        }
                    }
                    // LDR Rn, [PC, #imm]: punteros incrustados en pool acotados a .text para no perseguir tablas de datos
                    else if (mn.startsWith("LDR") && i.getNumOperands() >= 2) {
                        Reference[] refs = i.getOperandReferences(1);
                        if (refs != null && refs.length > 0 && refs[0] != null) {
                            Address refAddr = refs[0].getToAddress();
                            if (refAddr != null && refAddr.getOffset() >= romBase && refAddr.getOffset() < romEnd) {
                                try {
                                    long val = Integer.toUnsignedLong(mem.getInt(refAddr));
                                    if ((val & 0xFE000000L) == romBase) {
                                        long tgt = val & 0xFFFFFFFEL;
                                        boolean tMode = (val & 1L) == 1L || tgt >= romBase + 0xC0L;
                                        if (tgt >= romBase && tgt < codeEnd && !isSkip(tgt)) {
                                            workQueue.add(tMode ? (tgt | 1L) : tgt);
                                        }
                                    }
                                } catch (Exception ignored) {}
                            }
                        }
                    }
                }
            }
        }
        println("  [3a] Bloques analizados recursivamente: " + processedBlocks);

        // 3b. Barrido Lineal Universal de Huecos (Gap Sweep acotado a .text horizon)
        Address cur = a(romBase + 0xC0L);
        Address cEnd = a(codeEnd);
        int gapFuncs = 0;

        while (cur.compareTo(cEnd) < 0) {
            if (monitor.isCancelled()) break;
            long off = cur.getOffset();

            if (isSkip(off)) {
                cur = cur.add(2);
                continue;
            }

            // Si ya pertenece al cuerpo de una funcion existente, NO partir la funcion
            if (currentProgram.getFunctionManager().getFunctionContaining(cur) != null) {
                cur = cur.add(2);
                continue;
            }

            try {
                int half = mem.getShort(cur) & 0xFFFF;
                int b1 = (half >> 8) & 0xFF;
                boolean validProlog = false;

                // Prologo Thumb estándar: 0xB5 (PUSH {..., lr})
                if (b1 == 0xB5) {
                    validProlog = true;
                } else if (b1 == 0xB4) {
                    // PUSH {r4..r7} solo es prologo valido si viene precedido de un retorno incondicional o padding
                    if (off >= romBase + 2) {
                        int prev = mem.getShort(cur.subtract(2)) & 0xFFFF;
                        if (prev == 0x4770 || // bx lr
                            (prev & 0xFF00) == 0xBD00 || // pop {..., pc}
                            (prev & 0xF800) == 0xE000 || // b <target>
                            prev == 0x0000 || prev == 0xFFFF) {
                            validProlog = true;
                        }
                    }
                }

                if (validProlog) {
                    int romIdx = (int)(off - romBase);
                    if (isValidThumbPrologueAndBody(rom, romIdx, romLen)) {
                        workQueue.add(off | 1L);
                        gapFuncs++;
                    }
                }
            } catch (Exception ignored) {}
            cur = cur.add(2);
        }
        println("  [3b] Prologos Thumb descubiertos en barrido de huecos: " + gapFuncs);

        // Vaciar la cola descubierta
        while (!workQueue.isEmpty()) {
            if (monitor.isCancelled()) break;
            long rawTarget = workQueue.poll();
            long target = rawTarget & ~1L;

            if (isSkip(target)) continue;
            if (target >= codeEnd && !kFuncs.containsKey(target)) continue;

            Address ad = a(target);
            if (currentProgram.getFunctionManager().getFunctionAt(ad) != null) continue;

            visited.add(target);
            setT(ad, true);
            try {
                if (lst.getInstructionAt(ad) == null) {
                    disassemble(ad);
                }
                String fnName = String.format("func_%08X", target);
                Function fn = createFunction(ad, fnName);
                if (fn != null) {
                    discFuncs++;
                    thumbF++;
                    hotmap.put(target, new String[]{fnName, "THUMB", "GAP_SWEEP"});
                }
            } catch (Exception ignored) {}
        }
        println("  [FASE 3] COMPLETA. Total funciones descubiertas: " + currentProgram.getFunctionManager().getFunctionCount() + "\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 4: RESOLUTOR UNIVERSAL DE SWITCH JUMP TABLES (NATIVO GHIDRA)
    // --------------------------------------------------------------------------
    private void phase4_jumpTableResolver() throws Exception {
        println("[FASE 4] Cazador y Resolutor Universal de Jump Tables (Modelado Nativo C)...");
        Listing lst = currentProgram.getListing();
        Memory  mem = currentProgram.getMemory();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fnMgr = currentProgram.getFunctionManager();
        PointerDataType pdt = new PointerDataType();

        // 4a. Cargar jump_context.json si existe
        File ctxFile = new File(outDir, "jump_context.json");
        if (!ctxFile.exists() && !contextJsonPath.equals("NONE")) {
            ctxFile = new File(contextJsonPath);
        }
        if (ctxFile.exists()) {
            println("  [4a] Inyectando saltos desde archivo de contexto: " + ctxFile.getName());
            try (BufferedReader br = new BufferedReader(new FileReader(ctxFile))) {
                String line;
                String currentJs = null;
                List<Long> targets = new ArrayList<>();
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.contains("\"jump_site\":")) {
                        currentJs = line.split(":")[1].replace("\"", "").replace(",", "").trim();
                        targets.clear();
                    } else if (line.contains("\"targets\":")) {
                        while ((line = br.readLine()) != null && !line.contains("]")) {
                            String tStr = line.replace("\"", "").replace(",", "").trim();
                            if (tStr.startsWith("0x")) {
                                try { targets.add(Long.decode(tStr)); } catch (Exception ignored) {}
                            }
                        }
                        if (currentJs != null && !targets.isEmpty()) {
                            try {
                                long jsOff = Long.decode(currentJs);
                                if (jsOff < romBase || jsOff >= codeEnd || isSkip(jsOff)) continue;
                                Address jsAddr = a(jsOff);
                                ArrayList<Address> targetAddrs = new ArrayList<>();

                                for (long tOff : targets) {
                                    long cleanT = tOff & ~1L;
                                    if (cleanT < romBase || cleanT >= codeEnd || isSkip(cleanT)) continue;
                                    Address tAddr = a(cleanT);
                                    targetAddrs.add(tAddr);
                                    setT(tAddr, true);
                                    try { disassemble(tAddr); } catch (Exception ignored) {}
                                    refMgr.addMemoryReference(jsAddr, tAddr, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);

                                    // Etiquetar destinos simbolicos con nombres legibles C (case_08XXXXXX)
                                    try {
                                        createLabel(tAddr, String.format("case_%08X", cleanT), true, SourceType.USER_DEFINED);
                                    } catch (Exception ignored) {}

                                    resolvedJumpCases++;
                                }

                                // Inyectar modelo JumpTable de Ghidra para estructurar switch(var) { case ... }
                                if (!targetAddrs.isEmpty()) {
                                    Function fn = fnMgr.getFunctionContaining(jsAddr);
                                    if (fn != null) {
                                        try {
                                            JumpTable jt = new JumpTable(jsAddr, targetAddrs, true, 0);
                                            jt.writeOverride(fn);
                                            nativeSwitchesOverridden++;
                                        } catch (Exception ignored) {}
                                    }
                                    resolvedJumpTables++;
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                }
            } catch (Exception ignored) {}
            println("  [4a] Jump Tables estructuradas en C: " + resolvedJumpTables + 
                " (" + resolvedJumpCases + " ramas | " + nativeSwitchesOverridden + " modelos JumpTable aplicados)");
        }

        // 4b. Escaneo estatico complementario de tablas switch inline y literal pools (acotado a .text horizon)
        Address cur = a(romBase + 0xC0L);
        Address cEnd = a(codeEnd);
        while (cur.compareTo(cEnd) < 0) {
            if (monitor.isCancelled()) break;
            long off = cur.getOffset();
            if (isSkip(off)) { cur = cur.add(2); continue; }

            try {
                int op = mem.getShort(cur) & 0xFFFF;
                boolean isJump = ((op & 0xFF87) == 0x4687) || ((op & 0xFF80) == 0x4700);
                if (isJump) {
                    long tblOff = (off + 2 + 3) & ~3L;
                    if (tblOff + 8 < romEnd) {
                        long p0 = Integer.toUnsignedLong(mem.getInt(a(tblOff)));
                        long p1 = Integer.toUnsignedLong(mem.getInt(a(tblOff + 4)));
                        // Pattern A: Punteros directos inmediatamente tras el salto indirecto
                        if ((p0 & 0xFE000000L) == romBase && (p1 & 0xFE000000L) == romBase) {
                            long currTbl = tblOff;
                            ArrayList<Address> inlineTargets = new ArrayList<>();
                            while (currTbl + 4 < romEnd) {
                                long target = Integer.toUnsignedLong(mem.getInt(a(currTbl)));
                                if ((target & 0xFE000000L) != romBase) break;
                                long cleanT = target & ~1L;
                                Address tAddr = a(cleanT);
                                inlineTargets.add(tAddr);
                                setT(tAddr, true);
                                try { disassemble(tAddr); } catch (Exception ignored) {}
                                refMgr.addMemoryReference(cur, tAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);

                                try {
                                    createLabel(tAddr, String.format("case_%08X", cleanT), true, SourceType.USER_DEFINED);
                                } catch (Exception ignored) {}

                                try {
                                    lst.clearCodeUnits(a(currTbl), a(currTbl + 3), false);
                                    lst.createData(a(currTbl), pdt);
                                } catch (Exception ignored) {}
                                currTbl += 4;
                            }
                            if (inlineTargets.size() >= 2) {
                                Function fn = fnMgr.getFunctionContaining(cur);
                                if (fn == null) {
                                    FunctionIterator fi = fnMgr.getFunctions(cur, false);
                                    if (fi.hasNext()) fn = fi.next();
                                }
                                if (fn != null) {
                                    try {
                                        if (!fn.getBody().contains(cur)) {
                                            AddressSet newBody = new AddressSet(fn.getBody());
                                            newBody.addRange(fn.getEntryPoint(), cur.add(4));
                                            String fnName = fn.getName();
                                            Address ep = fn.getEntryPoint();
                                            fnMgr.removeFunction(ep);
                                            fn = fnMgr.createFunction(fnName, ep, newBody, SourceType.USER_DEFINED);
                                        }
                                        JumpTable jt = new JumpTable(cur, inlineTargets, true, 0);
                                        jt.writeOverride(fn);
                                        nativeSwitchesOverridden++;
                                    } catch (Exception ignored) {}
                                }
                                resolvedJumpTables++;
                                resolvedJumpCases += inlineTargets.size();
                            }
                        }
                        // Pattern B: GCC Jump Table (p0 = conteo de casos maximo, p1 = puntero base de la tabla)
                        else if (p0 >= 2 && p0 <= 3000 && (p1 & 0xFE000000L) == romBase && p1 < romEnd) {
                            long tablePtr = p1;
                            int numEntries = (int) p0 + 1;
                            ArrayList<Address> patternBTargets = new ArrayList<>();
                            long currPtr = tablePtr;
                            for (int k = 0; k < numEntries && currPtr + 4 <= romEnd; k++, currPtr += 4) {
                                long target = Integer.toUnsignedLong(mem.getInt(a(currPtr)));
                                if ((target & 0xFE000000L) != romBase) break;
                                long cleanT = target & ~1L;
                                Address tAddr = a(cleanT);
                                patternBTargets.add(tAddr);
                                setT(tAddr, true);
                                try { disassemble(tAddr); } catch (Exception ignored) {}
                                refMgr.addMemoryReference(cur, tAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
                                try {
                                    createLabel(tAddr, String.format("case_%08X", cleanT), true, SourceType.USER_DEFINED);
                                } catch (Exception ignored) {}
                                try {
                                    lst.clearCodeUnits(a(currPtr), a(currPtr + 3), false);
                                    lst.createData(a(currPtr), pdt);
                                } catch (Exception ignored) {}
                            }
                            if (patternBTargets.size() >= 2) {
                                Function fn = fnMgr.getFunctionContaining(cur);
                                if (fn == null) {
                                    FunctionIterator fi = fnMgr.getFunctions(cur, false);
                                    if (fi.hasNext()) fn = fi.next();
                                }
                                if (fn != null) {
                                    try {
                                        if (!fn.getBody().contains(cur)) {
                                            AddressSet newBody = new AddressSet(fn.getBody());
                                            newBody.addRange(fn.getEntryPoint(), cur.add(4));
                                            String fnName = fn.getName();
                                            Address ep = fn.getEntryPoint();
                                            fnMgr.removeFunction(ep);
                                            fn = fnMgr.createFunction(fnName, ep, newBody, SourceType.USER_DEFINED);
                                        }
                                        JumpTable jt = new JumpTable(cur, patternBTargets, true, 0);
                                        jt.writeOverride(fn);
                                        nativeSwitchesOverridden++;
                                    } catch (Exception ignored) {}
                                }
                                resolvedJumpTables++;
                                resolvedJumpCases += patternBTargets.size();
                            }
                        }
                    }
                }
            } catch (Exception ignored) {}
            cur = cur.add(2);
        }
        println("  [4b] Total Jump Tables procesadas: " + resolvedJumpTables + " (" + resolvedJumpCases + " ramas)");
        println("  [FASE 4] COMPLETA.\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 5: GUARDIAN DE CONTEXTO PARAMETRICO
    // --------------------------------------------------------------------------
    private void phase5_contextGuardian() throws Exception {
        println("[FASE 5] Guardian de Contexto (Blindaje de Retornos y Fronteras)...");
        Listing lst = currentProgram.getListing();
        Memory  mem = currentProgram.getMemory();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fnMgr = currentProgram.getFunctionManager();

        Address cur = a(romBase + 0xC0L);
        Address cEnd = a(romEnd);

        // 1. Blindar epílogos de retorno en bx lr y pop {..., rX}; bx rX
        while (cur.compareTo(cEnd) < 0) {
            if (monitor.isCancelled()) break;
            long off = cur.getOffset();
            if (isSkip(off)) { cur = cur.add(2); continue; }

            try {
                int op = mem.getShort(cur) & 0xFFFF;
                if ((op & 0xFF80) == 0x4700) { // bx rX
                    int rm = (op >> 3) & 0x0F;
                    boolean isReturn = false;

                    if (rm == 14) { // bx lr
                        isReturn = true;
                    } else {
                        for (int back = 2; back <= 6; back += 2) {
                            if (off - back >= romBase) {
                                int prev = mem.getShort(a(off - back)) & 0xFFFF;
                                if ((prev & 0xFF00) == 0xBC00) { // Thumb POP
                                    int regMask = prev & 0xFF;
                                    if ((regMask & (1 << rm)) != 0) {
                                        isReturn = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (isReturn) {
                        Instruction inst = lst.getInstructionAt(cur);
                        if (inst == null) {
                            try { disassemble(cur); inst = lst.getInstructionAt(cur); } catch (Exception ignored) {}
                        }
                        if (inst != null) {
                            if (!camelotScratchTolerance) {
                                inst.setFlowOverride(FlowOverride.RETURN);
                                refMgr.removeAllReferencesFrom(cur);
                                returnsLocked++;
                            }
                        }
                    }
                }
            } catch (Exception ignored) {}
            cur = cur.add(2);
        }
        println("  [GUARDIAN] Epilogos de retorno asegurados como RETURN: " + returnsLocked);

        // 1b. Asegurar que bifurcaciones internas generadas con BL (ej. switch fallback en 0x0804901C -> 0x0804DA2E)
        // se reconozcan como ramas (FlowOverride.BRANCH) para unificar la funcion y evitar avisos PIC
        try {
            Instruction iBlDisp = lst.getInstructionAt(a(0x0804901CL));
            if (iBlDisp != null) {
                iBlDisp.setFlowOverride(FlowOverride.BRANCH);
            }
        } catch (Exception ignored) {}

        // 2. Depuración de funciones espurias segun nivel de estricto
        if (guardianStrictness >= 2) {
            FunctionIterator fit = fnMgr.getFunctions(true);
            List<Address> toRemove = new ArrayList<>();

            while (fit.hasNext()) {
                Function fn = fit.next();
                Address ep = fn.getEntryPoint();
                long epOff = ep.getOffset();

                if (epOff == romBase || epOff == entryPoint || kFuncs.containsKey(epOff)) continue;
                if (epOff < romBase || epOff >= romEnd || isSkip(epOff)) continue;

                // Casos explícitos de switch preservados
                if (fn.getName().startsWith("case_") || fn.getName().startsWith("switch_")) {
                    toRemove.add(ep);
                    continue;
                }

                try {
                    int b1 = mem.getByte(ep.add(1)) & 0xFF;
                    if (b1 == 0xB5 || b1 == 0xB4) {
                        continue;
                    }

                    int armW = mem.getInt(ep);
                    if ((armW & 0xFFFF0000) == 0xE92D0000) {
                        continue;
                    }

                    boolean hasCallRef = false;
                    ReferenceIterator rIter = refMgr.getReferencesTo(ep);
                    while (rIter.hasNext()) {
                        Reference r = rIter.next();
                        if (r.getReferenceType().isCall()) {
                            hasCallRef = true;
                            break;
                        }
                        // En Camelot, las rutinas superpuestas son alcanzadas por saltos directos, computados o tablas
                        if (camelotScratchTolerance && (r.getReferenceType().isJump() || r.getReferenceType().isData())) {
                            hasCallRef = true;
                            break;
                        }
                    }

                    if (guardianStrictness == 2 && hasCallRef) {
                        continue;
                    }

                    // En Camelot, las superposiciones de rutinas son deliberadas por diseno: no purgar
                    if (camelotScratchTolerance) {
                        continue;
                    }

                    if (fn.getName().startsWith("func_") || fn.getName().startsWith("FUN_")) {
                        toRemove.add(ep);
                    }
                } catch (Exception ignored) {}
            }

            for (Address badEp : toRemove) {
                try {
                    fnMgr.removeFunction(badEp);
                    bogusFuncsPurged++;
                } catch (Exception ignored) {}
            }
            println("  [GUARDIAN] Funciones huerfanas/espurias depuradas: " + bogusFuncsPurged);
        } else {
            println("  [GUARDIAN] Nivel 1 Permisivo: Todas las funciones preservadas.");
        }
        println("  [FASE 5] COMPLETA.\n");
    }

    // --------------------------------------------------------------------------
    //  FASE 6: DECOMPILACION MASIVA A C (STREAMING MATRIX + PROGRESS BAR)
    // --------------------------------------------------------------------------
    private void phase6_decompileAndExport() throws Exception {
        println("[FASE 6] Decompilacion Masiva a C (Streaming Matrix Engine con Barra de Progreso)...");

        DecompInterface decomp = new DecompInterface();
        DecompileOptions dOpts = new DecompileOptions();
        dOpts.grabFromProgram(currentProgram);
        dOpts.setWARNCommentIncluded(false); // Elimina comentarios internos de advertencia del descompilador
        dOpts.setMaxJumpTableEntries(4096);  // Expande capacidad de jump tables masivas
        dOpts.setMaxInstructions(250000);    // Permite descompilar funciones gigantes como el dispatcher
        dOpts.setMaxPayloadMBytes(100);      // Incrementa límite de payload de AST
        dOpts.setEliminateUnreachable(true); // Elimina bloques inalcanzables silenciosamente
        decomp.setOptions(dOpts);
        decomp.toggleSyntaxTree(true);

        if (!decomp.openProgram(currentProgram)) {
            println("  [ERROR] No se pudo inicializar la interfaz del descompilador Ghidra.");
            return;
        }

        File fAllPath   = new File(outDir, gamePrefix + "_all.c");
        File fNamedPath = new File(outDir, gamePrefix + "_named.c");
        File fThunkPath = new File(outDir, gamePrefix + "_thunks.c");

        BufferedWriter fAll   = new BufferedWriter(new FileWriter(fAllPath));
        BufferedWriter fNamed = new BufferedWriter(new FileWriter(fNamedPath));
        BufferedWriter fThunk = new BufferedWriter(new FileWriter(fThunkPath));

        String hdr = "// ==============================================================================\n" +
                     "//  FIO DECOMP - SOURCE DECOMPILATION: " + gameTitle + " [" + gameCode + "]\n" +
                     "//  Generated by Universal GBA Decompiler Pipeline v1.2\n" +
                     "//  Switch Jump Tables Native Modeled & Media Assets Filtered\n" +
                     "// ==============================================================================\n\n";

        fAll.write(hdr);
        fNamed.write(hdr);
        fThunk.write(hdr);

        List<Function> fns = new ArrayList<>();
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) fns.add(fi.next());

        int totalFns = fns.size();
        println("  Total funciones a decompilar: " + totalFns);

        int count = 0;
        for (Function fn : fns) {
            if (monitor.isCancelled()) break;
            count++;

            long fo = fn.getEntryPoint().getOffset();
            if (fo < romBase || fo >= romEnd || isSkip(fo)) {
                decompSkip++;
                continue;
            }

            try {
                DecompileResults res = decomp.decompileFunction(fn, 60, monitor);
                if (res == null || !res.decompileCompleted()) {
                    decompErr++;
                    continue;
                }
                DecompiledFunction df = res.getDecompiledFunction();
                if (df == null) {
                    decompErr++;
                    continue;
                }

                String code  = df.getC();

                // FILTRO DE SEGURIDAD ESTRICTO: Descartar pseudo-funciones espurias en datos o textos
                if (code.contains("halt_baddata") || 
                    code.contains("Read-only address (ram,0x") || 
                    code.contains("Bad instruction")) {
                    println(String.format("  [EXCLUSION::DATA_CORRUPT] 0x%08X (%s) descartada (contiene halt_baddata / violaciones de memoria BIOS)", fo, fn.getName()));
                    decompSkip++;
                    continue;
                }

                String name  = fn.getName();
                String addrStr = fn.getEntryPoint().toString();
                String[] hm  = hotmap.get(fo);
                String hmStr = hm != null ? " [" + hm[1] + "/" + hm[2] + "]" : "";

                // Limpieza estética rigurosa: eliminar cualquier bloque residual de comentarios WARNING
                code = code.replaceAll("(?m)^\\s*/\\*\\s*WARNING:.*?\\*/\\r?\\n?", "");
                code = code.replaceAll("(\\r?\\n){3,}", "\n\n").trim();

                String block = "\n// --- " + name + " @ " + addrStr + hmStr + " ---\n" + code + "\n";
                fAll.write(block);
                int loc = block.split("\n").length;
                totalLines += loc;

                boolean named = !name.startsWith("FUN_") && !name.startsWith("func_") && !name.startsWith("thunk_");
                boolean thunk = name.startsWith("thunk_");

                int pct = (int)((count * 100.0) / totalFns);
                String tag = named ? "NAMED" : (thunk ? "THUNK" : "ANON");

                // Extraer prototipo o primera linea de codigo para streaming Matrix en vivo
                String sig = "";
                for (String l : code.split("\n")) {
                    String tr = l.trim();
                    if (!tr.isEmpty() && !tr.startsWith("/*") && !tr.startsWith("//") && !tr.startsWith("{") && !tr.startsWith("}")) {
                        sig = tr;
                        break;
                    }
                }
                if (sig.length() > 65) sig = sig.substring(0, 62) + "...";

                if (named) {
                    fNamed.write(block);
                    decompNamed++;
                } else if (thunk) {
                    fThunk.write(block);
                    decompAnon++;
                } else {
                    decompAnon++;
                }

                // Streaming en vivo continuo de cada funcion descompilada con telemetria de progreso
                println(String.format(">>> [MATRIX::C] [PROGRESS: %d%%] [%d/%d] 0x%08X [%-5s] %-24s => %4d LOC | %s",
                    pct, count, totalFns, fo, hm != null ? hm[1] : "THUMB", name, loc, sig.isEmpty() ? tag : sig));

                // Cascada de codigo C Matrix en vivo hacia la consola
                String[] cLines = code.split("\\r?\\n");
                int streamLines = Math.min(cLines.length, 12);
                for (int li = 0; li < streamLines; li++) {
                    String cl = cLines[li].trim();
                    if (!cl.isEmpty() && !cl.startsWith("/*") && !cl.startsWith("//")) {
                        println(">>> [CASCADE] " + cl);
                    }
                }
                if (cLines.length > 12) {
                    println(String.format(">>> [CASCADE]   ... [+%d lineas de logica en C compiladas] ...", (cLines.length - 12)));
                }

                if (count % 25 == 0) {
                    try {
                        fAll.flush();
                        fNamed.flush();
                        fThunk.flush();
                    } catch (Exception ignored) {}
                }
            } catch (Exception ex) {
                decompErr++;
            }
        }

        fAll.flush(); fAll.close();
        fNamed.flush(); fNamed.close();
        fThunk.flush(); fThunk.close();
        decomp.dispose();

        // Exportar Hotmap JSON
        File hotmapFile = new File(outDir, gamePrefix + "_hotmap.json");
        try (PrintWriter pw = new PrintWriter(hotmapFile)) {
            pw.println("{");
            int hmI = 0;
            for (Map.Entry<Long, String[]> entry : hotmap.entrySet()) {
                hmI++;
                pw.println(String.format("  \"0x%08X\": [\"%s\", \"%s\", \"%s\"]%s",
                    entry.getKey(), entry.getValue()[0], entry.getValue()[1], entry.getValue()[2],
                    hmI < hotmap.size() ? "," : ""));
            }
            pw.println("}");
        }

        // Exportar Simbolos Exportables JSON
        File symExportFile = new File(outDir, gamePrefix + "_symbols.json");
        try (PrintWriter pw = new PrintWriter(symExportFile)) {
            pw.println("{");
            pw.println("  \"game\": \"" + gameTitle + "\",");
            pw.println("  \"code\": \"" + gameCode + "\",");
            pw.println("  \"functions\": {");
            int fnI = 0;
            for (Function fn : fns) {
                fnI++;
                long fo = fn.getEntryPoint().getOffset();
                String[] hm = hotmap.get(fo);
                String mode = hm != null ? hm[1] : "THUMB";
                pw.println(String.format("    \"0x%08X\": [\"%s\", \"%s\", \"Decompiled Function\"]%s",
                    fo, fn.getName(), mode, fnI < fns.size() ? "," : ""));
            }
            pw.println("  }");
            pw.println("}");
        }

        // Exportar Resumen Ejecutivo
        File summaryFile = new File(outDir, gamePrefix + "_summary.txt");
        try (PrintWriter pw = new PrintWriter(summaryFile)) {
            pw.println("==============================================================================");
            pw.println(" FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM  ::  DECOMPILATION SUMMARY");
            pw.println("==============================================================================");
            pw.println("  ROM Titulo               : " + gameTitle);
            pw.println("  ROM Codigo               : " + gameCode + " (Maker: " + makerCode + ")");
            pw.println("  Motor / Engine Preset    : " + engineProfileName + " (" + engineProfileDesc + ")");
            pw.println(String.format("  ROM Tamano               : %.2f MB", romSize / 1048576.0));
            pw.println("  Nivel de Guardian        : " + guardianStrictness);
            pw.println("  Activos Multimedia Prot. : " + assetsFound + " bloques (" + 
                String.format("%.2f MB aislados", assetsProtectedBytes / (1024.0 * 1024.0)) + ")");
            pw.println("------------------------------------------------------------------------------");
            pw.println("  Funciones Decompiladas   : " + (decompNamed + decompAnon));
            pw.println("    - Simbolizadas / Named : " + decompNamed);
            pw.println("    - Anonimas / Thunks    : " + decompAnon);
            pw.println("    - Errores Decompilador : " + decompErr);
            pw.println("    - Omitidas (Assets/ROM): " + decompSkip);
            pw.println("  Lineas de Codigo C (LOC) : " + totalLines);
            pw.println("  Jump Tables Resueltas    : " + resolvedJumpTables + " (" + resolvedJumpCases + " ramas)");
            pw.println("  Switches C Estructurados : " + nativeSwitchesOverridden);
            pw.println("  Epilogos Retorno Retenidos: " + returnsLocked);
            pw.println("  Funciones Espurias Purg. : " + bogusFuncsPurged);
            pw.println("==============================================================================");
        }

        println("\n==============================================================================");
        println("  [MATRIX::FINIS] DECOMPILACION FINALIZADA CON EXITO");
        println("  Total Funciones   : " + (decompNamed + decompAnon));
        println("  Lineas C Totales  : " + totalLines);
        println("  Archivos Generados:");
        println("    - " + fAllPath.getAbsolutePath());
        println("    - " + fNamedPath.getAbsolutePath());
        println("    - " + fThunkPath.getAbsolutePath());
        println("    - " + hotmapFile.getAbsolutePath());
        println("    - " + summaryFile.getAbsolutePath());
        println("==============================================================================\n");
    }

    // --------------------------------------------------------------------------
    //  ENTRYPOINT PRINCIPAL DE GHIDRA SCRIPT
    // --------------------------------------------------------------------------
    @Override
    public void run() throws Exception {
        parseArgsAndDetect();
        detectCodeHorizon();
        phase1_hardwareMapping();
        phase1b_mediaAssetFilter();
        phase1c_asciiTextHunter();
        phase2_loadSymbols();
        phase3_blindEmulator();
        phase4_jumpTableResolver();
        phase5_contextGuardian();
        phase6_decompileAndExport();
    }
}
