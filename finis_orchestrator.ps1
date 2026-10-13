# ==============================================================================
#  FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM  ::  MASTER ORCHESTRATOR
#  Coordinates Ghidra Headless + Headless mGBA + Real-Time Overlay Progress Bar
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$RomPath,

    [ValidateSet("1", "2", "3")]
    [string]$Mode = "3", # 1: Solo Ghidra, 2: Solo Emulador, 3: Emulador + Ghidra

    [ValidateSet("1", "2", "3")]
    [string]$GuardianStrictness = "2", # 1: Permisivo, 2: Equilibrado, 3: Estricto

    [string]$ContextFile = "NONE",

    [string]$GhidraHome = ""
)

$BASE_DIR = $PSScriptRoot
$CORE_DIR = "$BASE_DIR\core"
$BRIDGE_DIR = "$BASE_DIR\bridge"
$EMU_DIR = "$BASE_DIR\emulator"
$PROJECTS_DIR = "$BASE_DIR\ghidra_projects"
$OUTPUT_ROOT = "$BASE_DIR\output"

# ---- 1. DETECCION DE GHIDRA ----
if (-not $GhidraHome) {
    if (Test-Path "$BASE_DIR\engine\ghidra\support\analyzeHeadless.bat") {
        $GhidraHome = "$BASE_DIR\engine\ghidra"
    } else {
        $possibleGhidra = @(
            "J:\Laboratorio\ghidra_12.1.4_PUBLIC",
            "C:\Users\Denis\Downloads\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC"
        )
        foreach ($g in $possibleGhidra) {
            if (Test-Path "$g\support\analyzeHeadless.bat") {
                $GhidraHome = $g
                break
            }
        }
    }
}

if (-not $GhidraHome -or -not (Test-Path "$GhidraHome\support\analyzeHeadless.bat")) {
    Write-Host "[ERROR] Ghidra Headless no encontrado en '$BASE_DIR\engine\ghidra'." -ForegroundColor Red
    Write-Host "Verifica que el motor este instalado en engine\ghidra o especifica -GhidraHome <ruta>" -ForegroundColor Red
    exit 1
}

$GHIDRA_HEADLESS = "$GhidraHome\support\analyzeHeadless.bat"

# ---- 2. VALIDACION DE ROM ----
if (-not (Test-Path $RomPath)) {
    Write-Host "[ERROR] Archivo ROM no encontrado: $RomPath" -ForegroundColor Red
    exit 1
}

$romFileName = [System.IO.Path]::GetFileName($RomPath)
$rawName     = [System.IO.Path]::GetFileNameWithoutExtension($RomPath)
$romBaseName = ($rawName -replace '[^A-Za-z0-9_]', '_') -replace '_+', '_'
$romBaseName = $romBaseName.Trim('_')
$OUTPUT_DIR  = "$OUTPUT_ROOT\$romBaseName"
$PROJECT_DIR = "$PROJECTS_DIR"
$PROJECT_NAME = "${romBaseName}_ghidra"

# Proteccion universal: cmd.exe / analyzeHeadless.bat colapsa si la ruta del ROM tiene parentesis
$romDir = [System.IO.Path]::GetDirectoryName((Resolve-Path $RomPath))
if ($RomPath -match '[\(\),]') {
    $cleanRomName = "$romBaseName.gba"
    $cleanRomPath = "$romDir\$cleanRomName"
    if (-not (Test-Path $cleanRomPath)) {
        try {
            New-Item -ItemType HardLink -Path $cleanRomPath -Target (Resolve-Path $RomPath) -Force | Out-Null
        } catch {
            Copy-Item -Path (Resolve-Path $RomPath) -Destination $cleanRomPath -Force
        }
    }
    $RomPath = $cleanRomPath
}

New-Item -ItemType Directory -Force $OUTPUT_DIR   | Out-Null
New-Item -ItemType Directory -Force $PROJECT_DIR  | Out-Null

# Limpiar bloqueos .lock
Remove-Item "$PROJECT_DIR\*.lock*" -Force -ErrorAction SilentlyContinue

$sha1 = (Get-FileHash $RomPath -Algorithm SHA1).Hash
$romSizeMb = [math]::Round((Get-Item $RomPath).Length / 1MB, 2)

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "   FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM  ::  NUCLEO UNIVERSAL" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "   ROM Archivo      : $romFileName ($romSizeMb MB)" -ForegroundColor White
Write-Host "   ROM SHA1         : $sha1" -ForegroundColor DarkGray
Write-Host "   Modo Ejecucion   : $(switch ($Mode) { '1' {'[1] Solo Ghidra'} '2' {'[2] Solo Emulador'} '3' {'[3] Emulador Headless + Ghidra (Hibrido)'} })" -ForegroundColor Cyan
Write-Host "   Guardian Nivel   : $(switch ($GuardianStrictness) { '1' {'1 (Permisivo)'} '2' {'2 (Equilibrado - RECOMENDADO)'} '3' {'3 (Estricto)'} })" -ForegroundColor Cyan
Write-Host "   Contexto Simbolos: $ContextFile" -ForegroundColor Cyan
Write-Host "   Directorio Salida: $OUTPUT_DIR" -ForegroundColor DarkCyan
Write-Host "   Ghidra Engine    : $GhidraHome" -ForegroundColor DarkGray
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ""

# ---- 3. EJECUCION DE EMULADOR HEADLESS EN SEGUNDO PLANO ----
$mgbaExe = "$EMU_DIR\mgba-sdl.exe"
if (-not (Test-Path $mgbaExe)) {
    $mgbaExe = "C:\Program Files\mGBA\mgba-sdl.exe"
}
if (-not (Test-Path $mgbaExe)) {
    $mgbaExe = "$EMU_DIR\mGBA.exe"
}

$jumpContextJson = "$OUTPUT_DIR\jump_context.json"
$mgbaProcess = $null

if ($Mode -eq "2" -or $Mode -eq "3") {
    if (Test-Path $mgbaExe) {
        Write-Host "[*] Lanzando mGBA HEADLESS en segundo plano (sin ventanas intrusivas)..." -ForegroundColor Green
        try {
            $mgbaProcess = Start-Process -FilePath $mgbaExe -ArgumentList @("-g", "`"$RomPath`"") -WindowStyle Hidden -PassThru
            Write-Host "    [mGBA Headless] Servidor GDB activo en 127.0.0.1:2345 (PID: $($mgbaProcess.Id))" -ForegroundColor Cyan
        } catch {
            Write-Host "    [WARN] No se pudo iniciar mGBA en modo oculto, continuando..." -ForegroundColor Yellow
        }
    }

    Write-Host "[*] Extrayendo Jump Tables y contexto dinamico via Bridge..." -ForegroundColor Yellow
    $bridgeScript = "$BRIDGE_DIR\universal_emulator_bridge.py"
    $bridgeArgs = @("$bridgeScript", "--rom", "$RomPath", "--out", "$jumpContextJson")
    if ($Mode -eq "2") {
        $bridgeArgs += @("--trace")
    }
    python @bridgeArgs
    
    if ($Mode -eq "2") {
        if ($mgbaProcess -and -not $mgbaProcess.HasExited) {
            Stop-Process -Id $mgbaProcess.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Host ""
        Write-Host "[+] MODO 2 COMPLETADO: Analisis de emulador y contexto guardado en:" -ForegroundColor Green
        Write-Host "    $jumpContextJson" -ForegroundColor White
        exit 0
    }
}
# Si el usuario eligio MODO UNIVERSAL (ContextFile = "NONE"), se respeta estrictamente.
# No se inyecta ningun archivo de simbolos hardcodeado.

# ---- 4. VERIFICACION DE ORQUESTADOR GHIDRA ----
$SCRIPT_NAME = "FinisOmnivmOrchestrator.java"
$SCRIPT_PATH = "$CORE_DIR"

if (-not (Test-Path "$SCRIPT_PATH\$SCRIPT_NAME")) {
    Write-Host "[ERROR] Script maestro $SCRIPT_PATH\$SCRIPT_NAME no existe." -ForegroundColor Red
    if ($mgbaProcess -and -not $mgbaProcess.HasExited) {
        Stop-Process -Id $mgbaProcess.Id -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

# ---- 5. EJECUCION GHIDRA HEADLESS CON STREAMING MATRIX & PROGRESS BAR ----
$LOG_FILE = "$OUTPUT_DIR\finis_orchestrator.log"
$env:GHIDRA_MAXMEM = "6G"

$ghidraArgs = @(
    $PROJECT_DIR,
    $PROJECT_NAME,
    "-import", $RomPath,
    "-processor", "ARM:LE:32:v4t",
    "-cspec", "default",
    "-loader", "BinaryLoader",
    "-loader-baseAddr", "0x08000000",
    "-loader-blockName", "ROM",
    "-noanalysis",
    "-postScript", $SCRIPT_NAME,
    $OUTPUT_DIR,
    $GuardianStrictness,
    $ContextFile,
    $romBaseName,
    "-scriptPath", $SCRIPT_PATH,
    "-max-cpu", [Environment]::ProcessorCount,
    "-log", $LOG_FILE,
    "-overwrite"
)

Write-Host ""
Write-Host "[*] Despertando Nucleo de Decompilacion Ghidra (Matriz de C pura)..." -ForegroundColor Yellow
Write-Host "    (Streaming de lineas de codigo C en tiempo real con barra de progreso superior)" -ForegroundColor DarkYellow
Write-Host ""

$startTime = Get-Date

$ProgressPreference = 'Continue'

try {
    & $GHIDRA_HEADLESS @ghidraArgs *>&1 | ForEach-Object {
        $line = $_.ToString().Trim()
        if (-not $line) { return }

        if ($line -match "\[PROGRESS:\s*(\d+)%\]\s*\[(\d+)/(\d+)\]\s*(0x[0-9A-Fa-f]+)\s*\[([^\]]+)\]\s*(\S+)\s*=>\s*(\d+)\s*LOC(?:\s*\|\s*(.*))?") {
            $pct      = [int]$matches[1]
            $curr     = $matches[2]
            $total    = $matches[3]
            $addr     = $matches[4]
            $archMode = $matches[5].Trim()
            $fn       = $matches[6]
            $loc      = $matches[7]
            $sig      = if ($matches[8]) { $matches[8].Trim() } else { "" }

            # 1. Barra de progreso nativa Write-Progress superior de PowerShell
            Write-Progress -Activity "FIO DECOMP :: MATRIX C DECOMPILER" `
                           -Status "[$pct%] $fn ($loc LOC) | $curr/$total | $archMode" `
                           -CurrentOperation "$sig" `
                           -PercentComplete $pct

            # 2. Actualizacion en tiempo real del titulo de la consola
            try { $Host.UI.RawUI.WindowTitle = "FIO Decomp [$pct%] [$curr/$total] - $fn ($loc LOC)" } catch {}

            # 3. Barra visual ASCII de caracteres de alta visibilidad
            $barWidth = 24
            $filled = [math]::Floor(($pct / 100) * $barWidth)
            $unfilled = $barWidth - $filled
            $barVisual = ("=" * $filled) + ("-" * $unfilled)

            Write-Host ""
            Write-Host ">>> [PROGRESO: $pct%] [$barVisual] [$curr/$total] $addr [$archMode] $fn ($loc LOC)" -ForegroundColor Cyan
            if ($sig) {
                Write-Host "    $sig" -ForegroundColor White
            }
        } elseif ($line -match ">>> \[CASCADE\]\s*(.*)") {
            $codeLine = $matches[1]
            Write-Host "    $codeLine" -ForegroundColor Green
        } elseif ($line -match ">>> \[MATRIX::") {
            Write-Host $line -ForegroundColor Green
        } elseif ($line -match "\[GUARDIAN\]") {
            Write-Host $line -ForegroundColor Green
        } elseif ($line -match "\[ROM DETECTADA\]|\[CONFIGURACION\]") {
            Write-Host $line -ForegroundColor White
        } elseif ($line -match "\[FASE") {
            Write-Host $line -ForegroundColor Yellow
        } elseif ($line -match "\[SUCCESS\]|\[OK\]") {
            Write-Host $line -ForegroundColor Green
        } elseif ($line -match "\[ERROR\]|\[!\]") {
            Write-Host $line -ForegroundColor Red
        } elseif ($line -match "===") {
            Write-Host $line -ForegroundColor DarkGreen
        } elseif ($line -match "Decompilando|Exportando") {
            Write-Host $line -ForegroundColor Gray
        } else {
            Write-Output $line
        }
    }
} catch {
    Write-Host "[ERROR] Fallo critico durante la ejecucion de Ghidra: $_" -ForegroundColor Red
} finally {
    Write-Progress -Activity "FIO DECOMP :: MATRIX C DECOMPILER" -Completed
    if ($mgbaProcess -and -not $mgbaProcess.HasExited) {
        Stop-Process -Id $mgbaProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

$elapsed = (Get-Date) - $startTime

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host " FIO DECOMP  ::  RESULTADOS FINALES ($([math]::Round($elapsed.TotalMinutes, 1)) min)" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green

$summaryFile = Get-ChildItem $OUTPUT_DIR -Filter "*_summary.txt" | Select-Object -First 1
if ($summaryFile) {
    Get-Content $summaryFile.FullName | Write-Host -ForegroundColor Green
}

Write-Host ""
Write-Host "Archivos generados en $($OUTPUT_DIR):" -ForegroundColor White
Get-ChildItem $OUTPUT_DIR | ForEach-Object {
    $sz = [math]::Round($_.Length / 1MB, 2)
    Write-Host "  - $($_.Name.PadRight(32)) : $sz MB" -ForegroundColor Green
}

Write-Host ""
Write-Host "Log completo en: $LOG_FILE" -ForegroundColor DarkCyan
Write-Host "==============================================================================" -ForegroundColor Green
