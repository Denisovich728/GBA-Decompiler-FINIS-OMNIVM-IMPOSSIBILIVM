@echo off
setlocal EnableDelayedExpansion
color 0a
title FIO DECOMP - GBA UNIVERSAL ENGINE v1.1

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo.
echo ==============================================================================
echo    _____ ___ ___     ____  _____ ____ ___  __  __ ____  
echo   ^|  ___^|_ _/ _ \   ^|  _ \^| ____/ ___/ _ \^|  \/  ^|  _ \ 
echo   ^| ^|_   ^| ^| ^| ^| ^|  ^| ^| ^| ^|  _^|^| ^|  ^| ^| ^| ^| ^|\/^| ^| ^|_) ^|
echo   ^|  _^|  ^| ^| ^|_^| ^|  ^| ^|_^| ^| ^|__^| ^|__^| ^|_^| ^| ^|  ^| ^|  __/ 
echo   ^|_^|   ^|___\___/   ^|____/^|_____\____\___/^|_^|  ^|_^|_^|    
echo ==============================================================================
echo       FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM v1.1
echo       [EMULADOR HEADLESS SILENCIOSO + FILTRO DE GRAFICOS Y AUDIO M4A]
echo       [TELEMETRIA MATRIX EN VIVO + BARRA DE PROGRESO SUPERPUESTA]
echo ==============================================================================
echo.

:: -----------------------------------------------------------------------------
::  PASO 1: DETECCION Y SELECCION DE ROM (.GBA)
:: -----------------------------------------------------------------------------
echo [*] Escaneando ROMs disponibles en el directorio del programa y roms\...
echo.

set ROM_COUNT=0

:: Escanear en la carpeta raiz y en roms\
if exist "%SCRIPT_DIR%*.gba" (
    for /f "delims=" %%F in ('dir /b "%SCRIPT_DIR%*.gba" 2^>nul') do (
        set /a ROM_COUNT+=1
        set "ROM_!ROM_COUNT!=%SCRIPT_DIR%%%F"
        set "ROM_NAME_!ROM_COUNT!=%%F"
    )
)

if exist "%SCRIPT_DIR%roms\*.gba" (
    for /f "delims=" %%F in ('dir /b "%SCRIPT_DIR%roms\*.gba" 2^>nul') do (
        set /a ROM_COUNT+=1
        set "ROM_!ROM_COUNT!=%SCRIPT_DIR%roms\%%F"
        set "ROM_NAME_!ROM_COUNT!=roms\%%F"
    )
)

:: Mostrar lista de ROMs
if %ROM_COUNT% GTR 0 (
    for /l %%I in (1,1,%ROM_COUNT%) do (
        echo   [%%I] !ROM_NAME_%%I!
    )
) else (
    echo   [-] No se encontraron archivos .gba en la carpeta local o en roms\
)

echo   [0] Ingresar ruta manual o arrastrar archivo .gba
echo.

:CHOOSE_ROM
set "ROM_SEL=1"
set /p "ROM_SEL=Selecciona el numero de ROM [1-%ROM_COUNT%] o [0] (Default: 1): "

if "%ROM_SEL%"=="0" goto MANUAL_ROM

if defined ROM_%ROM_SEL% (
    set "TARGET_ROM=!ROM_%ROM_SEL%!"
    goto ROM_SELECTED
)

:: Si el usuario pegó directamente una ruta de archivo
if exist "%ROM_SEL%" (
    set "TARGET_ROM=%ROM_SEL%"
    goto ROM_SELECTED
)

echo [!] Opcion invalida. Intenta nuevamente.
goto CHOOSE_ROM

:MANUAL_ROM
set /p "TARGET_ROM=Arrastra el archivo .gba o escribe su ruta completa: "
set TARGET_ROM=%TARGET_ROM:"=%
if not exist "%TARGET_ROM%" (
    echo [!] El archivo no existe: "%TARGET_ROM%"
    goto MANUAL_ROM
)

:ROM_SELECTED
echo.
echo [*] ROM seleccionada: "%TARGET_ROM%"
echo.

:: -----------------------------------------------------------------------------
::  PASO 2: SELECCION DE MODO DE DESCOMPILACION
:: -----------------------------------------------------------------------------
echo ------------------------------------------------------------------------------
echo  SELECCION DE MODO DE DESCOMPILACION:
echo ------------------------------------------------------------------------------
echo   [1] Solo Ghidra
echo       (Analisis Estatico + Emulador Ciego + Decompilador C)
echo.
echo   [2] Solo Emulador
echo       (mGBA Headless Tracer + Extraccion de Jump Tables Dinamicas a JSON)
echo.
echo   [3] Emulador Headless y Ghidra [RECOMENDADO]
echo       (mGBA 100%% silencioso en segundo plano + Ghidra Matrix Streaming en vivo)
echo ------------------------------------------------------------------------------
set "CHOICE_MODE=3"
set /p "CHOICE_MODE=Elige el modo [1, 2 o 3] (Default: 3): "

if not "%CHOICE_MODE%"=="1" if not "%CHOICE_MODE%"=="2" if not "%CHOICE_MODE%"=="3" (
    set "CHOICE_MODE=3"
)
echo [*] Modo seleccionado: [%CHOICE_MODE%]
echo.

:: -----------------------------------------------------------------------------
::  PASO 3: NIVEL DE ESTRICTO DEL GUARDIAN DE CONTEXTO
:: -----------------------------------------------------------------------------
echo ------------------------------------------------------------------------------
echo  NIVEL DE ESTRICTO DEL GUARDIAN DE CONTEXTO:
echo ------------------------------------------------------------------------------
echo   [1] Permisivo
echo       (Conserva getters/setters, leaf functions, ramas secundarias)
echo.
echo   [2] Equilibrado [RECOMENDADO PARA ESTE PROYECTO]
echo       (Preserva todas las funciones reales, llamadas y metodos;
echo        elimina ramas switch y loop huerfanas para evitar "Too many branches")
echo.
echo   [3] Estricto
echo       (Solo funciones canonicas con prologo PUSH {lr} o ARM STMFD)
echo ------------------------------------------------------------------------------
set "CHOICE_GUARDIAN=2"
set /p "CHOICE_GUARDIAN=Elige el nivel de guardian [1, 2 o 3] (Default: 2): "

if not "%CHOICE_GUARDIAN%"=="1" if not "%CHOICE_GUARDIAN%"=="2" if not "%CHOICE_GUARDIAN%"=="3" (
    set "CHOICE_GUARDIAN=2"
)
echo [*] Nivel de Guardian seleccionado: [%CHOICE_GUARDIAN%]
echo.

:: -----------------------------------------------------------------------------
::  PASO 4: LISTA DE CONTEXTO / SIMBOLOS
:: -----------------------------------------------------------------------------
echo ------------------------------------------------------------------------------
echo  LISTA DE CONTEXTO Y DICCIONARIO DE SIMBOLOS:
echo ------------------------------------------------------------------------------
echo   [1] Universal / Ciego [RECOMENDADO PARA ROMS NUEVAS]
echo       (Sin archivo externo: descompila en crudo generando func_08XXXXXX)
echo.
echo   [2] Cargar archivo de contexto / simbolos existente (JSON)
echo ------------------------------------------------------------------------------
set "CHOICE_CTX=1"
set /p "CHOICE_CTX=Elige opcion de contexto [1 o 2] (Default: 1): "

set "CONTEXT_FILE=NONE"

if "%CHOICE_CTX%"=="2" (
    echo.
    echo [*] Archivos JSON detectados en symbols\:
    set JSON_COUNT=0
    if exist "%SCRIPT_DIR%symbols\*.json" (
        for /f "delims=" %%J in ('dir /b "%SCRIPT_DIR%symbols\*.json" 2^>nul') do (
            set /a JSON_COUNT+=1
            set "JSON_!JSON_COUNT!=%SCRIPT_DIR%symbols\%%J"
            echo   [!JSON_COUNT!] symbols\%%J
        )
        echo   [0] Ingresar ruta manual de archivo .json
        set "JSON_SEL=1"
        set /p "JSON_SEL=Selecciona el archivo de simbolos [1-!JSON_COUNT!] o [0]: "
        if "!JSON_SEL!"=="0" (
            set /p "CONTEXT_FILE=Ruta completa del archivo .json: "
        ) else if defined JSON_!JSON_SEL! (
            set "CONTEXT_FILE=!JSON_%JSON_SEL%!"
        )
    ) else (
        set /p "CONTEXT_FILE=Ruta completa del archivo .json de simbolos: "
    )
    set CONTEXT_FILE=!CONTEXT_FILE:"=!
)

echo [*] Contexto configurado: "%CONTEXT_FILE%"
echo.

:: -----------------------------------------------------------------------------
::  PASO 5: EJECUCION DEL ORQUESTADOR MAESTRO
:: -----------------------------------------------------------------------------
echo ==============================================================================
echo  INICIANDO FIO DECOMP :: STREAMING MATRIX ENGINE
echo ==============================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%finis_orchestrator.ps1" -RomPath "%TARGET_ROM%" -Mode "%CHOICE_MODE%" -GuardianStrictness "%CHOICE_GUARDIAN%" -ContextFile "%CONTEXT_FILE%"

echo.
echo ==============================================================================
echo  [FIO DECOMP] PROCESO COMPLETADO EXITOSAMENTE.
echo ==============================================================================
echo.
pause
