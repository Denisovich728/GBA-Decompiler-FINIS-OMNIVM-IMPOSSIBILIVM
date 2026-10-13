# FIO Decomp
### *FINIS OMNIVM IMPOSSIBILIVM  ::  Universal Autonomous GBA Decompiler Pipeline*

```
==============================================================================
   _____ ___ ___     ____  _____ ____ ___  __  __ ____  
  |  ___|_ _/ _ \   |  _ \| ____/ ___/ _ \|  \/  |  _ \ 
  | |_   | | | | |  | | | |  _|| |  | | | | |\/| | |_) |
  |  _|  | | |_| |  | |_| | |__| |__| |_| | |  | |  __/ 
  |_|   |___\___/   |____/|_____\____\___/|_|  |_|_|    
==============================================================================
       FIO DECOMP  ::  FINIS OMNIVM IMPOSSIBILIVM v1.1
       [EMULADOR HEADLESS SILENCIOSO + FILTRO DE GRAFICOS Y AUDIO M4A]
       [TELEMETRIA MATRIX EN VIVO + BARRA DE PROGRESO SUPERPUESTA]
==============================================================================
```

---

## 1. Descripcion del Sistema

**FIO Decomp** (acronimo de *Finis Omnivm Impossibilivm Decompiler*) es un entorno universal y completamente desacoplado para la descompilacion masiva a C de cualquier ROM de **Game Boy Advance (ARMv4T / Thumb)**.

### Características Principales:
1. **Emulador Headless Silencioso:** Incluye una copia local de `mgba-sdl.exe` en `emulator\`. Se ejecuta 100% en segundo plano sin ventanas emergentes intrusivas; la consola permanece limpia mostrando únicamente el streaming de código C estilo Matrix.
2. **Barra de Progreso Superpuesta:** Integra `Write-Progress` nativo en la cabecera de la terminal junto a la actualización del título de la ventana en tiempo real (`FIO Decomp [45%] [2450/5400] - func_08XXXXXX (85 LOC)`), permitiendo ver el porcentaje exacto sin tapar ni detener el flujo continuo de código verde.
3. **Filtro Inteligente de Activos Multimedia (Audio y Gráficos):** Algoritmo de reconocimiento de firmas que detecta y aísla:
   - **Compresión BIOS:** LZ77 (`0x10`, `0x11`), Huffman (`0x24`, `0x28`), RLE (`0x30`) y Popuri (`0x70`).
   - **Audio M4A / Sappy:** Cabeceras de canciones (número de tracks, tabla de voces, punteros de secuencia).
   - **Muestras DirectSound PCM:** Cabeceras WaveData (frecuencia, loop start, loop length).
   - **Paletas de Color GBA (15-bit BGR):** Arreglos de halfwords con bit 15 en 0 (`color & 0x8000 == 0`).
   - **Zonas de Relleno:** Bloques de `0x00` o `0xFF` libres.
   *Todas estas regiones son bloqueadas automáticamente para evitar que Ghidra las descompile accidentalmente como código C.*
4. **"El Emulador Ciego":** Rastreo recursivo con propagación estricta de modos `T=1` (Thumb) y `T=0` (ARM) en saltos interworking (`BL`, `BLX`, `BX`) y gap sweep universal.
5. **Resolutor Universal de Jump Tables:** Caza switches inline y pools de punteros, enlazando ramas y evitando advertencias de `"Too many branches"`.
6. **Guardián de Contexto Paramétrico:** Blindaje de epílogos de retorno (`FlowOverride.RETURN` en `bx lr` y `pop; bx rX`) con 3 niveles de estricto configurables.

---

## 2. Estructura de Carpetas

```
J:\Laboratorio\GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM\
│
├── FIO_Decomp.bat               # Lanzador Interactivo Matrix (La Consola del Murciélago)
├── FINIS_OMNIVM.bat             # Alias de compatibilidad
├── finis_orchestrator.ps1        # Orquestador maestro en PowerShell (headless + progress bar)
│
├── emulator\                     # Binarios mGBA Headless integrados
│   ├── mgba-sdl.exe             # Ejecutable headless silencioso
│   └── mGBA.exe
│
├── core\                         # Núcleo Ghidra Desacoplado
│   ├── FinisOmnivmOrchestrator.java   # Script universal 100% dinámico de 7 fases
│   └── FinisOmnivmOrchestrator.class  # Bytecode compilado de alto rendimiento
│
├── bridge\                       # Puente Python
│   └── universal_emulator_bridge.py   # Extractor de jump tables y trazador GDB
│
├── roms\                         # Zona receptora de ROMs (.gba)
│   ├── fomt virgen.gba
│   └── MFOMT VIRGEN.gba
│
├── symbols\                      # Diccionarios de símbolos y contextos (.json)
│   ├── fomt_symbols.json
│   └── fomt_jump_context.json
│
├── ghidra_projects\              # Base de datos de proyectos headless
│
└── output\                       # Salida estructurada por juego
    └── <ROM_NAME>\
        ├── <rom>_all.c           # Código fuente C completo descompilado (>200k - 600k LOC)
        ├── <rom>_named.c         # Funciones simbolizadas / identificadas
        ├── <rom>_thunks.c        # Wrappers y thunks de interworking ARM/Thumb
        ├── <rom>_hotmap.json     # Mapa exhaustivo de bloques, modos y xrefs
        ├── <rom>_symbols.json    # Catálogo de símbolos exportable
        ├── <rom>_summary.txt     # Reporte ejecutivo de métricas
        └── jump_context.json     # Tablas de salto resueltas
```

---

## 3. Modo de Uso

Haz doble clic en:
```cmd
FIO_Decomp.bat
```

### Menú Interactivo:
1. **Selección de ROM:** Escanea automáticamente `roms\` o permite arrastrar cualquier archivo `.gba`.
2. **Modo:**
   - `[1]` Solo Ghidra (Estático puro).
   - `[2]` Solo Emulador (mGBA headless GDB tracer a JSON).
   - `[3]` Emulador Headless y Ghidra [RECOMENDADO] (mGBA silencioso en paralelo + Ghidra Matrix streaming).
3. **Nivel del Guardián:**
   - `[1]` Permisivo (Conserva leaf functions, getters/setters, fragmentos sin prólogo).
   - `[2]` Equilibrado [RECOMENDADO] (Protege funciones reales; purga pseudo-casos huérfanos).
   - `[3]` Estricto (Solo prólogos canónicos `PUSH {lr}`).
4. **Contexto / Símbolos:**
   - `[1]` Universal / Ciego [RECOMENDADO PARA ROMS NUEVAS] (`func_08XXXXXX`).
   - `[2]` Cargar archivo JSON existente (ej. `symbols\fomt_symbols.json`).

---

## 4. Presets y Configuración Multi-Motor (`finis_engine_config.json`)

FIO Decomp incluye un sistema de perfiles multi-motor para adaptar el comportamiento de descompilación a las particularidades de cada desarrollador de GBA:

- **Marvelous Entertainment (`fomt`):** Mapeo de bytecode RIFF SCR, descompresión 0x70 Popuri y decodificación de diálogos.
- **Game Freak (`pokemon`):** Decodificación de tablas Huffman con tablas de frecuencias GBA, bitreaders nativos y saltos a engine de script.
- **Capcom (`capcom` / Mega Man Battle Network):** Descompresión RLE / LZ77 mixta, mitigación de horizontes de descompilación y soporte para arquitecturas masivas de eventos.
- **Camelot Software Planning (`camelot` / Golden Sun):** Tolerancia a superposición deliberada de rutinas ARM/Thumb (`camelotScratchTolerance`) y desensamblado de dispatchers directos.

Consulta la guía completa en [`docs/MANUAL_DE_CONFIGURACION_Y_MOTORES.md`](docs/MANUAL_DE_CONFIGURACION_Y_MOTORES.md).

---

## 5. Términos de Licencia y Directrices de Publicación Obligatoria (GNU GPLv3)

Este software es software libre y está licenciado bajo la **GNU General Public License v3.0 (GPLv3)**.

### ⚠️ Regla Obligatoria para Proyectos Derivados y Descompilaciones:

Cualquier juego, ROM o proyecto descompilado total o parcialmente utilizando **FIO Decomp (FINIS OMNIVM IMPOSSIBILIVM)** que sea publicado, compartido o distribuido públicamente, **DEBE cumplir estrictamente con los siguientes requisitos**:

1. **Alojamiento en GitHub:**
   - Todo juego descompilado con este software debe ser subido y publicado en un repositorio de GitHub.

2. **Nomenclatura Obligatoria del Repositorio:**
   - El repositorio debe mantener obligatoriamente el formato con el sufijo/prefijo:
     ```
     FIO-DECOMP-(NOMBRE DE JUEGO)
     ```
     *(Ejemplos: `FIO-DECOMP-HARVEST-MOON-FOMT`, `FIO-DECOMP-MEGA-MAN-BATTLE-NETWORK`, `FIO-DECOMP-POKEMON-EMERALD`, `FIO-DECOMP-GOLDEN-SUN`).*

3. **Atribución y Créditos Obligatorios:**
   - Debe incluirse de forma visible en la cabecera del `README.md` del repositorio descompilado la atribución directa a este proyecto:
     ```markdown
     > Descompilado con [FIO Decomp - FINIS OMNIVM IMPOSSIBILIVM](https://github.com/Denisovich728/GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM)
     > Licenciado bajo los términos de la GNU GPLv3.
     ```

4. **Reciprocidad GPLv3:**
   - Conforme a la licencia GPLv3, las herramientas, mejoras o adaptaciones al pipeline de descompilación deben permanecer de código abierto y bajo la misma licencia.

---

## 6. Licencias de Terceros y Componentes Integrados (Third-Party Licenses)

Este proyecto integra y se apoya en tecnologías y motores de código abierto excepcionales, cuyos derechos de autor y licencias originales se respetan y reconocen íntegramente:

1. **Ghidra Software Reverse Engineering Framework**
   - **Autor:** National Security Agency (NSA) y la comunidad de Ghidra.
   - **Licencia:** [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) (Consulte [`licenses/LICENSE-GHIDRA-APACHE2.txt`](licenses/LICENSE-GHIDRA-APACHE2.txt)).
   - **Uso en FIO Decomp:** Motor central de análisis estático, desensamblado cruzado ARM/Thumb y descompilación de P-Code a lenguaje C (`core/FinisOmnivmOrchestrator.java`).

2. **mGBA (Game Boy Advance Emulator)**
   - **Autor:** Jeffrey Pfau (endrift) y colaboradores del proyecto mGBA.
   - **Licencia:** [Mozilla Public License Version 2.0 (MPL-2.0)](https://www.mozilla.org/en-US/MPL/2.0/) (Consulte [`licenses/LICENSE-MGBA-MPL2.txt`](licenses/LICENSE-MGBA-MPL2.txt)).
   - **Uso en FIO Decomp:** Ejecución headless silenciosa (`emulator/mgba-sdl.exe`, `emulator/mGBA.exe`) para análisis dinámico, extracción en caliente de tablas de salto, interrupciones de hardware y telemetría de ejecución. El código fuente completo de mGBA está disponible en su repositorio oficial: [https://github.com/mgba-emu/mgba](https://github.com/mgba-emu/mgba).


