# MANUAL DE CONFIGURACION, SWITCHES Y MOTORES GBA
## FIO DECOMP :: FINIS OMNIVM IMPOSSIBILIVM v1.3

---

## 1. Arquitectura de la Capa de Motores (Engine Profiles)

Los juegos de Game Boy Advance no fueron compilados con un único SDK estándar. Cada desarrollador de élite diseñó su propio compilador, gestor de memoria, arquitectura de llamadas y formato de empaquetado de assets:

* **Marvelous / Victor Interactive Software (HM: FoMT / MFoMT):** Código monolítico en bajo ROM con densas tablas de diálogo, zonas de trabajo EWRAM dedicadas y dispatchers `switch` calculados mediante índices base desplazados (`r0 << 2`).
* **Game Freak (Pokémon Gen 3):** Código C monolítico generado por GCC (`agbcc`), tablas `.rodata` delimitadas con alta pureza, motor de audio M4A/Sappy estándar y tabla de caracteres propietaria (`POKEMON_GEN3`, `0xBB..0xFE`).
* **Capcom / Flagship (Mega Man Battle Network, Minish Cap):** Código con *literal pools* y tablas de saltos en bytes (`00 04 08 0C...`) intercaladas dentro de las propias funciones. Utiliza rutinas críticas copiadas a la memoria rápida IWRAM (`0x08180000`) para interrupt handlers y renderers de sprites.
* **Camelot Software Planning (Golden Sun 1 y 2, Mario Golf / Tennis):** Arquitectura avanzada de **Overlays Segmentados**. El motor no es monolítico; además del núcleo de arranque, tiene motores secundarios (renderizador de batallas pseudo-3D, máquina virtual de scripts de eventos, motor de partículas de Psinergía) dispersos en bancos y clusters a lo largo de toda la ROM de 16 MB.

Para gobernar estas diferencias sin necesidad de modificar código fuente Java, **FIO Decomp v1.3** introduce un sistema de **Engine Profiles** y una **Tabla Maestra de Switches** parametrizable vía `finis_engine_config.json`.

---

## 2. Archivo de Configuración: `finis_engine_config.json`

El archivo de configuración reside en:
* `core/finis_engine_config.json` (leído por el orquestador Ghidra)
* `finis_engine_config.json` (copia en la raíz para edición rápida del usuario)

### Modos de Selección de Motor (`engine_mode`):
1. **`AUTO_DETECT` (Recomendado):** Lee la cabecera oficial GBA (`Game Title`, `Game Code`, `Maker Code`) al iniciar la ROM y asocia automáticamente el perfil correspondiente (`marvelous`, `game_freak`, `capcom`, `camelot` o `generic_gba`).
2. **Forzado Manual (`active_preset_override`):** Permite fijar un perfil explícito independientemente de la cabecera (por ejemplo: `"camelot"` o `"capcom"`).

---

## 3. Presets Oficiales Incorporados

### A. Preset `marvelous`
* **Juegos Objetivo:** *Harvest Moon: Friends of Mineral Town* (`A44E`), *More Friends of Mineral Town* (`BFGE`).
* **Horizonte:** `CONTINUOUS_PERMISSIVE` (Escaneo continuo hasta ~1.6 MB).
* **Heurística de Texto:** Filtro lingüístico ASCII Latin ajustado a diálogos de granja y nombres de herramientas.
* **Jump Tables:** Reconocimiento de tablas de punteros calculadas con índice `r0` y escalado `lsl #2`.
* **Filtro de Assets:** Shannon Entropy Cutoff `7.85` + aislamiento de bancos M4A.

### B. Preset `game_freak`
* **Juegos Objetivo:** *Pokémon Emerald* (`BPEE`), *Pokémon Ruby/Sapphire* (`AXVE`), *FireRed/LeafGreen* (`BPRE`).
* **Horizonte:** `CONTINUOUS_STRICT` (Corte riguroso en frontera `.rodata` ~1.95 MB).
* **Heurística de Texto:** Mapeo de tabla de caracteres `POKEMON_GEN3` (`0xBB - 0xFE` con terminador `0xFF`).
* **Jump Tables:** Despachadores con interworking ARM/Thumb y GCC computed tables.
* **Filtro de Assets:** Shannon Entropy Cutoff `7.92` con aislamiento profundo de tablas de audio y bloques LZ77/Huffman.

### C. Preset `capcom`
* **Juegos Objetivo:** *Mega Man Battle Network 1 al 6* (`AREE`, `AE2E`, `A6BE`), *Zelda: The Minish Cap* (`BZMP`).
* **Horizonte:** `CONTINUOUS_PERMISSIVE` con tolerancia a *literal pools* intercalados y tablas de chips en línea (evita el falso corte en los 314 KB y expande el horizonte a 660 KB+).
* **Memoria y Overlays:** Escaneo e inyección de rutinas rápidas de IWRAM (`0x08180000`).
* **Jump Tables:** Reconocimiento de tablas compactas de saltos indexadas en bytes (`00 04 08 0C...`).
* **Guardián:** Supresión de falsos positivos causados por punteros little-endian (`xx B5`).

### D. Preset `camelot`
* **Juegos Objetivo:** *Golden Sun* (`AGSE`), *Golden Sun: The Lost Age* (`AGFE`), *Mario Golf: Advance Tour* (`BMGE`), *Mario Tennis: Power Tour* (`BM8E`).
* **Horizonte:** `SEGMENTED_OVERLAYS` (Escaneo multi-cluster en la ROM completa de 16 MB).
* **Memoria BIOS:** Inicialización de vectores de interrupción en `0x00000000..0x00004000` (resuelve los errores `Unable to read bytes at ram:0000000a / 0000001c`).
* **Convención de Registros:** Tolerancia a llamadas con preservación atípica de registros scratch (`r4-r8`), resolviendo las advertencias de stack y variables de arrastre (`unaff_r6`).
* **Jump Tables:** Despachadores de máquina virtual de eventos de Camelot + tablas de saltos en ramas de batalla.

---

## 4. Tabla Maestra de Switches (Switchboard)

| Switch / Clave JSON | Tipo | Rango / Valores | Defecto | Descripción y Efecto en el Motor |
| :--- | :--- | :--- | :--- | :--- |
| `engine_mode` | String | `AUTO_DETECT`, `MANUAL` | `AUTO_DETECT` | Define si el motor se auto-configura por cabecera ROM o si se fuerza. |
| `active_preset_override` | String | `AUTO`, `marvelous`, `game_freak`, `capcom`, `camelot`, `generic_gba` | `AUTO` | Sobrescribe el perfil activo sin importar qué ROM se cargue. |
| `guardian_strictness_level` | Int | `1` (Permisivo), `2` (Equilibrado), `3` (Estricto) | `2` | Nivel de protección contra funciones huérfanas y código corrupto. |
| `max_decompiler_timeout_seconds` | Int | `10` .. `300` seg | `60` | Tiempo límite por función antes de abortar por seguridad. |
| `max_function_loc_threshold` | Int | `500` .. `10000` líneas | `3000` | Umbral máximo de LOC en C para alertar o segmentar mega-funciones. |
| `purge_spurious_orphans` | Bool | `true`, `false` | `true` | Elimina fragmentos y pseudo-funciones huérfanas descubiertas sin llamadas. |
| `lock_return_epilogues` | Bool | `true`, `false` | `true` | Bloquea el flujo en `bx lr` y `pop {..., pc}` impidiendo fallthrough a datos. |
| `initialize_bios_vectors` | Bool | `true`, `false` | `true` | Inicializa la memoria BIOS (`0x00000000`) con vectores para evitar errores Pcode. |
| **`code_horizon.mode`** | String | `CONTINUOUS_STRICT`, `CONTINUOUS_PERMISSIVE`, `SEGMENTED_OVERLAYS` | Dinámico | Determina cómo se delimita el código frente a los bancos de datos. |
| `code_horizon.window_size_bytes` | Int | `512` .. `4096` bytes | `2048` | Tamaño de ventana de análisis continuo de instrucciones. |
| `code_horizon.max_scan_mb` | Int | `1` .. `32` MB | Dinámico | Límite máximo de escaneo continuo en el espacio de memoria ROM. |
| `code_horizon.streak_tolerance_kb` | Int | `8` .. `128` KB | Dinámico | Tolerancia de datos no ejecutables consecutivos antes de declarar fin de .text. |
| `code_horizon.illegal_opcode_max_ratio`| Float | `0.01` .. `0.15` | `0.05` | Tasa máxima tolerable de opcodes ilegales por ventana en código válido. |
| `code_horizon.max_text_density_ratio` | Float | `0.40` .. `0.90` | `0.65` | Densidad máxima de caracteres ASCII antes de clasificar ventana como texto. |
| `code_horizon.allow_inline_literal_pools`| Bool | `true`, `false` | Dinámico | Permite que las funciones contengan constantes/punteros en su interior. |
| `code_horizon.inline_data_tolerance_ratio`| Float | `0.05` .. `0.20` | `0.12` | Tolerancia de datos intercalados en funciones de Capcom/Camelot. |
| `code_horizon.allow_segmented_overlays` | Bool | `true`, `false` | `true` (Camelot) | Habilita búsqueda de múltiples clusters de código a lo largo de toda la ROM. |
| `code_horizon.min_overlay_cluster_kb` | Int | `4` .. `64` KB | `8` | Tamaño mínimo de un cluster para ser considerado sub-motor/overlay. |
| `hardware_memory.init_bios_vectors` | Bool | `true`, `false` | `true` | Previene excepciones de lectura de punteros nulos y vectores de interrupción. |
| `hardware_memory.map_ewram_size_kb` | Int | `128` .. `512` KB | `256` | Tamaño mapeado de la memoria RAM externa (`0x02000000`). |
| `hardware_memory.map_iwram_size_kb` | Int | `32` .. `64` KB | `32` | Tamaño mapeado de la memoria RAM interna de alta velocidad (`0x03000000`). |
| `hardware_memory.scan_iwram_fast_overlays`| Bool | `true`, `false` | Dinámico | Escanea si la ROM contiene rutinas diseñadas para copiarse a IWRAM. |
| `asset_hunter.enable_entropy_filter` | Bool | `true`, `false` | `true` | Filtra activos multimedia mediante cálculo de Entropía de Shannon. |
| `asset_hunter.shannon_entropy_cutoff` | Float | `7.0` .. `8.0` | `7.85` | Umbral sobre el cual los bloques se bloquean como datos comprimidos/audio. |
| `asset_hunter.isolate_m4a_music_banks`| Bool | `true`, `false` | `true` | Detecta firmas acústicas M4A y aísla voicegroups, songtables y wave data. |
| `asset_hunter.isolate_lz77_blocks` | Bool | `true`, `false` | `true` | Reconoce cabeceras BIOS LZ77 (`0x10`, `0x11`) y las excluye de decompilación. |
| `text_hunter.charset_mode` | String | `ASCII`, `ASCII_LATIN`, `POKEMON_GEN3`, `ASCII_CAPCOM`, `ASCII_CAMELOT` | Dinámico | Tabla de decodificación y mapeo de caracteres utilizada. |
| `text_hunter.min_string_length` | Int | `2` .. `10` chars | `4` | Longitud mínima de cadena para considerarse texto legítimo. |
| `jump_tables.allow_byte_offset_tables`| Bool | `true`, `false` | Dinámico | Habilita el reconocimiento de tablas de saltos en bytes (estilo Capcom MMBN). |
| `jump_tables.allow_word_pointer_tables`| Bool | `true`, `false` | `true` | Habilita el reconocimiento de tablas de saltos con punteros de 32 bits. |
| `jump_tables.allow_camelot_script_tables`| Bool | `true`, `false` | `true` (Camelot) | Reconoce despachadores de máquina virtual de eventos de Golden Sun. |
| `decompiler_guardian.camelot_scratch_reg_tolerance`| Bool| `true`, `false` | `true` (Camelot) | Suprime advertencias de registros scratch no convencionales (`unaff_r6`). |

---

## 5. Estudio Forense: Golden Sun & Camelot Engine

### ¿Por qué Golden Sun: The Lost Age arrojó 33,885 líneas?
1. **El corte en 452 KB:**
   * En el modo universal estándar, el delimitador continuo detectó un hueco de datos a la altura de `0x08071428` y cortó el horizonte.
   * Eso capturó 697 funciones (33,885 líneas de C), que representan únicamente el **motor de arranque, menús base y cinemática inicial**.
2. **La Arquitectura Multi-Cluster de Camelot:**
   * Golden Sun 2 contiene **más de 7 grandes clusters de código** distribuidos a lo largo de los 16 MB de la ROM:
     * `0x08000654 - 0x080B1EE0` (~700 KB): Motor de campo, menús y movimiento.
     * `0x080C8978 - 0x0815F16C` (~550 KB): Sistema de combate y cálculo de estadísticas.
     * `0x082503B4 - 0x0829C904` (~310 KB): Renderizador pseudo-3D y transformaciones afines de batalla.
     * `0x08307510 - 0x084276F2` (~1.1 MB): Efectos visuales de Psinergía e invocaciones de Djinn.
     * `0x08484F54 - 0x08560146` (~900 KB): Máquina virtual de scripts de diálogos y eventos.
     * `0x0868074C - 0x087F8AA6` (~1.5 MB): Generador de mapas del mundo y navegación marítima.
     * `0x087FCF4A - 0x08EBF7D8` (~7.0 MB): Sub-rutinas de eventos y datos procedurales.
   * Al activar el preset `camelot` con `SEGMENTED_OVERLAYS: true`, el motor ahora escanea y enlaza **todos los clusters**, multiplicando el volumen de código extraído.

### ¿Qué significan las líneas con `unaff_r6`?
* En C estándar bajo GCC, los registros `r4..r7` se guardan en la pila (`push`) y se restauran (`pop`).
* Los programadores de Camelot escribieron rutinas en ensamblador a mano donde ciertas funciones auxiliares **no salvan `r6` ni `r7`**, sino que los esperan vivos del llamador anterior para maximizar la velocidad de dibujado.
* Ghidra interpreta esto como un registro "no afectado" (`unaffected register`) y genera variables como `(int)unaff_r6 + 0x16`. Con el switch `camelot_scratch_reg_tolerance: true`, el guardián modela estas llamadas con parámetros sintéticos limpios.

### ¿Por qué aparecían errores `Unable to read bytes at ram:0000000a`?
* Camelot llama directamente a la BIOS en el rango `0x00000000..0x00004000` (rutinas de división, desenpaquetado y vectores de interrupción).
* Al crearse la BIOS como bloque no inicializado en memoria, el descompilador no encontraba bytes que leer y lanzaba advertencias.
* Con el switch `initialize_bios_vectors: true`, la BIOS se crea como memoria inicializada con vectores estándar de Game Boy Advance, eliminando por completo esos 161 mensajes de error del log.

---

## 6. Instrucciones de Uso

### Uso Automático
Simplemente ejecuta `FINIS_OMNIVM.bat` o `FIO_Decomp.bat` y selecciona la ROM. El motor detectará el juego y aplicará su perfil correspondiente.

### Uso Personalizado
1. Abre `finis_engine_config.json` en cualquier editor de texto.
2. Modifica cualquier parámetro de la sección `global_engine_settings` o del preset que desees ajustar.
3. Guarda el archivo y ejecuta el descompilador. El sistema recargará los valores automáticamente en la Fase 0.
