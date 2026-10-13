# ==============================================================================
#  FINIS OMNIVM IMPOSSIBILIVM  ::  UNIVERSAL EMULATOR BRIDGE & JUMP SCANNER
#  Static Jump Table Extractor + Dynamic mGBA GDB Execution Tracer
# ==============================================================================

import os
import sys
import time
import socket
import struct
import json
import argparse
import subprocess

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2345
MGBA_PATH_DEFAULT = r"C:\Program Files\mGBA\mgba-sdl.exe"
MGBA_GUI_DEFAULT = r"C:\Program Files\mGBA\mGBA.exe"

class EmulatorGDBClient:
    """Cliente GDB socket de alta velocidad para mGBA"""
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self, timeout=3.0):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            self.sock.send(b"+")
            print(f"[*] Conectado exitosamente a mGBA GDB stub en {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] No se pudo conectar a mGBA en {self.host}:{self.port}: {e}")
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_cmd(self, cmd):
        if not self.sock:
            return b""
        checksum = sum(cmd.encode('ascii')) % 256
        packet = f"${cmd}#{checksum:02x}"
        self.sock.send(packet.encode('ascii'))
        
        resp = b""
        in_pack = False
        try:
            while True:
                ch = self.sock.recv(1)
                if not ch:
                    break
                if ch == b"$":
                    in_pack = True
                    resp = b""
                    continue
                if in_pack:
                    if ch == b"#":
                        self.sock.recv(2)
                        break
                    resp += ch
        except Exception:
            pass
        return resp

    def read_registers(self):
        res = self.send_cmd("g")
        if not res or res == b"-":
            return None
        hex_data = res.decode('ascii', errors='ignore')
        regs = {}
        reg_names = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"]
        for i, name in enumerate(reg_names):
            idx = i * 8
            if idx + 8 <= len(hex_data):
                val_hex = hex_data[idx:idx+8]
                val = int("".join(reversed([val_hex[j:j+2] for j in range(0, 8, 2)])), 16)
                regs[name] = val
        return regs

    def step(self):
        return self.send_cmd("s")

    def continue_exec(self):
        checksum = sum(b"c") % 256
        self.sock.send(f"$c#{checksum:02x}".encode('ascii'))

    def pause(self):
        if self.sock:
            self.sock.send(b"\x03")

def extract_universal_jump_tables(rom_bytes, base_addr=0x08000000):
    """
    Escaneo universal exhaustivo de Jump Tables en ARM / Thumb:
    1. Tablas Inline: mov pc, rX o bx rX seguidas de array de punteros
    2. Tablas Literal Pool: LDR rX, [PC, #imm] cargando puntero a tabla
    """
    tables = {}
    rom_len = len(rom_bytes)
    code_start = base_addr + 0xC0
    code_end = base_addr + rom_len

    # 1. Inline switch tables
    for off in range(0x0C0, rom_len - 12, 2):
        op = struct.unpack('<H', rom_bytes[off:off+2])[0]
        jump_site = base_addr + off
        
        # mov pc, rX (0x4687..0x468f) o bx rX (0x4700..0x4778)
        is_jump = ((op & 0xFF87) == 0x4687) or ((op & 0xFF80) == 0x4700)
        if not is_jump:
            continue
            
        tbl_off = (off + 2 + 3) & ~3
        if tbl_off + 8 >= rom_len:
            continue
            
        p0 = struct.unpack('<I', rom_bytes[tbl_off:tbl_off+4])[0]
        p1 = struct.unpack('<I', rom_bytes[tbl_off+4:tbl_off+8])[0]
        if (code_start <= (p0 & ~1) < code_end) and (code_start <= (p1 & ~1) < code_end):
            targets = []
            curr = tbl_off
            while curr + 4 <= rom_len:
                val = struct.unpack('<I', rom_bytes[curr:curr+4])[0]
                t_clean = val & ~1
                if code_start <= t_clean < code_end:
                    targets.append(val)
                    curr += 4
                else:
                    break
            if len(targets) >= 2:
                js_key = f"0x{jump_site:08X}"
                tables[js_key] = {
                    "jump_site": js_key,
                    "table_addr": f"0x{base_addr + tbl_off:08X}",
                    "jump_type": "INLINE_MOV_PC" if (op & 0xFF87) == 0x4687 else "INLINE_BX",
                    "entry_count": len(targets),
                    "unique_targets": len(set(targets)),
                    "targets": [f"0x{t:08X}" for t in sorted(list(set(targets)))],
                    "case_mapping": [f"case {idx}: 0x{t:08X}" for idx, t in enumerate(targets)]
                }

    # 2. Pool-referenced jump tables
    for off in range(0x0C0, rom_len - 12, 2):
        op = struct.unpack('<H', rom_bytes[off:off+2])[0]
        jump_site = base_addr + off
        is_jump = ((op & 0xFF87) == 0x4687) or ((op & 0xFF80) == 0x4700)
        if not is_jump:
            continue
            
        js_key = f"0x{jump_site:08X}"
        if js_key in tables:
            continue

        for back in range(2, 28, 2):
            if off - back < 0:
                break
            prev_op = struct.unpack('<H', rom_bytes[off-back:off-back+2])[0]
            if (prev_op & 0xF800) == 0x4800: # LDR rX, [PC, #imm]
                imm8 = prev_op & 0xFF
                pc_base = ((off - back + 4) & ~3)
                pool_off = pc_base + (imm8 * 4)
                if pool_off + 4 <= rom_len:
                    ptr = struct.unpack('<I', rom_bytes[pool_off:pool_off+4])[0]
                    ptr_clean = ptr & ~1
                    if code_start <= ptr_clean < code_end:
                        tbl_off = ptr_clean - base_addr
                        if 0 <= tbl_off < rom_len - 12:
                            p0 = struct.unpack('<I', rom_bytes[tbl_off:tbl_off+4])[0]
                            p1 = struct.unpack('<I', rom_bytes[tbl_off+4:tbl_off+8])[0]
                            if (code_start <= (p0 & ~1) < code_end) and (code_start <= (p1 & ~1) < code_end):
                                targets = []
                                curr = tbl_off
                                while curr + 4 <= rom_len:
                                    val = struct.unpack('<I', rom_bytes[curr:curr+4])[0]
                                    t_clean = val & ~1
                                    if code_start <= t_clean < code_end:
                                        targets.append(val)
                                        curr += 4
                                    else:
                                        break
                                if len(targets) >= 2:
                                    tables[js_key] = {
                                        "jump_site": js_key,
                                        "table_addr": f"0x{ptr_clean:08X}",
                                        "jump_type": "POOL_LDR_TABLE",
                                        "entry_count": len(targets),
                                        "unique_targets": len(set(targets)),
                                        "targets": [f"0x{t:08X}" for t in sorted(list(set(targets)))],
                                        "case_mapping": [f"case {idx}: 0x{t:08X}" for idx, t in enumerate(targets)]
                                    }
                                break

    return list(tables.values())

def trace_live_emulator(client, max_steps=10000, base_addr=0x08000000, rom_len=0x1000000):
    print(f"[*] Iniciando trazado dinamico contextualizador ({max_steps} pasos)...")
    dynamic_hits = {}
    code_start = base_addr + 0xC0
    code_end = base_addr + rom_len
    
    last_pc = 0
    client.pause()
    
    for step_i in range(max_steps):
        client.step()
        regs = client.read_registers()
        if not regs:
            continue
        pc = regs.get("pc", 0)
        cpsr = regs.get("cpsr", 0)
        is_thumb = (cpsr & 0x20) != 0
        
        if last_pc != 0 and abs(pc - last_pc) > 4:
            if code_start <= last_pc < code_end or code_start <= pc < code_end:
                key = f"0x{last_pc:08X}->0x{pc:08X}"
                if key not in dynamic_hits:
                    dynamic_hits[key] = {
                        "source": f"0x{last_pc:08X}",
                        "target": f"0x{pc:08X}",
                        "mode": "THUMB" if is_thumb else "ARM",
                        "count": 1
                    }
                else:
                    dynamic_hits[key]["count"] += 1
                    
        last_pc = pc
        if (step_i + 1) % 2500 == 0:
            print(f"  -> {step_i + 1}/{max_steps} pasos trazados. Ramas capturadas: {len(dynamic_hits)}")
            
    client.continue_exec()
    print(f"[+] Trazado completado. {len(dynamic_hits)} saltos dinamicos registrados.")
    return list(dynamic_hits.values())

def main():
    parser = argparse.ArgumentParser(description="Universal GBA Jump Scanner & Emulator Bridge")
    parser.add_argument("--rom", required=True, help="Ruta de la ROM .gba")
    parser.add_argument("--out", default="output/jump_context.json", help="Ruta de salida JSON")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host mGBA GDB")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto mGBA GDB")
    parser.add_argument("--trace", action="store_true", help="Trazar ramas dinamicas via mGBA GDB")
    parser.add_argument("--trace-steps", type=int, default=10000, help="Pasos a trazar")
    parser.add_argument("--launch-mgba", action="store_true", help="Lanzar mgba-sdl con gdb server")

    args = parser.parse_args()

    if not os.path.exists(args.rom):
        print(f"[-] ROM no encontrada: {args.rom}")
        sys.exit(1)

    with open(args.rom, "rb") as f:
        rom_bytes = f.read()

    game_title = rom_bytes[0xA0:0xAC].decode('ascii', errors='ignore').strip()
    game_code = rom_bytes[0xAC:0xB0].decode('ascii', errors='ignore').strip()
    print(f"[*] ROM Cargada: '{game_title}' [{game_code}] (Tamano: {len(rom_bytes) / (1024*1024):.2f} MB)")

    # 1. Extracción Estática Universal
    print("[1/2] Extrayendo Jump Tables estaticas (inline + literal pools)...")
    static_tables = extract_universal_jump_tables(rom_bytes)
    total_cases = sum(t["entry_count"] for t in static_tables)
    print(f"  -> {len(static_tables)} jump tables encontradas ({total_cases} casos totales).")

    # 2. Trazado Dinámico
    dynamic_branches = []
    if args.launch_mgba:
        if os.path.exists(MGBA_PATH_DEFAULT):
            print(f"[*] Lanzando mGBA SDL GDB: {MGBA_PATH_DEFAULT} -g \"{args.rom}\"")
            subprocess.Popen([MGBA_PATH_DEFAULT, "-g", args.rom])
            time.sleep(1.5)
        elif os.path.exists(MGBA_GUI_DEFAULT):
            print(f"[*] Lanzando mGBA GUI: {MGBA_GUI_DEFAULT} \"{args.rom}\"")
            subprocess.Popen([MGBA_GUI_DEFAULT, args.rom])
        else:
            print(f"[-] No se encontro mGBA en rutas conocidas.")

    if args.trace:
        client = EmulatorGDBClient(args.host, args.port)
        if client.connect():
            dynamic_branches = trace_live_emulator(client, max_steps=args.trace_steps, rom_len=len(rom_bytes))
            client.close()
        else:
            print("[-] No se pudo conectar a mGBA GDB. Omitiendo trazado dinamico.")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    context_data = {
        "game_title": game_title,
        "game_code": game_code,
        "rom_file": os.path.basename(args.rom),
        "total_jump_tables": len(static_tables),
        "total_cases": total_cases,
        "total_dynamic_branches": len(dynamic_branches),
        "jump_tables": static_tables,
        "dynamic_branches": dynamic_branches
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(context_data, f, indent=2)

    print(f"[+] Contexto exportado exitosamente a: {args.out}")

if __name__ == "__main__":
    main()
