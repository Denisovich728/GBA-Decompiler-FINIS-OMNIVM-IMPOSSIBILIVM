"""Canal de control entre el motor (lift.py) y la consola de mando (console.py).

Comunicacion por archivos en <arbol>/control/ (robusto ante cierres y apagones):
  commands.txt   la consola agrega lineas; el motor las consume
  status.json    el motor publica su estado en vivo
  engine.log     copia (tee) de todo lo que imprime el motor
"""
import json
import os
import sys
import time
from pathlib import Path

from common import TREE_DIR

CTL_DIR = TREE_DIR / "control"
CMD_FILE = CTL_DIR / "commands.txt"
STATUS_FILE = CTL_DIR / "status.json"
LOG_FILE = CTL_DIR / "engine.log"


class Tee:
    def __init__(self, stream, path):
        self.stream = stream
        self.f = open(path, "a", encoding="utf-8", errors="replace")

    def write(self, s):
        self.stream.write(s)
        self.f.write(s)
        return len(s)

    def flush(self):
        self.stream.flush()
        self.f.flush()

    def __getattr__(self, k):
        return getattr(self.stream, k)


class Control:
    def __init__(self):
        CTL_DIR.mkdir(parents=True, exist_ok=True)
        CMD_FILE.write_text("", encoding="utf-8")  # comandos viejos no se re-ejecutan
        self.offset = 0
        self.paused = False
        self.stop = False
        self.skip = False          # abandonar funcion actual
        self.retry = False         # reiniciar intentos de la funcion actual
        self.reset_all = False     # rebobinar lote a la primera funcion (func_080002E0)
        self.accept = False        # aceptar mejor candidato actual como approx manual
        self.extra_now = 0         # intentos extra para la funcion actual
        self.permute_now = 0       # iteraciones de permutador inmediatas
        self.minutes = None        # nuevo tope de minutos (funcion actual)
        self.extra_for = {}        # {func: intentos extra}
        self.skip_names = set()
        self.priority = []         # funciones a procesar a continuacion
        self.current = None
        self.status = {"phase": "idle"}
        self._last = 0.0

    # ---- estado publicado ----
    def publish(self, force=False, **kw):
        self.status.update(kw)
        now = time.time()
        if not force and now - self._last < 0.4:
            return
        self._last = now
        self.status["paused"] = self.paused
        self.status["ts"] = now
        tmp = STATUS_FILE.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self.status), encoding="utf-8")
            os.replace(tmp, STATUS_FILE)
        except OSError:
            pass

    # ---- comandos ----
    def poll(self):
        try:
            data = CMD_FILE.read_text(encoding="utf-8")
        except OSError:
            return
        if len(data) < self.offset:
            self.offset = 0
        chunk = data[self.offset:]
        if "\n" not in chunk:
            return
        complete = chunk[: chunk.rfind("\n") + 1]
        self.offset += len(complete)
        for line in complete.splitlines():
            self._apply(line.strip())

    def _apply(self, line):
        if not line:
            return
        p = line.split()
        cmd, args = p[0].lower(), p[1:]
        fn = next((a for a in args if a.startswith("func_")), None)
        nums = [int(a) for a in args if a.lstrip("-").isdigit()]
        n = nums[0] if nums else None
        say = lambda m: print(f"  [consola] {m}", flush=True)
        if cmd == "pause":
            self.paused = True; say("PAUSA (termina la operacion en curso)")
        elif cmd == "resume":
            self.paused = False; say("continuar")
        elif cmd == "skip":
            if fn:
                self.skip_names.add(fn); say(f"{fn} sera saltada cuando le toque")
            else:
                self.skip = True; say("saltar funcion actual")
        elif cmd == "retry":
            self.retry = True; say("reiniciar intentos de la funcion actual")
        elif cmd == "more" and n:
            if fn and fn != self.current:
                self.extra_for[fn] = self.extra_for.get(fn, 0) + n; say(f"+{n} intentos para {fn}")
            else:
                self.extra_now += n; say(f"+{n} intentos para la funcion actual")
        elif cmd == "minutes" and n:
            self.minutes = n; say(f"tope de tiempo de la funcion actual = {n} min")
        elif cmd == "permute" and n:
            self.permute_now += n; say(f"+{n} iteraciones de permutador sobre el mejor")
        elif cmd == "accept":
            self.accept = True; say("aceptar mejor candidato actual (manual)")
        elif cmd in ("goto", "prio") and fn:
            self.priority.append(fn)
            if cmd == "goto":
                self.skip = True
            say(f"{fn} se procesara {'ahora' if cmd == 'goto' else 'a continuacion'}")
        elif cmd in ("start", "go"):
            say("el motor ya esta en ejecucion")
        elif cmd == "stop":
            self.stop = True; self.skip = True; say("detener tras guardar la funcion actual")
        elif cmd == "reset":
            from common import reset_all_progress
            res = reset_all_progress()
            self.reset_all = True
            say(f"PROGRESO REINICIADO DESDE 0 ({res['removed_wip']} wip borrados, {res['restored_c']} restaurados) -> rebobinando a funcion #1")
        else:
            say(f"comando desconocido: {line}")

    def wait_if_paused(self):
        if not self.paused:
            return
        self.publish(force=True, phase="PAUSADO")
        while self.paused and not self.stop:
            time.sleep(0.5)
            self.poll()
            self.publish(phase="PAUSADO")

    def interrupted(self):
        """Para bucles internos: True si hay que abortar la operacion en curso."""
        self.poll()
        return self.skip or self.retry or self.reset_all or self.accept or self.stop or self.permute_now > 0


def install_tee():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    CTL_DIR.mkdir(parents=True, exist_ok=True)
    if os.environ.get("FOMT_UNIFIED") == "1":
        return  # el orquestador (run_sweep.py) ya vuelca la salida del subproceso a engine.log
    sys.stdout = Tee(sys.stdout, LOG_FILE)
