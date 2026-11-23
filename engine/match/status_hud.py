"""FOMT-MATCH-ENGINE :: PANEL DE CONTROL Y MONITOR MULTI-THREAD (STATUS HUD)
Ventana independiente en PyQt6 que monitorea el latido del motor de descompilacion,
la paridad global y los 4 flujos paralelos de ejecucion [F1], [F2], [F3], [F4].
Auto-adaptada a la resolucion y escalado DPI del monitor.
"""
import os
import re
import sys
import json
import time
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QGuiApplication
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QProgressBar, QPlainTextEdit, QFrame,
    QPushButton, QSplitter, QSizePolicy
)

# Constantes del entorno
WORKSPACE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_FILE = WORKSPACE_DIR / "logs" / "tanda_multithread.log"
STATE_FILE = WORKSPACE_DIR / "src_sweep" / "state.json"
SKIP_FLAG = WORKSPACE_DIR / "logs" / "skip.flag"

COLOR_BG_MAIN = "#0d1117"
COLOR_BG_CARD = "#161b22"
COLOR_BG_TERM = "#090d13"
COLOR_BORDER = "#30363d"
COLOR_TEXT_PRIMARY = "#f0f6fc"
COLOR_TEXT_MUTED = "#8b949e"
COLOR_CYAN = "#58a6ff"
COLOR_GREEN = "#3fb950"
COLOR_AMBER = "#d29922"
COLOR_RED = "#f85149"
COLOR_PURPLE = "#bc8cff"


class WorkerCard(QFrame):
    """Panel visual para un worker individual [F1]..[F4] optimizado para resolucion compacta."""
    def __init__(self, worker_id: str, parent=None):
        super().__init__(parent)
        self.worker_id = worker_id
        self.setObjectName("WorkerCard")
        self.setStyleSheet(f"""
            QFrame#WorkerCard {{
                background-color: {COLOR_BG_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 2px;
            }}
        """)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        # Encabezado del Worker
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        self.lbl_title = QLabel(f"WORKER [{self.worker_id}]")
        self.lbl_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.lbl_title.setStyleSheet(f"color: {COLOR_CYAN};")
        header_layout.addWidget(self.lbl_title)

        header_layout.addStretch()

        self.lbl_badge = QLabel("INACTIVO")
        self.lbl_badge.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self.lbl_badge.setStyleSheet(f"""
            background-color: #21262d;
            color: {COLOR_TEXT_MUTED};
            padding: 1px 6px;
            border-radius: 8px;
            border: 1px solid {COLOR_BORDER};
        """)
        header_layout.addWidget(self.lbl_badge)
        layout.addLayout(header_layout)

        # Caja de Ficha Tecnica de la Funcion Activa
        info_box = QFrame()
        info_box.setStyleSheet(f"""
            background-color: {COLOR_BG_MAIN};
            border: 1px solid #21262d;
            border-radius: 5px;
            padding: 2px;
        """)
        info_layout = QGridLayout(info_box)
        info_layout.setContentsMargins(5, 4, 5, 4)
        info_layout.setSpacing(2)

        self.lbl_fn_name = QLabel("Sin funcion asignada")
        self.lbl_fn_name.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        self.lbl_fn_name.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY};")
        info_layout.addWidget(self.lbl_fn_name, 0, 0, 1, 2)

        self.lbl_fn_meta = QLabel("Tamano: 0B | Preset: -")
        self.lbl_fn_meta.setFont(QFont("Segoe UI", 7, QFont.Weight.DemiBold))
        self.lbl_fn_meta.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        info_layout.addWidget(self.lbl_fn_meta, 1, 0, 1, 2)

        # Barra de progreso de paridad
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 10000)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("0.00%")
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #21262d;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                text-align: center;
                color: {COLOR_TEXT_PRIMARY};
                font-weight: bold;
                font-size: 10px;
                height: 15px;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_CYAN};
                border-radius: 2px;
            }}
        """)
        info_layout.addWidget(self.progress_bar, 2, 0, 1, 2)

        self.lbl_round = QLabel("Ronda: - | Evals: 0")
        self.lbl_round.setFont(QFont("Segoe UI", 7, QFont.Weight.DemiBold))
        self.lbl_round.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        info_layout.addWidget(self.lbl_round, 3, 0)

        self.lbl_diff = QLabel("Diff: -")
        self.lbl_diff.setFont(QFont("Consolas", 7))
        self.lbl_diff.setStyleSheet(f"color: {COLOR_AMBER};")
        info_layout.addWidget(self.lbl_diff, 4, 0, 1, 2)

        layout.addWidget(info_box)

        # Terminal de Logs del Worker
        self.terminal = QPlainTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setMaximumBlockCount(1500)
        self.terminal.setFont(QFont("Consolas", 8))
        self.terminal.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLOR_BG_TERM};
                color: #7ee787;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 2px;
            }}
        """)
        layout.addWidget(self.terminal, 1)

    def set_badge(self, text: str, color_hex: str):
        self.lbl_badge.setText(text)
        self.lbl_badge.setStyleSheet(f"""
            background-color: {color_hex}22;
            color: {color_hex};
            padding: 1px 6px;
            border-radius: 8px;
            border: 1px solid {color_hex}66;
            font-weight: bold;
        """)

    def update_state(self, fn_name: str, size: int, score: float, round_num: int, evals: int, preset: str, diff_str: str, status_tag: str):
        self.lbl_fn_name.setText(fn_name)
        self.lbl_fn_meta.setText(f"Tamano: {size}B | Preset: {preset}")
        
        pct = max(0.0, min(100.0, score * 100.0))
        self.progress_bar.setValue(int(pct * 100))
        self.progress_bar.setFormat(f"{pct:.2f}%")

        if pct >= 100.0:
            chunk_color = COLOR_GREEN
        elif pct >= 85.0:
            chunk_color = COLOR_CYAN
        elif pct >= 65.0:
            chunk_color = COLOR_AMBER
        else:
            chunk_color = COLOR_PURPLE

        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #21262d;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                text-align: center;
                color: {COLOR_TEXT_PRIMARY};
                font-weight: bold;
                font-size: 10px;
                height: 15px;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
                border-radius: 2px;
            }}
        """)

        self.lbl_round.setText(f"Ronda: #{round_num} | Evals: {evals}")
        if diff_str:
            self.lbl_diff.setText(f"{diff_str[:55]}...")
        else:
            self.lbl_diff.setText("Diff: byte-perfect")

        # Actualizar Badge
        if status_tag == "MATCH":
            self.set_badge("MATCH 100%", COLOR_GREEN)
        elif status_tag == "SUBIDA":
            self.set_badge("SUBIDA", COLOR_PURPLE)
        elif status_tag == "ROTANDO":
            self.set_badge("ROTANDO", COLOR_AMBER)
        elif status_tag == "ATACANDO":
            self.set_badge("ATACANDO", COLOR_CYAN)
        elif status_tag == "SEMILLA":
            self.set_badge("SEMILLA", COLOR_CYAN)

    def append_log(self, text: str):
        self.terminal.appendPlainText(text)
        sb = self.terminal.verticalScrollBar()
        sb.setValue(sb.maximum())


class StatusHUDWindow(QMainWindow):
    """Ventana principal del monitor de descompilacion auto-escalada al monitor."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FOMT MATCH ENGINE :: WORKER STATUS HUD")
        self.setStyleSheet(f"background-color: {COLOR_BG_MAIN}; color: {COLOR_TEXT_PRIMARY};")

        # Ajuste dinamico de resolucion al monitor primario
        screen = QGuiApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            # 95% del ancho disponible y 88% de la altura disponible para dejar espacio a barra de tareas y marco
            target_w = min(1480, max(980, int(avail.width() * 0.95)))
            target_h = min(820, max(540, int(avail.height() * 0.88)))
            self.resize(target_w, target_h)
            # Centrar la ventana en pantalla
            center_pt = avail.center()
            self.move(center_pt.x() - target_w // 2, center_pt.y() - target_h // 2)
        else:
            self.resize(1280, 720)

        self.file_pos = 0
        if LOG_FILE.exists():
            try:
                sz = LOG_FILE.stat().st_size
                self.file_pos = max(0, sz - 64 * 1024)
            except Exception:
                self.file_pos = 0

        self._init_ui()
        self._init_timers()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # Barra Superior: Header de Telemetria y Estado Global
        top_bar = QFrame()
        top_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {COLOR_BG_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 2px;
            }}
        """)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(8, 4, 8, 4)
        top_layout.setSpacing(10)

        # Titulo y Latido
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        lbl_app = QLabel("FOMT MATCH ENGINE")
        lbl_app.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        lbl_app.setStyleSheet(f"color: {COLOR_CYAN};")
        title_box.addWidget(lbl_app)

        self.lbl_engine_status = QLabel("VERIFICANDO MOTOR...")
        self.lbl_engine_status.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self.lbl_engine_status.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        title_box.addWidget(self.lbl_engine_status)
        top_layout.addLayout(title_box)

        top_layout.addStretch()

        # Medidores de Telemetria
        self.metric_matches = self._create_metric("MATCHES 100% C", "0 / 3068 (0.00%)", COLOR_GREEN)
        top_layout.addWidget(self.metric_matches)

        self.metric_text_cov = self._create_metric("COBERTURA .TEXT", "0 / 706,046 B (0.00%)", COLOR_CYAN)
        top_layout.addWidget(self.metric_text_cov)

        self.metric_parity = self._create_metric("PARIDAD PONDERADA", "0.00%", COLOR_PURPLE)
        top_layout.addWidget(self.metric_parity)

        self.metric_active = self._create_metric("COLA RESTANTE", "0 funcs", COLOR_AMBER)
        top_layout.addWidget(self.metric_active)

        # Boton de Accion Rapida: Saltar Funcion
        self.btn_skip = QPushButton("Saltar Funcion Actual")
        self.btn_skip.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self.btn_skip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_skip.setStyleSheet(f"""
            QPushButton {{
                background-color: #21262d;
                color: {COLOR_TEXT_PRIMARY};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 4px 10px;
            }}
            QPushButton:hover {{
                background-color: #30363d;
                border-color: {COLOR_AMBER};
                color: {COLOR_AMBER};
            }}
            QPushButton:pressed {{
                background-color: #161b22;
            }}
        """)
        self.btn_skip.clicked.connect(self._on_skip_clicked)
        top_layout.addWidget(self.btn_skip)

        main_layout.addWidget(top_bar)

        # Banner Intermedio: Ultimo Match Historico Detectado
        self.last_match_bar = QFrame()
        self.last_match_bar.setStyleSheet(f"""
            QFrame {{
                background-color: #0f1d15;
                border: 1px solid #238636;
                border-left: 4px solid {COLOR_GREEN};
                border-radius: 6px;
                padding: 3px 8px;
            }}
        """)
        lm_layout = QHBoxLayout(self.last_match_bar)
        lm_layout.setContentsMargins(8, 3, 8, 3)
        lm_layout.setSpacing(10)

        lbl_badge_lm = QLabel("ULTIMO MATCH 100% ZERO-DIFF")
        lbl_badge_lm.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        lbl_badge_lm.setStyleSheet(f"""
            background-color: #23863633;
            color: {COLOR_GREEN};
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid #23863688;
        """)
        lm_layout.addWidget(lbl_badge_lm)

        self.lbl_lm_func = QLabel("Cargando historial...")
        self.lbl_lm_func.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        self.lbl_lm_func.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY};")
        lm_layout.addWidget(self.lbl_lm_func)

        self.lbl_lm_details = QLabel("-")
        self.lbl_lm_details.setFont(QFont("Segoe UI", 8))
        self.lbl_lm_details.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        lm_layout.addWidget(self.lbl_lm_details)

        lm_layout.addStretch()

        self.lbl_lm_time = QLabel("")
        self.lbl_lm_time.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        self.lbl_lm_time.setStyleSheet(f"color: {COLOR_CYAN};")
        lm_layout.addWidget(self.lbl_lm_time)

        main_layout.addWidget(self.last_match_bar)

        # Seccion Central: 4 Columnas para los Workers F1..F4
        workers_container = QWidget()
        workers_layout = QHBoxLayout(workers_container)
        workers_layout.setContentsMargins(0, 0, 0, 0)
        workers_layout.setSpacing(6)

        self.workers = {}
        for wid in ("F1", "F2", "F3", "F4"):
            card = WorkerCard(wid)
            self.workers[wid] = card
            workers_layout.addWidget(card, 1)

        main_layout.addWidget(workers_container, 1)

        # Barra inferior de estado
        self.lbl_footer = QLabel(f"Directorio: {WORKSPACE_DIR} | Tanda Multi-Thread: logs/tanda_multithread.log")
        self.lbl_footer.setFont(QFont("Segoe UI", 7))
        self.lbl_footer.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        main_layout.addWidget(self.lbl_footer)

    def _create_metric(self, title: str, initial_value: str, color_hex: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            background-color: {COLOR_BG_MAIN};
            border: 1px solid #21262d;
            border-radius: 5px;
            padding: 2px 6px;
        """)
        box = QVBoxLayout(frame)
        box.setContentsMargins(4, 2, 4, 2)
        box.setSpacing(0)

        lbl_t = QLabel(title)
        lbl_t.setFont(QFont("Segoe UI", 6, QFont.Weight.Bold))
        lbl_t.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        box.addWidget(lbl_t)

        lbl_v = QLabel(initial_value)
        lbl_v.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lbl_v.setStyleSheet(f"color: {color_hex};")
        box.addWidget(lbl_v)
        frame.lbl_val = lbl_v
        return frame

    def _init_timers(self):
        # Timer de lectura continua de logs (cada 250ms)
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self._poll_logs)
        self.log_timer.start(250)

        # Timer de refresco de estado y proceso (cada 2500ms)
        self.state_timer = QTimer(self)
        self.state_timer.timeout.connect(self._refresh_state_and_process)
        self.state_timer.start(2500)
        self._refresh_state_and_process()

    def _on_skip_clicked(self):
        try:
            SKIP_FLAG.write_text("skip", encoding="utf-8")
            self.btn_skip.setText("Flag Skip Enviado!")
            self.btn_skip.setStyleSheet(f"""
                QPushButton {{
                    background-color: #3b2300;
                    color: {COLOR_AMBER};
                    border: 1px solid {COLOR_AMBER};
                    border-radius: 5px;
                    padding: 4px 10px;
                }}
            """)
            QTimer.singleShot(2500, lambda: self.btn_skip.setText("Saltar Funcion Actual"))
        except Exception as e:
            self.btn_skip.setText(f"Error: {e}")

    def _poll_logs(self):
        if not LOG_FILE.exists():
            return
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.file_pos)
                new_chunk = f.read()
                self.file_pos = f.tell()
                if new_chunk:
                    lines = new_chunk.splitlines()
                    for line in lines:
                        self._process_log_line(line)
        except Exception:
            pass

    def _process_log_line(self, line: str):
        # Detectar a que worker pertenece: [F1], [F2], [F3], [F4]
        m_w = re.search(r"\[(F[1-4])\]", line)
        if not m_w:
            return
        wid = m_w.group(1)
        card = self.workers.get(wid)
        if not card:
            return

        # Anadir a la terminal del worker
        card.append_log(line)

        # Parsear eventos de estado
        m_atk = re.search(
            r"\[ATACANDO\]\s+(\w+)\s+\((\d+)B\)\s+\|\s+Ronda\s+#(\d+)\s+\|\s+Evals:\s+(\d+)\s+\|.*?->\s+Actual:\s+([0-9.]+)%\s+\[([^\]]+)\](?:\s+\|\s+(Diff@[^|]+))?",
            line,
        )
        if m_atk:
            fn, sz, r_num, ev, act_pct, preset, diff = m_atk.groups()
            card.update_state(
                fn_name=fn,
                size=int(sz),
                score=float(act_pct) / 100.0,
                round_num=int(r_num),
                evals=int(ev),
                preset=preset,
                diff_str=diff or "",
                status_tag="ATACANDO",
            )
            return

        m_mat = re.search(r"\[MATCH(?: 100%(?: ZERO-DIFF)?)?\]\s+(\w+)\s+\((?:tam=\s*)?(\d+)B\)(?:.*?via\s+([^\s]+)\s+\[([^\]]+)\])?", line)
        if m_mat:
            fn, sz, via, preset = m_mat.groups()
            card.update_state(
                fn_name=fn,
                size=int(sz),
                score=1.0,
                round_num=1,
                evals=0,
                preset=preset or "zero-diff",
                diff_str="",
                status_tag="MATCH",
            )
            self.lbl_lm_func.setText(f"{fn} ({sz}B)")
            det = f"Worker: [{wid}]"
            if preset:
                det += f" | Preset: {preset}"
            if via:
                det += f" | Metodo: {via}"
            self.lbl_lm_details.setText(det)
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            self.lbl_lm_time.setText(f"En vivo: {ts}")
            return

        m_sub = re.search(r"\[SUBIDA DE PARIDAD\]\s+(\w+)\s+\((\d+)B\).*?->\s+([0-9.]+)%", line)
        if m_sub:
            fn, sz, pct = m_sub.groups()
            card.set_badge("SUBIDA", COLOR_PURPLE)
            return

        if "[ROTACION]" in line or "ROTACION POR ESTANCAMIENTO" in line:
            card.set_badge("ROTANDO", COLOR_AMBER)
            return

        m_sem = re.search(r"\[CHECKPOINT-SEMILLA\]\s+(\w+)\s+\(tam=\s*(\d+)B\).*?Nueva:\s+([0-9.]+)%\s+via\s+([^\s]+)\s+\[([^\]]+)\]", line)
        if m_sem:
            fn, sz, pct, via, preset = m_sem.groups()
            card.update_state(
                fn_name=fn,
                size=int(sz),
                score=float(pct) / 100.0,
                round_num=1,
                evals=1,
                preset=preset,
                diff_str=f"Semilla via {via}",
                status_tag="SEMILLA",
            )

    def _refresh_state_and_process(self):
        # 1. Comprobar proceso del motor
        is_running = self._check_engine_running()
        if is_running:
            self.lbl_engine_status.setText("MOTOR ACTIVO (PROCESANDO)")
            self.lbl_engine_status.setStyleSheet(f"color: {COLOR_GREEN};")
        else:
            self.lbl_engine_status.setText("MOTOR DETENIDO (IDLE)")
            self.lbl_engine_status.setStyleSheet(f"color: {COLOR_AMBER};")

        # 2. Refrescar estado de descompilacion desde state.json
        if not STATE_FILE.exists():
            return
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            total = len(state)
            matched = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "matched")
            approx = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "approx")
            wip = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "wip")
            orphan = sum(1 for v in state.values() if isinstance(v, dict) and v.get("status") == "orphan")

            pct_matched = 100.0 * matched / max(1, total)
            self.metric_matches.lbl_val.setText(f"{matched:,} / {total:,} ({pct_matched:.2f}%)")

            bytes_c = sum(v.get("size", 0) for v in state.values() if isinstance(v, dict) and v.get("status") == "matched")
            TOTAL_TEXT_BYTES = 706046
            pct_text = 100.0 * bytes_c / TOTAL_TEXT_BYTES
            self.metric_text_cov.lbl_val.setText(f"{bytes_c:,} / {TOTAL_TEXT_BYTES:,} B ({pct_text:.2f}%)")

            equiv_bytes = sum(v.get("size", 0) * v.get("best", 0.0) for v in state.values() if isinstance(v, dict))
            pct_equiv = 100.0 * equiv_bytes / TOTAL_TEXT_BYTES
            self.metric_parity.lbl_val.setText(f"{pct_equiv:.2f}% ({equiv_bytes:,.1f} B)")

            remaining = approx + wip + orphan
            self.metric_active.lbl_val.setText(f"{remaining:,} funcs ({wip} wip, {approx} app, {orphan} orph)")

        except Exception:
            pass

        # 3. Refrescar ultimo match historico
        self._refresh_last_match()

    def _refresh_last_match(self):
        history_file = WORKSPACE_DIR / "src_sweep" / "collection" / "history.jsonl"
        last_event = None
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(max(0, history_file.stat().st_size - 16384))
                    lines = f.readlines()
                    for line in reversed(lines):
                        line = line.strip()
                        if line:
                            try:
                                ev = json.loads(line)
                                if ev.get("status") == "matched" or ev.get("score") == 1.0:
                                    last_event = ev
                                    break
                            except Exception:
                                continue
            except Exception:
                pass

        if last_event:
            fn = last_event.get("func", "desconocida")
            addr = last_event.get("addr", "")
            preset = last_event.get("preset", "")
            via = last_event.get("via", "")
            ts = last_event.get("ts", "")
            sz_str = ""
            if STATE_FILE.exists():
                try:
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        st = json.load(f)
                    if fn in st:
                        sz = st[fn].get("size", 0)
                        if sz:
                            sz_str = f" ({sz}B)"
                except Exception:
                    pass

            self.lbl_lm_func.setText(f"{fn}{sz_str}")
            self.lbl_lm_details.setText(f"Direccion: {addr} | Preset: {preset} | Metodo: {via}")
            self.lbl_lm_time.setText(f"Confirmado: {ts}")

    def _check_engine_running(self) -> bool:
        try:
            cmd = 'tasklist /FI "IMAGENAME eq python.exe" /FO CSV /NH'
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            if "python.exe" in out.lower():
                if LOG_FILE.exists():
                    mtime = LOG_FILE.stat().st_mtime
                    if time.time() - mtime < 45:
                        return True
            return False
        except Exception:
            return False


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = StatusHUDWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
