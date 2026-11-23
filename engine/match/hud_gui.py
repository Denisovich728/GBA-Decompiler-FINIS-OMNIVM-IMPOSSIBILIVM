"""FOMT-MATCH-ENGINE :: HUD Cyberpunk & Techno-Hacker GUI (PyQt6).

Unifica:
1. Motor 1: FIO DECOMP (Ghidra Headless + mGBA tracer + Jump Context).
2. Motor 2: FOMT-MATCH-ENGINE (Sweep 1:1, Permutador, agbcc, DeepSeek).
3. Pipeline Hibrido: Lo que descompila FIO pasa directamente al pipeline de matching.
4. Adaptacion multi-threading dinamica y control fino de recursos hardware (Watts, Cooldown, Duty Cycle, Hilos).
5. Pasarela IA Multi-Proveedor (Ollama local, OpenAI, Anthropic, Google Gemini, Custom REST) con baúl cifrado AES-256.
6. Telemetria cyberpunk: Hexagonos, marcos angulares, matriz interactiva de la ROM y consolas de log ruidosas.
"""
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from PyQt6.QtCore import (
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QConicalGradient,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools" / "match"))
import common  # noqa
import ai_gateway  # noqa

# Directorio de FIO DECOMP
FIO_DIR = Path(r"J:\Laboratorio\GBA-Decompiler-FINIS-OMNIVM-IMPOSSIBILIVM")
FIO_ORCHESTRATOR_PS1 = FIO_DIR / "finis_orchestrator.ps1"
FIO_OUTPUT_DIR = FIO_DIR / "output"

# Paleta Cyberpunk / Techno-Hacker (Cyan Neón / Dark Slate)
CYAN_BRIGHT = QColor(0, 240, 255)
CYAN_GLOW   = QColor(0, 200, 230, 180)
CYAN_DARK   = QColor(0, 60, 80)
BG_MAIN     = QColor(6, 12, 19)
BG_PANEL    = QColor(10, 20, 30, 240)
BG_CONSOLE  = QColor(4, 8, 12)
BORDER_COLOR = QColor(0, 180, 220, 140)
GREEN_MATCH = QColor(0, 255, 128)
YELLOW_WARN = QColor(255, 200, 0)
ORANGE_WIP  = QColor(255, 120, 20)
RED_ERR     = QColor(255, 40, 60)
TXT_MUTED   = QColor(100, 140, 160)

CYBER_STYLE = """
QMainWindow {
    background-color: #060c13;
}
QWidget {
    color: #c0e8f0;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}
QGroupBox {
    border: 1px solid #00a0c0;
    border-radius: 0px;
    margin-top: 14px;
    font-weight: bold;
    color: #00f0ff;
    background-color: rgba(8, 18, 28, 0.7);
    padding: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    background-color: #060c13;
    color: #00f0ff;
    letter-spacing: 1px;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #002b36, stop:1 #004b5c);
    border: 1px solid #00d0e8;
    color: #00f0ff;
    font-weight: bold;
    padding: 6px 14px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #004b5c, stop:1 #007d99);
    border: 1px solid #ffffff;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #00a0c0;
    color: #000000;
}
QPushButton:disabled {
    border-color: #003040;
    color: #005060;
    background: #081018;
}
QLineEdit, QComboBox, QSpinBox {
    background-color: #04080c;
    border: 1px solid #007090;
    color: #00f0ff;
    padding: 4px 8px;
    selection-background-color: #00d0e8;
    selection-color: #000000;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #00f0ff;
    background-color: #08121a;
}
QComboBox QAbstractItemView {
    background-color: #04080c;
    border: 1px solid #00f0ff;
    selection-background-color: #005060;
    color: #00f0ff;
}
QTextEdit {
    background-color: #04080c;
    border: 1px solid #005060;
    color: #a0d8e8;
    font-family: "Consolas", monospace;
    font-size: 11px;
}
QProgressBar {
    border: 1px solid #007090;
    background-color: #04080c;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
    height: 16px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0080a0, stop:1 #00f0ff);
}
QTabWidget::pane {
    border: 1px solid #007090;
    background-color: #060e16;
}
QTabBar::tab {
    background: #061018;
    border: 1px solid #004050;
    padding: 6px 16px;
    color: #60a0b0;
    margin-right: 2px;
    font-weight: bold;
    letter-spacing: 1px;
}
QTabBar::tab:selected {
    background: #003040;
    border: 1px solid #00f0ff;
    border-bottom: none;
    color: #00f0ff;
}
QScrollBar:vertical {
    background: #04080c;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #005060;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #00f0ff;
}
QSlider::groove:horizontal {
    border: 1px solid #005060;
    height: 6px;
    background: #04080c;
}
QSlider::sub-page:horizontal {
    background: #00f0ff;
}
QSlider::handle:horizontal {
    background: #00d0e8;
    border: 1px solid #ffffff;
    width: 14px;
    margin-top: -5px;
    margin-bottom: -5px;
}
QSplitter::handle {
    background: #003040;
}
"""


class CyberRadarWidget(QWidget):
    """Widget de radar giratorio estilo HUD militar/cyberpunk."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(84, 84)
        self.angle = 0.0
        self.timer = QTimer(self)
        self.timer.setInterval(40)  # ~25 FPS
        self.timer.timeout.connect(self._rotate)
        self.timer.start()

    def _rotate(self):
        self.angle = (self.angle + 3.0) % 360.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        cx = w / 2.0
        cy = h / 2.0
        radius = min(cx, cy) - 4.0

        # Fondo circular oscuro
        painter.setBrush(QBrush(QColor(4, 10, 16, 230)))
        painter.setPen(QPen(QColor(0, 140, 180, 180), 1.2))
        painter.drawEllipse(QPointF(cx, cy), radius, radius)

        # Anillos concéntricos
        pen_ring = QPen(QColor(0, 180, 220, 80), 0.8)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(pen_ring)
        painter.drawEllipse(QPointF(cx, cy), radius * 0.66, radius * 0.66)
        painter.drawEllipse(QPointF(cx, cy), radius * 0.33, radius * 0.33)

        # Cruz y marcas de ángulo
        pen_cross = QPen(QColor(0, 220, 255, 90), 0.8)
        painter.setPen(pen_cross)
        painter.drawLine(QPointF(cx - radius, cy), QPointF(cx + radius, cy))
        painter.drawLine(QPointF(cx, cy - radius), QPointF(cx, cy + radius))

        # Ticks en borde exterior
        for deg in range(0, 360, 30):
            rad = math.radians(deg)
            x1 = cx + (radius - 3) * math.cos(rad)
            y1 = cy + (radius - 3) * math.sin(rad)
            x2 = cx + radius * math.cos(rad)
            y2 = cy + radius * math.sin(rad)
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Haz de radar rotativo con gradiente cónico
        grad = QConicalGradient(cx, cy, -self.angle)
        grad.setColorAt(0.0, QColor(0, 240, 255, 140))
        grad.setColorAt(0.18, QColor(0, 180, 220, 20))
        grad.setColorAt(0.25, QColor(0, 0, 0, 0))
        grad.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(grad))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPie(QRectF(cx - radius, cy - radius, radius * 2, radius * 2), int(self.angle * 16), int(60 * 16))

        # Línea líder de la aguja
        rad_sweep = math.radians(self.angle)
        sx = cx + radius * math.cos(rad_sweep)
        sy = cy + radius * math.sin(rad_sweep)
        painter.setPen(QPen(CYAN_BRIGHT, 1.4))
        painter.drawLine(QPointF(cx, cy), QPointF(sx, sy))

        # Micro target blip
        blip_x = cx + radius * 0.55 * math.cos(math.radians(45))
        blip_y = cy + radius * 0.55 * math.sin(math.radians(45))
        painter.setBrush(QBrush(GREEN_MATCH))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(blip_x, blip_y), 2.2, 2.2)


class CyberWireframeMeshWidget(QWidget):
    """Proyector 3D interactivo de malla vectorial / poliedro cyber."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(84, 84)
        self.rot_x = 0.0
        self.rot_y = 0.0
        self.rot_z = 0.0

        # Vértices de un octaedro estrellado / icosaedro 3D
        phi = (1.0 + math.sqrt(5.0)) / 2.0
        scale = 0.9
        raw_verts = [
            (-1,  phi, 0), ( 1,  phi, 0), (-1, -phi, 0), ( 1, -phi, 0),
            (0, -1,  phi), (0,  1,  phi), (0, -1, -phi), (0,  1, -phi),
            ( phi, 0, -1), ( phi, 0,  1), (-phi, 0, -1), (-phi, 0,  1)
        ]
        self.verts = [(x * scale / phi, y * scale / phi, z * scale / phi) for x, y, z in raw_verts]

        # Aristas
        self.edges = []
        for i in range(len(self.verts)):
            for j in range(i + 1, len(self.verts)):
                d = sum((self.verts[i][k] - self.verts[j][k]) ** 2 for k in range(3))
                if 1.2 < d < 2.3:  # Conectar vecinos
                    self.edges.append((i, j))

        self.timer = QTimer(self)
        self.timer.setInterval(40)
        self.timer.timeout.connect(self._step_rotation)
        self.timer.start()

    def _step_rotation(self):
        self.rot_x += 0.025
        self.rot_y += 0.038
        self.rot_z += 0.015
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        cx = w / 2.0
        cy = h / 2.0
        radius = min(cx, cy) - 6.0

        # Marco exterior sutil
        painter.setPen(QPen(QColor(0, 100, 140, 90), 1))
        painter.drawRect(2, 2, w - 4, h - 4)

        # Matriz de rotación 3D
        cos_x, sin_x = math.cos(self.rot_x), math.sin(self.rot_x)
        cos_y, sin_y = math.cos(self.rot_y), math.sin(self.rot_y)
        cos_z, sin_z = math.cos(self.rot_z), math.sin(self.rot_z)

        projected = []
        for x, y, z in self.verts:
            # Rotar en X
            y1 = y * cos_x - z * sin_x
            z1 = y * sin_x + z * cos_x
            # Rotar en Y
            x2 = x * cos_y + z1 * sin_y
            z2 = -x * sin_y + z1 * cos_y
            # Rotar en Z
            x3 = x2 * cos_z - y1 * sin_z
            y3 = x2 * sin_z + y1 * cos_z

            # Perspectiva
            dist = 3.0
            factor = dist / (dist + z2)
            px = cx + x3 * radius * factor
            py = cy + y3 * radius * factor
            projected.append((px, py, z2))

        # Dibujar aristas
        pen_edge = QPen(CYAN_GLOW, 1.0)
        painter.setPen(pen_edge)
        for i, j in self.edges:
            x1, y1, z1 = projected[i]
            x2, y2, z2 = projected[j]
            # Profundidad de color
            avg_z = (z1 + z2) / 2.0
            alpha = int(max(40, min(240, 140 + avg_z * 80)))
            painter.setPen(QPen(QColor(0, 240, 255, alpha), 1.0))
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Nodos / Vértices brillantes
        painter.setBrush(QBrush(CYAN_BRIGHT))
        painter.setPen(Qt.PenStyle.NoPen)
        for px, py, z in projected:
            size = 2.4 if z > 0 else 1.6
            painter.drawEllipse(QPointF(px, py), size, size)


class CyberHazardBanner(QWidget):
    """Banner de precaución techno-hacker con chevron y rayas diagonales."""

    def __init__(self, text="MASTER CAUTION // SYSTEM ACTIVE", parent=None):
        super().__init__(parent)
        self.text = text
        self.setFixedHeight(22)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()

        # Fondo negro translúcido
        painter.fillRect(0, 0, w, h, QBrush(QColor(4, 10, 16, 220)))

        # Rayas de peligro diagonales en los extremos
        stripe_w = 4
        gap = 5
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(255, 180, 0, 180)))

        # Franja izquierda (32px)
        for x in range(2, 36, gap + stripe_w):
            poly = QPolygonF([
                QPointF(x, h - 2),
                QPointF(x + stripe_w, h - 2),
                QPointF(x + stripe_w + 6, 2),
                QPointF(x + 6, 2),
            ])
            painter.drawPolygon(poly)

        # Franja derecha (32px)
        for x in range(w - 38, w - 4, gap + stripe_w):
            poly = QPolygonF([
                QPointF(x, h - 2),
                QPointF(x + stripe_w, h - 2),
                QPointF(x + stripe_w + 6, 2),
                QPointF(x + 6, 2),
            ])
            painter.drawPolygon(poly)

        # Borde exterior
        painter.setPen(QPen(QColor(255, 180, 0, 120), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(0, 0, w - 1, h - 1)

        # Texto centrado
        painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        painter.setPen(QColor(255, 200, 0))
        painter.drawText(QRectF(40, 2, w - 80, h - 4), Qt.AlignmentFlag.AlignCenter, f">>> {self.text} <<<")


class CyberFrame(QFrame):
    """Marco angular recortado con bisel techno-hacker y muescas HUD."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.title = title
        self.cut_size = 14
        self.setStyleSheet("background: transparent;")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())
        c = float(self.cut_size)

        path = QPainterPath()
        path.moveTo(c, 0)
        path.lineTo(w - c, 0)
        path.lineTo(w, c)
        path.lineTo(w, h - c)
        path.lineTo(w - c, h)
        path.lineTo(c, h)
        path.lineTo(0, h - c)
        path.lineTo(0, c)
        path.closeSubpath()

        painter.fillPath(path, QBrush(BG_PANEL))

        pen = QPen(BORDER_COLOR, 1.2)
        painter.setPen(pen)
        painter.drawPath(path)

        # Esquinas reforzadas con brackets neón
        corner_pen = QPen(CYAN_BRIGHT, 2.0)
        painter.setPen(corner_pen)
        painter.drawLine(QPointF(c, 0), QPointF(c + 18, 0))
        painter.drawLine(QPointF(w - c - 18, h), QPointF(w - c, h))
        painter.drawLine(QPointF(0, c), QPointF(0, c + 18))
        painter.drawLine(QPointF(w, h - c - 18), QPointF(w, h - c))

        # Micro-muescas técnicas estilo HUD militar
        painter.setPen(QPen(CYAN_BRIGHT, 1.0))
        painter.drawLine(QPointF(w - 30, 4), QPointF(w - 15, 4))
        painter.drawLine(QPointF(w - 25, 8), QPointF(w - 15, 8))
        painter.drawLine(QPointF(15, h - 4), QPointF(30, h - 4))
        painter.drawLine(QPointF(15, h - 8), QPointF(25, h - 8))

        if self.title:
            painter.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            painter.setPen(CYAN_BRIGHT)
            painter.drawText(QRectF(18, 4, w - 36, 18), Qt.AlignmentFlag.AlignLeft, f"// {self.title.upper()} //")


class RomMatrixCanvas(QWidget):
    """Grid interactivo de la ROM estilo visualizador de RAM/Matrix."""

    functionSelected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manifest = []
        self.state = {}
        self.active_func = ""
        self.cols = 80
        self.rows = 14
        self.setMinimumHeight(140)
        self.setMouseTracking(True)

    def update_data(self, manifest, state, active_func=""):
        self.manifest = manifest
        self.state = state
        self.active_func = active_func
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        painter.fillRect(0, 0, w, h, QBrush(BG_CONSOLE))

        n_funcs = len(self.manifest)
        if n_funcs == 0:
            painter.setPen(TXT_MUTED)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "[ROM MANIFEST VACIO - INICIA UN ESCANEO O BARRIDO]")
            return

        total_cells = self.cols * self.rows
        pad_x = 10
        pad_y = 10
        cell_w = max(2.0, (w - pad_x * 2) / float(self.cols))
        cell_h = max(2.0, (h - pad_y * 2) / float(self.rows))

        for r in range(self.rows):
            for c in range(self.cols):
                cell_idx = r * self.cols + c
                f_start = (cell_idx * n_funcs) // total_cells
                f_end = max(f_start + 1, ((cell_idx + 1) * n_funcs) // total_cells)
                bucket = self.manifest[f_start:f_end]

                has_active = any(f["name"] == self.active_func for f in bucket)
                statuses = [self.state.get(f["name"], {}).get("status", "pending") for f in bucket]

                if has_active:
                    color = CYAN_BRIGHT
                elif "matched" in statuses:
                    color = GREEN_MATCH
                elif "approx" in statuses:
                    color = YELLOW_WARN
                elif "wip" in statuses:
                    color = ORANGE_WIP
                elif "orphan" in statuses:
                    color = RED_ERR
                else:
                    color = QColor(25, 45, 60)

                x = pad_x + c * cell_w
                y = pad_y + r * cell_h
                painter.fillRect(QRectF(x, y, max(1.0, cell_w - 1), max(1.0, cell_h - 1)), QBrush(color))


class ProcessWorker(QThread):
    """Ejecutor de subprocesos con captura ruidosa de logs en vivo."""

    lineReceived = pyqtSignal(str)
    processFinished = pyqtSignal(int)

    def __init__(self, cmd, cwd=None, env=None):
        super().__init__()
        self.cmd = cmd
        self.cwd = cwd
        self.env = env
        self.proc = None

    def run(self):
        env = os.environ.copy()
        if self.env:
            env.update(self.env)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                cwd=str(self.cwd or ROOT_DIR),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            import codecs
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            while True:
                chunk = self.proc.stdout.read1(1024)
                if not chunk:
                    break
                text = decoder.decode(chunk).replace("\r\n", "\n").replace("\r", "\n")
                self.lineReceived.emit(text)
            rc = self.proc.wait()
            self.processFinished.emit(rc)
        except Exception as ex:
            self.lineReceived.emit(f"\n[FATAL WORKER ERROR] {ex}\n")
            self.processFinished.emit(1)

    def terminate_process(self):
        if self.proc:
            try:
                import psutil
                p = psutil.Process(self.proc.pid)
                for child in p.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                p.kill()
            except Exception:
                pass


class TechnoHackerMainWindow(QMainWindow):
    """Ventana Maestra PyQt6 estilo Cyberpunk HUD."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("FOMT-MATCH-ENGINE // CYBERNETIC DECOMP & RE-SYNTH SUITE")
        self.resize(1380, 900)
        self.setMinimumSize(1080, 720)
        self.setStyleSheet(CYBER_STYLE)

        self.current_worker = None
        self.manifest_data = []
        self.state_data = {}
        self.active_func = ""

        self._build_ui()
        self._load_config_into_ui()
        self._start_polling()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Cabecera Cyberpunk Superior con Telemetría y Gadgets Vectoriales HUD
        header_frame = CyberFrame("System Cybernetics // Tactical Telemetry Node")
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(14, 22, 14, 10)
        h_layout.setSpacing(12)

        # Bloque Izquierdo: Logo y Banner de Precaución
        v_left = QVBoxLayout()
        v_left.setSpacing(4)
        lbl_logo = QLabel("FOMT :: CYBER-MATCH")
        lbl_logo.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        lbl_logo.setStyleSheet("color: #00f0ff; letter-spacing: 2px;")
        v_left.addWidget(lbl_logo)

        self.hazard_banner = CyberHazardBanner("MASTER CAUTION // GBA DECOMP CORE // NEURAL LINK ACTIVE")
        v_left.addWidget(self.hazard_banner)
        h_layout.addLayout(v_left)

        h_layout.addSpacing(16)

        # Bloque Central: Telemetría de Energía y Coincidencia
        v_mid = QVBoxLayout()
        v_mid.setSpacing(4)
        h_stats = QHBoxLayout()
        h_stats.setSpacing(14)

        self.lbl_cpu = QLabel("CPU: --% [13/16T]")
        self.lbl_cpu.setStyleSheet("color: #00e0b0; font-weight: bold; font-size: 11px;")
        h_stats.addWidget(self.lbl_cpu)

        self.lbl_power = QLabel("PWR: ~35W | VRM: OK")
        self.lbl_power.setStyleSheet("color: #ffd000; font-weight: bold; font-size: 11px;")
        h_stats.addWidget(self.lbl_power)

        self.lbl_match_stat = QLabel("1:1 MATCH: 0 / 3068 (0.0%)")
        self.lbl_match_stat.setStyleSheet("color: #00f0ff; font-weight: bold; font-size: 11px;")
        h_stats.addWidget(self.lbl_match_stat)
        v_mid.addLayout(h_stats)

        # Indicadores tácticos estilo HUD (04 / 07 / 24)
        h_tactical = QHBoxLayout()
        h_tactical.setSpacing(8)
        for badge_txt, col in [("▼ 04 GBA", "#00d0e8"), ("▼ 07 THUMB", "#00ff80"), ("▼ 24 AGBCC", "#ffd000"), ("SEC: LEVEL-5", "#ff7814")]:
            b_lbl = QLabel(badge_txt)
            b_lbl.setStyleSheet(f"color: {col}; border: 1px solid {col}; padding: 1px 6px; font-weight: bold; font-size: 9px; background: rgba(0,20,30,0.6);")
            h_tactical.addWidget(b_lbl)
        h_tactical.addStretch()
        v_mid.addLayout(h_tactical)
        h_layout.addLayout(v_mid)

        h_layout.addStretch()

        # Bloque Derecho: Radar Rotativo 360° + Malla Vectorial 3D + Badge de Estado
        self.radar_widget = CyberRadarWidget()
        h_layout.addWidget(self.radar_widget)

        self.mesh_widget = CyberWireframeMeshWidget()
        h_layout.addWidget(self.mesh_widget)

        v_right = QVBoxLayout()
        v_right.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status_badge = QLabel("STANDBY")
        self.lbl_status_badge.setStyleSheet(
            "background-color: #003040; color: #00f0ff; border: 1px solid #00f0ff; "
            "padding: 6px 16px; font-weight: bold; letter-spacing: 2px; font-size: 12px;"
        )
        v_right.addWidget(self.lbl_status_badge)
        h_layout.addLayout(v_right)

        main_layout.addWidget(header_frame)

        # 2. Splitter Principal: Centro (Matriz + Pestañas de Control)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)

        # Panel Superior: ROM Matrix Visualizer
        matrix_frame = CyberFrame("ROM Binary Stream Matrix // 0x080000C0 - 0x080E4000")
        mat_layout = QVBoxLayout(matrix_frame)
        mat_layout.setContentsMargins(12, 22, 12, 10)
        self.matrix_canvas = RomMatrixCanvas()
        mat_layout.addWidget(self.matrix_canvas)

        # Leyenda de estados
        leg_layout = QHBoxLayout()
        leg_layout.setSpacing(14)
        legends = [
            ("█ MATCH 1:1", "#00ff80"),
            ("▓ APPROX >=90%", "#ffc800"),
            ("▒ WIP", "#ff7814"),
            ("× ORPHAN / ERR", "#ff283c"),
            ("◈ ACTIVE INFERENCE", "#00f0ff"),
            ("· UNTOUCHED", "#304858"),
        ]
        for txt, col in legends:
            l = QLabel(txt)
            l.setStyleSheet(f"color: {col}; font-weight: bold; font-size: 10px;")
            leg_layout.addWidget(l)
        leg_layout.addStretch()
        mat_layout.addLayout(leg_layout)

        splitter.addWidget(matrix_frame)

        # Panel Inferior: Pestañas de Consolas, Puentes y Hardware/IA
        tabs_frame = CyberFrame("Neural Link & Hardware Governor")
        tabs_layout = QVBoxLayout(tabs_frame)
        tabs_layout.setContentsMargins(10, 20, 10, 10)

        self.tabs = QTabWidget()

        # TAB 1: Dual Consoles (Consolas Ruidosas Lado a Lado)
        tab_consoles = QWidget()
        tc_layout = QHBoxLayout(tab_consoles)
        tc_layout.setContentsMargins(4, 4, 4, 4)

        split_logs = QSplitter(Qt.Orientation.Horizontal)

        # Consola Izquierda: FIO DECOMP LOG
        grp_fio = QGroupBox("MOTOR 1 // FIO DECOMP (Ghidra + mGBA Headless)")
        fio_v = QVBoxLayout(grp_fio)
        fio_v.setContentsMargins(6, 12, 6, 6)
        self.txt_fio_log = QTextEdit()
        self.txt_fio_log.setReadOnly(True)
        self.txt_fio_log.setStyleSheet("background-color: #04080c; color: #00e0ff; border: 1px solid #005070;")
        fio_v.addWidget(self.txt_fio_log)
        split_logs.addWidget(grp_fio)

        # Consola Derecha: FOMT-MATCH-ENGINE LOG
        grp_match = QGroupBox("MOTOR 2 // FOMT-MATCH-ENGINE (agbcc + Permutador + DeepSeek)")
        match_v = QVBoxLayout(grp_match)
        match_v.setContentsMargins(6, 12, 6, 6)
        self.txt_match_log = QTextEdit()
        self.txt_match_log.setReadOnly(True)
        self.txt_match_log.setStyleSheet("background-color: #04080c; color: #a0f080; border: 1px solid #007050;")
        match_v.addWidget(self.txt_match_log)
        split_logs.addWidget(grp_match)

        tc_layout.addWidget(split_logs)
        self.tabs.addTab(tab_consoles, "CONSOLAS DUALES (LOG RUIDOSO)")

        # TAB 2: Control del Pipeline Hibrido y Seleccion de ROM
        tab_bridge = QWidget()
        tb_layout = QVBoxLayout(tab_bridge)

        bridge_grid = QGridLayout()
        bridge_grid.setContentsMargins(10, 10, 10, 10)

        # ROM Target Path
        bridge_grid.addWidget(QLabel("ROM TARGET (.GBA):"), 0, 0)
        self.txt_rom_path = QLineEdit(str(common.ROM_PATH))
        bridge_grid.addWidget(self.txt_rom_path, 0, 1)
        btn_browse_rom = QPushButton("Examinar ROM...")
        btn_browse_rom.clicked.connect(self._browse_rom)
        bridge_grid.addWidget(btn_browse_rom, 0, 2)

        # Dropdown de ROMs descubiertas
        bridge_grid.addWidget(QLabel("ROMS DETECTADAS:"), 1, 0)
        self.cmb_discovered_roms = QComboBox()
        self._refresh_rom_list()
        self.cmb_discovered_roms.currentIndexChanged.connect(self._on_discovered_rom_changed)
        bridge_grid.addWidget(self.cmb_discovered_roms, 1, 1, 1, 2)

        # Pipeline Flow Checkbox
        self.chk_auto_bridge = QCheckBox("PASO AUTOMATICO: Inyectar pseudo-C de FIO DECOMP directo al Motor 2 de Matching")
        self.chk_auto_bridge.setChecked(True)
        self.chk_auto_bridge.setStyleSheet("color: #00f0ff; font-weight: bold;")
        bridge_grid.addWidget(self.chk_auto_bridge, 2, 0, 1, 3)

        # Nivel Guardian FIO
        bridge_grid.addWidget(QLabel("GUARDIAN DE CONTEXTO FIO:"), 3, 0)
        self.cmb_guardian = QComboBox()
        self.cmb_guardian.addItems(["1: Permisivo (todos los getters/branches)", "2: Equilibrado (Recomendado)", "3: Estricto (Solo prologos canonicos)"])
        self.cmb_guardian.setCurrentIndex(1)
        bridge_grid.addWidget(self.cmb_guardian, 3, 1, 1, 2)

        # Fase Inicial Matching
        bridge_grid.addWidget(QLabel("FASE INICIAL MOTOR 2:"), 4, 0)
        self.cmb_phase = QComboBox()
        self.cmb_phase.addItems([
            "Fase 1: CPU Pura (Semilla C89 + agbcc + Permutador | CERO LLM)",
            "Fase 2: DeepSeek + Permutador (Huerfanas y WIP)",
            "Fase 3: Nombrado Semantico con DeepSeek (Funciones Matched)"
        ])
        self.cmb_phase.setCurrentIndex(0)
        bridge_grid.addWidget(self.cmb_phase, 4, 1, 1, 2)

        tb_layout.addLayout(bridge_grid)
        tb_layout.addStretch()
        self.tabs.addTab(tab_bridge, "PUENTE HIBRIDO (FIO -> MATCH)")

        # TAB 3: Gobernador de Hardware y Multi-Threading
        tab_hw = QWidget()
        thw_layout = QVBoxLayout(tab_hw)

        hw_grid = QGridLayout()
        hw_grid.setContentsMargins(10, 10, 10, 10)
        hw_grid.setSpacing(12)

        # Detección de núcleos lógicos disponibles
        total_cpus = os.cpu_count() or 16

        # Threads
        hw_grid.addWidget(QLabel(f"HILOS ACTIVOS (1..{total_cpus}):"), 0, 0)
        self.spn_threads = QSpinBox()
        self.spn_threads.setRange(1, total_cpus)
        self.spn_threads.setValue(min(13, total_cpus))
        hw_grid.addWidget(self.spn_threads, 0, 1)

        # Target Cap en Watts
        hw_grid.addWidget(QLabel("LIMITE ELECTRICO (WATTS):"), 1, 0)
        self.spn_watts = QSpinBox()
        self.spn_watts.setRange(25, 135)
        self.spn_watts.setValue(61)
        self.spn_watts.setSuffix(" W")
        hw_grid.addWidget(self.spn_watts, 1, 1)

        # Cooldown térmico
        hw_grid.addWidget(QLabel("COOLDOWN ENTRE INFERENCIAS (SEG):"), 2, 0)
        self.spn_cooldown = QSpinBox()
        self.spn_cooldown.setRange(0, 30)
        self.spn_cooldown.setValue(1)
        self.spn_cooldown.setSuffix(" s")
        hw_grid.addWidget(self.spn_cooldown, 2, 1)

        # Duty cycle %
        hw_grid.addWidget(QLabel("DUTY CYCLE DE TRABAJO (%):"), 3, 0)
        self.spn_duty = QSpinBox()
        self.spn_duty.setRange(20, 100)
        self.spn_duty.setValue(100)
        self.spn_duty.setSuffix(" %")
        hw_grid.addWidget(self.spn_duty, 3, 1)

        # Prioridad de proceso
        hw_grid.addWidget(QLabel("PRIORIDAD DE PROCESO (OS):"), 4, 0)
        self.cmb_prio = QComboBox()
        self.cmb_prio.addItems(["below_normal (Recomendado)", "idle (Ahorro silencioso)", "normal (Maximo rendimiento)"])
        hw_grid.addWidget(self.cmb_prio, 4, 1)

        # Presets de Hardware
        hw_grid.addWidget(QLabel("PRESETS DE POTENCIA:"), 5, 0)
        btn_box = QHBoxLayout()
        for p_name, p_w in [("ECO (32W)", 32), ("BALANCED (45W)", 45), ("PERFORMANCE (65W)", 65), ("UNLEASHED (95W)", 95)]:
            b = QPushButton(p_name)
            b.clicked.connect(lambda _, w=p_w: self._apply_power_preset(w))
            btn_box.addWidget(b)
        hw_grid.addLayout(btn_box, 5, 1)

        btn_save_hw = QPushButton("GUARDAR CONFIGURACION DE HARDWARE")
        btn_save_hw.clicked.connect(self._save_hardware_config)
        hw_grid.addWidget(btn_save_hw, 6, 0, 1, 2)

        thw_layout.addLayout(hw_grid)
        thw_layout.addStretch()
        self.tabs.addTab(tab_hw, "GOBERNADOR DE HARDWARE (CPU/WATTS)")

        # TAB 4: Configuración de IA Multi-Proveedor & Baúl Cifrado
        tab_ai = QWidget()
        tai_layout = QVBoxLayout(tab_ai)

        ai_grid = QGridLayout()
        ai_grid.setContentsMargins(10, 10, 10, 10)
        ai_grid.setSpacing(10)

        ai_grid.addWidget(QLabel("PROVEEDOR DE IA:"), 0, 0)
        self.cmb_provider = QComboBox()
        self.cmb_provider.addItems([
            "ollama (Local - Sin API Key)",
            "openai (GPT-4o, o1, etc.)",
            "anthropic (Claude 3.5 Sonnet)",
            "google (Gemini 1.5 Pro / Flash)",
            "custom (OpenAI-Compatible REST / LMStudio / vLLM)"
        ])
        self.cmb_provider.currentIndexChanged.connect(self._on_provider_changed)
        ai_grid.addWidget(self.cmb_provider, 0, 1)

        ai_grid.addWidget(QLabel("MODELO DE IA:"), 1, 0)
        self.txt_ai_model = QLineEdit("deepseek-coder-v2:latest")
        ai_grid.addWidget(self.txt_ai_model, 1, 1)

        ai_grid.addWidget(QLabel("API KEY / TOKEN (CIFRADO AES-256):"), 2, 0)
        self.txt_api_key = QLineEdit()
        self.txt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_api_key.setPlaceholderText("Clave cifrada de forma segura con AES-256...")
        ai_grid.addWidget(self.txt_api_key, 2, 1)

        ai_grid.addWidget(QLabel("ENDPOINT / BASE URL (OPCIONAL):"), 3, 0)
        self.txt_base_url = QLineEdit()
        self.txt_base_url.setPlaceholderText("Ej: http://localhost:11434/api/chat o https://api.openai.com/v1")
        ai_grid.addWidget(self.txt_base_url, 3, 1)

        btn_save_ai = QPushButton("GUARDAR EN BAUL CIFRADO (AES-256)")
        btn_save_ai.setStyleSheet("border-color: #00ff80; color: #00ff80; font-weight: bold;")
        btn_save_ai.clicked.connect(self._save_ai_config)
        ai_grid.addWidget(btn_save_ai, 4, 0, 1, 2)

        lbl_vault_note = QLabel("// Las claves se guardan cifradas con AES-256 ligadas al hardware local en credentials_vault.enc //")
        lbl_vault_note.setStyleSheet("color: #00e0b0; font-style: italic;")
        ai_grid.addWidget(lbl_vault_note, 5, 0, 1, 2)

        tai_layout.addLayout(ai_grid)
        tai_layout.addStretch()
        self.tabs.addTab(tab_ai, "PASARELA DE IA (LLMS & BAUL CIFRADO)")

        tabs_layout.addWidget(self.tabs)
        splitter.addWidget(tabs_frame)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 6)
        main_layout.addWidget(splitter)

        # 3. Barra de Botones Inferior (Controles Tácticos)
        btn_panel = CyberFrame()
        bp_layout = QHBoxLayout(btn_panel)
        bp_layout.setContentsMargins(14, 12, 14, 12)
        bp_layout.setSpacing(10)

        self.btn_fio_decomp = QPushButton("EJECUTAR FIO DECOMP")
        self.btn_fio_decomp.setStyleSheet("border-color: #00f0ff; color: #00f0ff;")
        self.btn_fio_decomp.clicked.connect(self._run_fio_decomp)
        bp_layout.addWidget(self.btn_fio_decomp)

        self.btn_start_match = QPushButton("INICIAR MOTOR 2 (MATCHING)")
        self.btn_start_match.setStyleSheet("border-color: #00ff80; color: #00ff80;")
        self.btn_start_match.clicked.connect(self._run_matching_engine)
        bp_layout.addWidget(self.btn_start_match)

        self.btn_pipeline_full = QPushButton("PIPELINE MAESTRO: FIO -> MATCH 1:1")
        self.btn_pipeline_full.setStyleSheet("border-color: #ffd000; color: #ffd000; font-weight: bold;")
        self.btn_pipeline_full.clicked.connect(self._run_master_pipeline)
        bp_layout.addWidget(self.btn_pipeline_full)

        bp_layout.addSpacing(20)

        self.btn_pause = QPushButton("PAUSAR")
        self.btn_pause.clicked.connect(self._send_pause)
        bp_layout.addWidget(self.btn_pause)

        self.btn_stop = QPushButton("ABORTAR / STOP")
        self.btn_stop.setStyleSheet("border-color: #ff283c; color: #ff283c;")
        self.btn_stop.clicked.connect(self._send_stop)
        bp_layout.addWidget(self.btn_stop)

        self.btn_clear_logs = QPushButton("LIMPIAR LOGS")
        self.btn_clear_logs.clicked.connect(self._clear_logs)
        bp_layout.addWidget(self.btn_clear_logs)

        main_layout.addWidget(btn_panel)

    def _refresh_rom_list(self):
        self.cmb_discovered_roms.clear()
        found_roms = []
        # Buscar en directorio local y en FIO
        for p in [ROOT_DIR, FIO_DIR, FIO_DIR / "roms"]:
            if p.exists():
                for f in p.glob("*.gba"):
                    if f.is_file() and f not in found_roms:
                        found_roms.append(f)
        for r in found_roms:
            self.cmb_discovered_roms.addItem(f"{r.name}  [{r.parent.name}]", str(r))

    def _on_discovered_rom_changed(self, idx):
        if idx >= 0:
            target_path = self.cmb_discovered_roms.itemData(idx)
            if target_path:
                self.txt_rom_path.setText(target_path)

    def _browse_rom(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar ROM GBA", str(ROOT_DIR), "GBA ROM (*.gba)")
        if file_path:
            self.txt_rom_path.setText(file_path)

    def _load_config_into_ui(self):
        cfg = common.load_engine_config()
        self.spn_threads.setValue(cfg.get("threads", 13))
        self.spn_watts.setValue(cfg.get("watts", 61))
        self.spn_cooldown.setValue(int(cfg.get("cooldown", 1)))
        self.spn_duty.setValue(int(cfg.get("duty_cycle", 100)))

        prio_map = {"below_normal": 0, "idle": 1, "normal": 2}
        self.cmb_prio.setCurrentIndex(prio_map.get(cfg.get("priority", "below_normal"), 0))

        provider = cfg.get("ai_provider", "ollama").lower()
        idx_prov = 0
        for i in range(self.cmb_provider.count()):
            if self.cmb_provider.itemText(i).startswith(provider):
                idx_prov = i
                break
        self.cmb_provider.setCurrentIndex(idx_prov)
        self.txt_ai_model.setText(cfg.get("ai_model", cfg.get("model", "deepseek-coder-v2:latest")))

        # Cargar baúl cifrado
        cred = ai_gateway.get_provider_credential(provider)
        self.txt_api_key.setText(cred.get("api_key", ""))
        self.txt_base_url.setText(cred.get("base_url", ""))

    def _on_provider_changed(self, idx):
        provider = self.cmb_provider.currentText().split()[0].lower()
        cred = ai_gateway.get_provider_credential(provider)
        self.txt_api_key.setText(cred.get("api_key", ""))
        self.txt_base_url.setText(cred.get("base_url", ""))
        if provider == "openai":
            self.txt_ai_model.setText("gpt-4o")
        elif provider == "anthropic":
            self.txt_ai_model.setText("claude-3-5-sonnet-20241022")
        elif provider == "google":
            self.txt_ai_model.setText("gemini-1.5-pro")
        elif provider == "ollama":
            self.txt_ai_model.setText("deepseek-coder-v2:latest")

    def _apply_power_preset(self, watts: int):
        tuned = common.auto_tune_for_watts(watts)
        self.spn_watts.setValue(watts)
        self.spn_threads.setValue(tuned.get("threads", 8))
        self.spn_cooldown.setValue(int(tuned.get("cooldown", 1.5)))
        self.spn_duty.setValue(tuned.get("duty_cycle", 85))
        prio_map = {"below_normal": 0, "idle": 1, "normal": 2}
        self.cmb_prio.setCurrentIndex(prio_map.get(tuned.get("priority", "below_normal"), 0))

    def _save_hardware_config(self):
        prio_values = ["below_normal", "idle", "normal"]
        cfg_update = {
            "threads": self.spn_threads.value(),
            "watts": self.spn_watts.value(),
            "cooldown": float(self.spn_cooldown.value()),
            "duty_cycle": self.spn_duty.value(),
            "priority": prio_values[self.cmb_prio.currentIndex()],
        }
        common.save_engine_config(cfg_update)
        self._append_match_log(f"  [CONFIG HARDWARE GUARDADA] {cfg_update['threads']}T, {cfg_update['watts']}W, Cooldown {cfg_update['cooldown']}s\n")
        QMessageBox.information(self, "Hardware Config", "Parametros de CPU y consumo electrico guardados exitosamente.")

    def _save_ai_config(self):
        provider = self.cmb_provider.currentText().split()[0].lower()
        model = self.txt_ai_model.text().strip()
        api_key = self.txt_api_key.text().strip()
        base_url = self.txt_base_url.text().strip()

        # Guardar en baúl cifrado AES-256
        ai_gateway.set_provider_credential(provider, api_key=api_key, base_url=base_url, model=model)

        # Actualizar engine_config.json
        common.save_engine_config({
            "ai_provider": provider,
            "ai_model": model,
            "model": model,
        })
        self._append_match_log(f"  [BAUL CIFRADO ACTUALIZADO] Proveedor: {provider.upper()} | Modelo: {model}\n")
        QMessageBox.information(self, "Baul Cifrado", f"Credenciales cifradas con AES-256 para '{provider.upper()}' guardadas.")

    def _clear_logs(self):
        self.txt_fio_log.clear()
        self.txt_match_log.clear()

    def _start_polling(self):
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(600)
        self.poll_timer.timeout.connect(self._poll_status)
        self.poll_timer.start()

    def _poll_status(self):
        try:
            if common.MANIFEST.exists() and not self.manifest_data:
                self.manifest_data = common.load_manifest()
            self.state_data = common.load_state()
            status_file = common.TREE_DIR / "control" / "status.json"
            status = {}
            if status_file.exists():
                status = json.loads(status_file.read_text(encoding="utf-8"))
            self.active_func = status.get("func", "")
            phase_txt = status.get("phase", "STANDBY")
            self.lbl_status_badge.setText(phase_txt[:32].upper())

            n_matched = sum(1 for v in self.state_data.values() if v.get("status") == "matched")
            n_total = len(self.manifest_data) or 1
            pct = (n_matched / n_total) * 100.0
            self.lbl_match_stat.setText(f"1:1 MATCH: {n_matched} / {n_total} ({pct:.2f}%)")

            self.matrix_canvas.update_data(self.manifest_data, self.state_data, self.active_func)
        except Exception:
            pass

        # Leer engine.log
        engine_log = common.TREE_DIR / "control" / "engine.log"
        if engine_log.exists() and not self.current_worker:
            try:
                with open(engine_log, "rb") as f:
                    f.seek(max(0, f.seek(0, os.SEEK_END) - 6000))
                    chunk = f.read().decode("utf-8", "replace")
                    if chunk:
                        lines = chunk.splitlines()[-40:]
                        self.txt_match_log.setPlainText("\n".join(lines))
                        self.txt_match_log.moveCursor(QTextCursor.MoveOperation.End)
            except Exception:
                pass

        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            cfg = common.load_engine_config()
            th = cfg.get("threads", 8)
            self.lbl_cpu.setText(f"CPU: {cpu:3.0f}% [{th}/16T]")
            pwr = common.estimate_power(th, cfg.get("cooldown", 1.5), cfg.get("duty_cycle", 85), cfg.get("priority", "below_normal"))
            self.lbl_power.setText(f"PWR: ~{pwr['total_avg_w']}W / {pwr['total_peak_w']}W pk | VRM: OK")
        except Exception:
            pass

    def _append_fio_log(self, text):
        self.txt_fio_log.moveCursor(QTextCursor.MoveOperation.End)
        self.txt_fio_log.insertPlainText(text)
        self.txt_fio_log.moveCursor(QTextCursor.MoveOperation.End)

    def _append_match_log(self, text):
        self.txt_match_log.moveCursor(QTextCursor.MoveOperation.End)
        self.txt_match_log.insertPlainText(text)
        self.txt_match_log.moveCursor(QTextCursor.MoveOperation.End)

    def _run_fio_decomp(self):
        if self.current_worker and self.current_worker.isRunning():
            self._append_fio_log("[!] Proceso ya en ejecucion. Pulsa STOP primero.\n")
            return

        rom_path = self.txt_rom_path.text().strip()
        guardian = str(self.cmb_guardian.currentIndex() + 1)
        self._append_fio_log(f"[*] INICIANDO MOTOR 1 (FIO DECOMP) sobre '{rom_path}' [Guardian: {guardian}]...\n")
        self.tabs.setCurrentIndex(0)

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(FIO_ORCHESTRATOR_PS1),
            "-RomPath", rom_path,
            "-Mode", "3",
            "-GuardianStrictness", guardian,
            "-ContextFile", "NONE",
        ]

        self.current_worker = ProcessWorker(cmd, cwd=FIO_DIR)
        self.current_worker.lineReceived.connect(self._append_fio_log)
        self.current_worker.processFinished.connect(self._on_fio_finished)
        self.current_worker.start()

    def _on_fio_finished(self, rc):
        self._append_fio_log(f"\n[+] FIO DECOMP FINALIZADO (Exit Code: {rc})\n")
        if self.chk_auto_bridge.isChecked() and rc == 0:
            self._append_fio_log("[*] PUENTE ACTIVADO -> Transfiriendo referencias a FOMT-MATCH-ENGINE...\n")
            self._run_matching_engine()

    def _run_matching_engine(self):
        if self.current_worker and self.current_worker.isRunning():
            self._append_match_log("[!] Proceso ya en ejecucion. Pulsa STOP primero.\n")
            return

        phase = str(self.cmb_phase.currentIndex() + 1)
        self._append_match_log(f"[*] INICIANDO MOTOR 2 (MATCHING SUITE) en Fase {phase}...\n")
        self.tabs.setCurrentIndex(0)

        cmd = [
            sys.executable,
            str(ROOT_DIR / "run_sweep.py"),
            "--phase", phase,
            "--autostart",
        ]

        self.current_worker = ProcessWorker(cmd, cwd=ROOT_DIR)
        self.current_worker.lineReceived.connect(self._append_match_log)
        self.current_worker.processFinished.connect(lambda rc: self._append_match_log(f"\n[+] Motor 2 detenido (Code: {rc})\n"))
        self.current_worker.start()

    def _run_master_pipeline(self):
        self._append_fio_log("====================================================================\n")
        self._append_fio_log(" INICIANDO PIPELINE MAESTRO HIBRIDO (FIO DECOMP -> FOMT-MATCH-ENGINE)\n")
        self._append_fio_log("====================================================================\n")
        self.chk_auto_bridge.setChecked(True)
        self._run_fio_decomp()

    def _send_pause(self):
        cmd_file = common.TREE_DIR / "control" / "commands.txt"
        cmd_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cmd_file, "a", encoding="utf-8") as f:
            f.write("pause\n")
        self._append_match_log("  [GUI -> ENGINE] Comando enviado: PAUSE\n")

    def _send_stop(self):
        if self.current_worker and self.current_worker.isRunning():
            self.current_worker.terminate_process()
            self._append_match_log("  [GUI -> ENGINE] Proceso abortado forzosamente.\n")
            self._append_fio_log("  [GUI -> FIO] Proceso abortado forzosamente.\n")
        cmd_file = common.TREE_DIR / "control" / "commands.txt"
        cmd_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cmd_file, "a", encoding="utf-8") as f:
            f.write("stop\n")
        stop_flag = common.TREE_DIR / "control" / "stop.flag"
        try:
            stop_flag.write_text("stop", encoding="utf-8")
        except OSError:
            pass


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = TechnoHackerMainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
