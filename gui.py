"""
DevPulse PyQt6 Graphical User Interface (gui.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
ARCHITECTURE & DESIGN PRINCIPLES:
1. THIN PRESENTATION LAYER:
   Contains ZERO cryptographic algorithms and ZERO tracking logic.
   Directly calls verified functions from secret.py, focus.py, ergo.py, and audit.py.
2. 100% OFFLINE & NATIVE QT:
   Uses standard PyQt6 widgets and default platform styling (Breeze on KDE).
   No QtWebEngine, no matplotlib, no custom CSS theming.
3. REAL DATABASE INTROSPECTION:
   Queries focus.db (focus_events, window_switches), audit.db (secret_events),
   and introspects ergo.db with PRAGMA table_info rather than assuming schema.
   Missing databases or empty tables show zeros gracefully without crashing.
4. WAYLAND RESILIENT & CLEAN SHUTDOWN:
   Supports both drag-and-drop and standard Qt file selection dialogs.
   Cleanly terminates background processes (including swayidle) on window close.
================================================================================
"""

import sys
import os
import shlex
import shutil
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime, date
from typing import Optional, List, Dict, Any, Tuple

# Check PyQt6 availability with friendly guidance
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
        QHBoxLayout, QSplitter, QTextEdit, QLineEdit, QPushButton,
        QLabel, QGroupBox, QFileDialog, QMessageBox, QDialog,
        QDialogButtonBox, QSpinBox, QRadioButton, QButtonGroup,
        QScrollArea, QFrame, QProgressBar, QGridLayout,
        QSystemTrayIcon, QMenu, QStatusBar
    )
    from PyQt6.QtCore import Qt, QProcess, pyqtSignal, QTimer
    from PyQt6.QtGui import (
        QFont, QDragEnterEvent, QDropEvent, QIcon, QPixmap, QPainter,
        QColor, QAction
    )
except ImportError:
    print(
        "\n[DevPulse Error] PyQt6 is not installed.\n"
        "On Debian 13 (Trixie), please install it via apt:\n"
        "  sudo apt update && sudo apt install -y python3-pyqt6\n",
        file=sys.stderr
    )
    sys.exit(1)

# Check PyYAML availability
try:
    import yaml
except ImportError:
    yaml = None

# Import existing core modules (NO crypto or tracking logic re-implemented here)
import secret
import focus
import ergo
import audit


# Subcommands permitted in the integrated console
ALLOWED_SUBCOMMANDS = {
    "keygen", "fingerprint", "send", "open", "selftest", "focus", "ergo", "audit", "gui"
}


# ==============================================================================
# Tray Icon & Graphical Helper Functions
# ==============================================================================

def create_circle_icon(color_hex: str, size: int = 22) -> QIcon:
    """Renders a simple filled anti-aliased circle icon with QPainter without image files."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(color_hex))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(1, 1, size - 2, size - 2)
    painter.end()
    return QIcon(pixmap)


def get_latest_focus_category() -> Optional[str]:
    """
    Reads the most recent row in focus_events from focus.db in read-only mode.
    Returns category ('focus', 'distraction', 'neutral') or None if unavailable.
    Never crashes.
    """
    db_path = focus.get_db_path()
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='focus_events';")
        if not cur.fetchone():
            conn.close()
            return None
        cur.execute("SELECT category FROM focus_events ORDER BY id DESC LIMIT 1;")
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


# ==============================================================================
# Database Helper Functions (Tolerant & Privacy-Preserving)
# ==============================================================================

def get_today_focus_metrics() -> Dict[str, Any]:
    """
    Reads focus.db for today's metrics.
    Tables: focus_events(timestamp, window_class, category, duration_seconds)
            window_switches(timestamp, window_class)
    Returns zeros if database is missing. Never crashes.
    """
    db_path = focus.get_db_path()
    metrics = {
        "focus_seconds": 0.0,
        "distraction_seconds": 0.0,
        "neutral_seconds": 0.0,
        "total_seconds": 0.0,
        "focus_score": 0.0,
        "switch_count": 0
    }
    if not db_path.exists():
        return metrics

    today_iso = date.today().isoformat()
    try:
        conn = sqlite3.connect(str(db_path), timeout=3.0)
        cur = conn.cursor()

        # Check existing tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cur.fetchall()]

        if "focus_events" in tables:
            cur.execute("""
                SELECT category, SUM(duration_seconds)
                FROM focus_events
                WHERE date(timestamp) = ?
                GROUP BY category
            """, (today_iso,))
            for cat, dur in cur.fetchall():
                val = float(dur) if dur else 0.0
                if cat == "focus":
                    metrics["focus_seconds"] = val
                elif cat == "distraction":
                    metrics["distraction_seconds"] = val
                elif cat == "neutral":
                    metrics["neutral_seconds"] = val

        if "window_switches" in tables:
            cur.execute("SELECT COUNT(*) FROM window_switches WHERE date(timestamp) = ?", (today_iso,))
            row = cur.fetchone()
            metrics["switch_count"] = row[0] if row else 0

        conn.close()

        total = metrics["focus_seconds"] + metrics["distraction_seconds"] + metrics["neutral_seconds"]
        metrics["total_seconds"] = total
        denom = metrics["focus_seconds"] + metrics["distraction_seconds"]
        if denom > 0:
            metrics["focus_score"] = round((metrics["focus_seconds"] / denom) * 100.0, 1)
        else:
            metrics["focus_score"] = 100.0 if total > 0 else 0.0

    except Exception:
        pass

    return metrics


def get_today_ergo_metrics() -> Dict[str, Any]:
    """
    Reads ergo.db by inspecting tables and columns via PRAGMA table_info.
    Returns counts for today. Returns zeros if database is missing.
    """
    db_path = ergo.get_ergo_db_path()
    metrics = {
        "break_shown": 0,
        "rest_detected": 0,
        "commit_detected": 0,
        "manual_done": 0,
        "total_breaks": 0,
        "active_minutes": 0,
        "last_break_time": "None recorded today"
    }

    # Fetch active minutes from focus.db if available
    focus_m = get_today_focus_metrics()
    metrics["active_minutes"] = int(round(focus_m["total_seconds"] / 60.0))

    if not db_path.exists():
        return metrics

    today_iso = date.today().isoformat()
    try:
        conn = sqlite3.connect(str(db_path), timeout=3.0)
        table_name, columns = audit.inspect_ergo_schema(conn)

        if not table_name or "event_type" not in columns or "timestamp" not in columns:
            conn.close()
            return metrics

        cur = conn.cursor()
        cur.execute(f"""
            SELECT event_type, COUNT(*)
            FROM {table_name}
            WHERE date(timestamp) = ?
            GROUP BY event_type
        """, (today_iso,))

        for etype, cnt in cur.fetchall():
            if etype in metrics:
                metrics[etype] = cnt

        metrics["total_breaks"] = metrics["break_shown"]

        # If a dedicated active/duration column exists in ergo table schema, prioritize it
        for col in ["duration_seconds", "active_seconds", "duration", "active_minutes"]:
            if col in columns:
                cur.execute(f"""
                    SELECT SUM({col})
                    FROM {table_name}
                    WHERE date(timestamp) = ?
                """, (today_iso,))
                row = cur.fetchone()
                if row and row[0]:
                    if col == "active_minutes":
                        metrics["active_minutes"] = int(round(row[0]))
                    else:
                        metrics["active_minutes"] = int(round(row[0] / 60.0))
                break

        # Last break timestamp
        cur.execute(f"""
            SELECT timestamp
            FROM {table_name}
            WHERE event_type = 'break_shown'
            ORDER BY id DESC
            LIMIT 1
        """)
        last_row = cur.fetchone()
        if last_row and last_row[0]:
            try:
                dt = datetime.fromisoformat(last_row[0])
                metrics["last_break_time"] = dt.strftime("%H:%M:%S")
            except Exception:
                metrics["last_break_time"] = str(last_row[0])

        conn.close()
    except Exception:
        pass

    return metrics


def get_today_audit_metrics() -> Dict[str, int]:
    """
    Reads audit.db for SecretBridge operations today.
    Table: secret_events(id, timestamp, event_type, mode)
    Returns zeros if database is missing.
    """
    db_path = audit.get_audit_db_path()
    metrics = {
        "encrypted_today": 0,
        "decrypted_today": 0,
        "total_secret_events": 0
    }
    if not db_path.exists():
        return metrics

    today_iso = date.today().isoformat()
    try:
        conn = sqlite3.connect(str(db_path), timeout=3.0)
        cur = conn.cursor()
        cur.execute("""
            SELECT event_type, COUNT(*)
            FROM secret_events
            WHERE date(timestamp) = ?
            GROUP BY event_type
        """, (today_iso,))

        for etype, cnt in cur.fetchall():
            if etype == "message_encrypted":
                metrics["encrypted_today"] = cnt
            elif etype == "message_decrypted":
                metrics["decrypted_today"] = cnt
            metrics["total_secret_events"] += cnt

        conn.close()
    except Exception:
        pass

    return metrics


# ==============================================================================
# Helper Functions & Dialogs
# ==============================================================================

def mask_env_content(raw_text: str) -> str:
    """Masks secret values in a .env file while keeping variable names visible."""
    masked_lines = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            masked_lines.append(line)
        elif "=" in line:
            key, _ = line.split("=", 1)
            masked_lines.append(f"{key.strip()}=****")
        else:
            masked_lines.append(line)
    return "\n".join(masked_lines)


class PassphraseDialog(QDialog):
    """Modal dialog to securely enter and confirm a passphrase twice."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Enter Passphrase")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Passphrase:"))
        self.pass1_edit = QLineEdit(self)
        self.pass1_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass1_edit)

        layout.addWidget(QLabel("Confirm Passphrase:"))
        self.pass2_edit = QLineEdit(self)
        self.pass2_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass2_edit)

        self.error_label = QLabel("", self)
        self.error_label.setStyleSheet("color: red;")
        layout.addWidget(self.error_label)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self
        )
        self.buttons.accepted.connect(self.validate)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def validate(self) -> None:
        p1 = self.pass1_edit.text()
        p2 = self.pass2_edit.text()
        if not p1:
            self.error_label.setText("Passphrase cannot be empty.")
            return
        if p1 != p2:
            self.error_label.setText("Passphrases do not match.")
            return
        self.accept()

    def get_passphrase(self) -> str:
        return self.pass1_edit.text()


class FileDropArea(QFrame):
    """A drop target that also provides a fallback button for Wayland reliability."""
    fileSelected = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Sunken)

        layout = QHBoxLayout(self)
        self.label = QLabel("Drag & drop a .env file here, or click Browse:", self)
        layout.addWidget(self.label)

        self.browse_btn = QPushButton("Browse...", self)
        self.browse_btn.clicked.connect(self.browse_file)
        layout.addWidget(self.browse_btn)

    def browse_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select .env File", "", "Environment Files (*.env *.env.* *env*);;All Files (*)"
        )
        if filename:
            self.fileSelected.emit(filename)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if urls:
            local_path = urls[0].toLocalFile()
            if local_path and os.path.isfile(local_path):
                self.fileSelected.emit(local_path)
                event.acceptProposedAction()


# ==============================================================================
# Reusable Monospace YAML Configuration Editor
# ==============================================================================

class YamlEditorWidget(QWidget):
    """
    Monospace YAML file editor with validation, automatic .bak backups,
    and default restoration.
    """

    def __init__(
        self,
        file_path: Path,
        default_content: str,
        help_text: str,
        log_callback,
        parent: Optional[QWidget] = None
    ):
        super().__init__(parent)
        self.file_path = file_path
        self.default_content = default_content
        self.help_text = help_text
        self.log_callback = log_callback

        self.init_ui()
        self.reload_from_disk()

    def init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header with title and one-line help text
        header_layout = QHBoxLayout()
        title_lbl = QLabel(f"<b>Configuration:</b> <code>{self.file_path.name}</code>", self)
        header_layout.addWidget(title_lbl)

        help_lbl = QLabel(f"<span style='color: #666;'>({self.help_text})</span>", self)
        header_layout.addWidget(help_lbl)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Monospace Text Editor
        self.editor = QTextEdit(self)
        self.editor.setFont(QFont("Monospace", 9))
        self.editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.editor)

        # Action Buttons Bar
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Configuration", self)
        self.save_btn.clicked.connect(self.save_yaml)
        btn_layout.addWidget(self.save_btn)

        self.reload_btn = QPushButton("Reload from Disk", self)
        self.reload_btn.clicked.connect(self.reload_from_disk)
        btn_layout.addWidget(self.reload_btn)

        self.reset_btn = QPushButton("Reset to Defaults", self)
        self.reset_btn.clicked.connect(self.reset_defaults)
        btn_layout.addWidget(self.reset_btn)

        btn_layout.addStretch()
        self.custom_btn_layout = QHBoxLayout()
        btn_layout.addLayout(self.custom_btn_layout)

        layout.addLayout(btn_layout)

    def reload_from_disk(self) -> None:
        """Loads YAML content from disk, writing defaults if file does not exist."""
        if not self.file_path.exists():
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                self.file_path.write_text(self.default_content, encoding="utf-8")
            except Exception as e:
                self.log_callback(f"Error creating default {self.file_path.name}: {e}")

        try:
            content = self.file_path.read_text(encoding="utf-8")
            self.editor.setPlainText(content)
            self.log_callback(f"Loaded {self.file_path.name} into editor")
        except Exception as e:
            self.editor.setPlainText(f"# Error reading {self.file_path.name}: {e}")

    def save_yaml(self) -> bool:
        """Validates YAML syntax, creates a .bak backup, and writes to disk."""
        content = self.editor.toPlainText()

        # Validate with yaml.safe_load
        if yaml is not None:
            try:
                parsed = yaml.safe_load(content)
                if not isinstance(parsed, dict) and parsed is not None:
                    QMessageBox.warning(self, "Invalid YAML", "Configuration must be a top-level YAML mapping/dictionary.")
                    return False
            except Exception as e:
                QMessageBox.warning(self, "YAML Syntax Error", f"Failed to validate YAML:\n\n{e}")
                return False

        # Create .bak copy before writing
        if self.file_path.exists():
            try:
                bak_path = self.file_path.with_name(self.file_path.name + ".bak")
                shutil.copyfile(self.file_path, bak_path)
            except Exception as e:
                self.log_callback(f"Notice: Could not write backup file: {e}")

        try:
            self.file_path.write_text(content, encoding="utf-8")
            self.log_callback(f"Saved {self.file_path.name} (backup copy at {self.file_path.name}.bak)")
            QMessageBox.information(
                self,
                "Saved",
                f"Configuration saved successfully!\n\nA backup copy was preserved at:\n{self.file_path.name}.bak"
            )
            return True
        except Exception as e:
            QMessageBox.critical(self, "Error Saving", f"Failed to write file:\n{e}")
            return False

    def reset_defaults(self) -> None:
        """Prompts user before resetting editor and file to defaults."""
        res = QMessageBox.question(
            self,
            "Reset Configuration",
            f"Are you sure you want to reset {self.file_path.name} to default settings?\n"
            "A .bak backup of your current file will be preserved.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if res == QMessageBox.StandardButton.Yes:
            self.editor.setPlainText(self.default_content)
            self.save_yaml()


# ==============================================================================
# Tab 1: Dashboard
# ==============================================================================

class DashboardTab(QWidget):
    """Live system overview with focus metrics, activity bars, event counters, and audit trigger."""

    def __init__(self, run_command_callback, log_callback, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.run_command_callback = run_command_callback
        self.log_callback = log_callback

        self.init_ui()

        # Auto-refresh timer every 10 seconds (10,000 ms)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(10000)

        self.refresh_data()

    def init_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Header controls
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h2>Today's Activity Overview</h2>", self))
        header_layout.addStretch()

        self.timer_info = QLabel("Auto-refresh: 10s", self)
        self.timer_info.setStyleSheet("color: #777; font-size: 11px;")
        header_layout.addWidget(self.timer_info)

        self.refresh_btn = QPushButton("Refresh Now", self)
        self.refresh_btn.clicked.connect(self.refresh_data)
        header_layout.addWidget(self.refresh_btn)

        self.audit_btn = QPushButton("Generate Audit Report", self)
        self.audit_btn.clicked.connect(self.generate_audit_report)
        header_layout.addWidget(self.audit_btn)

        layout.addLayout(header_layout)

        # Top Section: Focus Score Progress Bar
        score_group = QGroupBox("Focus Score (Focus / [Focus + Distraction])", self)
        score_layout = QVBoxLayout(score_group)

        self.score_bar = QProgressBar(self)
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        self.score_bar.setFixedHeight(26)
        self.score_bar.setFormat("%p% Focus Score")
        self.score_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_layout.addWidget(self.score_bar)

        layout.addWidget(score_group)

        # Middle Section: Time Breakdown Simple Bars
        breakdown_group = QGroupBox("Active Time Breakdown (Minutes Today)", self)
        grid = QGridLayout(breakdown_group)

        grid.addWidget(QLabel("<b>Focus Time:</b>", self), 0, 0)
        self.focus_bar = QProgressBar(self)
        self.focus_bar.setTextVisible(True)
        grid.addWidget(self.focus_bar, 0, 1)
        self.focus_lbl = QLabel("0m", self)
        grid.addWidget(self.focus_lbl, 0, 2)

        grid.addWidget(QLabel("<b>Distraction Time:</b>", self), 1, 0)
        self.distract_bar = QProgressBar(self)
        self.distract_bar.setTextVisible(True)
        grid.addWidget(self.distract_bar, 1, 1)
        self.distract_lbl = QLabel("0m", self)
        grid.addWidget(self.distract_lbl, 1, 2)

        grid.addWidget(QLabel("<b>Neutral Time:</b>", self), 2, 0)
        self.neutral_bar = QProgressBar(self)
        self.neutral_bar.setTextVisible(True)
        grid.addWidget(self.neutral_bar, 2, 1)
        self.neutral_lbl = QLabel("0m", self)
        grid.addWidget(self.neutral_lbl, 2, 2)

        layout.addWidget(breakdown_group)

        # Bottom Section: Event Counters
        counters_group = QGroupBox("Today's Event Totals", self)
        cnt_layout = QGridLayout(counters_group)

        self.switches_val = QLabel("<b>0</b>", self)
        cnt_layout.addWidget(QLabel("Window Switches:"), 0, 0)
        cnt_layout.addWidget(self.switches_val, 0, 1)

        self.breaks_val = QLabel("<b>0</b>", self)
        cnt_layout.addWidget(QLabel("Breaks Prompted:"), 0, 2)
        cnt_layout.addWidget(self.breaks_val, 0, 3)

        self.rests_val = QLabel("<b>0</b>", self)
        cnt_layout.addWidget(QLabel("Natural Rests (5m+):"), 1, 0)
        cnt_layout.addWidget(self.rests_val, 1, 1)

        self.enc_val = QLabel("<b>0</b>", self)
        cnt_layout.addWidget(QLabel("Messages Encrypted:"), 1, 2)
        cnt_layout.addWidget(self.enc_val, 1, 3)

        self.dec_val = QLabel("<b>0</b>", self)
        cnt_layout.addWidget(QLabel("Messages Decrypted:"), 2, 2)
        cnt_layout.addWidget(self.dec_val, 2, 3)

        layout.addWidget(counters_group)
        layout.addStretch()

    def refresh_data(self) -> None:
        """Queries databases and refreshes all dashboard values."""
        focus_m = get_today_focus_metrics()
        ergo_m = get_today_ergo_metrics()
        audit_m = get_today_audit_metrics()

        # Update Score
        score = int(round(focus_m["focus_score"]))
        self.score_bar.setValue(score)

        # Update Time Breakdown Bars (in whole minutes)
        f_min = int(round(focus_m["focus_seconds"] / 60.0))
        d_min = int(round(focus_m["distraction_seconds"] / 60.0))
        n_min = int(round(focus_m["neutral_seconds"] / 60.0))
        total_min = max(1, f_min + d_min + n_min)

        self.focus_bar.setRange(0, total_min)
        self.focus_bar.setValue(f_min)
        self.focus_lbl.setText(f"{f_min} min")

        self.distract_bar.setRange(0, total_min)
        self.distract_bar.setValue(d_min)
        self.distract_lbl.setText(f"{d_min} min")

        self.neutral_bar.setRange(0, total_min)
        self.neutral_bar.setValue(n_min)
        self.neutral_lbl.setText(f"{n_min} min")

        # Update Counters
        self.switches_val.setText(f"<b>{focus_m['switch_count']}</b>")
        self.breaks_val.setText(f"<b>{ergo_m['total_breaks']}</b>")
        self.rests_val.setText(f"<b>{ergo_m['rest_detected']}</b>")
        self.enc_val.setText(f"<b>{audit_m['encrypted_today']}</b>")
        self.dec_val.setText(f"<b>{audit_m['decrypted_today']}</b>")

    def generate_audit_report(self) -> None:
        self.log_callback("Triggered 'audit' command from Dashboard")
        self.run_command_callback(["audit"])


# ==============================================================================
# Tab 2: FocusPulse
# ==============================================================================

class FocusPulseTab(QWidget):
    """FocusPulse window activity controller, live status, metrics, and YAML editor."""

    def __init__(
        self,
        run_devpulse_proc,
        stop_devpulse_proc,
        run_command_callback,
        log_callback,
        state_changed_callback=None,
        parent: Optional[QWidget] = None
    ):
        super().__init__(parent)
        self.run_devpulse_proc = run_devpulse_proc
        self.stop_devpulse_proc = stop_devpulse_proc
        self.run_command_callback = run_command_callback
        self.log_callback = log_callback
        self.state_changed_callback = state_changed_callback
        self.is_running = False

        self.init_ui()
        self.refresh_stats()

    def init_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Control & Status Header
        ctrl_group = QGroupBox("FocusPulse Tracker Control", self)
        ctrl_layout = QHBoxLayout(ctrl_group)

        self.start_stop_btn = QPushButton("Start FocusPulse", self)
        self.start_stop_btn.setFixedHeight(34)
        self.start_stop_btn.clicked.connect(self.toggle_service)
        ctrl_layout.addWidget(self.start_stop_btn)

        self.status_lbl = QLabel("Status: <b>Stopped</b>", self)
        ctrl_layout.addWidget(self.status_lbl)

        self.selftest_btn = QPushButton("Run Selftest", self)
        self.selftest_btn.setFixedHeight(34)
        self.selftest_btn.clicked.connect(self.trigger_selftest)
        ctrl_layout.addWidget(self.selftest_btn)

        ctrl_layout.addStretch()

        self.refresh_stats_btn = QPushButton("Refresh Stats", self)
        self.refresh_stats_btn.clicked.connect(self.refresh_stats)
        ctrl_layout.addWidget(self.refresh_stats_btn)

        layout.addWidget(ctrl_group)

        # Today's Summary Numbers
        summary_group = QGroupBox("Today's Focus Metrics", self)
        sum_layout = QGridLayout(summary_group)

        self.f_time_lbl = QLabel("0s", self)
        sum_layout.addWidget(QLabel("Focus Time:"), 0, 0)
        sum_layout.addWidget(self.f_time_lbl, 0, 1)

        self.d_time_lbl = QLabel("0s", self)
        sum_layout.addWidget(QLabel("Distraction Time:"), 0, 2)
        sum_layout.addWidget(self.d_time_lbl, 0, 3)

        self.n_time_lbl = QLabel("0s", self)
        sum_layout.addWidget(QLabel("Neutral Time:"), 0, 4)
        sum_layout.addWidget(self.n_time_lbl, 0, 5)

        self.sw_lbl = QLabel("0", self)
        sum_layout.addWidget(QLabel("Window Switches:"), 1, 0)
        sum_layout.addWidget(self.sw_lbl, 1, 1)

        self.score_lbl = QLabel("0.0%", self)
        sum_layout.addWidget(QLabel("Focus Score:"), 1, 2)
        sum_layout.addWidget(self.score_lbl, 1, 3)

        layout.addWidget(summary_group)

        # Built-in YAML Editor for ~/.config/devpulse/focus.yaml
        yaml_help = "Allow-list is evaluated first, then block-list. Everything else defaults to neutral."
        self.yaml_editor = YamlEditorWidget(
            file_path=focus.get_rules_path(),
            default_content=focus.DEFAULT_FOCUS_YAML,
            help_text=yaml_help,
            log_callback=self.log_callback,
            parent=self
        )
        layout.addWidget(self.yaml_editor)

    def toggle_service(self) -> None:
        if not self.is_running:
            success = self.run_devpulse_proc("focus", ["focus", "start"], self.on_process_ended)
            if success:
                self.is_running = True
                self.start_stop_btn.setText("Stop FocusPulse")
                self.status_lbl.setText("Status: <span style='color: green;'><b>Running</b></span>")
                self.log_callback("FocusPulse background tracker started")
                if self.state_changed_callback:
                    self.state_changed_callback()
        else:
            self.stop_devpulse_proc("focus")
            self.is_running = False
            self.start_stop_btn.setText("Start FocusPulse")
            self.status_lbl.setText("Status: <b>Stopped</b>")
            self.log_callback("FocusPulse background tracker stopped")
            self.refresh_stats()
            if self.state_changed_callback:
                self.state_changed_callback()

    def on_process_ended(self) -> None:
        self.is_running = False
        self.start_stop_btn.setText("Start FocusPulse")
        self.status_lbl.setText("Status: <b>Stopped</b>")
        self.refresh_stats()
        if self.state_changed_callback:
            self.state_changed_callback()

    def trigger_selftest(self) -> None:
        self.log_callback("Running 'focus selftest' through console...")
        self.run_command_callback(["focus", "selftest"])

    def refresh_stats(self) -> None:
        m = get_today_focus_metrics()
        self.f_time_lbl.setText(f"<b>{focus.format_duration(m['focus_seconds'])}</b>")
        self.d_time_lbl.setText(f"<b>{focus.format_duration(m['distraction_seconds'])}</b>")
        self.n_time_lbl.setText(f"<b>{focus.format_duration(m['neutral_seconds'])}</b>")
        self.sw_lbl.setText(f"<b>{m['switch_count']}</b>")
        self.score_lbl.setText(f"<b>{m['focus_score']}%</b>")


# ==============================================================================
# Tab 3: ErgoGuard
# ==============================================================================

class ErgoGuardTab(QWidget):
    """ErgoGuard monitor controller, reset triggers, event counts, and ergo.yaml editor."""

    def __init__(
        self,
        run_devpulse_proc,
        stop_devpulse_proc,
        run_command_callback,
        log_callback,
        state_changed_callback=None,
        parent: Optional[QWidget] = None
    ):
        super().__init__(parent)
        self.run_devpulse_proc = run_devpulse_proc
        self.stop_devpulse_proc = stop_devpulse_proc
        self.run_command_callback = run_command_callback
        self.log_callback = log_callback
        self.state_changed_callback = state_changed_callback
        self.is_running = False

        self.init_ui()
        self.refresh_stats()

    def init_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Control Header
        ctrl_group = QGroupBox("ErgoGuard Monitor Control", self)
        ctrl_layout = QHBoxLayout(ctrl_group)

        self.start_stop_btn = QPushButton("Start ErgoGuard", self)
        self.start_stop_btn.setFixedHeight(34)
        self.start_stop_btn.clicked.connect(self.toggle_service)
        ctrl_layout.addWidget(self.start_stop_btn)

        self.status_lbl = QLabel("Status: <b>Stopped</b>", self)
        ctrl_layout.addWidget(self.status_lbl)

        self.done_btn = QPushButton("Done (Reset Timers)", self)
        self.done_btn.setFixedHeight(34)
        self.done_btn.clicked.connect(self.trigger_done)
        ctrl_layout.addWidget(self.done_btn)

        self.selftest_btn = QPushButton("Run Selftest", self)
        self.selftest_btn.setFixedHeight(34)
        self.selftest_btn.clicked.connect(self.trigger_selftest)
        ctrl_layout.addWidget(self.selftest_btn)

        ctrl_layout.addStretch()

        self.refresh_btn = QPushButton("Refresh Stats", self)
        self.refresh_btn.clicked.connect(self.refresh_stats)
        ctrl_layout.addWidget(self.refresh_btn)

        layout.addWidget(ctrl_group)

        # Today's Event Counts
        events_group = QGroupBox("Today's Ergonomic Statistics", self)
        ev_layout = QGridLayout(events_group)

        self.active_time_lbl = QLabel("0m", self)
        ev_layout.addWidget(QLabel("Active Work Time:"), 0, 0)
        ev_layout.addWidget(self.active_time_lbl, 0, 1)

        self.breaks_lbl = QLabel("0", self)
        ev_layout.addWidget(QLabel("Breaks Prompted:"), 0, 2)
        ev_layout.addWidget(self.breaks_lbl, 0, 3)

        self.rests_lbl = QLabel("0", self)
        ev_layout.addWidget(QLabel("Natural Rests (5m+):"), 1, 0)
        ev_layout.addWidget(self.rests_lbl, 1, 1)

        self.commits_lbl = QLabel("0", self)
        ev_layout.addWidget(QLabel("Git Commits:"), 1, 2)
        ev_layout.addWidget(self.commits_lbl, 1, 3)

        self.manual_lbl = QLabel("0", self)
        ev_layout.addWidget(QLabel("Manual Resets:"), 2, 0)
        ev_layout.addWidget(self.manual_lbl, 2, 1)

        self.last_break_lbl = QLabel("None", self)
        ev_layout.addWidget(QLabel("Last Break Time:"), 2, 2)
        ev_layout.addWidget(self.last_break_lbl, 2, 3)

        layout.addWidget(events_group)

        # Built-in YAML Editor for ~/.config/devpulse/ergo.yaml
        yaml_help = "Break intervals in active minutes. Git watch roots scanned 1 level deep."
        self.yaml_editor = YamlEditorWidget(
            file_path=ergo.get_ergo_yaml_path(),
            default_content=ergo.DEFAULT_ERGO_YAML,
            help_text=yaml_help,
            log_callback=self.log_callback,
            parent=self
        )

        # Add "Test timings (1/2 min)" and "Restore 20/45/90" buttons
        self.test_timings_btn = QPushButton("Test Timings (1/2 min)", self)
        self.test_timings_btn.clicked.connect(self.apply_test_timings)
        self.yaml_editor.custom_btn_layout.addWidget(self.test_timings_btn)

        self.restore_timings_btn = QPushButton("Restore 20/45/90", self)
        self.restore_timings_btn.clicked.connect(self.apply_default_timings)
        self.yaml_editor.custom_btn_layout.addWidget(self.restore_timings_btn)

        layout.addWidget(self.yaml_editor)

    def toggle_service(self) -> None:
        if not self.is_running:
            success = self.run_devpulse_proc("ergo", ["ergo", "start"], self.on_process_ended)
            if success:
                self.is_running = True
                self.start_stop_btn.setText("Stop ErgoGuard")
                self.status_lbl.setText("Status: <span style='color: green;'><b>Running</b></span>")
                self.log_callback("ErgoGuard background monitor started")
                if self.state_changed_callback:
                    self.state_changed_callback()
        else:
            self.stop_devpulse_proc("ergo")
            self.is_running = False
            self.start_stop_btn.setText("Start ErgoGuard")
            self.status_lbl.setText("Status: <b>Stopped</b>")
            self.log_callback("ErgoGuard background monitor stopped")
            self.refresh_stats()
            if self.state_changed_callback:
                self.state_changed_callback()

    def on_process_ended(self) -> None:
        self.is_running = False
        self.start_stop_btn.setText("Start ErgoGuard")
        self.status_lbl.setText("Status: <b>Stopped</b>")
        self.refresh_stats()
        if self.state_changed_callback:
            self.state_changed_callback()

    def trigger_done(self) -> None:
        self.log_callback("Running 'ergo done' through console...")
        self.run_command_callback(["ergo", "done"])

    def trigger_selftest(self) -> None:
        self.log_callback("Running 'ergo selftest' through console...")
        self.run_command_callback(["ergo", "selftest"])

    def refresh_stats(self) -> None:
        m = get_today_ergo_metrics()
        self.active_time_lbl.setText(f"<b>{m['active_minutes']} min</b>")
        self.breaks_lbl.setText(f"<b>{m['total_breaks']}</b>")
        self.rests_lbl.setText(f"<b>{m['rest_detected']}</b>")
        self.commits_lbl.setText(f"<b>{m['commit_detected']}</b>")
        self.manual_lbl.setText(f"<b>{m['manual_done']}</b>")
        self.last_break_lbl.setText(f"<b>{m['last_break_time']}</b>")

    def _modify_break_intervals(self, eye_min: int, stretch_min: int, walk_min: int) -> None:
        """Helper to modify intervals in YAML editor and disk after reading real structure."""
        content = self.yaml_editor.editor.toPlainText()
        data = None
        if yaml is not None:
            try:
                data = yaml.safe_load(content)
            except Exception:
                pass

        if not isinstance(data, dict) or "breaks" not in data:
            data = ergo.load_ergo_config()

        # Update values on real structure
        data["breaks"]["eye"]["interval_minutes"] = eye_min
        data["breaks"]["stretch"]["interval_minutes"] = stretch_min
        data["breaks"]["walk"]["interval_minutes"] = walk_min

        if yaml is not None:
            new_yaml = yaml.dump(data, sort_keys=False, default_flow_style=False)
        else:
            new_yaml = ergo.DEFAULT_ERGO_YAML

        self.yaml_editor.editor.setPlainText(new_yaml)
        self.yaml_editor.save_yaml()

    def apply_test_timings(self) -> None:
        self._modify_break_intervals(eye_min=1, stretch_min=2, walk_min=3)
        self.log_callback("Configured short test intervals: Eye=1m, Stretch=2m, Walk=3m")

    def apply_default_timings(self) -> None:
        self._modify_break_intervals(eye_min=20, stretch_min=45, walk_min=90)
        self.log_callback("Restored default ergonomic intervals: Eye=20m, Stretch=45m, Walk=90m")


# ==============================================================================
# SecretBridge Tab (Preserved 100% Intact as Requested)
# ==============================================================================

class SecretBridgeTab(QWidget):
    """Full GUI implementation of SecretBridge calling existing functions in secret.py and audit.py."""

    def __init__(self, log_callback, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.log_callback = log_callback
        self.current_file_path: Optional[str] = None
        self.init_ui()
        self.refresh_my_key()

    def init_ui(self) -> None:
        main_layout = QHBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        main_layout.addWidget(splitter)

        # Left Side
        left_widget = QWidget(self)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(4, 4, 4, 4)

        # My Key Area
        key_group = QGroupBox("My Identity & Public Key", self)
        key_layout = QVBoxLayout(key_group)

        self.my_key_label = QLabel("Loading key...", self)
        self.my_key_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        key_layout.addWidget(self.my_key_label)

        key_btn_layout = QHBoxLayout()
        self.copy_my_key_btn = QPushButton("Copy My Public Key", self)
        self.copy_my_key_btn.clicked.connect(self.copy_my_key)
        key_btn_layout.addWidget(self.copy_my_key_btn)

        self.my_key_copied_lbl = QLabel("", self)
        self.my_key_copied_lbl.setStyleSheet("color: green; font-weight: bold;")
        key_btn_layout.addWidget(self.my_key_copied_lbl)

        key_btn_layout.addStretch()

        self.gen_key_btn = QPushButton("Generate New Keys", self)
        self.gen_key_btn.clicked.connect(self.generate_keys)
        key_btn_layout.addWidget(self.gen_key_btn)

        key_layout.addLayout(key_btn_layout)
        left_layout.addWidget(key_group)

        # Mode Selector
        mode_btn_layout = QHBoxLayout()
        mode_btn_layout.addWidget(QLabel("Action:", self))
        self.mode_send_radio = QRadioButton("SEND (Encrypt .env for Chat)", self)
        self.mode_open_radio = QRadioButton("OPEN (Decrypt Chat Message)", self)
        self.mode_send_radio.setChecked(True)

        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.mode_send_radio, 1)
        self.mode_group.addButton(self.mode_open_radio, 2)
        self.mode_group.idToggled.connect(self.on_mode_toggled)

        mode_btn_layout.addWidget(self.mode_send_radio)
        mode_btn_layout.addWidget(self.mode_open_radio)
        mode_btn_layout.addStretch()
        left_layout.addLayout(mode_btn_layout)

        # Containers
        self.send_container = QWidget(self)
        self.init_send_ui(self.send_container)
        left_layout.addWidget(self.send_container)

        self.open_container = QWidget(self)
        self.init_open_ui(self.open_container)
        self.open_container.hide()
        left_layout.addWidget(self.open_container)

        left_layout.addStretch()
        splitter.addWidget(left_widget)

        # Right Side Help
        right_widget = QWidget(self)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(4, 4, 4, 4)

        self.help_group = QGroupBox("How SecretBridge Works", self)
        help_group_layout = QVBoxLayout(self.help_group)

        self.help_text = QTextEdit(self)
        self.help_text.setReadOnly(True)
        help_group_layout.addWidget(self.help_text)

        right_layout.addWidget(self.help_group)
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)

        self.update_help_text("send")

    def init_send_ui(self, container: QWidget) -> None:
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        file_group = QGroupBox("1. Select .env File", container)
        file_layout = QVBoxLayout(file_group)

        self.drop_area = FileDropArea(self)
        self.drop_area.fileSelected.connect(self.on_file_selected)
        file_layout.addWidget(self.drop_area)

        file_actions_layout = QHBoxLayout()
        self.sample_btn = QPushButton("Create Sample .env (Safe Test)", self)
        self.sample_btn.clicked.connect(self.create_sample_env)
        file_actions_layout.addWidget(self.sample_btn)

        self.selected_file_label = QLabel("No file selected", self)
        self.selected_file_label.setStyleSheet("font-style: italic;")
        file_actions_layout.addWidget(self.selected_file_label)
        file_actions_layout.addStretch()
        file_layout.addLayout(file_actions_layout)

        file_layout.addWidget(QLabel("Masked Preview (Variable names visible, values hidden):", self))
        self.preview_edit = QTextEdit(self)
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setFixedHeight(90)
        self.preview_edit.setFont(QFont("Monospace", 9))
        file_layout.addWidget(self.preview_edit)

        layout.addWidget(file_group)

        enc_group = QGroupBox("2. Encryption Options", container)
        enc_layout = QVBoxLayout(enc_group)

        type_layout = QHBoxLayout()
        self.type_pub_radio = QRadioButton("Public-Key (SealedBox)", self)
        self.type_pass_radio = QRadioButton("Passphrase (Scrypt)", self)
        self.type_pub_radio.setChecked(True)
        self.type_pub_radio.toggled.connect(self.on_crypto_type_toggled)

        type_layout.addWidget(self.type_pub_radio)
        type_layout.addWidget(self.type_pass_radio)
        type_layout.addStretch()
        enc_layout.addLayout(type_layout)

        self.pubkey_container = QWidget(self)
        pub_layout = QVBoxLayout(self.pubkey_container)
        pub_layout.setContentsMargins(0, 0, 0, 0)

        pub_input_layout = QHBoxLayout()
        pub_input_layout.addWidget(QLabel("Recipient Public Key:", self))
        self.recipient_key_edit = QLineEdit(self)
        self.recipient_key_edit.setPlaceholderText("DEVPULSE-PUB-v1:<base64> or path to public.key file")
        self.recipient_key_edit.textChanged.connect(self.on_recipient_key_changed)
        pub_input_layout.addWidget(self.recipient_key_edit)

        self.use_own_key_btn = QPushButton("Use My Own Key (Test)", self)
        self.use_own_key_btn.clicked.connect(self.use_own_key)
        pub_input_layout.addWidget(self.use_own_key_btn)
        pub_layout.addLayout(pub_input_layout)

        self.recipient_fp_label = QLabel("Recipient Fingerprint: (enter key to verify)", self)
        self.recipient_fp_label.setStyleSheet("font-weight: bold; color: #2b7a78;")
        pub_layout.addWidget(self.recipient_fp_label)

        enc_layout.addWidget(self.pubkey_container)

        expiry_layout = QHBoxLayout()
        expiry_layout.addWidget(QLabel("Expires in (hours, 0 = none):", self))
        self.expiry_spin = QSpinBox(self)
        self.expiry_spin.setRange(0, 720)
        self.expiry_spin.setValue(0)
        expiry_layout.addWidget(self.expiry_spin)
        expiry_layout.addStretch()
        enc_layout.addLayout(expiry_layout)

        layout.addWidget(enc_group)

        action_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt & Generate Token", self)
        self.encrypt_btn.setFixedHeight(34)
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        action_layout.addWidget(self.encrypt_btn)
        layout.addLayout(action_layout)

        result_group = QGroupBox("3. Encrypted Message Token (Paste into Discord/Slack/WhatsApp)", container)
        res_layout = QVBoxLayout(result_group)

        self.token_output = QLineEdit(self)
        self.token_output.setReadOnly(True)
        self.token_output.setFont(QFont("Monospace", 9))
        res_layout.addWidget(self.token_output)

        copy_layout = QHBoxLayout()
        self.copy_token_btn = QPushButton("Copy Token", self)
        self.copy_token_btn.clicked.connect(self.copy_token)
        copy_layout.addWidget(self.copy_token_btn)

        self.token_copied_lbl = QLabel("", self)
        self.token_copied_lbl.setStyleSheet("color: green; font-weight: bold;")
        copy_layout.addWidget(self.token_copied_lbl)
        copy_layout.addStretch()
        res_layout.addLayout(copy_layout)

        layout.addWidget(result_group)

    def init_open_ui(self, container: QWidget) -> None:
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        in_group = QGroupBox("1. Paste Encrypted Message Token", container)
        in_layout = QVBoxLayout(in_group)

        self.open_input = QTextEdit(self)
        self.open_input.setPlaceholderText("Paste DEVPULSE-v1:... or DEVPULSE-v1P:... message here")
        self.open_input.setFixedHeight(80)
        self.open_input.setFont(QFont("Monospace", 9))
        in_layout.addWidget(self.open_input)

        self.decrypt_btn = QPushButton("Decrypt Message", self)
        self.decrypt_btn.setFixedHeight(34)
        self.decrypt_btn.clicked.connect(self.decrypt_token)
        in_layout.addWidget(self.decrypt_btn)

        layout.addWidget(in_group)

        out_group = QGroupBox("2. Decrypted Content", container)
        out_layout = QVBoxLayout(out_group)

        self.open_meta_label = QLabel("Sender: (none) | Created: (none)", self)
        self.open_meta_label.setStyleSheet("font-weight: bold;")
        out_layout.addWidget(self.open_meta_label)

        self.decrypted_content_edit = QTextEdit(self)
        self.decrypted_content_edit.setReadOnly(True)
        self.decrypted_content_edit.setFont(QFont("Monospace", 9))
        out_layout.addWidget(self.decrypted_content_edit)

        save_layout = QHBoxLayout()
        self.save_file_btn = QPushButton("Save as File...", self)
        self.save_file_btn.setEnabled(False)
        self.save_file_btn.clicked.connect(self.save_decrypted_file)
        save_layout.addWidget(self.save_file_btn)
        save_layout.addStretch()
        out_layout.addLayout(save_layout)

        layout.addWidget(out_group)
        self.last_decrypted_payload: Optional[dict] = None

    def on_mode_toggled(self, button_id: int, checked: bool) -> None:
        if checked:
            if button_id == 1:
                self.send_container.show()
                self.open_container.hide()
                self.update_help_text("send")
                self.log_callback("Switched to SecretBridge SEND mode")
            else:
                self.send_container.hide()
                self.open_container.show()
                self.update_help_text("open")
                self.log_callback("Switched to SecretBridge OPEN mode")

    def on_crypto_type_toggled(self, checked: bool) -> None:
        self.pubkey_container.setVisible(checked)

    def refresh_my_key(self) -> None:
        try:
            pub_key, fingerprint = secret.load_own_public_key()
            pub_str = secret.format_public_key(bytes(pub_key))
            self.my_key_str = pub_str
            self.my_key_label.setText(f"Public Key: {pub_str}\nFingerprint: {fingerprint}")
            self.copy_my_key_btn.setEnabled(True)
        except secret.KeyNotFoundError:
            self.my_key_str = ""
            self.my_key_label.setText("No keypair found. Click 'Generate New Keys' to create one.")
            self.copy_my_key_btn.setEnabled(False)
        except Exception as e:
            self.my_key_str = ""
            self.my_key_label.setText(f"Error loading keys: {e}")
            self.copy_my_key_btn.setEnabled(False)

    def copy_my_key(self) -> None:
        if hasattr(self, "my_key_str") and self.my_key_str:
            QApplication.clipboard().setText(self.my_key_str)
            self.my_key_copied_lbl.setText("Copied!")
            QTimer.singleShot(2000, lambda: self.my_key_copied_lbl.setText(""))
            self.log_callback("Copied own public key to clipboard")

    def generate_keys(self) -> None:
        target_dir = secret.get_config_dir()
        priv_path = target_dir / "private.key"

        if priv_path.exists():
            res = QMessageBox.question(
                self,
                "Warning: Overwrite Existing Keys?",
                "Overwriting keys means you will PERMANENTLY LOSE the ability to decrypt "
                "any past messages sent to your current public key.\n\n"
                "Are you sure you want to regenerate keys?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if res != QMessageBox.StandardButton.Yes:
                return

        try:
            pub_str, fingerprint, _, _ = secret.generate_keypair(name="User", force=True)
            audit.log_secret_event("key_generated")
            self.refresh_my_key()
            self.log_callback(f"Keypair generated successfully (Fingerprint: {fingerprint})")
            QMessageBox.information(
                self,
                "Keys Generated",
                f"New Curve25519 keypair generated!\n\nFingerprint: {fingerprint}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Key Generation Error", f"Failed to generate keys: {e}")

    def on_file_selected(self, path: str) -> None:
        self.current_file_path = path
        self.selected_file_label.setText(Path(path).name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            masked = mask_env_content(content)
            self.preview_edit.setPlainText(masked)
            self.log_callback(f"Loaded file: {Path(path).name}")
        except Exception as e:
            self.preview_edit.setPlainText(f"(Error previewing file: {e})")

    def create_sample_env(self) -> None:
        try:
            sample_content = (
                "# Sample configuration for SecretBridge testing\n"
                "API_KEY=sk_test_fake_not_a_real_key_12345\n"
                "DATABASE_URL=postgresql://app_user:fake_password@localhost:5432/sample_db\n"
                "JWT_SECRET=super_secret_sample_key_9999\n"
                "PORT=8080\n"
            )
            sample_path = Path(tempfile.gettempdir()) / "fake_sample.env"
            sample_path.write_text(sample_content, encoding="utf-8")
            self.on_file_selected(str(sample_path))
            self.log_callback(f"Created sample test file at {sample_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create sample .env: {e}")

    def use_own_key(self) -> None:
        if hasattr(self, "my_key_str") and self.my_key_str:
            self.recipient_key_edit.setText(self.my_key_str)
            self.log_callback("Filled recipient box with own public key for testing")
        else:
            QMessageBox.warning(self, "No Key", "Please generate your keypair first.")

    def on_recipient_key_changed(self, text: str) -> None:
        cleaned = text.strip()
        if not cleaned:
            self.recipient_fp_label.setText("Recipient Fingerprint: (enter key to verify)")
            return
        try:
            _, fingerprint = secret.parse_public_key_input(cleaned)
            self.recipient_fp_label.setText(
                f"Recipient Fingerprint: {fingerprint} (Confirm this matches what your friend sees)"
            )
        except Exception:
            self.recipient_fp_label.setText("Recipient Fingerprint: [Invalid key format]")

    def encrypt_file(self) -> None:
        if not self.current_file_path or not os.path.isfile(self.current_file_path):
            QMessageBox.warning(self, "Missing File", "Please select a .env file to encrypt.")
            return

        sender_name = secret.load_sender_name()
        expires = self.expiry_spin.value() or None

        try:
            payload_bytes = secret.build_payload(
                file_path=Path(self.current_file_path),
                sender_name=sender_name,
                expires_hours=expires
            )

            if self.type_pass_radio.isChecked():
                dlg = PassphraseDialog(self)
                if dlg.exec() != QDialog.DialogCode.Accepted:
                    return
                passphrase = dlg.get_passphrase()
                token = secret.encrypt_with_passphrase(payload_bytes, passphrase)
                audit.log_secret_event("message_encrypted", mode="passphrase")
                self.token_output.setText(token)
                self.log_callback("Encrypted .env using Passphrase (Scrypt + SecretBox)")
                QMessageBox.information(
                    self,
                    "Passphrase Mode Reminder",
                    "Remember to share the passphrase through a DIFFERENT channel\n"
                    "(such as a voice call), never in the chat where you send the token!"
                )
            else:
                recipient_input = self.recipient_key_edit.text().strip()
                if not recipient_input:
                    QMessageBox.warning(self, "Missing Recipient", "Please enter the recipient's public key.")
                    return
                recipient_pub, recipient_fp = secret.parse_public_key_input(recipient_input)
                token = secret.encrypt_for_public_key(payload_bytes, recipient_pub)
                audit.log_secret_event("message_encrypted", mode="public_key")
                self.token_output.setText(token)
                self.log_callback(f"Encrypted .env for recipient (Fingerprint: {recipient_fp})")

        except secret.FileSizeExceededError as e:
            QMessageBox.warning(self, "File Too Large", str(e))
        except secret.SecretBridgeError as e:
            QMessageBox.warning(self, "SecretBridge Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Encryption Failed", f"An unexpected error occurred: {e}")

    def copy_token(self) -> None:
        token = self.token_output.text().strip()
        if token:
            QApplication.clipboard().setText(token)
            self.token_copied_lbl.setText("Copied!")
            QTimer.singleShot(2000, lambda: self.token_copied_lbl.setText(""))
            self.log_callback("Copied encrypted token to clipboard")

    def decrypt_token(self) -> None:
        token = self.open_input.toPlainText().strip()
        if not token:
            QMessageBox.warning(self, "Empty Token", "Please paste an encrypted message token.")
            return

        mode = "passphrase" if token.startswith(secret.CIPHERTEXT_PASSPHRASE_PREFIX) else "public_key"

        passphrase = None
        if token.startswith(secret.CIPHERTEXT_PASSPHRASE_PREFIX):
            dlg = QDialog(self)
            dlg.setWindowTitle("Decryption Passphrase")
            dlg_layout = QVBoxLayout(dlg)
            dlg_layout.addWidget(QLabel("Enter passphrase to decrypt this message:", dlg))
            pw_edit = QLineEdit(dlg)
            pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
            dlg_layout.addWidget(pw_edit)
            btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dlg)
            btn_box.accepted.connect(dlg.accept)
            btn_box.rejected.connect(dlg.reject)
            dlg_layout.addWidget(btn_box)

            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            passphrase = pw_edit.text()

        try:
            payload = secret.decrypt_message(token, passphrase=passphrase)
            audit.log_secret_event("message_decrypted", mode=mode)
            self.last_decrypted_payload = payload

            sender = payload.get("sender_name", "Anonymous")
            created = payload.get("created_at", "Unknown")
            fname = payload.get("filename", "unnamed.env")

            self.open_meta_label.setText(
                f"Sender: {sender} (NOTE: Not cryptographically verified) | Created: {created} | File: {fname}"
            )

            import base64
            content = base64.b64decode(payload.get("file_content_b64", "")).decode("utf-8", errors="replace")
            self.decrypted_content_edit.setPlainText(content)
            self.save_file_btn.setEnabled(True)
            self.log_callback(f"Successfully decrypted message from {sender}")

        except secret.ExpiredMessageError as e:
            audit.log_secret_event("message_expired", mode=mode)
            QMessageBox.warning(self, "Message Expired", str(e))
        except secret.DecryptionFailedError as e:
            audit.log_secret_event("decrypt_failed", mode=mode)
            QMessageBox.warning(self, "Decryption Failed", str(e))
        except secret.SecretBridgeError as e:
            QMessageBox.warning(self, "Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt: {e}")

    def save_decrypted_file(self) -> None:
        if not self.last_decrypted_payload:
            return

        suggested_name = self.last_decrypted_payload.get("filename", ".env")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", suggested_name)
        if not save_path:
            return

        target = Path(save_path)
        if target.exists():
            res = QMessageBox.question(
                self,
                "Confirm Overwrite",
                f"File '{target.name}' already exists. Overwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if res != QMessageBox.StandardButton.Yes:
                return

        try:
            saved_path, _ = secret.write_decrypted_file(
                self.last_decrypted_payload, out_path=target, force=True
            )
            self.log_callback(f"Saved decrypted file to {saved_path} (mode 600)")
            QMessageBox.information(
                self,
                "Saved Successfully",
                f"File saved to:\n{saved_path}\n\nPermissions set to 600 (owner read/write only)."
            )
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save file: {e}")

    def update_help_text(self, mode: str) -> None:
        if mode == "send":
            self.help_text.setHtml(
                "<h3>How to Send a .env File Safely</h3>"
                "<ol>"
                "<li><b>Pick your file:</b> Click Browse or drag a .env file. The preview masks secrets (showing <code>****</code>) so you can verify variable names.</li>"
                "<li><b>Choose mode:</b>"
                "<ul>"
                "<li><b>Public-Key (Recommended):</b> Paste your teammate's public key (<code>DEVPULSE-PUB-v1:...</code>). Only their private key can open it.</li>"
                "<li><b>Passphrase:</b> Encrypt with a password using memory-hard Scrypt.</li>"
                "</ul></li>"
                "<li><b>Compare fingerprint:</b> Call your friend and ensure the 8-character fingerprint matches before sending!</li>"
                "<li><b>Encrypt:</b> Click Encrypt and copy the single-line token.</li>"
                "<li><b>Share:</b> Paste the token into chat. If using a passphrase, share the password on a phone call—never in chat!</li>"
                "</ol>"
            )
        else:
            self.help_text.setHtml(
                "<h3>How to Open an Encrypted Message</h3>"
                "<ol>"
                "<li><b>Copy token:</b> Copy the <code>DEVPULSE-v1:...</code> or <code>DEVPULSE-v1P:...</code> line from your chat app.</li>"
                "<li><b>Paste & Decrypt:</b> Paste it into the box and click Decrypt. If passphrase-protected, enter the agreed password.</li>"
                "<li><b>Review:</b> Verify the environment variables and check the sender metadata.</li>"
                "<li><b>Save:</b> Click <i>Save as File</i> to save it with secure <code>600</code> Linux permissions (owner read/write only).</li>"
                "</ol>"
            )


# ==============================================================================
# Main DevPulse Application Window
# ==============================================================================

class MainWindow(QMainWindow):
    """Main DevPulse desktop window hosting 4 operational tabs, console dock, and system tray."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DevPulse")
        self.resize(1080, 800)

        self.force_quit = False
        self.has_shown_tray_message = False
        self.paused_services: Optional[Tuple[bool, bool]] = None

        # Background process tracking
        self.bg_processes: Dict[str, QProcess] = {}
        self.process_end_callbacks: Dict[str, Any] = {}

        # Menu Bar (File -> Quit)
        self.init_menu_bar()

        # Status Bar ("FocusPulse: running | ErgoGuard: stopped")
        self.statusBar().showMessage("FocusPulse: stopped | ErgoGuard: stopped")

        # Main splitter (Top: Tabs, Bottom: Collapsible Console)
        main_splitter = QSplitter(Qt.Orientation.Vertical, self)
        self.setCentralWidget(main_splitter)

        # ----------------------------------------------------------------------
        # Top Panel: 4 Functional Tabs
        # ----------------------------------------------------------------------
        self.tabs = QTabWidget(self)

        # Tab 1: Dashboard
        self.dashboard_tab = DashboardTab(self.execute_console_command_list, self.log_console, self)
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # Tab 2: SecretBridge
        self.secretbridge_tab = SecretBridgeTab(self.log_console, self)
        self.tabs.addTab(self.secretbridge_tab, "SecretBridge")

        # Tab 3: FocusPulse
        self.focuspulse_tab = FocusPulseTab(
            self.start_managed_process,
            self.stop_managed_process,
            self.execute_console_command_list,
            self.log_console,
            self.update_services_state,
            self
        )
        self.tabs.addTab(self.focuspulse_tab, "FocusPulse")

        # Tab 4: ErgoGuard
        self.ergoguard_tab = ErgoGuardTab(
            self.start_managed_process,
            self.stop_managed_process,
            self.execute_console_command_list,
            self.log_console,
            self.update_services_state,
            self
        )
        self.tabs.addTab(self.ergoguard_tab, "ErgoGuard")

        # Default to Dashboard tab
        self.tabs.setCurrentIndex(0)
        main_splitter.addWidget(self.tabs)

        # ----------------------------------------------------------------------
        # Bottom Panel: Sandboxed DevPulse Console
        # ----------------------------------------------------------------------
        console_widget = QWidget(self)
        console_layout = QVBoxLayout(console_widget)
        console_layout.setContentsMargins(6, 6, 6, 6)

        console_header = QHBoxLayout()
        console_header.addWidget(QLabel("DevPulse Console (Subcommands Only):", self))
        console_header.addStretch()

        self.clear_btn = QPushButton("Clear Console", self)
        self.clear_btn.clicked.connect(self.clear_console)
        console_header.addWidget(self.clear_btn)
        console_layout.addLayout(console_header)

        # Monospace dark console output
        self.console_output = QTextEdit(self)
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Monospace", 9))
        self.console_output.setStyleSheet(
            "background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #313244; padding: 4px;"
        )
        console_layout.addWidget(self.console_output)

        # Input line
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("devpulse >", self))
        self.cmd_input = QLineEdit(self)
        self.cmd_input.setPlaceholderText("Enter devpulse subcommand (e.g., focus summary, ergo status, audit --since-days 3)")
        self.cmd_input.returnPressed.connect(self.on_cmd_entered)
        input_layout.addWidget(self.cmd_input)

        self.run_btn = QPushButton("Run", self)
        self.run_btn.clicked.connect(self.on_cmd_entered)
        input_layout.addWidget(self.run_btn)

        console_layout.addLayout(input_layout)
        main_splitter.addWidget(console_widget)

        # Proportions: 72% tabs, 28% console
        main_splitter.setStretchFactor(0, 72)
        main_splitter.setStretchFactor(1, 28)

        self.console_process: Optional[QProcess] = None

        # ----------------------------------------------------------------------
        # System Tray Setup & 5-Second Polling Timer
        # ----------------------------------------------------------------------
        self.init_system_tray()

        self.tray_timer = QTimer(self)
        self.tray_timer.timeout.connect(self.update_tray_state)
        self.tray_timer.start(5000)

        self.update_services_state()
        self.log_console("DevPulse GUI ready. 100% offline.")

    def init_menu_bar(self) -> None:
        """Configures the desktop menu bar."""
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&File")

        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.setStatusTip("Exit DevPulse and stop all monitoring services")
        quit_action.triggered.connect(self.quit_application)
        file_menu.addAction(quit_action)

    def init_system_tray(self) -> None:
        """Initializes the QSystemTrayIcon with painted circle icons and right-click menu."""
        self.icon_green = create_circle_icon("#2ecc71")
        self.icon_amber = create_circle_icon("#f39c12")
        self.icon_red = create_circle_icon("#e74c3c")
        self.icon_gray = create_circle_icon("#95a5a6")

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.icon_gray)

        # Tray right-click context menu
        self.tray_menu = QMenu(self)

        self.action_toggle_window = QAction("Hide Window", self)
        self.action_toggle_window.triggered.connect(self.toggle_window_visibility)
        self.tray_menu.addAction(self.action_toggle_window)

        self.tray_menu.addSeparator()

        self.action_toggle_focus = QAction("Start FocusPulse", self)
        self.action_toggle_focus.triggered.connect(self.focuspulse_tab.toggle_service)
        self.tray_menu.addAction(self.action_toggle_focus)

        self.action_toggle_ergo = QAction("Start ErgoGuard", self)
        self.action_toggle_ergo.triggered.connect(self.ergoguard_tab.toggle_service)
        self.tray_menu.addAction(self.action_toggle_ergo)

        self.action_break_done = QAction("Break done (reset timers)", self)
        self.action_break_done.triggered.connect(self.ergoguard_tab.trigger_done)
        self.tray_menu.addAction(self.action_break_done)

        self.action_pause_all = QAction("Pause all", self)
        self.action_pause_all.triggered.connect(self.toggle_pause_all)
        self.tray_menu.addAction(self.action_pause_all)

        self.tray_menu.addSeparator()

        self.action_tray_quit = QAction("Quit", self)
        self.action_tray_quit.triggered.connect(self.quit_application)
        self.tray_menu.addAction(self.action_tray_quit)

        self.tray_icon.setContextMenu(self.tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)

        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon.show()

    def update_services_state(self) -> None:
        """Synchronizes status bar and tray menu actions whenever services start/stop."""
        focus_running = self.focuspulse_tab.is_running
        ergo_running = self.ergoguard_tab.is_running

        # Update Status Bar
        f_str = "running" if focus_running else "stopped"
        e_str = "running" if ergo_running else "stopped"
        self.statusBar().showMessage(f"FocusPulse: {f_str} | ErgoGuard: {e_str}")

        # Update Tray Menu Action Labels
        self.action_toggle_focus.setText("Stop FocusPulse" if focus_running else "Start FocusPulse")
        self.action_toggle_ergo.setText("Stop ErgoGuard" if ergo_running else "Start ErgoGuard")

        if self.paused_services is None:
            self.action_pause_all.setText("Pause all")
        else:
            self.action_pause_all.setText("Resume all")

        self.update_tray_state()

    def update_tray_state(self) -> None:
        """
        Polls focus.db (read-only) every 5 seconds or on transition:
        - Gray if FocusPulse not running; green=focus, red=distraction, amber=neutral.
        - Tooltip displays today's focus score and minutes until next break.
        """
        focus_running = self.focuspulse_tab.is_running
        ergo_running = self.ergoguard_tab.is_running

        # 1. Update Tray Icon Color
        if not focus_running:
            self.tray_icon.setIcon(self.icon_gray)
        else:
            category = get_latest_focus_category()
            if category == "focus":
                self.tray_icon.setIcon(self.icon_green)
            elif category == "distraction":
                self.tray_icon.setIcon(self.icon_red)
            elif category == "neutral":
                self.tray_icon.setIcon(self.icon_amber)
            else:
                self.tray_icon.setIcon(self.icon_amber)

        # 2. Update Tooltip
        focus_m = get_today_focus_metrics()
        score = focus_m["focus_score"]

        if ergo_running:
            try:
                ergo_cfg = ergo.load_ergo_config()
                interval_min = ergo_cfg.get("breaks", {}).get("eye", {}).get("interval_minutes", 20)
                ergo_m = get_today_ergo_metrics()
                active_min = ergo_m["active_minutes"]
                mins_left = max(1, interval_min - (active_min % interval_min))
                tooltip = f"DevPulse\nFocus Score: {score}%\nNext break in: ~{mins_left}m"
            except Exception:
                tooltip = f"DevPulse\nFocus Score: {score}%"
        else:
            tooltip = f"DevPulse\nFocus Score: {score}%"

        self.tray_icon.setToolTip(tooltip)

        # 3. Update Toggle Window Text
        if self.isVisible() and not self.isMinimized():
            self.action_toggle_window.setText("Hide Window")
        else:
            self.action_toggle_window.setText("Show Window")

    def toggle_pause_all(self) -> None:
        """Stops both background services when pausing, and restarts them on resume."""
        if self.paused_services is None:
            was_focus = self.focuspulse_tab.is_running
            was_ergo = self.ergoguard_tab.is_running

            if was_focus:
                self.focuspulse_tab.toggle_service()
            if was_ergo:
                self.ergoguard_tab.toggle_service()

            self.paused_services = (was_focus, was_ergo)
            self.log_console("Paused all background services")
        else:
            resume_focus, resume_ergo = self.paused_services
            if not resume_focus and not resume_ergo:
                resume_focus, resume_ergo = True, True

            if resume_focus and not self.focuspulse_tab.is_running:
                self.focuspulse_tab.toggle_service()
            if resume_ergo and not self.ergoguard_tab.is_running:
                self.ergoguard_tab.toggle_service()

            self.paused_services = None
            self.log_console("Resumed background services")

        self.update_services_state()

    def toggle_window_visibility(self) -> None:
        """Toggles main window between shown and hidden."""
        if self.isVisible() and not self.isMinimized():
            self.hide()
            self.action_toggle_window.setText("Show Window")
        else:
            self.showNormal()
            self.activateWindow()
            self.raise_()
            self.action_toggle_window.setText("Hide Window")
        self.update_tray_state()

    def on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handles left-click or double-click on the system tray icon."""
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.toggle_window_visibility()

    # --------------------------------------------------------------------------
    # Managed Background Process Runner (FocusPulse & ErgoGuard)
    # --------------------------------------------------------------------------
    def start_managed_process(self, name: str, args: List[str], on_exit_callback=None) -> bool:
        """Starts a named persistent service process (focus start or ergo start) and streams to console."""
        if name in self.bg_processes and self.bg_processes[name].state() == QProcess.ProcessState.Running:
            self.stop_managed_process(name)

        devpulse_script = Path(__file__).parent / "devpulse.py"
        if not devpulse_script.is_file():
            self.log_console(f"Error: devpulse.py not found at {devpulse_script}")
            return False

        proc = QProcess(self)
        proc.setProgram(sys.executable)
        proc.setArguments([str(devpulse_script), *args])

        proc.readyReadStandardOutput.connect(lambda: self._on_proc_stdout(proc))
        proc.readyReadStandardError.connect(lambda: self._on_proc_stderr(proc))

        if on_exit_callback:
            self.process_end_callbacks[name] = on_exit_callback
            proc.finished.connect(lambda exit_code: self._on_managed_finished(name, exit_code))

        self.log_console(f"$ devpulse {' '.join(args)} (Service: {name})")
        proc.start()
        self.bg_processes[name] = proc
        return True

    def stop_managed_process(self, name: str) -> None:
        """Stops a named persistent service cleanly with up to 3 seconds wait."""
        if name in self.bg_processes:
            proc = self.bg_processes[name]
            if proc.state() == QProcess.ProcessState.Running:
                self.log_console(f"Stopping service '{name}'...")
                proc.terminate()
                if not proc.waitForFinished(3000):
                    proc.kill()
                    proc.waitForFinished(500)
            del self.bg_processes[name]

    def _on_proc_stdout(self, proc: QProcess) -> None:
        data = proc.readAllStandardOutput().data().decode("utf-8", errors="replace")
        self.console_output.insertPlainText(data)
        self.console_output.ensureCursorVisible()

    def _on_proc_stderr(self, proc: QProcess) -> None:
        data = proc.readAllStandardError().data().decode("utf-8", errors="replace")
        self.console_output.insertPlainText(data)
        self.console_output.ensureCursorVisible()

    def _on_managed_finished(self, name: str, exit_code: int) -> None:
        self.log_console(f"Service '{name}' exited with code {exit_code}")
        cb = self.process_end_callbacks.pop(name, None)
        if cb:
            cb()
        self.update_services_state()

    # --------------------------------------------------------------------------
    # General Console Process Runner
    # --------------------------------------------------------------------------
    def log_console(self, text: str) -> None:
        """Appends a timestamped log line to the console panel."""
        time_str = datetime.now().strftime("%H:%M:%S")
        self.console_output.append(f"[{time_str}] {text}")

    def clear_console(self) -> None:
        self.console_output.clear()

    def on_cmd_entered(self) -> None:
        raw_cmd = self.cmd_input.text().strip()
        if not raw_cmd:
            return
        self.cmd_input.clear()
        self.execute_console_command(raw_cmd)

    def execute_console_command(self, raw_cmd: str) -> None:
        """Parses and validates that the command is strictly a devpulse subcommand."""
        try:
            tokens = shlex.split(raw_cmd)
        except ValueError as e:
            self.log_console(f"Command syntax error: {e}")
            return

        if not tokens:
            return

        # Strip redundant prefixes
        if tokens[0] in ("python", "python3", "devpulse", "devpulse.py", "./devpulse.py"):
            tokens = tokens[1:]
            if tokens and tokens[0].endswith(".py"):
                tokens = tokens[1:]

        if not tokens:
            return

        subcommand = tokens[0]

        # Security Sandbox: Reject general shell commands
        if subcommand not in ALLOWED_SUBCOMMANDS:
            self.log_console(
                f"[REJECTED] '{subcommand}' is not a devpulse subcommand.\n"
                f"Permitted subcommands: {', '.join(sorted(ALLOWED_SUBCOMMANDS))}"
            )
            return

        self.run_devpulse(tokens)

    def execute_console_command_list(self, args: List[str]) -> None:
        self.run_devpulse(args)

    def run_devpulse(self, args: List[str]) -> bool:
        """
        Reusable function to execute devpulse.py with arguments and stream output live.
        Can be used by other tabs or console inputs to run one-off tasks.
        """
        if self.console_process and self.console_process.state() == QProcess.ProcessState.Running:
            self.log_console("Terminating previous console command...")
            self.console_process.terminate()
            self.console_process.waitForFinished(1000)

        devpulse_script = Path(__file__).parent / "devpulse.py"
        if not devpulse_script.is_file():
            self.log_console(f"Error: devpulse.py not found at {devpulse_script}")
            return False

        self.log_console(f"$ devpulse {' '.join(args)}")

        self.console_process = QProcess(self)
        self.console_process.setProgram(sys.executable)
        self.console_process.setArguments([str(devpulse_script), *args])

        self.console_process.readyReadStandardOutput.connect(self._on_console_stdout)
        self.console_process.readyReadStandardError.connect(self._on_console_stderr)
        self.console_process.finished.connect(self._on_console_finished)

        self.console_process.start()
        return True

    def _on_console_stdout(self) -> None:
        if self.console_process:
            data = self.console_process.readAllStandardOutput().data().decode("utf-8", errors="replace")
            self.console_output.insertPlainText(data)
            self.console_output.ensureCursorVisible()

    def _on_console_stderr(self) -> None:
        if self.console_process:
            data = self.console_process.readAllStandardError().data().decode("utf-8", errors="replace")
            self.console_output.insertPlainText(data)
            self.console_output.ensureCursorVisible()

    def _on_console_finished(self, exit_code: int) -> None:
        self.log_console(f"Command finished with exit code {exit_code}\n")
        # Trigger dashboard refresh on command finish
        self.dashboard_tab.refresh_data()
        self.focuspulse_tab.refresh_stats()
        self.ergoguard_tab.refresh_stats()
        self.update_services_state()

    # --------------------------------------------------------------------------
    # Window Close & Shutdown Management
    # --------------------------------------------------------------------------
    def cleanup_processes(self) -> None:
        """
        Stops focus and ergo processes started by the GUI by sending a graceful terminate first
        and waiting up to 3 seconds, then killing only if needed, so ergo can stop its own swayidle child.
        Ensures no QProcess is destroyed while running.
        """
        for name in list(self.bg_processes.keys()):
            proc = self.bg_processes.get(name)
            if proc and proc.state() == QProcess.ProcessState.Running:
                self.log_console(f"Terminating service '{name}'...")
                proc.terminate()
                if not proc.waitForFinished(3000):
                    proc.kill()
                    proc.waitForFinished(500)
        self.bg_processes.clear()

        if self.console_process and self.console_process.state() == QProcess.ProcessState.Running:
            self.console_process.terminate()
            if not self.console_process.waitForFinished(3000):
                self.console_process.kill()
                self.console_process.waitForFinished(500)
            self.console_process = None

        # Terminate any orphan swayidle processes if spawned by ergo
        swayidle_bin = shutil.which("swayidle")
        if swayidle_bin:
            try:
                import subprocess
                subprocess.run(["pkill", "-f", "swayidle.*DevPulse"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    def closeEvent(self, event) -> None:
        """Closing window with X button hides to tray instead of quitting if tray is available."""
        if not self.force_quit and QSystemTrayIcon.isSystemTrayAvailable() and self.tray_icon.isVisible():
            self.hide()
            if not self.has_shown_tray_message:
                self.tray_icon.showMessage(
                    "DevPulse",
                    "DevPulse is still running in the system tray.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000
                )
                self.has_shown_tray_message = True
            self.update_tray_state()
            event.ignore()
        else:
            self.cleanup_processes()
            self.tray_icon.hide()
            event.accept()

    def quit_application(self) -> None:
        """Quits DevPulse after cleanly terminating all child processes."""
        self.force_quit = True
        self.log_console("Shutting down DevPulse and child processes...")
        self.cleanup_processes()
        self.tray_icon.hide()
        QApplication.instance().quit()


# ==============================================================================
# GUI Main Entry Point
# ==============================================================================

def main() -> int:
    """Initializes and runs the PyQt6 application."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
