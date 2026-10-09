"""
FocusPulse Activity Tracker & Distraction Monitor (focus.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
ARCHITECTURE & PRIVACY NOTES:
1. PRIVACY-FIRST DATABASE:
   Window titles are used ONLY in-memory for real-time classification (e.g.
   distinguishing YouTube tabs from GitHub tabs). Window titles are NEVER
   written to SQLite or stored on disk. Only (timestamp, window_class, category)
   are persisted.
2. 100% OFFLINE & LOCAL:
   Uses kdotool on KDE Plasma 6.3 Wayland, local YAML rules, and local SQLite.
   Zero network calls, zero telemetry.
3. FAULT TOLERANCE:
   Window inspection calls never crash the daemon. If kdotool fails, exits
   with non-zero, or is temporarily unavailable (e.g. during screen lock),
   the state defaults to 'unknown' and polling continues seamlessly.
================================================================================
"""

import os
import sys
import time
import shutil
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime, date, timedelta
from typing import Optional, Tuple, Dict, Any, List

# PyYAML is installed on Debian 13 via: sudo apt install python3-yaml
try:
    import yaml
except ImportError:
    yaml = None


# Default rules template written on first run
DEFAULT_FOCUS_YAML = """# FocusPulse Classification Rules (~/.config/devpulse/focus.yaml)
# Rules are evaluated: allow-list first, then block-list. Everything else is neutral.

allow:
  classes:
    - code
    - vscodium
    - konsole
    - kate
    - pycharm
    - alacritty
    - kitty
    - gnome-terminal
    - xfce4-terminal
  titles:
    - GitHub
    - Stack Overflow
    - docs
    - documentation
    - Python
    - Debian
    - Git
    - API
    - Rust
    - DevPulse

block:
  classes:
    - discord
    - telegram-desktop
    - steam
    - spotify
    - slack
  titles:
    - YouTube
    - Reddit
    - Netflix
    - Instagram
    - Twitch
    - X
    - Twitter
    - Facebook
    - TikTok
"""


# ==============================================================================
# Helper & Path Functions
# ==============================================================================

def get_devpulse_dir() -> Path:
    """
    Returns the DevPulse configuration directory.
    Respects DEVPULSE_HOME environment variable if set, otherwise ~/.config/devpulse.
    """
    env_override = os.environ.get("DEVPULSE_HOME")
    if env_override:
        path = Path(env_override).expanduser().resolve()
    else:
        path = Path("~/.config/devpulse").expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_rules_path() -> Path:
    """Returns the path to focus.yaml."""
    return get_devpulse_dir() / "focus.yaml"


def get_db_path() -> Path:
    """Returns the path to focus.db."""
    return get_devpulse_dir() / "focus.db"


def find_kdotool() -> Optional[str]:
    """
    Locates the kdotool executable.
    Checks system PATH first (shutil.which), then ~/.cargo/bin/kdotool.
    """
    system_path = shutil.which("kdotool")
    if system_path:
        return system_path

    cargo_path = Path.home() / ".cargo" / "bin" / "kdotool"
    if cargo_path.is_file() and os.access(cargo_path, os.X_OK):
        return str(cargo_path)

    return None


def get_active_window(kdotool_bin: Optional[str] = None) -> Tuple[str, str]:
    """
    Queries KDE Plasma 6.3 Wayland for the current active window using kdotool.
    Returns: (window_class, window_title).
    If kdotool is missing, fails, or returns empty output, returns ('unknown', 'unknown').
    Never crashes or raises unhandled exceptions.
    """
    bin_path = kdotool_bin or find_kdotool()
    if not bin_path:
        return "unknown", "unknown"

    window_class = "unknown"
    window_title = "unknown"

    # 1. Fetch active window class name
    try:
        proc_class = subprocess.run(
            [bin_path, "getactivewindow", "getwindowclassname"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1.5
        )
        if proc_class.returncode == 0 and proc_class.stdout.strip():
            window_class = proc_class.stdout.strip()
    except Exception:
        window_class = "unknown"

    # 2. Fetch active window title name
    try:
        proc_title = subprocess.run(
            [bin_path, "getactivewindow", "getwindowname"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1.5
        )
        if proc_title.returncode == 0 and proc_title.stdout.strip():
            window_title = proc_title.stdout.strip()
    except Exception:
        window_title = "unknown"

    return window_class, window_title


# ==============================================================================
# Rules Loading & Window Classification
# ==============================================================================

def load_rules(rules_file: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads classification rules from focus.yaml.
    Creates a default configuration file if none exists.
    Falls back to built-in defaults if PyYAML is missing or the file is corrupt.
    """
    target = rules_file or get_rules_path()

    # Automatically create default configuration file on first run
    if not target.exists():
        try:
            target.write_text(DEFAULT_FOCUS_YAML, encoding="utf-8")
        except OSError:
            pass

    if yaml is None:
        # Fallback if python3-yaml is not installed
        return {
            "allow": {
                "classes": ["code", "vscodium", "konsole", "kate", "pycharm", "alacritty", "kitty"],
                "titles": ["GitHub", "Stack Overflow", "docs", "documentation", "Python", "Debian", "Git", "API"]
            },
            "block": {
                "classes": ["discord", "telegram-desktop", "steam", "spotify", "slack"],
                "titles": ["YouTube", "Reddit", "Netflix", "Instagram", "Twitch", "X", "Twitter", "Facebook", "TikTok"]
            }
        }

    try:
        with open(target, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass

    return {"allow": {"classes": [], "titles": []}, "block": {"classes": [], "titles": []}}


def classify_window(window_class: str, window_title: str, rules: Dict[str, Any]) -> str:
    """
    Classifies a window into 'focus', 'distraction', or 'neutral'.
    - Checks allow-list first (classes and title keywords).
    - Checks block-list second (classes and title keywords).
    - Defaults to 'neutral'.
    All comparisons are case-insensitive.
    """
    cls_lower = window_class.lower()
    title_lower = window_title.lower()

    allow_section = rules.get("allow", {}) or {}
    allow_classes = [str(c).lower() for c in allow_section.get("classes", []) or []]
    allow_titles = [str(t).lower() for t in allow_section.get("titles", []) or []]

    block_section = rules.get("block", {}) or {}
    block_classes = [str(c).lower() for c in block_section.get("classes", []) or []]
    block_titles = [str(t).lower() for t in block_section.get("titles", []) or []]

    # Rule 1: Allow-list check (evaluated first)
    for ac in allow_classes:
        if ac and ac in cls_lower:
            return "focus"
    for at in allow_titles:
        if at and at in title_lower:
            return "focus"

    # Rule 2: Block-list check (evaluated second)
    for bc in block_classes:
        if bc and bc in cls_lower:
            return "distraction"
    for bt in block_titles:
        if bt and bt in title_lower:
            return "distraction"

    # Rule 3: Neutral default
    return "neutral"


# ==============================================================================
# Database Management (Privacy-Preserving SQLite)
# ==============================================================================

def init_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Initializes the SQLite database with the privacy-first schema.
    Window titles are NEVER stored. Only timestamp, window_class, and category.
    """
    target = db_path or get_db_path()
    conn = sqlite3.connect(str(target), timeout=10.0)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS focus_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_class TEXT NOT NULL,
                category TEXT NOT NULL,
                duration_seconds REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS window_switches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_class TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_focus_timestamp ON focus_events(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_switches_timestamp ON window_switches(timestamp);")
    return conn


def flush_events_to_db(conn: sqlite3.Connection, events_buffer: List[Tuple[str, str, str, float]]) -> None:
    """
    Flushes buffered events to SQLite in a single transaction.
    Events format: [(timestamp_iso, window_class, category, duration_seconds), ...]
    """
    if not events_buffer:
        return
    with conn:
        conn.executemany(
            "INSERT INTO focus_events (timestamp, window_class, category, duration_seconds) VALUES (?, ?, ?, ?)",
            events_buffer
        )
    events_buffer.clear()


def log_switch_to_db(conn: sqlite3.Connection, timestamp_iso: str, window_class: str) -> None:
    """Logs a debounced window switch to SQLite."""
    with conn:
        conn.execute(
            "INSERT INTO window_switches (timestamp, window_class) VALUES (?, ?)",
            (timestamp_iso, window_class)
        )


# ==============================================================================
# Desktop Notifications with Rate Limiting
# ==============================================================================

class NotificationManager:
    """
    Handles desktop notifications using notify-send with rate limits:
    - Maximum 3 notifications per hour (sliding 3600-second window).
    - Rapid switching alert (>15 switches in 10 minutes).
    - Distraction alert (>2 min continuous, then reminded after 5 more minutes).
    """

    def __init__(self) -> None:
        self.notify_bin = shutil.which("notify-send")
        self.notification_history: List[float] = []
        self.last_switch_alert_time: float = 0.0
        self.distraction_start_time: Optional[float] = None
        self.last_distraction_alert_time: float = 0.0

    def can_notify(self) -> bool:
        """Enforces maximum 3 notifications per hour."""
        if not self.notify_bin:
            return False
        now = time.time()
        # Keep only notifications sent within the last hour (3600 seconds)
        self.notification_history = [t for t in self.notification_history if now - t < 3600]
        return len(self.notification_history) < 3

    def notify(self, title: str, message: str) -> bool:
        """Sends a desktop notification via notify-send if within hourly quota."""
        if not self.can_notify() or not self.notify_bin:
            return False

        try:
            subprocess.run(
                [self.notify_bin, "-a", "DevPulse Focus", title, message],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0
            )
            now = time.time()
            self.notification_history.append(now)
            return True
        except Exception:
            return False

    def check_switch_frequency(self, switch_timestamps: List[float]) -> None:
        """
        Triggers an alert if more than 15 switches occurred in the last 10 minutes (600s).
        """
        now = time.time()
        recent_switches = [t for t in switch_timestamps if now - t <= 600]
        count = len(recent_switches)

        # Alert if >15 switches and at least 10 minutes since the previous switch alert
        if count > 15 and (now - self.last_switch_alert_time >= 600):
            if self.notify("Focus Alert", f"{count} app switches in 10 min. Try single-tasking!"):
                self.last_switch_alert_time = now

    def update_distraction_tracking(self, category: str, window_class: str, display_name: str) -> None:
        """
        Monitors continuous distraction:
        - If distraction lasts > 2 minutes: sends gentle notification.
        - Repeats only after 5 more minutes of continuous distraction.
        - Resets when user switches back to focus or neutral.
        """
        now = time.time()

        if category == "distraction":
            if self.distraction_start_time is None:
                self.distraction_start_time = now
                self.last_distraction_alert_time = 0.0

            duration = now - self.distraction_start_time

            # First notification at 2 minutes (120 seconds)
            if duration >= 120 and self.last_distraction_alert_time == 0.0:
                short_name = display_name if display_name and display_name != "unknown" else window_class
                if self.notify("FocusPulse Distraction", f"{short_name} for 2 min. Back to it?"):
                    self.last_distraction_alert_time = now

            # Subsequent notification after 5 more minutes (300 seconds)
            elif duration >= 120 and self.last_distraction_alert_time > 0.0:
                if (now - self.last_distraction_alert_time) >= 300:
                    minutes_elapsed = int(duration // 60)
                    short_name = display_name if display_name and display_name != "unknown" else window_class
                    if self.notify("FocusPulse Distraction", f"{short_name} for {minutes_elapsed} min. Back to it?"):
                        self.last_distraction_alert_time = now

        else:
            # User is in focus or neutral, reset distraction timer
            self.distraction_start_time = None
            self.last_distraction_alert_time = 0.0


# ==============================================================================
# Core Daemon: focus start
# ==============================================================================

def run_focus_tracker() -> None:
    """
    Main loop for 'devpulse focus start'.
    - Polls active window every 2 seconds via kdotool.
    - Debounces window changes (new window must persist >= 3 seconds).
    - Classifies window into focus, distraction, or neutral.
    - Prints a live console line whenever the classification changes.
    - Flushes events to SQLite every 30 seconds.
    - Handles Ctrl+C cleanly and prints summary.
    """
    rules = load_rules()
    kdotool_bin = find_kdotool()
    conn = init_db()
    notifier = NotificationManager()

    print("=" * 65)
    print(" DevPulse FocusPulse - Active Window Tracker")
    print("=" * 65)
    if kdotool_bin:
        print(f"KDE Wayland Tool : {kdotool_bin}")
    else:
        print("Warning: kdotool not found. Install it to enable window tracking:")
        print("  cargo install kdotool  (or place kdotool binary in ~/.cargo/bin/)")
    print(f"Rules File       : {get_rules_path()}")
    print(f"Database (SQLite): {get_db_path()}")
    print("Polling Interval : 2 seconds | Debounce: 3 seconds | Flush: 30 seconds")
    print("Press Ctrl+C at any time to stop and view your summary.")
    print("=" * 65)

    events_buffer: List[Tuple[str, str, str, float]] = []
    switch_timestamps: List[float] = []

    # Current committed window state
    current_class = "unknown"
    current_title = "unknown"
    current_category = "neutral"

    # Debounce tracking variables
    candidate_class = "unknown"
    candidate_title = "unknown"
    candidate_first_seen: float = 0.0

    last_poll_time = time.time()
    last_flush_time = time.time()

    try:
        # Initial probe
        init_cls, init_title = get_active_window(kdotool_bin)
        current_class = init_cls
        current_title = init_title
        current_category = classify_window(init_cls, init_title, rules)

        candidate_class = init_cls
        candidate_title = init_title
        candidate_first_seen = time.time()

        timestamp_str = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp_str}] {current_category.upper()}: {current_title} ({current_class})")

        while True:
            time.sleep(2.0)
            now = time.time()
            elapsed_interval = now - last_poll_time
            last_poll_time = now

            # Poll active window
            polled_cls, polled_title = get_active_window(kdotool_bin)

            # Debounce Logic:
            # If the polled window is different from our candidate, start a new candidate
            if polled_cls != candidate_class or polled_title != candidate_title:
                candidate_class = polled_cls
                candidate_title = polled_title
                candidate_first_seen = now
            else:
                # The candidate has remained active. Check if it reached the 3-second debounce threshold
                if (now - candidate_first_seen) >= 3.0:
                    # If this candidate is different from our committed window, commit the switch!
                    if candidate_class != current_class or candidate_title != current_title:
                        old_category = current_category
                        current_class = candidate_class
                        current_title = candidate_title
                        current_category = classify_window(current_class, current_title, rules)

                        # Record debounced switch
                        switch_timestamps.append(now)
                        now_iso = datetime.now().isoformat()
                        log_switch_to_db(conn, now_iso, current_class)

                        # Print live line whenever classification changes
                        if current_category != old_category:
                            time_label = datetime.now().strftime("%H:%M:%S")
                            display = current_title if len(current_title) <= 50 else current_title[:47] + "..."
                            print(f"[{time_label}] {current_category.upper()}: {display} ({current_class})")

            # Check switch frequency notification (>15 in 10 minutes)
            notifier.check_switch_frequency(switch_timestamps)

            # Check continuous distraction notification
            notifier.update_distraction_tracking(current_category, current_class, current_title)

            # Buffer this 2-second heartbeat event for SQLite (never stores titles)
            now_iso = datetime.now().isoformat()
            events_buffer.append((now_iso, current_class, current_category, elapsed_interval))

            # Periodic flush every 30 seconds
            if now - last_flush_time >= 30.0:
                flush_events_to_db(conn, events_buffer)
                last_flush_time = now

    except KeyboardInterrupt:
        print("\n\nStopping FocusPulse tracker...")
        # Flush any remaining buffer before exiting
        if events_buffer:
            flush_events_to_db(conn, events_buffer)
        conn.close()
        print("Session saved cleanly to database.\n")
        # Print summary of today's focus stats
        print_summary()


# ==============================================================================
# Summary Reporter: focus summary
# ==============================================================================

def format_duration(seconds: float) -> str:
    """Formats seconds into human-readable hours, minutes, and seconds."""
    total_sec = int(round(seconds))
    hrs = total_sec // 3600
    rem = total_sec % 3600
    mins = rem // 60
    secs = rem % 60

    parts = []
    if hrs > 0:
        parts.append(f"{hrs}h")
    if mins > 0 or hrs > 0:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def get_summary_data(target_date: Optional[date] = None, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Calculates focus metrics for a specific date (defaults to today).
    Returns: focus_time, distraction_time, neutral_time, focus_score, switch_count, top_apps.
    """
    day = target_date or date.today()
    day_str = day.isoformat()  # e.g. '2026-10-09'

    target = db_path or get_db_path()
    if not target.exists():
        return {
            "focus_seconds": 0.0,
            "distraction_seconds": 0.0,
            "neutral_seconds": 0.0,
            "total_seconds": 0.0,
            "focus_score": 0.0,
            "switch_count": 0,
            "top_apps": []
        }

    conn = sqlite3.connect(str(target))
    try:
        cur = conn.cursor()

        # 1. Category durations for today
        cur.execute("""
            SELECT category, SUM(duration_seconds)
            FROM focus_events
            WHERE date(timestamp) = ?
            GROUP BY category
        """, (day_str,))

        category_times = {"focus": 0.0, "distraction": 0.0, "neutral": 0.0}
        for cat, dur in cur.fetchall():
            if cat in category_times and dur is not None:
                category_times[cat] = float(dur)

        focus_sec = category_times["focus"]
        distraction_sec = category_times["distraction"]
        neutral_sec = category_times["neutral"]
        total_sec = focus_sec + distraction_sec + neutral_sec

        # 2. Focus score: focus / (focus + distraction) as percentage
        denom = focus_sec + distraction_sec
        if denom > 0:
            focus_score = (focus_sec / denom) * 100.0
        else:
            focus_score = 100.0 if total_sec > 0 else 0.0

        # 3. Switch count for today
        cur.execute("""
            SELECT COUNT(*)
            FROM window_switches
            WHERE date(timestamp) = ?
        """, (day_str,))
        row = cur.fetchone()
        switch_count = row[0] if row else 0

        # 4. Top 5 apps by time for today
        cur.execute("""
            SELECT window_class, SUM(duration_seconds) as total_dur, category
            FROM focus_events
            WHERE date(timestamp) = ?
            GROUP BY window_class
            ORDER BY total_dur DESC
            LIMIT 5
        """, (day_str,))

        top_apps = []
        for app_cls, dur, cat in cur.fetchall():
            top_apps.append({
                "class": app_cls,
                "seconds": float(dur) if dur else 0.0,
                "category": cat
            })

        return {
            "focus_seconds": focus_sec,
            "distraction_seconds": distraction_sec,
            "neutral_seconds": neutral_sec,
            "total_seconds": total_sec,
            "focus_score": focus_score,
            "switch_count": switch_count,
            "top_apps": top_apps
        }
    finally:
        conn.close()


def print_summary() -> None:
    """Displays today's focus summary to stdout."""
    today = date.today()
    data = get_summary_data(today)

    focus_str = format_duration(data["focus_seconds"])
    distract_str = format_duration(data["distraction_seconds"])
    neutral_str = format_duration(data["neutral_seconds"])
    total_str = format_duration(data["total_seconds"])

    print("=" * 65)
    print(f" DevPulse FocusPulse - Today's Summary ({today.strftime('%A, %b %d, %Y')})")
    print("=" * 65)
    print(f"Focus Time        : {focus_str}")
    print(f"Distraction Time  : {distract_str}")
    print(f"Neutral Time      : {neutral_str}")
    print(f"Total Logged Time : {total_str}")
    print(f"Focus Score       : {data['focus_score']:.1f}%  (focus / [focus + distraction])")
    print(f"Window Switches   : {data['switch_count']} switches")
    print("-" * 65)
    print("Top 5 Applications by Time:")

    if not data["top_apps"]:
        print("  (No application activity logged yet today)")
    else:
        for idx, app in enumerate(data["top_apps"], 1):
            dur_formatted = format_duration(app["seconds"])
            cat_tag = app["category"].upper()
            print(f"  {idx}. {app['class']:<24} {dur_formatted:>10}  [{cat_tag}]")
    print("=" * 65)


# ==============================================================================
# Self-Test Suite: focus selftest
# ==============================================================================

def run_focus_selftest() -> int:
    """
    Tests the window classification logic with simulated window names and classes.
    Requires no external binaries (no kdotool needed).
    Prints PASS or FAIL for each test case.
    """
    print("=" * 65)
    print(" Running DevPulse FocusPulse Classification Self-Test...")
    print("=" * 65)

    test_rules = {
        "allow": {
            "classes": ["code", "konsole", "kate"],
            "titles": ["GitHub", "Stack Overflow", "docs", "Python"]
        },
        "block": {
            "classes": ["discord", "steam"],
            "titles": ["YouTube", "Reddit", "Netflix", "Twitch"]
        }
    }

    test_cases = [
        # (window_class, window_title, expected_category, description)
        ("code", "devpulse.py - Visual Studio Code", "focus", "Allowed class (code editor)"),
        ("konsole", "bash - Terminal", "focus", "Allowed class (konsole)"),
        ("firefox", "Pull Requests · user/DevPulse · GitHub", "focus", "Browser with allowed keyword (GitHub)"),
        ("google-chrome", "Python 3 Documentation - docs", "focus", "Browser with allowed keyword (docs)"),
        ("discord", "General - Chat", "distraction", "Blocked class (discord)"),
        ("steam", "Store Page", "distraction", "Blocked class (steam)"),
        ("firefox", "Lo-Fi Beats to Relax to - YouTube", "distraction", "Browser with blocked keyword (YouTube)"),
        ("chromium", "r/popular - Reddit", "distraction", "Browser with blocked keyword (Reddit)"),
        ("dolphin", "/home/user/Downloads", "neutral", "Neutral file manager (dolphin)"),
        ("systemsettings", "KDE System Settings", "neutral", "Neutral utility (systemsettings)"),
        # Precedence test: matching both allow and block keywords
        ("firefox", "GitHub Discussions: Building a YouTube bot", "focus", "Precedence: allow-list before block-list"),
        # Fallback test: unknown/empty inputs
        ("unknown", "unknown", "neutral", "Unknown window class and title fallback to neutral")
    ]

    passed = 0
    total = len(test_cases)

    for idx, (win_cls, win_title, expected, desc) in enumerate(test_cases, 1):
        actual = classify_window(win_cls, win_title, test_rules)
        if actual == expected:
            print(f"  [PASS] Test {idx:02d}: {desc} -> {actual}")
            passed += 1
        else:
            print(f"  [FAIL] Test {idx:02d}: {desc} -> Got {actual}, Expected {expected}")

    print("-" * 65)
    if passed == total:
        print(f" FOCUS SELF-TEST SUMMARY: ALL {total}/{total} TESTS PASSED [PASS]")
        print(" Classifier logic is verified and functioning correctly.")
        print("=" * 65 + "\n")
        return 0
    else:
        print(f" FOCUS SELF-TEST SUMMARY: {passed}/{total} TESTS PASSED [FAIL]")
        print("=" * 65 + "\n")
        return 1
