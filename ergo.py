"""
ErgoGuard Ergonomic Break & Rest Monitor (ergo.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
ARCHITECTURE & PRIVACY NOTES:
1. PRIVACY-FIRST DATABASE:
   Logs only timestamps and high-level event types (break_shown, rest_detected,
   commit_detected, manual_done) to ~/.config/devpulse/ergo.db.
   NO keystrokes, NO window titles, NO file names are ever logged.
2. 100% OFFLINE & LOCAL:
   Uses swayidle on KDE Plasma 6.3 Wayland for idle/active detection,
   local filesystem mtime polling for git commits, and notify-send for alerts.
   Zero network calls, zero telemetry.
3. FAULT TOLERANCE:
   If swayidle is missing, fails, or exits, ErgoGuard prints a friendly notice
   and continues running using elapsed wall-clock time. Never crashes.
================================================================================
"""

import os
import sys
import time
import shutil
import sqlite3
import threading
import subprocess
from pathlib import Path
from datetime import datetime, date
from typing import Optional, Tuple, Dict, Any, List

# PyYAML is installed on Debian 13 via: sudo apt install python3-yaml
try:
    import yaml
except ImportError:
    yaml = None


# Default rules template written on first run
DEFAULT_ERGO_YAML = """# ErgoGuard Break Intervals & Settings (~/.config/devpulse/ergo.yaml)
# Intervals are in active minutes.

breaks:
  eye:
    interval_minutes: 20
    message: "20-20-20: look at something 20 feet away for 20 seconds"
  stretch:
    interval_minutes: 45
    message: "Stand up and stretch your back and shoulders"
  walk:
    interval_minutes: 90
    message: "Walk around and drink some water"

# List of folders to watch for git commits (watches subdirectories 1 level deep)
git_watch_dirs:
  - "~"
"""


# ==============================================================================
# Path & Directory Helpers
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


def get_ergo_yaml_path() -> Path:
    """Returns the path to ergo.yaml."""
    return get_devpulse_dir() / "ergo.yaml"


def get_ergo_db_path() -> Path:
    """Returns the path to ergo.db."""
    return get_devpulse_dir() / "ergo.db"


def get_done_flag_path() -> Path:
    """Returns the path to ergo_done.flag used for manual break acknowledgment."""
    return get_devpulse_dir() / "ergo_done.flag"


# ==============================================================================
# Configuration Loading
# ==============================================================================

def load_ergo_config(config_file: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads break intervals and git watch directories from ergo.yaml.
    Creates default file on first run. If PyYAML is missing, falls back to defaults.
    """
    target = config_file or get_ergo_yaml_path()

    if not target.exists():
        try:
            target.write_text(DEFAULT_ERGO_YAML, encoding="utf-8")
        except OSError:
            pass

    default_config = {
        "breaks": {
            "eye": {
                "interval_minutes": 20,
                "message": "20-20-20: look at something 20 feet away for 20 seconds"
            },
            "stretch": {
                "interval_minutes": 45,
                "message": "Stand up and stretch your back and shoulders"
            },
            "walk": {
                "interval_minutes": 90,
                "message": "Walk around and drink some water"
            }
        },
        "git_watch_dirs": ["~"]
    }

    if yaml is None:
        return default_config

    try:
        with open(target, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict) and "breaks" in data:
                return data
    except Exception:
        pass

    return default_config


# ==============================================================================
# SQLite Database Logging
# ==============================================================================

def init_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Initializes the SQLite database at ~/.config/devpulse/ergo.db.
    Logs ONLY timestamp and event_type (break_shown, rest_detected, commit_detected, manual_done).
    Strict privacy: no keystrokes or window titles are ever stored.
    """
    target = db_path or get_ergo_db_path()
    conn = sqlite3.connect(str(target), timeout=10.0)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ergo_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ergo_timestamp ON ergo_events(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ergo_event_type ON ergo_events(event_type);")
    return conn


def log_event(conn: sqlite3.Connection, event_type: str, timestamp_str: Optional[str] = None) -> None:
    """Logs a single ergonomic event into ergo.db."""
    ts = timestamp_str or datetime.now().isoformat()
    try:
        with conn:
            conn.execute(
                "INSERT INTO ergo_events (timestamp, event_type) VALUES (?, ?)",
                (ts, event_type)
            )
    except Exception:
        pass


# ==============================================================================
# Desktop Notifications with Rate Limiting
# ==============================================================================

def send_desktop_notification(title: str, message: str) -> bool:
    """
    Sends a non-blocking desktop notification using notify-send.
    Returns True if successful, False otherwise. Never crashes.
    """
    notify_bin = shutil.which("notify-send")
    if not notify_bin:
        return False
    try:
        subprocess.run(
            [notify_bin, "-a", "DevPulse ErgoGuard", "-t", "8000", title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0
        )
        return True
    except Exception:
        return False


# ==============================================================================
# Core Break State Logic (Pure Functions - Fully Unit-Testable)
# ==============================================================================

def create_ergo_state(current_time: float, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Initializes the tracking state machine for ErgoGuard.
    All intervals are stored in seconds.
    """
    cfg = config or load_ergo_config()
    breaks_cfg = cfg.get("breaks", {})

    return {
        "is_active": True,
        "last_update_time": current_time,
        "active_seconds": 0.0,
        "last_idle_time": None,
        "active_at_last_break": {
            "eye": 0.0,
            "stretch": 0.0,
            "walk": 0.0
        },
        "intervals": {
            "eye": breaks_cfg.get("eye", {}).get("interval_minutes", 20) * 60.0,
            "stretch": breaks_cfg.get("stretch", {}).get("interval_minutes", 45) * 60.0,
            "walk": breaks_cfg.get("walk", {}).get("interval_minutes", 90) * 60.0,
        },
        "messages": {
            "eye": breaks_cfg.get("eye", {}).get("message", "20-20-20: look at something 20 feet away for 20 seconds"),
            "stretch": breaks_cfg.get("stretch", {}).get("message", "Stand up and stretch your back and shoulders"),
            "walk": breaks_cfg.get("walk", {}).get("message", "Walk around and drink some water"),
        },
        "due_since": None,        # Timestamp when highest priority break first became due
        "due_break_type": None,   # 'walk', 'stretch', or 'eye'
        "notification_history": [],  # Sliding window of timestamps (max 3 per hour)
    }


def reset_breaks_to_current(state: Dict[str, Any]) -> None:
    """Resets all break clocks to the current active seconds total."""
    current_active = state["active_seconds"]
    state["active_at_last_break"]["eye"] = current_active
    state["active_at_last_break"]["stretch"] = current_active
    state["active_at_last_break"]["walk"] = current_active
    state["due_since"] = None
    state["due_break_type"] = None


def reset_specific_break(state: Dict[str, Any], break_type: str) -> None:
    """
    Resets the timer for the taken break.
    Hierarchical reset: taking a walk resets stretch and eye too.
    Taking a stretch resets eye too.
    """
    current_active = state["active_seconds"]
    state["active_at_last_break"][break_type] = current_active
    if break_type == "walk":
        state["active_at_last_break"]["stretch"] = current_active
        state["active_at_last_break"]["eye"] = current_active
    elif break_type == "stretch":
        state["active_at_last_break"]["eye"] = current_active

    state["due_since"] = None
    state["due_break_type"] = None


def get_due_break_type(state: Dict[str, Any]) -> Optional[str]:
    """
    Determines if any break is due based on accumulated active seconds.
    Priority order: walk (90m) > stretch (45m) > eye (20m).
    If several are due at once, returns only the longest one.
    """
    current_active = state["active_seconds"]
    walk_due = (current_active - state["active_at_last_break"]["walk"]) >= state["intervals"]["walk"]
    stretch_due = (current_active - state["active_at_last_break"]["stretch"]) >= state["intervals"]["stretch"]
    eye_due = (current_active - state["active_at_last_break"]["eye"]) >= state["intervals"]["eye"]

    if walk_due:
        return "walk"
    if stretch_due:
        return "stretch"
    if eye_due:
        return "eye"
    return None


def can_send_notification(state: Dict[str, Any], current_time: float) -> bool:
    """
    Checks if a notification can be sent under the 3 per hour rate limit.
    Maintains a sliding 3600-second window.
    """
    # Filter notifications from within the last 3600 seconds
    state["notification_history"] = [t for t in state["notification_history"] if (current_time - t) < 3600.0]
    return len(state["notification_history"]) < 3


def update_ergo_tick(
    state: Dict[str, Any],
    current_time: float,
    idle_event: Optional[str] = None,
    is_commit: bool = False,
    is_manual_done: bool = False
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Advances ErgoGuard state machine by one step.
    Parameters:
      - state: The mutable state dictionary.
      - current_time: Current epoch timestamp in seconds.
      - idle_event: 'IDLE', 'ACTIVE', or None.
      - is_commit: True if a git commit was detected this tick.
      - is_manual_done: True if ergo done was triggered.

    Returns: (updated_state, action_dict_or_None)
      action_dict may be:
        {"action": "show_break", "type": str, "message": str, "reason": "pause"|"timeout"|"commit"}
        {"action": "rest_detected", "duration_seconds": float}
        {"action": "manual_done"}
    """
    # Step 1: Accumulate active time
    if state["is_active"]:
        delta = current_time - state["last_update_time"]
        if delta > 0:
            state["active_seconds"] += delta
    state["last_update_time"] = current_time

    # Step 2: Handle manual done flag
    if is_manual_done:
        reset_breaks_to_current(state)
        return state, {"action": "manual_done"}

    # Step 3: Handle swayidle events
    if idle_event == "IDLE":
        if state["is_active"]:
            state["is_active"] = False
            state["last_idle_time"] = current_time

    elif idle_event == "ACTIVE":
        if not state["is_active"] and state["last_idle_time"] is not None:
            # Idle duration is (ACTIVE time - IDLE time) + 3 seconds (swayidle 3s timeout)
            idle_duration = (current_time - state["last_idle_time"]) + 3.0
            state["is_active"] = True
            state["last_idle_time"] = None

            # Real rest check: 5 minutes (300 seconds) or more
            if idle_duration >= 300.0:
                reset_breaks_to_current(state)
                return state, {"action": "rest_detected", "duration_seconds": idle_duration}
        else:
            state["is_active"] = True
            state["last_idle_time"] = None

    # Step 4: Check if any break is due
    due_type = get_due_break_type(state)

    if due_type is not None:
        if state["due_break_type"] != due_type:
            state["due_break_type"] = due_type
            state["due_since"] = current_time

        reason = None
        # Trigger Condition A: Git commit happened
        if is_commit:
            reason = "commit"
        # Trigger Condition B: Natural pause (user just transitioned to IDLE)
        elif idle_event == "IDLE":
            reason = "pause"
        # Trigger Condition C: Max wait of 5 minutes (300s) reached without a pause
        elif state["due_since"] is not None and (current_time - state["due_since"]) >= 300.0:
            reason = "timeout"

        if reason is not None:
            # Enforce 3 notifications per hour rate limit
            if can_send_notification(state, current_time):
                state["notification_history"].append(current_time)
                msg = state["messages"].get(due_type, "Time for a break!")
                if reason == "commit":
                    msg = f"Nice commit! Good moment for a break. {msg}"

                # Reset the taken break
                reset_specific_break(state, due_type)

                return state, {
                    "action": "show_break",
                    "type": due_type,
                    "message": msg,
                    "reason": reason
                }
    else:
        state["due_since"] = None
        state["due_break_type"] = None

    return state, None


# ==============================================================================
# Git Commit Watcher
# ==============================================================================

class GitCommitWatcher:
    """
    Watches project folders for Git commits by checking mtime of .git/logs/HEAD.
    Scans subdirectories one level deep. Zero network calls, 100% local.
    """

    def __init__(self, watch_roots: List[str]) -> None:
        self.watch_roots = [Path(os.path.expanduser(p)).resolve() for p in watch_roots]
        self.last_mtimes: Dict[str, float] = {}
        # Initial scan to establish baseline mtimes without triggering on startup
        self.scan_for_commits(initial=True)

    def scan_for_commits(self, initial: bool = False) -> bool:
        """
        Scans for changed .git/logs/HEAD files.
        Returns True if a new commit was detected, False otherwise.
        """
        commit_detected = False

        for root in self.watch_roots:
            if not root.is_dir():
                continue

            candidates = []
            # Check if root itself is a git repository
            if (root / ".git" / "logs" / "HEAD").is_file():
                candidates.append(root / ".git" / "logs" / "HEAD")

            # Check direct subdirectories (1 level deep)
            try:
                for entry in root.iterdir():
                    if entry.is_dir():
                        head_log = entry / ".git" / "logs" / "HEAD"
                        if head_log.is_file():
                            candidates.append(head_log)
            except (PermissionError, OSError):
                continue

            for log_file in candidates:
                key = str(log_file)
                try:
                    mtime = log_file.stat().st_mtime
                    if key in self.last_mtimes:
                        if mtime > self.last_mtimes[key]:
                            self.last_mtimes[key] = mtime
                            if not initial:
                                commit_detected = True
                    else:
                        self.last_mtimes[key] = mtime
                except OSError:
                    continue

        return commit_detected


# ==============================================================================
# Idle Event Listener Thread (swayidle wrapper)
# ==============================================================================

class SwayIdleListener:
    """
    Spawns swayidle in a background thread and pushes 'IDLE' and 'ACTIVE' events.
    Command: swayidle -w timeout 3 'echo IDLE' resume 'echo ACTIVE'
    If swayidle is missing or exits, handles it gracefully without crashing.
    """

    def __init__(self) -> None:
        self.swayidle_bin = shutil.which("swayidle")
        self.proc: Optional[subprocess.Popen] = None
        self.events_queue: List[str] = []
        self.lock = threading.Lock()
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if not self.swayidle_bin:
            return False

        try:
            cmd = [
                self.swayidle_bin,
                "-w",
                "timeout", "3", "echo IDLE",
                "resume", "echo ACTIVE"
            ]
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            self.running = True
            self.thread = threading.Thread(target=self._read_loop, daemon=True)
            self.thread.start()
            return True
        except Exception:
            return False

    def _read_loop(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        try:
            for line in self.proc.stdout:
                if not self.running:
                    break
                stripped = line.strip()
                if stripped in ("IDLE", "ACTIVE"):
                    with self.lock:
                        self.events_queue.append(stripped)
        except Exception:
            pass

    def pop_events(self) -> List[str]:
        """Pops and returns all pending idle/active events."""
        with self.lock:
            events = list(self.events_queue)
            self.events_queue.clear()
            return events

    def stop(self) -> None:
        self.running = False
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None


# ==============================================================================
# CLI Command Implementations
# ==============================================================================

def run_ergo_start() -> None:
    """
    Main loop for 'devpulse ergo start'.
    Tracks active time, natural pauses, real rests, git commits, and breaks.
    Logs events to SQLite at ~/.config/devpulse/ergo.db.
    """
    config = load_ergo_config()
    conn = init_db()
    done_flag_path = get_done_flag_path()

    # Track last mtime of done flag to detect changes
    last_done_mtime = done_flag_path.stat().st_mtime if done_flag_path.exists() else 0.0

    idle_listener = SwayIdleListener()
    swayidle_available = idle_listener.start()

    git_watcher = GitCommitWatcher(config.get("git_watch_dirs", ["~"]))

    now = time.time()
    state = create_ergo_state(now, config)

    print("=" * 65)
    print(" DevPulse ErgoGuard - Ergonomic Break & Rest Monitor")
    print("=" * 65)
    if swayidle_available:
        print("Idle Detection   : swayidle (KDE Plasma 6.3 Wayland active)")
    else:
        print("Idle Detection   : swayidle not found. Running on active wall-clock time.")
        print("                   (Install via: sudo apt install swayidle)")
    print(f"Configuration    : {get_ergo_yaml_path()}")
    print(f"Database (SQLite): {get_ergo_db_path()}")
    print(f"Break Intervals  : Eye (20m), Stretch (45m), Walk (90m)")
    print("Natural Pauses   : Breaks notify on next pause or after 5m max wait.")
    print("Real Rest Reset  : 5+ minutes away automatically resets break clocks.")
    print("Manual Reset     : Run 'python3 devpulse.py ergo done' from another terminal.")
    print("Press Ctrl+C to stop monitor and view summary.")
    print("=" * 65)

    last_git_check = time.time()
    session_start_time = time.time()
    total_breaks_shown = 0
    total_rests_detected = 0

    try:
        while True:
            time.sleep(1.0)
            now = time.time()

            # Check manual done flag
            is_manual_done = False
            if done_flag_path.exists():
                try:
                    current_flag_mtime = done_flag_path.stat().st_mtime
                    if current_flag_mtime > last_done_mtime:
                        last_done_mtime = current_flag_mtime
                        is_manual_done = True
                except OSError:
                    pass

            # Check git commits every 5 seconds
            is_commit = False
            if now - last_git_check >= 5.0:
                is_commit = git_watcher.scan_for_commits()
                last_git_check = now
                if is_commit:
                    time_tag = datetime.now().strftime("%H:%M:%S")
                    print(f"[{time_tag}] COMMIT DETECTED: New git commit recorded.")
                    log_event(conn, "commit_detected")

            # Pop swayidle events
            pending_events = idle_listener.pop_events() if swayidle_available else []
            if not pending_events:
                pending_events = [None]  # Regular tick

            for evt in pending_events:
                state, action = update_ergo_tick(
                    state=state,
                    current_time=now,
                    idle_event=evt,
                    is_commit=is_commit,
                    is_manual_done=is_manual_done
                )

                if action:
                    act_type = action.get("action")

                    if act_type == "show_break":
                        break_type = action["type"]
                        msg = action["message"]
                        reason = action["reason"]
                        time_tag = datetime.now().strftime("%H:%M:%S")
                        print(f"[{time_tag}] BREAK [{break_type.upper()} - {reason}]: {msg}")

                        # Send desktop notification via notify-send
                        send_desktop_notification(f"ErgoGuard: {break_type.capitalize()} Break", msg)
                        log_event(conn, "break_shown")
                        total_breaks_shown += 1

                    elif act_type == "rest_detected":
                        mins = int(action["duration_seconds"] // 60)
                        time_tag = datetime.now().strftime("%H:%M:%S")
                        print(f"[{time_tag}] REST DETECTED: {mins} min away. All break timers reset.")
                        log_event(conn, "rest_detected")
                        total_rests_detected += 1

                    elif act_type == "manual_done":
                        time_tag = datetime.now().strftime("%H:%M:%S")
                        print(f"[{time_tag}] MANUAL BREAK DONE: All break timers reset.")
                        log_event(conn, "manual_done")

    except KeyboardInterrupt:
        print("\n\nStopping ErgoGuard monitor...")
        idle_listener.stop()
        conn.close()

        total_session_sec = int(time.time() - session_start_time)
        active_sec = int(state["active_seconds"])
        print("-" * 65)
        print(" Session Summary:")
        print(f"   Total Run Time  : {total_session_sec // 60}m {total_session_sec % 60}s")
        print(f"   Active Work Time: {active_sec // 60}m {active_sec % 60}s")
        print(f"   Breaks Prompted : {total_breaks_shown}")
        print(f"   Rests Detected  : {total_rests_detected}")
        print("=" * 65)


def run_ergo_done() -> int:
    """
    Signals the running ErgoGuard monitor that a break was taken.
    Writes the current timestamp into ~/.config/devpulse/ergo_done.flag.
    """
    flag_file = get_done_flag_path()
    try:
        flag_file.write_text(str(time.time()), encoding="utf-8")
        print("[ErgoGuard] Break completed! Reset signal sent to running monitor.")
        return 0
    except Exception as e:
        sys.stderr.write(f"[ErgoGuard Error] Failed to write done flag: {e}\n")
        return 1


def run_ergo_status() -> int:
    """
    Displays today's ergonomic metrics and the timestamp of the last break taken.
    """
    db_file = get_ergo_db_path()
    if not db_file.exists():
        print("=" * 65)
        print(" DevPulse ErgoGuard - Today's Status")
        print("=" * 65)
        print("No ergonomic activity has been logged yet.")
        print("Run 'python3 devpulse.py ergo start' to begin monitoring.")
        print("=" * 65)
        return 0

    today_str = date.today().isoformat()
    conn = sqlite3.connect(str(db_file))
    try:
        cur = conn.cursor()

        # Counts per event_type for today
        cur.execute("""
            SELECT event_type, COUNT(*)
            FROM ergo_events
            WHERE date(timestamp) = ?
            GROUP BY event_type
        """, (today_str,))

        counts = {
            "break_shown": 0,
            "rest_detected": 0,
            "commit_detected": 0,
            "manual_done": 0
        }
        for etype, cnt in cur.fetchall():
            if etype in counts:
                counts[etype] = cnt

        # Last break timestamp
        cur.execute("""
            SELECT timestamp
            FROM ergo_events
            WHERE event_type = 'break_shown'
            ORDER BY id DESC
            LIMIT 1
        """)
        last_row = cur.fetchone()
        last_break_str = "None recorded today"
        if last_row:
            try:
                dt = datetime.fromisoformat(last_row[0])
                last_break_str = dt.strftime("%H:%M:%S (%A, %b %d)")
            except Exception:
                last_break_str = last_row[0]

        print("=" * 65)
        print(f" DevPulse ErgoGuard - Today's Status ({date.today().strftime('%A, %b %d, %Y')})")
        print("=" * 65)
        print(f"Breaks Prompted (break_shown)   : {counts['break_shown']}")
        print(f"Natural Rests (rest_detected)   : {counts['rest_detected']}")
        print(f"Git Commits (commit_detected)   : {counts['commit_detected']}")
        print(f"Manual Done (manual_done)       : {counts['manual_done']}")
        print("-" * 65)
        print(f"Last Break Time                 : {last_break_str}")
        print("=" * 65)
        return 0
    finally:
        conn.close()


# ==============================================================================
# Self-Test Suite: ergo selftest
# ==============================================================================

def run_ergo_selftest() -> int:
    """
    Tests ErgoGuard logic with simulated timestamps without external dependencies:
      1. Active-time counting (active vs idle)
      2. Real rest reset after 5 minutes idle
      3. 'Show on pause' (natural pause triggering)
      4. 5-minute max wait timeout (break triggers even without pause)
      5. Max 3 notifications per hour cap
    Prints PASS or FAIL per test and a final summary.
    """
    print("=" * 65)
    print(" Running DevPulse ErgoGuard Offline Logic Self-Test...")
    print("=" * 65)

    tests_passed = 0
    total_tests = 5

    # --------------------------------------------------------------------------
    # Test 1: Active-time counting
    # --------------------------------------------------------------------------
    print("\n[Test 1/5] Active-Time Counting (Active vs Idle)...")
    try:
        t0 = 1000.0
        state = create_ergo_state(t0)

        # Advance 60 seconds while ACTIVE
        state, _ = update_ergo_tick(state, t0 + 60.0)
        assert abs(state["active_seconds"] - 60.0) < 0.01, f"Expected 60s active, got {state['active_seconds']}"

        # Transition to IDLE
        state, _ = update_ergo_tick(state, t0 + 60.0, idle_event="IDLE")
        assert not state["is_active"], "State should be idle"

        # Advance 120 seconds while IDLE
        state, _ = update_ergo_tick(state, t0 + 180.0)
        assert abs(state["active_seconds"] - 60.0) < 0.01, "Active time should NOT advance while idle"

        print("  Active time accumulated only during active periods.")
        print("  Result: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"  Result: FAIL ({e})")

    # --------------------------------------------------------------------------
    # Test 2: Rest reset after 5 minutes idle
    # --------------------------------------------------------------------------
    print("\n[Test 2/5] Real Rest Reset after 5+ Minutes Idle...")
    try:
        t0 = 1000.0
        state = create_ergo_state(t0)
        # Advance 18 minutes (1080s) active time
        state, _ = update_ergo_tick(state, t0 + 1080.0)
        assert state["active_seconds"] == 1080.0

        # User goes IDLE at t0 + 1080.0
        state, _ = update_ergo_tick(state, t0 + 1080.0, idle_event="IDLE")

        # User returns ACTIVE at t0 + 1080 + 310s (5m 10s idle)
        t_active = t0 + 1080.0 + 310.0
        state, action = update_ergo_tick(state, t_active, idle_event="ACTIVE")

        assert action is not None, "Expected rest action"
        assert action.get("action") == "rest_detected", f"Expected rest_detected, got {action}"
        # Break timers should have been reset to current active seconds
        assert state["active_at_last_break"]["eye"] == state["active_seconds"]
        assert state["active_at_last_break"]["walk"] == state["active_seconds"]

        print("  5+ minutes of idle correctly detected as real rest and reset break clocks.")
        print("  Result: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"  Result: FAIL ({e})")

    # --------------------------------------------------------------------------
    # Test 3: Show on pause (Wait for natural pause)
    # --------------------------------------------------------------------------
    print("\n[Test 3/5] 'Show on Pause' (Natural Pause Triggering)...")
    try:
        t0 = 1000.0
        state = create_ergo_state(t0)

        # Eye break interval is 20m (1200s). Advance 1205 seconds active.
        t_due = t0 + 1205.0
        state, action = update_ergo_tick(state, t_due)

        # Break is due, but user is still ACTIVE: must NOT notify yet!
        assert action is None, "Should not notify while user is continuously typing"
        assert state["due_break_type"] == "eye", "Eye break should be flagged as due"

        # User pauses and transitions to IDLE
        state, action = update_ergo_tick(state, t_due + 2.0, idle_event="IDLE")
        assert action is not None, "Expected notification on pause"
        assert action.get("action") == "show_break"
        assert action.get("type") == "eye"
        assert action.get("reason") == "pause"

        print("  Break waited for user's natural pause (IDLE) before notifying.")
        print("  Result: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"  Result: FAIL ({e})")

    # --------------------------------------------------------------------------
    # Test 4: 5-minute max wait timeout
    # --------------------------------------------------------------------------
    print("\n[Test 4/5] 5-Minute Max Wait (Timeout Triggering)...")
    try:
        t0 = 1000.0
        state = create_ergo_state(t0)

        # Eye break due at 1200s
        t_due = t0 + 1200.0
        state, action = update_ergo_tick(state, t_due)
        assert action is None, "Should not notify immediately"

        # 4 minutes later (240s): still continuous active typing, no pause yet
        state, action = update_ergo_tick(state, t_due + 240.0)
        assert action is None, "Should not notify at 4 minutes"

        # 5 minutes and 1 second later (301s): max wait reached!
        state, action = update_ergo_tick(state, t_due + 301.0)
        assert action is not None, "Expected notification after 5 minutes max wait"
        assert action.get("action") == "show_break"
        assert action.get("reason") == "timeout"

        print("  Break fired after 5 minutes of continuous typing without a pause.")
        print("  Result: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"  Result: FAIL ({e})")

    # --------------------------------------------------------------------------
    # Test 5: Rate limit of max 3 notifications per hour
    # --------------------------------------------------------------------------
    print("\n[Test 5/5] Rate Limit Cap (Max 3 Notifications per Hour)...")
    try:
        t0 = 10000.0
        state = create_ergo_state(t0)

        # Trigger 3 break notifications in the same hour
        for i in range(3):
            # Advance active time to make eye break due
            state["active_seconds"] += 1300.0
            state, action = update_ergo_tick(state, t0 + (i * 200.0), idle_event="IDLE")
            assert action is not None and action["action"] == "show_break", f"Break {i+1} should fire"

        assert len(state["notification_history"]) == 3, "Should have 3 recorded notifications"

        # Try to trigger a 4th break within the same hour
        state["active_seconds"] += 1300.0
        state, action = update_ergo_tick(state, t0 + 800.0, idle_event="IDLE")
        assert action is None, "4th notification in the same hour must be blocked by rate limit"

        # Advance time past 1 hour (3601 seconds)
        state["active_seconds"] += 1300.0
        state, action = update_ergo_tick(state, t0 + 3700.0, idle_event="IDLE")
        assert action is not None and action["action"] == "show_break", "Notification should fire after 1 hour window resets"

        print("  Hourly rate limiter capped notifications at 3/hour and reset after 60 min.")
        print("  Result: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"  Result: FAIL ({e})")

    # --------------------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------------------
    print("\n" + "=" * 65)
    if tests_passed == total_tests:
        print(f" ERGO SELF-TEST SUMMARY: ALL {total_tests}/{total_tests} TESTS PASSED [PASS]")
        print(" ErgoGuard break state engine is verified and functioning correctly.")
        print("=" * 65 + "\n")
        return 0
    else:
        print(f" ERGO SELF-TEST SUMMARY: {tests_passed}/{total_tests} TESTS PASSED [FAIL]")
        print("=" * 65 + "\n")
        return 1
