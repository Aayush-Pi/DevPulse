"""
AuditPulse Privacy-Auditing and Reporting Engine (audit.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
PRIVACY & INTEGRITY PRINCIPLES:
1. STRICTLY METADATA-ONLY AUDITING:
   Only timestamps, event types, and encryption modes are ever logged to audit.db.
   NEVER logs file names, file contents, private/public keys, passphrases,
   sender names, or ciphertext tokens.
2. ZERO FAILURE PROPAGATION:
   log_secret_event() catches all internal exceptions silently. It will NEVER
   raise or interrupt cryptographic operations or user workflows.
3. LOCAL & OFFLINE:
   Reads only local SQLite databases (focus.db, ergo.db, audit.db). Zero network
   traffic, zero telemetry.
4. INTEGRITY CHECKSUM:
   Reports compute a canonical SHA-256 digest over the JSON payload (excluding the
   integrity field).
   NOTE ON SECURITY: This detects accidental file corruption or manual edits; it
   is not a cryptographic digital signature, since any determined local user
   with Python could recalculate the SHA-256 digest.
================================================================================
"""

import os
import sys
import json
import socket
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple, List


DEVPULSE_VERSION = "0.1"


# ==============================================================================
# Path Helpers
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


def get_audit_db_path() -> Path:
    """Returns the path to audit.db."""
    return get_devpulse_dir() / "audit.db"


def get_focus_db_path() -> Path:
    """Returns the path to focus.db."""
    return get_devpulse_dir() / "focus.db"


def get_ergo_db_path() -> Path:
    """Returns the path to ergo.db."""
    return get_devpulse_dir() / "ergo.db"


# ==============================================================================
# Task 1: Audit Database & Logging Function
# ==============================================================================

def _init_audit_db(db_path: Path) -> sqlite3.Connection:
    """
    Initializes the SQLite database at ~/.config/devpulse/audit.db.
    Creates secret_events table if it does not exist.
    """
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secret_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                mode TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secret_timestamp ON secret_events(timestamp);")
    return conn


def log_secret_event(event_type: str, mode: Optional[str] = None) -> None:
    """
    Logs a SecretBridge lifecycle event to audit.db.
    Allowed event_type: key_generated, message_encrypted, message_decrypted,
                        decrypt_failed, message_expired.
    Allowed mode: "public_key", "passphrase", or None.

    CRITICAL SAFETY GUARANTEE:
    This function will NEVER raise an exception under any circumstance.
    If database writes fail (e.g. disk full, permission denied, locked DB),
    it silently fails so encryption and decryption are never disrupted.
    """
    try:
        db_path = get_audit_db_path()
        conn = _init_audit_db(db_path)
        now_utc = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute(
                "INSERT INTO secret_events (timestamp, event_type, mode) VALUES (?, ?, ?)",
                (now_utc, str(event_type), str(mode) if mode else None)
            )
        conn.close()
    except Exception:
        # Silently absorb all errors to ensure encryption workflows never break
        pass


# ==============================================================================
# Task 3: Aggregation & Schema Introspection
# ==============================================================================

def inspect_ergo_schema(conn: sqlite3.Connection) -> Tuple[str, List[str]]:
    """
    Dynamically inspects ergo.db using SQLite PRAGMA table_info rather than
    hardcoding table or column names.
    Returns: (table_name, list_of_column_names).
    """
    cur = conn.cursor()
    # Find all table names
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in cur.fetchall()]

    if not tables:
        return "", []

    # Prefer 'ergo_events' if present, otherwise take first non-internal table
    target_table = "ergo_events" if "ergo_events" in tables else tables[0]

    cur.execute(f"PRAGMA table_info({target_table});")
    # PRAGMA table_info columns: (cid, name, type, notnull, dflt_value, pk)
    columns = [row[1] for row in cur.fetchall()]

    return target_table, columns


def collect_secretbridge_metrics(since_iso: str) -> Dict[str, Any]:
    """Reads audit.db and aggregates SecretBridge events since given ISO timestamp."""
    db_path = get_audit_db_path()
    if not db_path.exists():
        return {"by_event_type": {}, "by_mode": {}, "total_events": 0}

    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()

        cur.execute("""
            SELECT event_type, COUNT(*)
            FROM secret_events
            WHERE timestamp >= ?
            GROUP BY event_type
        """, (since_iso,))
        by_event = {row[0]: row[1] for row in cur.fetchall()}

        cur.execute("""
            SELECT COALESCE(mode, 'none'), COUNT(*)
            FROM secret_events
            WHERE timestamp >= ?
            GROUP BY mode
        """, (since_iso,))
        by_mode = {row[0]: row[1] for row in cur.fetchall()}

        total = sum(by_event.values())
        conn.close()
        return {
            "by_event_type": by_event,
            "by_mode": by_mode,
            "total_events": total
        }
    except Exception:
        return {"by_event_type": {}, "by_mode": {}, "total_events": 0}


def collect_focuspulse_metrics(since_iso: str) -> Dict[str, Any]:
    """
    Reads focus.db (focus_events and window_switches) since given ISO timestamp.
    STRICT PRIVACY: Never reads or returns window titles.
    """
    db_path = get_focus_db_path()
    if not db_path.exists():
        return {
            "focus_seconds": 0.0,
            "distraction_seconds": 0.0,
            "neutral_seconds": 0.0,
            "total_seconds": 0.0,
            "focus_score_percent": 0.0,
            "window_switch_count": 0,
            "top_app_classes": []
        }

    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()

        # Check if tables exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cur.fetchall()]

        focus_sec = 0.0
        distract_sec = 0.0
        neutral_sec = 0.0
        top_apps = []

        if "focus_events" in tables:
            cur.execute("""
                SELECT category, SUM(duration_seconds)
                FROM focus_events
                WHERE timestamp >= ?
                GROUP BY category
            """, (since_iso,))
            for cat, dur in cur.fetchall():
                val = float(dur) if dur else 0.0
                if cat == "focus":
                    focus_sec = val
                elif cat == "distraction":
                    distract_sec = val
                elif cat == "neutral":
                    neutral_sec = val

            # Top 5 app classes by time
            cur.execute("""
                SELECT window_class, SUM(duration_seconds) as total_dur
                FROM focus_events
                WHERE timestamp >= ?
                GROUP BY window_class
                ORDER BY total_dur DESC
                LIMIT 5
            """, (since_iso,))
            for app_cls, dur in cur.fetchall():
                top_apps.append({
                    "class": app_cls,
                    "seconds": round(float(dur), 1) if dur else 0.0
                })

        # Window switches count
        switch_count = 0
        if "window_switches" in tables:
            cur.execute("SELECT COUNT(*) FROM window_switches WHERE timestamp >= ?", (since_iso,))
            row = cur.fetchone()
            switch_count = row[0] if row else 0

        conn.close()

        total_sec = focus_sec + distract_sec + neutral_sec
        denom = focus_sec + distract_sec
        if denom > 0:
            focus_score = round((focus_sec / denom) * 100.0, 1)
        else:
            focus_score = 100.0 if total_sec > 0 else 0.0

        return {
            "focus_seconds": round(focus_sec, 1),
            "distraction_seconds": round(distract_sec, 1),
            "neutral_seconds": round(neutral_sec, 1),
            "total_seconds": round(total_sec, 1),
            "focus_score_percent": focus_score,
            "window_switch_count": switch_count,
            "top_app_classes": top_apps
        }
    except Exception:
        return {
            "focus_seconds": 0.0,
            "distraction_seconds": 0.0,
            "neutral_seconds": 0.0,
            "total_seconds": 0.0,
            "focus_score_percent": 0.0,
            "window_switch_count": 0,
            "top_app_classes": []
        }


def collect_ergoguard_metrics(since_iso: str) -> Tuple[Dict[str, Any], str, List[str]]:
    """
    Reads ergo.db by first dynamically introspecting tables/columns via PRAGMA table_info.
    Returns: (metrics_dict, table_name_found, columns_found).
    """
    db_path = get_ergo_db_path()
    if not db_path.exists():
        return {
            "by_event_type": {
                "break_shown": 0,
                "rest_detected": 0,
                "commit_detected": 0,
                "manual_done": 0
            },
            "total_breaks": 0
        }, "(database not created yet)", []

    try:
        conn = sqlite3.connect(str(db_path))
        table_name, columns = inspect_ergo_schema(conn)

        if not table_name or "event_type" not in columns or "timestamp" not in columns:
            conn.close()
            return {
                "by_event_type": {
                    "break_shown": 0,
                    "rest_detected": 0,
                    "commit_detected": 0,
                    "manual_done": 0
                },
                "total_breaks": 0
            }, table_name or "(empty database)", columns

        cur = conn.cursor()
        cur.execute(f"""
            SELECT event_type, COUNT(*)
            FROM {table_name}
            WHERE timestamp >= ?
            GROUP BY event_type
        """, (since_iso,))

        counts = {
            "break_shown": 0,
            "rest_detected": 0,
            "commit_detected": 0,
            "manual_done": 0
        }
        for etype, cnt in cur.fetchall():
            counts[etype] = cnt

        conn.close()
        total_breaks = counts.get("break_shown", 0)

        return {
            "by_event_type": counts,
            "total_breaks": total_breaks
        }, table_name, columns

    except Exception:
        return {
            "by_event_type": {
                "break_shown": 0,
                "rest_detected": 0,
                "commit_detected": 0,
                "manual_done": 0
            },
            "total_breaks": 0
        }, "(error reading ergo.db)", []


# ==============================================================================
# Report Generation & Integrity Checksum
# ==============================================================================

def compute_report_hash(report_dict: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 digest of the report payload EXCLUDING
    the 'integrity' key. Uses sorted keys and compact separators.
    """
    copy_dict = {k: v for k, v in report_dict.items() if k != "integrity"}
    canonical_json = json.dumps(copy_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def generate_audit_report(since_days: int = 7) -> Tuple[Dict[str, Any], str, List[str]]:
    """
    Compiles the full audit report for the given lookback period.
    Returns: (report_dict, ergo_table_found, ergo_columns_found).
    """
    now_utc = datetime.now(timezone.utc)
    start_utc = now_utc - timedelta(days=since_days)
    since_iso = start_utc.isoformat()

    hostname = socket.gethostname() or "localhost"

    secret_data = collect_secretbridge_metrics(since_iso)
    focus_data = collect_focuspulse_metrics(since_iso)
    ergo_data, ergo_table, ergo_cols = collect_ergoguard_metrics(since_iso)

    report: Dict[str, Any] = {
        "report_generated_at": now_utc.isoformat(),
        "device_hostname": hostname,
        "devpulse_version": DEVPULSE_VERSION,
        "period": {
            "since_days": since_days,
            "start_timestamp": since_iso,
            "end_timestamp": now_utc.isoformat()
        },
        "secretbridge": secret_data,
        "focuspulse": focus_data,
        "ergoguard": ergo_data,
        "privacy": {
            "statement": (
                "No window titles, no keystrokes, no file contents, no cryptographic keys, "
                "and no personal data leave this computer. All metrics are computed locally "
                "from privacy-preserving event logs."
            )
        }
    }

    # Add SHA-256 integrity digest
    report["integrity"] = compute_report_hash(report)
    return report, ergo_table, ergo_cols


def write_audit_report(report: Dict[str, Any], out_path: Path) -> Path:
    """
    Writes the audit report to disk formatted with indent=2 and strict 0o600 permissions.
    """
    resolved_path = out_path.resolve()
    content = json.dumps(report, indent=2) + "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with open(os.open(resolved_path, flags, 0o600), "w", encoding="utf-8") as f:
        f.write(content)

    return resolved_path


def verify_audit_report(report_path: Path) -> Tuple[bool, str, str]:
    """
    Reads an audit report, recomputes the SHA-256 hash over the content without
    the 'integrity' field, and checks if it matches.
    Returns: (is_valid, stored_hash, computed_hash).
    """
    if not report_path.is_file():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "integrity" not in data:
        return False, "missing", "unknown"

    stored_hash = str(data["integrity"])
    computed_hash = compute_report_hash(data)

    return (stored_hash == computed_hash), stored_hash, computed_hash


# ==============================================================================
# Task 4: Self-Test Suite (Isolated in Temp Directory)
# ==============================================================================

def run_audit_selftest() -> int:
    """
    Executes automated self-test using a temporary DEVPULSE_HOME:
      1. Seeds fake data into audit.db, focus.db, and ergo.db.
      2. Generates audit report and checks metric counts.
      3. Verifies that NO window titles, keys, or passwords appear in JSON text.
      4. Verifies that --verify returns VALID.
      5. Edits one number and verifies that --verify returns TAMPERED.
    Never touches user's real configuration or data files.
    """
    import tempfile

    print("=" * 65)
    print(" Running DevPulse AuditPulse Self-Test Suite...")
    print("=" * 65)

    original_env = os.environ.get("DEVPULSE_HOME")
    tests_passed = 0
    total_tests = 5

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_home = Path(tmp_dir) / "devpulse_test_home"
        tmp_home.mkdir(parents=True, exist_ok=True)
        os.environ["DEVPULSE_HOME"] = str(tmp_home)

        try:
            # Step 1: Seed audit.db
            audit_conn = _init_audit_db(tmp_home / "audit.db")
            with audit_conn:
                audit_conn.execute("INSERT INTO secret_events (timestamp, event_type, mode) VALUES (?, ?, ?)",
                                   ("2026-10-09T10:00:00Z", "key_generated", None))
                audit_conn.execute("INSERT INTO secret_events (timestamp, event_type, mode) VALUES (?, ?, ?)",
                                   ("2026-10-09T10:05:00Z", "message_encrypted", "public_key"))
                audit_conn.execute("INSERT INTO secret_events (timestamp, event_type, mode) VALUES (?, ?, ?)",
                                   ("2026-10-09T10:10:00Z", "message_decrypted", "public_key"))
            audit_conn.close()

            # Step 2: Seed focus.db (with dummy window classes)
            focus_conn = sqlite3.connect(str(tmp_home / "focus.db"))
            with focus_conn:
                focus_conn.execute("""
                    CREATE TABLE focus_events (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        window_class TEXT,
                        category TEXT,
                        duration_seconds REAL
                    );
                """)
                focus_conn.execute("INSERT INTO focus_events VALUES (1, '2026-10-09T10:00:00Z', 'kate', 'focus', 300.0);")
                focus_conn.execute("INSERT INTO focus_events VALUES (2, '2026-10-09T10:05:00Z', 'firefox', 'distraction', 100.0);")
                focus_conn.execute("""
                    CREATE TABLE window_switches (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        window_class TEXT
                    );
                """)
                focus_conn.execute("INSERT INTO window_switches VALUES (1, '2026-10-09T10:05:00Z', 'firefox');")
            focus_conn.close()

            # Step 3: Seed ergo.db
            ergo_conn = sqlite3.connect(str(tmp_home / "ergo.db"))
            with ergo_conn:
                ergo_conn.execute("""
                    CREATE TABLE ergo_events (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        event_type TEXT
                    );
                """)
                ergo_conn.execute("INSERT INTO ergo_events VALUES (1, '2026-10-09T10:00:00Z', 'break_shown');")
                ergo_conn.execute("INSERT INTO ergo_events VALUES (2, '2026-10-09T10:30:00Z', 'rest_detected');")
                ergo_conn.execute("INSERT INTO ergo_events VALUES (3, '2026-10-09T11:00:00Z', 'commit_detected');")
            ergo_conn.close()

            # Test 1: Generate report and verify expected metrics
            print("\n[Test 1/5] Report Metric Aggregation & Counts...")
            report, ergo_tbl, ergo_cols = generate_audit_report(since_days=7)

            assert report["secretbridge"]["total_events"] == 3, "SecretBridge events count mismatch"
            assert report["focuspulse"]["focus_seconds"] == 300.0, "Focus seconds mismatch"
            assert report["focuspulse"]["distraction_seconds"] == 100.0, "Distraction seconds mismatch"
            assert report["focuspulse"]["focus_score_percent"] == 75.0, "Focus score mismatch (300 / 400 = 75%)"
            assert report["focuspulse"]["window_switch_count"] == 1, "Switch count mismatch"
            assert report["ergoguard"]["total_breaks"] == 1, "Ergo breaks mismatch"
            assert report["ergoguard"]["by_event_type"]["commit_detected"] == 1, "Commit count mismatch"
            print("  All event counts, time sums, and focus scores match seeded data.")
            print(f"  Introspected ergo.db table: '{ergo_tbl}' with columns: {ergo_cols}")
            print("  Result: PASS")
            tests_passed += 1

            # Test 2: Privacy Audit - Ensure zero titles, keys, or passwords in report text
            print("\n[Test 2/5] Privacy Verification (No titles, keys, or file contents)...")
            report_text = json.dumps(report)
            forbidden_tokens = ["DEVPULSE-PUB-v1:", "DEVPULSE-v1:", "password", "YouTube", "GitHub -", "private.key"]
            leaks = [tok for tok in forbidden_tokens if tok in report_text]
            assert not leaks, f"Privacy violation detected, forbidden tokens found: {leaks}"
            assert "window_title" not in report_text, "Window title key present in report"
            print("  Confirmed: zero window titles, file contents, or keys appear in JSON output.")
            print("  Result: PASS")
            tests_passed += 1

            # Test 3: Write report and verify permissions (0o600)
            print("\n[Test 3/5] Report Serialization & File Permissions (600)...")
            out_file = tmp_home / "test_report.json"
            write_audit_report(report, out_file)
            assert out_file.is_file(), "Report file was not created"
            mode = out_file.stat().st_mode & 0o777
            assert mode == 0o600, f"Expected permissions 600, got octal {oct(mode)}"
            print(f"  File created with mode {oct(mode)} (user read/write only).")
            print("  Result: PASS")
            tests_passed += 1

            # Test 4: Integrity Verification - Untampered report is VALID
            print("\n[Test 4/5] Integrity Verification (Untampered -> VALID)...")
            is_valid, stored, computed = verify_audit_report(out_file)
            assert is_valid, "Untampered report failed hash verification"
            assert stored == computed, "Stored hash != computed hash"
            print(f"  SHA-256 Digest: {stored[:16]}... matches computed hash.")
            print("  Result: PASS [VALID]")
            tests_passed += 1

            # Test 5: Integrity Verification - Tampered report is TAMPERED
            print("\n[Test 5/5] Tamper Detection (Modified number -> TAMPERED)...")
            with open(out_file, "r", encoding="utf-8") as f:
                tampered_data = json.load(f)
            # Tamper: change focus_seconds from 300.0 to 999.0
            tampered_data["focuspulse"]["focus_seconds"] = 999.0
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(tampered_data, f, indent=2)

            is_valid_after, stored_after, computed_after = verify_audit_report(out_file)
            assert not is_valid_after, "Tampered report was incorrectly declared valid"
            assert stored_after != computed_after, "Hashes matched despite modification"
            print(f"  Stored:   {stored_after[:16]}...")
            print(f"  Computed: {computed_after[:16]}... (Mismatch detected)")
            print("  Result: PASS [TAMPERED detected correctly]")
            tests_passed += 1

        finally:
            if original_env is not None:
                os.environ["DEVPULSE_HOME"] = original_env
            else:
                os.environ.pop("DEVPULSE_HOME", None)

    print("\n" + "=" * 65)
    if tests_passed == total_tests:
        print(f" AUDIT SELF-TEST SUMMARY: ALL {total_tests}/{total_tests} TESTS PASSED [PASS]")
        print(" AuditPulse engine and tamper verification functioning correctly.")
        print("=" * 65 + "\n")
        return 0
    else:
        print(f" AUDIT SELF-TEST SUMMARY: {tests_passed}/{total_tests} TESTS PASSED [FAIL]")
        print("=" * 65 + "\n")
        return 1
