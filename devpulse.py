#!/usr/bin/env python3
"""
DevPulse CLI (devpulse.py) - Command-line interface for SecretBridge.
Part of the offline developer utilities suite.

Provides commands:
  - keygen: Generate personal Curve25519 keypair
  - fingerprint: View or verify a public key fingerprint
  - send: Encrypt and package a .env file for chat transmission
  - open: Decrypt an incoming SecretBridge token
  - selftest: Run an automated verification cycle with dummy keys
"""

import sys
import os
import argparse
import getpass
import tempfile
from pathlib import Path
from typing import Optional

# Import the core modules for SecretBridge, FocusPulse, ErgoGuard, and AuditPulse
import secret
import focus
import ergo
import audit


def format_error(msg: str) -> None:
    """Prints a clear, friendly error message to standard error without tracebacks."""
    sys.stderr.write(f"\n[DevPulse Error] {msg}\n\n")


# ==============================================================================
# Command Handler: keygen
# ==============================================================================

def cmd_keygen(args: argparse.Namespace) -> int:
    """
    Generates a new personal Curve25519 keypair and creates ~/.config/devpulse.
    Saves keys with strict permissions and outputs the public key and fingerprint.
    """
    try:
        pub_str, fingerprint, priv_path, pub_path = secret.generate_keypair(
            name=args.name,
            force=args.force
        )
        # Log key generation event to audit.db
        audit.log_secret_event("key_generated")

        print("=" * 60)
        print(" DevPulse Keypair Generated Successfully")
        print("=" * 60)
        print(f"Name / Identity   : {args.name}")
        print(f"Private Key File  : {priv_path} (mode 600 - keep safe!)")
        print(f"Public Key File   : {pub_path}")
        print(f"Public Fingerprint: {fingerprint}")
        print("\nShare this single-line public key with your teammates:")
        print(pub_str)
        print("=" * 60)
        return 0
    except secret.SecretBridgeError as e:
        format_error(str(e))
        return 1
    except Exception as e:
        format_error(f"Failed to generate keys: {e}")
        return 1


# ==============================================================================
# Command Handler: fingerprint
# ==============================================================================

def cmd_fingerprint(args: argparse.Namespace) -> int:
    """
    Displays the fingerprint of either:
    - The user's own configured public key (if --key is omitted), or
    - A colleague's public key (string or file) to verify identity out-of-band.
    """
    try:
        if args.key:
            _, fingerprint = secret.parse_public_key_input(args.key)
            print(f"Key Fingerprint: {fingerprint}")
            print("(Compare this fingerprint with your friend over a voice call or in person)")
        else:
            _, fingerprint = secret.load_own_public_key()
            config_dir = secret.get_config_dir()
            print(f"Your Public Key Fingerprint: {fingerprint}")
            print(f"Config Directory: {config_dir}")
        return 0
    except secret.SecretBridgeError as e:
        format_error(str(e))
        return 1
    except Exception as e:
        format_error(f"Could not compute fingerprint: {e}")
        return 1


# ==============================================================================
# Command Handler: send
# ==============================================================================

def cmd_send(args: argparse.Namespace) -> int:
    """
    Packages and encrypts a file.
    Supports either:
    - Asymmetric mode: --to <recipient public key or file>
    - Symmetric mode: --passphrase
    """
    file_path = Path(args.file)
    sender_name = secret.load_sender_name()

    try:
        payload_bytes = secret.build_payload(
            file_path=file_path,
            sender_name=sender_name,
            expires_hours=args.expires_hours
        )

        if args.passphrase:
            # Passphrase mode
            print(f"Encrypting '{file_path.name}' with passphrase protection...")
            pw1 = getpass.getpass("Enter secret passphrase: ")
            if not pw1:
                format_error("Passphrase cannot be empty.")
                return 1
            pw2 = getpass.getpass("Confirm secret passphrase: ")
            if pw1 != pw2:
                format_error("Passphrases do not match. Aborted.")
                return 1

            token = secret.encrypt_with_passphrase(payload_bytes, pw1)
            audit.log_secret_event("message_encrypted", mode="passphrase")
            print("\n" + "=" * 60)
            print(" SecretBridge Token (Passphrase-Protected):")
            print("=" * 60)
            print(token)
            print("=" * 60)
            print("\n[!] IMPORTANT: Share the passphrase over a separate secure channel")
            print("    (e.g., via a quick phone call), NEVER in the same chat as this token!")
            if args.expires_hours:
                print(f"    This message will expire in {args.expires_hours} hour(s).")
            print()
            return 0

        elif args.to:
            # Public-key mode
            recipient_pub, recipient_fp = secret.parse_public_key_input(args.to)
            token = secret.encrypt_for_public_key(payload_bytes, recipient_pub)
            audit.log_secret_event("message_encrypted", mode="public_key")

            print("\n" + "=" * 60)
            print(" SecretBridge Token (Public-Key Encrypted):")
            print("=" * 60)
            print(token)
            print("=" * 60)
            print(f"\nRecipient Key Fingerprint: {recipient_fp}")
            print("Confirm this matches what your friend sees on their device.")
            if args.expires_hours:
                print(f"This message will expire in {args.expires_hours} hour(s).")
            print()
            return 0

        else:
            format_error("You must specify either --to <recipient_key> or --passphrase.")
            return 1

    except secret.SecretBridgeError as e:
        format_error(str(e))
        return 1
    except Exception as e:
        format_error(f"Encryption failed: {e}")
        return 1


# ==============================================================================
# Command Handler: open
# ==============================================================================

def cmd_open(args: argparse.Namespace) -> int:
    """
    Decrypts an incoming SecretBridge token.
    Reads token from --text, piped stdin, or an interactive prompt.
    """
    token = args.text

    # If --text wasn't provided, read from stdin or prompt the user
    if not token:
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()
        else:
            try:
                token = input("Paste SecretBridge token (DEVPULSE-v1:... or DEVPULSE-v1P:...): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return 1

    if not token:
        format_error("No message token was provided.")
        return 1

    # Check prefix to prompt for passphrase if needed
    passphrase = None
    if token.startswith(secret.CIPHERTEXT_PASSPHRASE_PREFIX):
        try:
            passphrase = getpass.getpass("Enter decryption passphrase: ")
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.")
            return 1

    mode = "passphrase" if token.startswith(secret.CIPHERTEXT_PASSPHRASE_PREFIX) else "public_key" if token.startswith(secret.CIPHERTEXT_PUBLIC_PREFIX) else None

    try:
        payload = secret.decrypt_message(token, passphrase=passphrase)
        # Log successful decryption
        audit.log_secret_event("message_decrypted", mode=mode)

        # Print sender context and unverified status
        sender = payload.get("sender_name", "Anonymous")
        created = payload.get("created_at", "Unknown")
        orig_filename = payload.get("filename", "unnamed.env")

        print("\n" + "-" * 50)
        print(f"Sender Identity : {sender} (NOTE: Not cryptographically verified)")
        print(f"Created At      : {created} (UTC)")
        print(f"Original Name   : {orig_filename}")
        print("-" * 50)

        if args.print:
            # Print file contents directly to terminal
            raw_b64 = payload.get("file_content_b64", "")
            import base64
            content = base64.b64decode(raw_b64).decode("utf-8", errors="replace")
            print("\n--- BEGIN FILE CONTENT ---")
            print(content, end="")
            if not content.endswith("\n"):
                print()
            print("--- END FILE CONTENT ---\n")
            return 0
        else:
            # Write securely to disk
            out_path = Path(args.out) if args.out else None
            saved_path, _ = secret.write_decrypted_file(payload, out_path=out_path, force=args.force)
            print(f"[+] Successfully decrypted and saved to: {saved_path}")
            print(f"    File permissions set to 600 (owner read/write only).")
            print()
            return 0

    except secret.ExpiredMessageError as e:
        audit.log_secret_event("message_expired", mode=mode)
        format_error(str(e))
        return 1
    except secret.DecryptionFailedError as e:
        audit.log_secret_event("decrypt_failed", mode=mode)
        format_error(str(e))
        return 1
    except secret.SecretBridgeError as e:
        format_error(str(e))
        return 1
    except Exception as e:
        format_error(f"Decryption failed: {e}")
        return 1


# ==============================================================================
# Command Handlers: focus (FocusPulse subcommands)
# ==============================================================================

def cmd_focus_start(args: argparse.Namespace) -> int:
    """Starts the FocusPulse real-time window tracking daemon."""
    try:
        focus.run_focus_tracker()
        return 0
    except KeyboardInterrupt:
        print("\nFocusPulse stopped.")
        return 0
    except Exception as e:
        format_error(f"FocusPulse encountered an error: {e}")
        return 1


def cmd_focus_summary(args: argparse.Namespace) -> int:
    """Displays today's focus metrics, distraction time, and top apps."""
    try:
        focus.print_summary()
        return 0
    except Exception as e:
        format_error(f"Could not load focus summary: {e}")
        return 1


def cmd_focus_selftest(args: argparse.Namespace) -> int:
    """Runs the offline unit test suite for window classification rules."""
    try:
        return focus.run_focus_selftest()
    except Exception as e:
        format_error(f"Self-test failed to execute: {e}")
        return 1


# ==============================================================================
# Command Handlers: ergo (ErgoGuard subcommands)
# ==============================================================================

def cmd_ergo_start(args: argparse.Namespace) -> int:
    """Starts the ErgoGuard break and rest monitoring daemon."""
    try:
        ergo.run_ergo_start()
        return 0
    except KeyboardInterrupt:
        print("\nErgoGuard stopped.")
        return 0
    except Exception as e:
        format_error(f"ErgoGuard encountered an error: {e}")
        return 1


def cmd_ergo_done(args: argparse.Namespace) -> int:
    """Signals that a break was taken and resets break timers."""
    try:
        return ergo.run_ergo_done()
    except Exception as e:
        format_error(f"Failed to record completed break: {e}")
        return 1


def cmd_ergo_status(args: argparse.Namespace) -> int:
    """Displays today's ergonomic break statistics and last break time."""
    try:
        return ergo.run_ergo_status()
    except Exception as e:
        format_error(f"Could not load ergonomic status: {e}")
        return 1


def cmd_ergo_selftest(args: argparse.Namespace) -> int:
    """Runs the offline unit test suite for ErgoGuard break state logic."""
    try:
        return ergo.run_ergo_selftest()
    except Exception as e:
        format_error(f"ErgoGuard self-test failed to execute: {e}")
        return 1


# ==============================================================================
# Command Handler: audit (AuditPulse)
# ==============================================================================

def cmd_audit(args: argparse.Namespace) -> int:
    """Handles 'devpulse audit' report generation, verification, and self-test."""
    if args.selftest:
        return audit.run_audit_selftest()

    if args.verify:
        verify_path = Path(args.verify)
        try:
            is_valid, stored, computed = audit.verify_audit_report(verify_path)
            if is_valid:
                print("=" * 65)
                print(f" DevPulse AuditPulse Verification: VALID [PASS]")
                print("=" * 65)
                print(f"File Verified    : {verify_path}")
                print(f"SHA-256 Digest   : {stored}")
                print("Status           : Integrity verified. The file has not been altered.")
                print("=" * 65)
                return 0
            else:
                print("=" * 65)
                print(f" DevPulse AuditPulse Verification: TAMPERED [FAIL]")
                print("=" * 65)
                print(f"File Verified    : {verify_path}")
                print(f"Stored Digest    : {stored}")
                print(f"Computed Digest  : {computed}")
                print("Status           : File content does not match checksum. Modifications detected!")
                print("=" * 65)
                return 1
        except Exception as e:
            format_error(f"Failed to verify report: {e}")
            return 1

    # Generate and save report
    try:
        report, ergo_table, ergo_cols = audit.generate_audit_report(since_days=args.since_days)
        out_path = Path(args.out)
        saved_path = audit.write_audit_report(report, out_path)

        # Print short readable summary to the terminal
        sb = report["secretbridge"]
        fp = report["focuspulse"]
        eg = report["ergoguard"]

        print("=" * 65)
        print(f" DevPulse AuditPulse Report Generated (Period: Last {args.since_days} Days)")
        print("=" * 65)
        print(f"Report File       : {saved_path} (mode 600 - user rw only)")
        print(f"Device Hostname   : {report['device_hostname']}")
        print(f"Integrity Checksum: {report['integrity']}")
        if ergo_table:
            cols_str = ", ".join(ergo_cols) if ergo_cols else "none"
            print(f"Introspected Ergo : Table '{ergo_table}' (Columns: {cols_str})")
        print("-" * 65)
        print(f"SecretBridge : {sb['total_events']} events logged")
        print(f"FocusPulse   : {fp['focus_seconds']}s focus | {fp['distraction_seconds']}s distraction | Score: {fp['focus_score_percent']}% | {fp['window_switch_count']} switches")
        print(f"ErgoGuard    : {eg['total_breaks']} breaks prompted | {eg['by_event_type'].get('rest_detected', 0)} rests | {eg['by_event_type'].get('commit_detected', 0)} commits")
        print("-" * 65)
        print("Privacy Guarantee: No window titles, keystrokes, contents, or keys stored.")
        print("=" * 65)
        return 0
    except Exception as e:
        format_error(f"Failed to compile audit report: {e}")
        return 1


# ==============================================================================
# Command Handler: gui (PyQt6 Desktop Interface)
# ==============================================================================

def cmd_gui(args: argparse.Namespace) -> int:
    """Launches the DevPulse PyQt6 desktop graphical interface."""
    try:
        import gui
        return gui.main()
    except ImportError as e:
        format_error(
            "PyQt6 is not installed.\n"
            "On Debian 13 (Trixie), please install it via apt:\n"
            "  sudo apt update && sudo apt install -y python3-pyqt6"
        )
        return 1
    except Exception as e:
        format_error(f"Failed to launch GUI: {e}")
        return 1


# ==============================================================================
# Command Handler: selftest
# ==============================================================================

def cmd_selftest(args: argparse.Namespace) -> int:
    """
    Executes a comprehensive, 100% offline self-test.
    Creates temporary folders and dummy .env files, tests both public-key and
    passphrase workflows, and verifies output byte-for-byte without modifying
    the user's real ~/.config/devpulse keys.
    """
    print("=" * 60)
    print(" Running DevPulse / SecretBridge Self-Test Suite...")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        alice_home = tmp_path / "alice_config"
        bob_home = tmp_path / "bob_config"
        work_dir = tmp_path / "workspace"
        work_dir.mkdir()

        # Step 1: Create dummy .env file
        dummy_env = work_dir / ".env.test"
        dummy_content = (
            b"# Dummy configuration for SecretBridge selftest\n"
            b"API_KEY=not-a-real-key-1234567890\n"
            b"DATABASE_URL=postgresql://dummy_user:dummy_pass@localhost:5432/testdb\n"
            b"JWT_SECRET=super_secret_local_test_key\n"
        )
        dummy_env.write_bytes(dummy_content)

        tests_passed = 0
        total_tests = 4

        # Test 1: Keygen for Alice and Bob
        print("\n[Test 1/4] Key Generation & Permissions Check...")
        try:
            alice_pub, alice_fp, _, _ = secret.generate_keypair("Alice", config_dir=alice_home)
            bob_pub, bob_fp, _, _ = secret.generate_keypair("Bob", config_dir=bob_home)

            assert (alice_home / "private.key").stat().st_mode & 0o777 == 0o600
            assert (alice_home).stat().st_mode & 0o777 == 0o700
            print(f"  Alice Fingerprint: {alice_fp}")
            print(f"  Bob Fingerprint  : {bob_fp}")
            print("  Result: PASS")
            tests_passed += 1
        except Exception as e:
            print(f"  Result: FAIL ({e})")

        # Test 2: Public-key SealedBox round-trip (Bob sends to Alice)
        print("\n[Test 2/4] Public-Key (SealedBox) Round-Trip...")
        try:
            payload = secret.build_payload(dummy_env, "Bob")
            parsed_alice_pub, _ = secret.parse_public_key_input(alice_pub)
            token = secret.encrypt_for_public_key(payload, parsed_alice_pub)

            assert token.startswith("DEVPULSE-v1:")
            # Alice decrypts
            decrypted_payload = secret.decrypt_message(token, config_dir=alice_home)
            out_file = work_dir / "alice_received.env"
            saved_path, content = secret.write_decrypted_file(decrypted_payload, out_path=out_file)

            assert content == dummy_content
            assert saved_path.stat().st_mode & 0o777 == 0o600
            print("  Decrypted content matches dummy .env exactly byte-for-byte.")
            print("  Result: PASS")
            tests_passed += 1
        except Exception as e:
            print(f"  Result: FAIL ({e})")

        # Test 3: Passphrase Scrypt + SecretBox round-trip
        print("\n[Test 3/4] Passphrase (Scrypt + SecretBox) Round-Trip...")
        try:
            test_pw = "correct-horse-battery-staple-42"
            payload = secret.build_payload(dummy_env, "Alice")
            p_token = secret.encrypt_with_passphrase(payload, test_pw)

            assert p_token.startswith("DEVPULSE-v1P:")
            # Decrypt with correct passphrase
            decrypted_p = secret.decrypt_message(p_token, passphrase=test_pw)
            out_pw_file = work_dir / "decrypted_pw.env"
            _, content_pw = secret.write_decrypted_file(decrypted_p, out_path=out_pw_file)
            assert content_pw == dummy_content

            # Verify that wrong passphrase fails cleanly
            wrong_failed = False
            try:
                secret.decrypt_message(p_token, passphrase="wrong-passphrase")
            except secret.DecryptionFailedError:
                wrong_failed = True

            assert wrong_failed, "Wrong passphrase did not raise DecryptionFailedError"
            print("  Correct passphrase succeeded; incorrect passphrase properly rejected.")
            print("  Result: PASS")
            tests_passed += 1
        except Exception as e:
            print(f"  Result: FAIL ({e})")

        # Test 4: Expired message rejection
        print("\n[Test 4/4] Expiration Safety Check...")
        try:
            # Build payload with negative expiration (already expired)
            payload_expired = secret.build_payload(dummy_env, "Alice", expires_hours=-1.0)
            exp_token = secret.encrypt_with_passphrase(payload_expired, "pw123")
            expired_rejected = False
            try:
                secret.decrypt_message(exp_token, passphrase="pw123")
            except secret.ExpiredMessageError:
                expired_rejected = True

            assert expired_rejected, "Expired message was not rejected"
            print("  Expired message was correctly intercepted and refused.")
            print("  Result: PASS")
            tests_passed += 1
        except Exception as e:
            print(f"  Result: FAIL ({e})")

    print("\n" + "=" * 60)
    if tests_passed == total_tests:
        print(f" SELF-TEST SUMMARY: ALL {total_tests}/{total_tests} TESTS PASSED [PASS]")
        print(" SecretBridge is fully functioning and verified offline.")
        print("=" * 60 + "\n")
        return 0
    else:
        print(f" SELF-TEST SUMMARY: {tests_passed}/{total_tests} TESTS PASSED [FAIL]")
        print("=" * 60 + "\n")
        return 1


# ==============================================================================
# CLI Argument Parser Setup
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser for DevPulse."""
    parser = argparse.ArgumentParser(
        prog="devpulse",
        description="DevPulse / SecretBridge: Encrypt and share .env files securely over chat."
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # 1. keygen
    parser_keygen = subparsers.add_parser("keygen", help="Generate a new Curve25519 keypair")
    parser_keygen.add_argument("--name", required=True, help="Your name or handle (e.g. Alice)")
    parser_keygen.add_argument("--force", action="store_true", help="Overwrite existing keys")
    parser_keygen.set_defaults(func=cmd_keygen)

    # 2. fingerprint
    parser_fp = subparsers.add_parser("fingerprint", help="Show public key fingerprint")
    parser_fp.add_argument("--key", help="Public key string or file to inspect (default: own key)")
    parser_fp.set_defaults(func=cmd_fingerprint)

    # 3. send
    parser_send = subparsers.add_parser("send", help="Encrypt a file for secure chat delivery")
    parser_send.add_argument("file", help="Path to the .env or config file to encrypt (max 64 KB)")
    send_mode = parser_send.add_mutually_exclusive_group(required=True)
    send_mode.add_argument("--to", help="Recipient's public key string or path to public.key file")
    send_mode.add_argument("--passphrase", action="store_true", help="Encrypt with a passphrase instead of a public key")
    parser_send.add_argument("--expires-hours", type=float, default=None, help="Set message expiration in hours")
    parser_send.set_defaults(func=cmd_send)

    # 4. open
    parser_open = subparsers.add_parser("open", help="Decrypt and view/save a received SecretBridge message")
    parser_open.add_argument("--text", help="The raw DEVPULSE-v1:... or DEVPULSE-v1P:... message string")
    parser_open.add_argument("--out", help="Custom destination filename (default: original filename)")
    parser_open.add_argument("--print", action="store_true", help="Display content in terminal instead of saving to file")
    parser_open.add_argument("--force", action="store_true", help="Overwrite existing file on disk")
    parser_open.set_defaults(func=cmd_open)

    # 5. selftest
    parser_selftest = subparsers.add_parser("selftest", help="Run automated offline cryptographic test suite")
    parser_selftest.set_defaults(func=cmd_selftest)

    # 6. focus
    parser_focus = subparsers.add_parser("focus", help="FocusPulse window activity and distraction tracker")
    focus_subparsers = parser_focus.add_subparsers(dest="focus_command", required=True, help="Focus subcommands")

    p_focus_start = focus_subparsers.add_parser("start", help="Start real-time window tracking and distraction alerts")
    p_focus_start.set_defaults(func=cmd_focus_start)

    p_focus_summary = focus_subparsers.add_parser("summary", help="Show today's focus metrics and top applications")
    p_focus_summary.set_defaults(func=cmd_focus_summary)

    p_focus_selftest = focus_subparsers.add_parser("selftest", help="Run offline unit tests for window classification rules")
    p_focus_selftest.set_defaults(func=cmd_focus_selftest)

    # 7. ergo
    parser_ergo = subparsers.add_parser("ergo", help="ErgoGuard ergonomic break, rest, and commit monitor")
    ergo_subparsers = parser_ergo.add_subparsers(dest="ergo_command", required=True, help="ErgoGuard subcommands")

    p_ergo_start = ergo_subparsers.add_parser("start", help="Start ergonomic break monitoring with idle detection")
    p_ergo_start.set_defaults(func=cmd_ergo_start)

    p_ergo_done = ergo_subparsers.add_parser("done", help="Acknowledge taking a break and reset break timers")
    p_ergo_done.set_defaults(func=cmd_ergo_done)

    p_ergo_status = ergo_subparsers.add_parser("status", help="Show today's break and rest event counts")
    p_ergo_status.set_defaults(func=cmd_ergo_status)

    p_ergo_selftest = ergo_subparsers.add_parser("selftest", help="Run offline unit tests for ergonomic break state logic")
    p_ergo_selftest.set_defaults(func=cmd_ergo_selftest)

    # 8. audit
    parser_audit = subparsers.add_parser("audit", help="AuditPulse privacy report, checksum verification, and test suite")
    parser_audit.add_argument("--out", default="audit_report.json", help="Output file path (default: audit_report.json)")
    parser_audit.add_argument("--since-days", type=int, default=7, help="Lookback period in days (default: 7)")
    parser_audit.add_argument("--verify", help="Verify the integrity SHA-256 checksum of an existing report file")
    parser_audit.add_argument("--selftest", action="store_true", help="Run automated isolated audit self-test suite")
    parser_audit.set_defaults(func=cmd_audit)

    # 9. gui
    parser_gui = subparsers.add_parser("gui", help="Launch the DevPulse PyQt6 desktop graphical interface")
    parser_gui.set_defaults(func=cmd_gui)

    return parser


def main() -> None:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        exit_code = args.func(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
