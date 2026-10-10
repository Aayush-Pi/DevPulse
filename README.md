# DevPulse
# DevPulse

**One offline Linux tool for three developer problems: leaking secrets in chat, losing focus, and ignoring breaks.**

> Status: **v0.1.0-alpha**. Built for a college ideathon. Tested on Debian 13 (trixie), KDE Plasma 6.3, Wayland only. Tested on Windows and Mac OS - only SecretBridge and audit-report works on systems other than kde plasma wayland.

## What it does

| Module | What it solves | How |
|---|---|---|
| **SecretBridge** | `.env` keys pasted into Discord/Slack stay in chat history forever | Encrypts files locally (PyNaCl SealedBox or passphrase) into one pasteable line |
| **FocusPulse** | Context switching, with no cloud tracker | Reads the active window locally, classifies focus/distraction/neutral, stores only app class + category |
| **ErgoGuard** | Break popups that interrupt mid-sentence | 20-20-20 style reminders that wait for a natural pause in typing |
| **Audit report** | Compliance without a cloud | Local `audit_report.json` with counts only, plus a SHA-256 integrity check |

No network calls. No telemetry. No window titles, keystrokes, file contents or keys are stored.

## Install (Debian 13, KDE Plasma Wayland)

```
sudo apt install python3-nacl python3-yaml python3-pyqt6 swayidle libnotify-bin
git clone https://github.com/[you]/devpulse.git
cd devpulse
```

FocusPulse needs [kdotool](https://github.com/jinliu/kdotool) for window detection on Wayland. It is not in Debian's repos and needs a newer Rust than trixie ships:

```
sudo apt install rustup pkg-config libdbus-1-dev
rustup default stable
cargo install kdotool
```

## Quick start

```
python3 devpulse.py gui                 # desktop app (tray icon + console)
python3 devpulse.py keygen --name You   # create your keypair
python3 devpulse.py send --to <their public key> .env
python3 devpulse.py open                # paste a DEVPULSE-v1:... message
python3 devpulse.py focus start
python3 devpulse.py ergo start
python3 devpulse.py audit
python3 devpulse.py selftest            # also: focus selftest, ergo selftest, audit --selftest
```

## How SecretBridge shares keys

Each person runs `keygen` once and shares their **public** key (safe to post anywhere). You encrypt to their public key; only their private key can open it. Compare the 8-character fingerprint on a call to rule out a swapped key.

## Known limitations (alpha)

- **Expiry is a soft check.** Anyone with the ciphertext and the key could bypass it in custom code.
- **Sender is not authenticated.** The sender name inside a message is unverified.
- **Not a secrets vault.** Not a replacement for Vault, `sops` or 1Password for production.
- **ErgoGuard is not posture detection.** It is an idle-aware break reminder.
- **Linux only**: KDE Plasma on Wayland. X11, GNOME and Windows are untested.
- The audit checksum detects accidental edits, not a determined attacker.
- Window-switch counts include browser tab changes.

## Project layout

`devpulse.py` CLI · `secret.py` · `focus.py` · `ergo.py` · `audit.py` · `gui.py`

## Config and data

Everything lives in `~/.config/devpulse/` (keys with 600 permissions, `focus.yaml`, `ergo.yaml`, SQLite databases).

## License

AGPL-3.0. See `LICENSE`.
