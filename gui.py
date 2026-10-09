"""
DevPulse PyQt6 Graphical User Interface (gui.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
ARCHITECTURE & DESIGN PRINCIPLES:
1. THIN PRESENTATION LAYER:
   Contains ZERO cryptographic algorithms and ZERO tracking logic.
   Directly calls verified functions from secret.py and audit.py.
2. 100% OFFLINE & NATIVE QT:
   Uses standard PyQt6 widgets and default platform styling (Breeze on KDE).
   No QtWebEngine, no matplotlib, no custom CSS theming.
3. SANDBOXED CONSOLE PROCESS RUNNER:
   Executes ONLY devpulse.py subcommands via QProcess. Rejects any arbitrary
   shell commands to prevent shell injection or accidental commands.
4. WAYLAND RESILIENT:
   Supports both drag-and-drop and standard Qt file selection dialogs.
================================================================================
"""

import sys
import os
import shlex
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, List

# Check PyQt6 availability with friendly guidance
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
        QHBoxLayout, QSplitter, QTextEdit, QLineEdit, QPushButton,
        QLabel, QGroupBox, QFileDialog, QMessageBox, QDialog,
        QDialogButtonBox, QSpinBox, QRadioButton, QButtonGroup,
        QScrollArea, QFrame
    )
    from PyQt6.QtCore import Qt, QProcess, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent
except ImportError:
    print(
        "\n[DevPulse Error] PyQt6 is not installed.\n"
        "On Debian 13 (Trixie), please install it via apt:\n"
        "  sudo apt update && sudo apt install -y python3-pyqt6\n",
        file=sys.stderr
    )
    sys.exit(1)

# Import existing core modules (NO crypto or tracking logic re-implemented here)
import secret
import audit


# Subcommands permitted in the integrated console
ALLOWED_SUBCOMMANDS = {
    "keygen", "fingerprint", "send", "open", "selftest", "focus", "ergo", "audit", "gui"
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def mask_env_content(raw_text: str) -> str:
    """
    Masks secret values in a .env file while keeping variable names and comments visible.
    Example:
      DATABASE_URL=postgres://user:pass@localhost:5432/db -> DATABASE_URL=****
      # Production Config -> # Production Config
    """
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


# ==============================================================================
# Passphrase Entry Modal Dialog
# ==============================================================================

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


# ==============================================================================
# Wayland-Compatible File Drop Zone
# ==============================================================================

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
# SecretBridge Tab
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

        # Main horizontal splitter: Left side (Tool), Right side (Help)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        main_layout.addWidget(splitter)

        # ----------------------------------------------------------------------
        # Left Side: The Cryptography Tool
        # ----------------------------------------------------------------------
        left_widget = QWidget(self)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(4, 4, 4, 4)

        # Top Section: My Key Area
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

        # Mode Selector: SEND vs OPEN
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

        # Stacked / Conditional Area Container
        self.send_container = QWidget(self)
        self.init_send_ui(self.send_container)
        left_layout.addWidget(self.send_container)

        self.open_container = QWidget(self)
        self.init_open_ui(self.open_container)
        self.open_container.hide()
        left_layout.addWidget(self.open_container)

        left_layout.addStretch()
        splitter.addWidget(left_widget)

        # ----------------------------------------------------------------------
        # Right Side: Interactive Help Panel
        # ----------------------------------------------------------------------
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

    # --------------------------------------------------------------------------
    # SEND UI Builder
    # --------------------------------------------------------------------------
    def init_send_ui(self, container: QWidget) -> None:
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # File Selection & Sample Generator
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

        # Masked Preview
        file_layout.addWidget(QLabel("Masked Preview (Variable names visible, values hidden):", self))
        self.preview_edit = QTextEdit(self)
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setFixedHeight(90)
        self.preview_edit.setFont(QFont("Monospace", 9))
        file_layout.addWidget(self.preview_edit)

        layout.addWidget(file_group)

        # Encryption Settings
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

        # Public key recipient field
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

        # Expiry options
        expiry_layout = QHBoxLayout()
        expiry_layout.addWidget(QLabel("Expires in (hours, 0 = none):", self))
        self.expiry_spin = QSpinBox(self)
        self.expiry_spin.setRange(0, 720)
        self.expiry_spin.setValue(0)
        expiry_layout.addWidget(self.expiry_spin)
        expiry_layout.addStretch()
        enc_layout.addLayout(expiry_layout)

        layout.addWidget(enc_group)

        # Encrypt Action & Token Output
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

    # --------------------------------------------------------------------------
    # OPEN UI Builder
    # --------------------------------------------------------------------------
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

    # --------------------------------------------------------------------------
    # Event Handlers & Core Interactions
    # --------------------------------------------------------------------------
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
                # Passphrase mode
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
                # Public-key mode
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

    # --------------------------------------------------------------------------
    # Right-Side Guide Text
    # --------------------------------------------------------------------------
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
# Placeholder Tab Builder
# ==============================================================================

def create_placeholder_tab(title: str, subtitle: str) -> QWidget:
    """Builds a placeholder view for tabs scheduled for Round 2."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    lbl_title = QLabel(title, widget)
    lbl_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #555;")
    layout.addWidget(lbl_title)

    lbl_sub = QLabel(f"Coming in Round 2\n\n{subtitle}", widget)
    lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl_sub.setStyleSheet("font-size: 13px; color: #777; margin-top: 10px;")
    layout.addWidget(lbl_sub)

    return widget


# ==============================================================================
# Main DevPulse Application Window
# ==============================================================================

class MainWindow(QMainWindow):
    """Main DevPulse desktop window hosting the 4 tabs and bottom console dock."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DevPulse")
        self.resize(1020, 760)

        # Main splitter (Top: Tabs, Bottom: Collapsible Console)
        main_splitter = QSplitter(Qt.Orientation.Vertical, self)
        self.setCentralWidget(main_splitter)

        # ----------------------------------------------------------------------
        # Top Panel: 4-Tab Widget
        # ----------------------------------------------------------------------
        self.tabs = QTabWidget(self)

        # Tab 1: Dashboard (Placeholder)
        self.tabs.addTab(
            create_placeholder_tab("Dashboard", "System health overview and daily developer productivity indicators."),
            "Dashboard"
        )

        # Tab 2: SecretBridge (Fully Built)
        self.secretbridge_tab = SecretBridgeTab(self.log_console, self)
        self.tabs.addTab(self.secretbridge_tab, "SecretBridge")

        # Tab 3: FocusPulse (Placeholder)
        self.tabs.addTab(
            create_placeholder_tab("FocusPulse", "Active window tracker and distraction classifier for KDE Wayland."),
            "FocusPulse"
        )

        # Tab 4: ErgoGuard (Placeholder)
        self.tabs.addTab(
            create_placeholder_tab("ErgoGuard", "Idle detector, natural rest pauses, and Git commit break triggers."),
            "ErgoGuard"
        )

        # Default to SecretBridge tab
        self.tabs.setCurrentIndex(1)
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

        # Set splitter proportions (75% top tabs, 25% console)
        main_splitter.setStretchFactor(0, 75)
        main_splitter.setStretchFactor(1, 25)

        self.active_process: Optional[QProcess] = None
        self.log_console("DevPulse GUI ready. Using offline modules.")

    # --------------------------------------------------------------------------
    # Console & Process Execution Engine
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

        # Strip redundant command prefixes if user typed them
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

    def run_devpulse(self, args: List[str]) -> bool:
        """
        Reusable function to execute devpulse.py with arguments and stream output live.
        Other tabs can call this later to run background trackers or status commands.
        """
        if self.active_process and self.active_process.state() == QProcess.ProcessState.Running:
            self.log_console("Terminating previous process...")
            self.active_process.terminate()
            self.active_process.waitForFinished(1000)

        devpulse_script = Path(__file__).parent / "devpulse.py"
        if not devpulse_script.is_file():
            self.log_console(f"Error: Could not locate devpulse.py at {devpulse_script}")
            return False

        self.log_console(f"$ devpulse {' '.join(args)}")

        self.active_process = QProcess(self)
        self.active_process.setProgram(sys.executable)
        self.active_process.setArguments([str(devpulse_script), *args])

        self.active_process.readyReadStandardOutput.connect(self._on_stdout_ready)
        self.active_process.readyReadStandardError.connect(self._on_stderr_ready)
        self.active_process.finished.connect(self._on_process_finished)

        self.active_process.start()
        return True

    def _on_stdout_ready(self) -> None:
        if self.active_process:
            data = self.active_process.readAllStandardOutput().data().decode("utf-8", errors="replace")
            self.console_output.insertPlainText(data)
            self.console_output.ensureCursorVisible()

    def _on_stderr_ready(self) -> None:
        if self.active_process:
            data = self.active_process.readAllStandardError().data().decode("utf-8", errors="replace")
            self.console_output.insertPlainText(data)
            self.console_output.ensureCursorVisible()

    def _on_process_finished(self, exit_code: int) -> None:
        self.log_console(f"Process finished with exit code {exit_code}\n")


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
