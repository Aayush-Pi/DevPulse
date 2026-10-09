"""
SecretBridge Cryptography and Business Logic Module (secret.py)
Part of DevPulse - An offline-first suite for developer workflows.

================================================================================
IMPORTANT ARCHITECTURAL & SECURITY LIMITATIONS:
1. EXPIRY IS A SOFT CLIENT-SIDE CHECK:
   The encrypted payload contains a timestamp. While an expired message will
   refuse to open in DevPulse, an attacker who obtains the ciphertext and the
   private key/passphrase could technically decrypt the raw payload and read
   the expired content with custom code. Expiry is an operational safety net,
   not an cryptographic self-destruct mechanism.
2. SENDER IS NOT AUTHENTICATED IN PUBLIC-KEY MODE:
   SealedBox uses an ephemeral Curve25519 keypair for encryption. The recipient
   can verify that only they can decrypt it, and that the message was not
   tampered with, but the sender's identity is NOT signed or authenticated.
   The sender_name in the payload is unverified metadata.
3. NOT A REPLACEMENT FOR A SECRETS VAULT:
   SecretBridge is intended for quick, safe peer-to-peer transmission of .env
   and config files across chat tools (Slack, Discord, WhatsApp). It is not a
   substitute for production secret management systems (like HashiCorp Vault,
   AWS Secrets Manager, or Google Secret Manager).
================================================================================
"""

from __future__ import annotations

import os
import sys
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any

# PyNaCl is the only crypto library used.
# On Debian 13: sudo apt install python3-nacl
try:
    import nacl.public
    import nacl.secret
    import nacl.pwhash.scrypt as nacl_scrypt
    import nacl.utils
    import nacl.exceptions
except ImportError:
    # Friendly notice if PyNaCl is not yet installed
    nacl = None
    nacl_scrypt = None


# Maximum supported file size is 64 KB (65,536 bytes)
MAX_FILE_SIZE_BYTES = 64 * 1024

# Message format prefixes
PUBKEY_PREFIX = "DEVPULSE-PUB-v1:"
CIPHERTEXT_PUBLIC_PREFIX = "DEVPULSE-v1:"
CIPHERTEXT_PASSPHRASE_PREFIX = "DEVPULSE-v1P:"


# ==============================================================================
# Custom Exceptions (Enables friendly, traceback-free error handling in CLI)
# ==============================================================================

class SecretBridgeError(Exception):
    """Base exception for all SecretBridge domain errors."""
    pass


class DependencyMissingError(SecretBridgeError):
    """Raised when python3-nacl is not installed."""
    pass


class KeyNotFoundError(SecretBridgeError):
    """Raised when expected key files do not exist."""
    pass


class KeyExistsError(SecretBridgeError):
    """Raised when keys already exist and --force was not specified."""
    pass


class FileSizeExceededError(SecretBridgeError):
    """Raised when an input file exceeds the 64 KB limit."""
    pass


class DecryptionFailedError(SecretBridgeError):
    """Raised when decryption fails due to wrong key, bad passphrase, or tampering."""
    pass


class ExpiredMessageError(SecretBridgeError):
    """Raised when a message's expiration time has passed."""
    pass


class InvalidMessageFormatError(SecretBridgeError):
    """Raised when a message cannot be decoded or parsed."""
    pass


# ==============================================================================
# Internal Helper Functions
# ==============================================================================

def _ensure_pynacl_available() -> None:
    """Verifies that PyNaCl is installed before running cryptographic routines."""
    if nacl is None or nacl_scrypt is None:
        raise DependencyMissingError(
            "PyNaCl library is missing.\n"
            "On Debian 13, please install it via apt:\n"
            "  sudo apt update && sudo apt install python3-nacl"
        )


def get_config_dir() -> Path:
    """
    Returns the path to the DevPulse configuration directory.
    Uses DEVPULSE_HOME environment variable if set, otherwise ~/.config/devpulse.
    This allows simulating multiple users (e.g. Alice and Bob) on one system.
    """
    env_override = os.environ.get("DEVPULSE_HOME")
    if env_override:
        return Path(env_override).expanduser().resolve()
    return Path("~/.config/devpulse").expanduser().resolve()


def compute_fingerprint(public_key_bytes: bytes) -> str:
    """
    Computes a human-readable 8-character fingerprint for a public key.
    Uses the first 8 hex characters of the SHA-256 hash of the public key bytes,
    formatted as XXXX-XXXX in uppercase (e.g., 'A1B2-C3D4').
    """
    full_hash = hashlib.sha256(public_key_bytes).hexdigest().upper()
    first_eight = full_hash[:8]
    return f"{first_eight[:4]}-{first_eight[4:8]}"


# ==============================================================================
# Key Management Functions
# ==============================================================================

def generate_keypair(
    name: str,
    force: bool = False,
    config_dir: Optional[Path] = None
) -> Tuple[str, str, Path, Path]:
    """
    Generates a new Curve25519 keypair for the user.
    - Creates the config folder with 700 permissions (user rwx only).
    - Saves the private key to private.key with 600 permissions (user rw only).
    - Saves the public key to public.key and sender info to config.json.
    - Refuses to overwrite existing keys unless force=True.
    Returns: (public_key_string, fingerprint, priv_path, pub_path).
    """
    _ensure_pynacl_available()

    target_dir = config_dir or get_config_dir()
    priv_path = target_dir / "private.key"
    pub_path = target_dir / "public.key"
    conf_path = target_dir / "config.json"

    # Enforce directory security
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target_dir, 0o700)
    except OSError:
        pass

    # Safety check against accidental key overwrites
    if priv_path.exists() and not force:
        raise KeyExistsError(
            f"Keys already exist in {target_dir}.\n"
            "Overwriting them means you will PERMANENTLY LOSE the ability to decrypt\n"
            "any past messages sent to your current public key.\n"
            "To overwrite anyway, re-run with --force."
        )

    # Generate new Curve25519 private key
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key

    # Save private key with strict 600 permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with open(os.open(priv_path, flags, 0o600), "wb") as f:
        f.write(bytes(private_key))

    # Save public key
    with open(os.open(pub_path, flags, 0o644), "wb") as f:
        f.write(bytes(public_key))

    # Save configuration profile
    with open(os.open(conf_path, flags, 0o600), "w", encoding="utf-8") as f:
        json.dump({"name": name.strip() or "Anonymous"}, f, indent=2)

    pub_b64 = base64.b64encode(bytes(public_key)).decode("ascii")
    pub_key_str = f"{PUBKEY_PREFIX}{pub_b64}"
    fingerprint = compute_fingerprint(bytes(public_key))

    return pub_key_str, fingerprint, priv_path, pub_path


def load_own_private_key(config_dir: Optional[Path] = None) -> nacl.public.PrivateKey:
    """
    Loads the user's private key from their configuration directory.
    Raises KeyNotFoundError if private.key is not found.
    """
    _ensure_pynacl_available()
    target_dir = config_dir or get_config_dir()
    priv_path = target_dir / "private.key"

    if not priv_path.exists():
        raise KeyNotFoundError(
            f"No private key found at {priv_path}.\n"
            "Please generate your keypair first using:\n"
            "  python3 devpulse.py keygen --name \"YourName\""
        )

    with open(priv_path, "rb") as f:
        raw = f.read()

    # Support raw 32 bytes or base64 encoded
    if len(raw) == 32:
        return nacl.public.PrivateKey(raw)
    else:
        try:
            decoded = base64.b64decode(raw.strip())
            return nacl.public.PrivateKey(decoded)
        except Exception:
            raise KeyNotFoundError(f"Private key file at {priv_path} is corrupted.")


def load_own_public_key(config_dir: Optional[Path] = None) -> Tuple[nacl.public.PublicKey, str]:
    """
    Loads the user's public key from their configuration directory.
    Returns: (PublicKey object, fingerprint string).
    """
    _ensure_pynacl_available()
    target_dir = config_dir or get_config_dir()
    pub_path = target_dir / "public.key"

    if not pub_path.exists():
        raise KeyNotFoundError(
            f"No public key found at {pub_path}.\n"
            "Please generate your keypair first using:\n"
            "  python3 devpulse.py keygen --name \"YourName\""
        )

    with open(pub_path, "rb") as f:
        raw = f.read().strip()

    if len(raw) == 32:
        pub_bytes = raw
    else:
        # Check if formatted string or base64
        text = raw.decode("utf-8", errors="ignore").strip()
        if text.startswith(PUBKEY_PREFIX):
            text = text[len(PUBKEY_PREFIX):]
        try:
            pub_bytes = base64.b64decode(text)
        except Exception:
            raise KeyNotFoundError(f"Public key file at {pub_path} is corrupted.")

    pub_key = nacl.public.PublicKey(pub_bytes)
    return pub_key, compute_fingerprint(pub_bytes)


def load_sender_name(config_dir: Optional[Path] = None) -> str:
    """Reads sender name from config.json, defaulting to 'Anonymous' if missing."""
    target_dir = config_dir or get_config_dir()
    conf_path = target_dir / "config.json"
    if conf_path.exists():
        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("name", "Anonymous")
        except Exception:
            return "Anonymous"
    return "Anonymous"


def parse_public_key_input(key_input: str) -> Tuple[nacl.public.PublicKey, str]:
    """
    Parses a public key from either:
    1. A file path pointing to a public key file, or
    2. A public key string starting with DEVPULSE-PUB-v1: or raw base64.
    Returns: (PublicKey object, fingerprint string).
    """
    _ensure_pynacl_available()
    cleaned = key_input.strip()

    # Check if key_input is a path to an existing file
    potential_file = Path(cleaned)
    if potential_file.is_file():
        try:
            with open(potential_file, "rb") as f:
                content = f.read().strip()
            if len(content) == 32:
                pub_bytes = content
            else:
                text = content.decode("utf-8", errors="ignore").strip()
                if text.startswith(PUBKEY_PREFIX):
                    text = text[len(PUBKEY_PREFIX):]
                pub_bytes = base64.b64decode(text)
        except Exception as e:
            raise InvalidMessageFormatError(f"Could not read public key file '{cleaned}': {e}")
    else:
        # Parse direct string input
        if cleaned.startswith(PUBKEY_PREFIX):
            cleaned = cleaned[len(PUBKEY_PREFIX):]
        try:
            pub_bytes = base64.b64decode(cleaned)
        except Exception:
            raise InvalidMessageFormatError(
                "Invalid public key format. Expected 'DEVPULSE-PUB-v1:<base64>' or a valid key file."
            )

    if len(pub_bytes) != 32:
        raise InvalidMessageFormatError(
            f"Invalid public key length ({len(pub_bytes)} bytes). Curve25519 requires exactly 32 bytes."
        )

    try:
        pub_key = nacl.public.PublicKey(pub_bytes)
        return pub_key, compute_fingerprint(pub_bytes)
    except Exception as e:
        raise InvalidMessageFormatError(f"Failed to load public key: {e}")


# ==============================================================================
# Payload Construction
# ==============================================================================

def build_payload(
    file_path: Path,
    sender_name: str,
    expires_hours: Optional[float] = None
) -> bytes:
    """
    Reads the target file and packages it into a structured JSON payload.
    - Rejects files larger than 64 KB.
    - Encodes file content in base64 to preserve exact binary/text bytes.
    - Records UTC created_at time and optional expires_at time.
    Returns: utf-8 encoded JSON bytes.
    """
    if not file_path.exists():
        raise SecretBridgeError(f"File not found: '{file_path}'")
    if not file_path.is_file():
        raise SecretBridgeError(f"Path is not a regular file: '{file_path}'")

    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileSizeExceededError(
            f"File '{file_path.name}' is {file_size / 1024:.1f} KB, which exceeds "
            f"the 64 KB limit ({MAX_FILE_SIZE_BYTES / 1024:.0f} KB).\n"
            "SecretBridge is designed for .env and configuration files."
        )

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    now_utc = datetime.now(timezone.utc)
    expires_utc_str = None
    if expires_hours is not None and expires_hours > 0:
        expires_dt = now_utc + timedelta(hours=expires_hours)
        expires_utc_str = expires_dt.isoformat()

    payload_data = {
        "version": 1,
        "filename": file_path.name,
        "file_content_b64": base64.b64encode(file_bytes).decode("ascii"),
        "created_at": now_utc.isoformat(),
        "expires_at": expires_utc_str,
        "sender_name": sender_name.strip() or "Anonymous"
    }

    return json.dumps(payload_data, separators=(",", ":")).encode("utf-8")


# ==============================================================================
# Encryption Functions
# ==============================================================================

def encrypt_for_public_key(
    payload_bytes: bytes,
    recipient_pubkey: nacl.public.PublicKey
) -> str:
    """
    Encrypts a payload for a recipient using nacl.public.SealedBox (Curve25519).
    SealedBox generates an ephemeral keypair under the hood, meaning only the
    recipient's private key can decrypt it, and no one else can read it.
    Returns: Single line 'DEVPULSE-v1:<urlsafe_base64>'.
    """
    _ensure_pynacl_available()
    sealed_box = nacl.public.SealedBox(recipient_pubkey)
    ciphertext = sealed_box.encrypt(payload_bytes)
    b64_cipher = base64.urlsafe_b64encode(ciphertext).decode("ascii")
    return f"{CIPHERTEXT_PUBLIC_PREFIX}{b64_cipher}"


def encrypt_with_passphrase(
    payload_bytes: bytes,
    passphrase: str
) -> str:
    """
    Encrypts a payload using symmetric cryptography (Passphrase mode):
    1. Generates a cryptographically secure random salt using nacl.utils.random.
    2. Derives a 256-bit key from the passphrase using nacl.pwhash.scrypt.
    3. Encrypts the payload with nacl.secret.SecretBox (XSalsa20-Poly1305).
    4. Packs the random salt and ciphertext together.
    Returns: Single line 'DEVPULSE-v1P:<urlsafe_base64>'.
    """
    _ensure_pynacl_available()
    if not passphrase:
        raise SecretBridgeError("Passphrase cannot be empty.")

    # Generate random salt
    salt = nacl.utils.random(nacl_scrypt.SALTBYTES)

    # Derive key via scrypt
    derived_key = nacl_scrypt.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=nacl_scrypt.OPSLIMIT_INTERACTIVE,
        memlimit=nacl_scrypt.MEMLIMIT_INTERACTIVE
    )

    # Encrypt using SecretBox
    secret_box = nacl.secret.SecretBox(derived_key)
    ciphertext_with_nonce = secret_box.encrypt(payload_bytes)

    # Combine salt (fixed length) + ciphertext_with_nonce
    combined = salt + bytes(ciphertext_with_nonce)
    b64_output = base64.urlsafe_b64encode(combined).decode("ascii")
    return f"{CIPHERTEXT_PASSPHRASE_PREFIX}{b64_output}"


# ==============================================================================
# Decryption and Verification Functions
# ==============================================================================

def decrypt_message(
    message_token: str,
    passphrase: Optional[str] = None,
    config_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Inspects the prefix of the message token and decrypts it:
    - DEVPULSE-v1: Decrypts using own private key with SealedBox.
    - DEVPULSE-v1P: Decrypts using passphrase via Scrypt + SecretBox.
    - Enforces soft-expiry check on UTC timestamp.
    Returns: Dict containing payload fields (filename, content, created_at, sender).
    """
    _ensure_pynacl_available()
    cleaned = message_token.strip()

    is_pubkey_mode = cleaned.startswith(CIPHERTEXT_PUBLIC_PREFIX)
    is_passphrase_mode = cleaned.startswith(CIPHERTEXT_PASSPHRASE_PREFIX)

    if not (is_pubkey_mode or is_passphrase_mode):
        raise InvalidMessageFormatError(
            "Unrecognized message prefix.\n"
            "Valid SecretBridge messages start with either:\n"
            f"  - '{CIPHERTEXT_PUBLIC_PREFIX}' (Public-key SealedBox)\n"
            f"  - '{CIPHERTEXT_PASSPHRASE_PREFIX}' (Passphrase SecretBox)"
        )

    if is_pubkey_mode:
        raw_b64 = cleaned[len(CIPHERTEXT_PUBLIC_PREFIX):]
        try:
            ciphertext = base64.urlsafe_b64decode(raw_b64)
        except Exception:
            raise InvalidMessageFormatError("Message data is corrupted (invalid base64 encoding).")

        priv_key = load_own_private_key(config_dir=config_dir)
        try:
            unseal_box = nacl.public.SealedBox(priv_key)
            plaintext_bytes = unseal_box.decrypt(ciphertext)
        except nacl.exceptions.CryptoError:
            raise DecryptionFailedError(
                "Decryption failed.\n"
                "This message was encrypted for a different public key, or the ciphertext was altered."
            )

    else:  # Passphrase mode
        if passphrase is None:
            raise SecretBridgeError("A passphrase is required to decrypt this message.")

        raw_b64 = cleaned[len(CIPHERTEXT_PASSPHRASE_PREFIX):]
        try:
            combined = base64.urlsafe_b64decode(raw_b64)
        except Exception:
            raise InvalidMessageFormatError("Message data is corrupted (invalid base64 encoding).")

        salt_len = nacl_scrypt.SALTBYTES
        if len(combined) <= salt_len:
            raise InvalidMessageFormatError("Message payload is incomplete or truncated.")

        salt = combined[:salt_len]
        ciphertext = combined[salt_len:]

        try:
            derived_key = nacl_scrypt.kdf(
                nacl.secret.SecretBox.KEY_SIZE,
                passphrase.encode("utf-8"),
                salt,
                opslimit=nacl_scrypt.OPSLIMIT_INTERACTIVE,
                memlimit=nacl_scrypt.MEMLIMIT_INTERACTIVE
            )
            secret_box = nacl.secret.SecretBox(derived_key)
            plaintext_bytes = secret_box.decrypt(ciphertext)
        except (nacl.exceptions.CryptoError, Exception):
            raise DecryptionFailedError(
                "Decryption failed. The passphrase entered is incorrect or the message was altered."
            )

    # Parse and validate JSON structure
    try:
        payload = json.loads(plaintext_bytes.decode("utf-8"))
    except Exception:
        raise InvalidMessageFormatError("Decrypted content could not be parsed as SecretBridge JSON payload.")

    # Check expiration date
    expires_at_str = payload.get("expires_at")
    if expires_at_str:
        try:
            expires_dt = datetime.fromisoformat(expires_at_str)
            now_utc = datetime.now(timezone.utc)
            if now_utc > expires_dt:
                diff = now_utc - expires_dt
                raise ExpiredMessageError(
                    f"This message expired on {expires_at_str} UTC (expired {diff.total_seconds() / 3600:.1f} hours ago).\n"
                    "By design, DevPulse will refuse to open expired messages."
                )
        except ExpiredMessageError:
            raise
        except Exception:
            # If date format is somehow malformed, proceed with caution
            pass

    return payload


def write_decrypted_file(
    payload: Dict[str, Any],
    out_path: Optional[Path] = None,
    force: bool = False
) -> Tuple[Path, bytes]:
    """
    Writes the decrypted file to disk with strict 600 permissions.
    - Uses original filename from payload unless overridden by out_path.
    - Refuses to overwrite existing files unless force=True.
    Returns: (resolved Path, raw file bytes).
    """
    raw_b64 = payload.get("file_content_b64", "")
    try:
        content_bytes = base64.b64decode(raw_b64)
    except Exception:
        raise InvalidMessageFormatError("Failed to decode base64 file content inside payload.")

    target_name = out_path if out_path else Path(payload.get("filename", "decrypted_secret.env"))
    target_path = Path(target_name).resolve()

    if target_path.exists() and not force:
        raise SecretBridgeError(
            f"Destination file '{target_path.name}' already exists.\n"
            "Use --force to overwrite it, or --out <filename> to save under a different name."
        )

    # Write file securely with 600 permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with open(os.open(target_path, flags, 0o600), "wb") as f:
        f.write(content_bytes)

    return target_path, content_bytes
def format_public_key(public_key) -> str:
    """Turn a public key into the shareable one-line DEVPULSE-PUB-v1:<base64> string."""
    return f"{PUBKEY_PREFIX}{base64.b64encode(bytes(public_key)).decode('ascii')}"
