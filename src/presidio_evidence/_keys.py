"""Key material helpers (ADR-0001 D3): generation and fail-closed loading.

Keys are 32-byte raw Ed25519, hex-encoded (64 lowercase chars). Private keys
load from a file whose mode is enforced to ``0600`` (no group/other bits) or
from an environment variable — never from the repo, never logged. This module
never emits key material in an exception message or anywhere else; the caller
receives the hex string and nothing more. Key custody stays out-of-band
(the operator holds production keys): there is no key storage here, only
generation and loading.

Ed25519 needs the optional ``cryptography`` dependency (``[crypto]`` extra).
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from ._errors import EvidenceError
from ._signing import _require_crypto

_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
#: Upper bound on bytes read from a key file: a 64-char hex key plus generous
#: whitespace. Anything larger is not a raw Ed25519 key and is refused unread.
_MAX_KEY_FILE_BYTES = 256
#: The only permission bits a private-key file may carry (owner read/write).
#: ``0600`` and the stricter ``0400`` pass; any group/other or execute bit fails.
_ALLOWED_MODE_BITS = 0o600


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return ``(private_key_hex, public_key_hex)`` for a fresh Ed25519 key.

    Both are 64-char lowercase hex of the raw 32-byte keys — the format every
    producer and the ``trust-store@1`` schema use. Custody is the caller's.
    """
    ed25519 = _require_crypto()
    from cryptography.hazmat.primitives import serialization

    sk = ed25519.Ed25519PrivateKey.generate()
    private_hex = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    return private_hex, public_key_hex(private_hex)


def public_key_hex(private_key_hex: str) -> str:
    """Derive the 64-char hex public key from a hex Ed25519 private key.

    This is what goes into a trust store; rotation = append it to the signer's
    ``public_key`` list (ADR-0001 D3). A malformed private key raises
    :class:`EvidenceError` without echoing the input.
    """
    ed25519 = _require_crypto()
    from cryptography.hazmat.primitives import serialization

    try:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise EvidenceError("invalid Ed25519 private key (expected 32 raw bytes as hex)") from exc
    return (
        sk.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def _normalise_key_hex(raw: str, origin: str) -> str:
    """Trim, lowercase, and validate the 64-hex shape. Never echoes ``raw``."""
    key = raw.strip().lower()
    if not _KEY_HEX_RE.match(key):
        raise EvidenceError(f"{origin}: expected a 64-char hex Ed25519 private key")
    return key


def _read_key_file(path: Path) -> str:
    """Open-then-fstat (no TOCTOU window): regular file, mode ⊆ 0600, bounded read."""
    if os.name != "posix":  # pragma: no cover - mode bits are meaningless elsewhere
        raise EvidenceError(
            "private-key file mode enforcement needs a POSIX filesystem; "
            "load the key from an environment variable instead"
        )
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise EvidenceError(f"private-key file {path}: {exc.strerror or 'cannot open'}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EvidenceError(f"private-key file {path}: not a regular file")
        if stat.S_IMODE(st.st_mode) & ~_ALLOWED_MODE_BITS:
            raise EvidenceError(
                f"private-key file {path}: mode {stat.S_IMODE(st.st_mode):04o} is too permissive "
                "(require 0600: owner read/write only)"
            )
        if st.st_size > _MAX_KEY_FILE_BYTES:
            raise EvidenceError(f"private-key file {path}: too large to be a raw Ed25519 key")
        data = os.read(fd, _MAX_KEY_FILE_BYTES)
    finally:
        os.close(fd)
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"private-key file {path}: not ASCII hex") from exc


def load_private_key(path: str | os.PathLike[str] | None = None, *, env: str | None = None) -> str:
    """Load a hex Ed25519 private key from a ``0600`` file or an env var (D3).

    Exactly one source must be given. ``path`` is opened and checked via
    ``fstat`` (regular file, no group/other permission bits, bounded size);
    ``env`` names an environment variable holding the hex. Whitespace is
    trimmed and hex is lowercased; anything that is not a 64-char hex string
    is rejected. Error messages name the source, never the material.
    """
    if (path is None) == (env is None):
        raise EvidenceError("load_private_key: give exactly one of path= or env=")
    if path is not None:
        p = Path(path)
        return _normalise_key_hex(_read_key_file(p), f"private-key file {p}")
    value = os.environ.get(env)  # type: ignore[arg-type]
    if value is None:
        raise EvidenceError(f"environment variable {env} is not set")
    return _normalise_key_hex(value, f"environment variable {env}")


def write_private_key(path: str | os.PathLike[str], private_key_hex: str) -> None:
    """Write ``private_key_hex`` to a new file created with mode ``0600``.

    Refuses to overwrite (``O_EXCL``) so a key is never silently replaced; the
    mode is set at creation, never widened afterwards. Validates the hex shape
    first so a malformed value is never persisted.
    """
    key = _normalise_key_hex(private_key_hex, "private key")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise EvidenceError(f"cannot create private-key file {path}: {exc.strerror}") from exc
    try:
        os.write(fd, (key + "\n").encode("ascii"))
    finally:
        os.close(fd)
