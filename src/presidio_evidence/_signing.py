"""Layer 1 — detached signatures over the signer-bound message (ADR-0001 D3).

The signed message is ``canonical_bytes({"content_hash": ..., "signer": ...})``;
binding the signer identity into the message blocks cross-signer replay. Ed25519
(default) needs the optional ``cryptography`` dependency (``[crypto]`` extra);
HMAC-SHA256 (back-compat) uses only the stdlib. Verification is **fail-closed**:
any failure returns ``False``, never raises.
"""

from __future__ import annotations

import hashlib
import hmac

from ._canonical import canonical_bytes
from ._constants import SIGNING_ALGORITHMS
from ._errors import EvidenceError


def signing_message(content_hash: str, signer: str) -> bytes:
    """The canonical bytes a detached signature is computed over."""
    return canonical_bytes({"content_hash": content_hash, "signer": signer})


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise EvidenceError(
            "Ed25519 needs the optional dependency: pip install 'presidio-evidence[crypto]'"
        ) from exc
    return ed25519


def sign_hmac(content_hash: str, signer: str, key: str) -> str:
    """Detached HMAC-SHA256 signature (lowercase hex)."""
    return hmac.new(
        key.encode("utf-8"), signing_message(content_hash, signer), hashlib.sha256
    ).hexdigest()


def sign_ed25519(content_hash: str, signer: str, private_key_hex: str) -> str:
    """Detached Ed25519 signature (lowercase hex). Deterministic (RFC 8032)."""
    ed25519 = _require_crypto()
    try:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise EvidenceError(f"invalid Ed25519 private key: {exc}") from exc
    return sk.sign(signing_message(content_hash, signer)).hex()


def sign_evidence(content_hash: str, signer: str, *, key: str, alg: str = "ed25519") -> str:
    """Sign for ``alg`` (``ed25519`` default, ``hmac-sha256`` stdlib fallback)."""
    if alg == "ed25519":
        return sign_ed25519(content_hash, signer, key)
    if alg == "hmac-sha256":
        return sign_hmac(content_hash, signer, key)
    raise EvidenceError(f"unknown signing algorithm {alg!r}; expected one of {SIGNING_ALGORITHMS}")


def verify_hmac(content_hash: str, signer: str, signature: str, key: str) -> bool:
    """Timing-safe HMAC-SHA256 verification (fail-closed)."""
    return hmac.compare_digest(sign_hmac(content_hash, signer, key), signature)


def verify_ed25519(content_hash: str, signer: str, signature: str, public_key_hex: str) -> bool:
    """Ed25519 verification (fail-closed: bad key/sig/hex returns ``False``)."""
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature), signing_message(content_hash, signer))
        return True
    except (InvalidSignature, ValueError):
        return False
