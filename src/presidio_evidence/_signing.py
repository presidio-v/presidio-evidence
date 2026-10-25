"""Layer 1 — detached signatures over the signer-bound message (ADR-0001 D3).

The signed message is ``canonical_bytes({"content_hash": ..., "signer": ...})``
for ``evidence-ref@1``/``@2``; binding the signer identity into the message
blocks cross-signer replay. ``evidence-ref@3`` (ADR-0004) also binds the subject
and the tier: ``canonical_bytes({"assurance_tier", "content_hash", "framework",
"item_id", "signer"})``, see :func:`signing_message_v3`. Ed25519
(default) needs the optional ``cryptography`` dependency (``[crypto]`` extra);
HMAC-SHA256 (back-compat) uses only the stdlib. Verification is **fail-closed**:
any failure returns ``False``, never raises.
"""

from __future__ import annotations

import hashlib
import hmac

from ._canonical import canonical_bytes
from ._constants import ASSURANCE_TIERS, DEFAULT_ASSURANCE_TIER, SIGNING_ALGORITHMS
from ._errors import EvidenceError


def signing_message(content_hash: str, signer: str) -> bytes:
    """The canonical bytes a detached signature is computed over."""
    return canonical_bytes({"content_hash": content_hash, "signer": signer})


def signing_message_v3(
    content_hash: str,
    signer: str,
    framework: str,
    item_id: str,
    assurance_tier: str | None = None,
) -> bytes:
    """The ``evidence-ref@3`` message: subject- and tier-bound (ADR-0004 D2).

    ``assurance_tier`` is the resolved tier; ``None`` means the default
    (``"attested"``), exactly as an absent wire field does.
    """
    tier = DEFAULT_ASSURANCE_TIER if assurance_tier is None else assurance_tier
    if tier not in ASSURANCE_TIERS:
        raise EvidenceError(f"assurance_tier must be one of {ASSURANCE_TIERS}, got {tier!r}")
    return canonical_bytes(
        {
            "assurance_tier": tier,
            "content_hash": content_hash,
            "framework": framework,
            "item_id": item_id,
            "signer": signer,
        }
    )


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise EvidenceError(
            "Ed25519 needs the optional dependency: pip install 'presidio-evidence[crypto]'"
        ) from exc
    return ed25519


def _hmac_hex(message: bytes, key: str) -> str:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _ed25519_sign(message: bytes, private_key_hex: str) -> str:
    ed25519 = _require_crypto()
    try:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise EvidenceError(f"invalid Ed25519 private key: {exc}") from exc
    return sk.sign(message).hex()


def sign_message(message: bytes, *, key: str, alg: str = "ed25519") -> str:
    """Detached signature over prepared message bytes for ``alg``."""
    if alg == "ed25519":
        return _ed25519_sign(message, key)
    if alg == "hmac-sha256":
        return _hmac_hex(message, key)
    raise EvidenceError(f"unknown signing algorithm {alg!r}; expected one of {SIGNING_ALGORITHMS}")


def verify_message(message: bytes, signature: str, key: str, *, alg: str) -> bool:
    """Verify a detached signature over message bytes (fail-closed)."""
    if alg == "hmac-sha256":
        return hmac.compare_digest(_hmac_hex(message, key), signature)
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        pk.verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_hmac(content_hash: str, signer: str, key: str) -> str:
    """Detached HMAC-SHA256 signature (lowercase hex)."""
    return _hmac_hex(signing_message(content_hash, signer), key)


def sign_ed25519(content_hash: str, signer: str, private_key_hex: str) -> str:
    """Detached Ed25519 signature (lowercase hex). Deterministic (RFC 8032)."""
    return _ed25519_sign(signing_message(content_hash, signer), private_key_hex)


def sign_evidence(content_hash: str, signer: str, *, key: str, alg: str = "ed25519") -> str:
    """Sign the @1/@2 message for ``alg`` (``ed25519`` default, ``hmac-sha256`` stdlib)."""
    return sign_message(signing_message(content_hash, signer), key=key, alg=alg)


def sign_evidence_v3(
    content_hash: str,
    signer: str,
    framework: str,
    item_id: str,
    *,
    key: str,
    alg: str = "ed25519",
    assurance_tier: str | None = None,
) -> str:
    """Sign the subject-bound ``evidence-ref@3`` message (ADR-0004)."""
    message = signing_message_v3(content_hash, signer, framework, item_id, assurance_tier)
    return sign_message(message, key=key, alg=alg)


def verify_hmac(content_hash: str, signer: str, signature: str, key: str) -> bool:
    """Timing-safe HMAC-SHA256 verification (fail-closed)."""
    return verify_message(signing_message(content_hash, signer), signature, key, alg="hmac-sha256")


def verify_ed25519(content_hash: str, signer: str, signature: str, public_key_hex: str) -> bool:
    """Ed25519 verification (fail-closed: bad key/sig/hex returns ``False``)."""
    message = signing_message(content_hash, signer)
    return verify_message(message, signature, public_key_hex, alg="ed25519")
