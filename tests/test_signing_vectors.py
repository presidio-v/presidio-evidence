"""Layer-1 conformance: golden signatures reproduce; tamper cases fail closed."""

from __future__ import annotations

import hashlib
import hmac as hmaclib

from conftest import VECTORS, canonical_bytes, load_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

ED = load_json(VECTORS / "signing" / "ed25519-golden.json")
HM = load_json(VECTORS / "signing" / "hmac-sha256-golden.json")


def _message(content_hash: str, signer: str) -> bytes:
    return canonical_bytes({"content_hash": content_hash, "signer": signer})


def _verify_ed25519(content_hash, signer, signature_hex, public_key_hex) -> bool:
    """Reference fail-closed verifier: any failure is False, never an exception."""
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), _message(content_hash, signer))
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify_hmac(content_hash, signer, signature_hex, key) -> bool:
    expected = hmaclib.new(key.encode(), _message(content_hash, signer), hashlib.sha256)
    return hmaclib.compare_digest(expected.hexdigest(), signature_hex)


def test_ed25519_public_key_derives_from_private():
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ED["private_key_hex"]))
    assert sk.public_key().public_bytes_raw().hex() == ED["public_key_hex"]


def test_ed25519_golden_signature_reproduces():
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ED["private_key_hex"]))
    msg = _message(ED["content_hash"], ED["signer"])
    assert msg.decode("utf-8") == ED["message_canonical"]
    assert sk.sign(msg).hex() == ED["signature_hex"]  # Ed25519 is deterministic (RFC 8032)


def test_ed25519_golden_signature_verifies():
    assert _verify_ed25519(
        ED["content_hash"], ED["signer"], ED["signature_hex"], ED["public_key_hex"]
    )


def test_ed25519_tamper_cases_fail_closed():
    for case in ED["tamper_cases"]:
        verified = _verify_ed25519(
            case["content_hash"], case["signer"], case["signature_hex"], case["public_key_hex"]
        )
        assert verified is case["verifies"] is False, case["reason"]


def test_hmac_golden_signature_reproduces():
    msg = _message(HM["content_hash"], HM["signer"])
    sig = hmaclib.new(HM["key"].encode(), msg, hashlib.sha256).hexdigest()
    assert sig == HM["signature_hex"]


def test_hmac_tamper_cases_fail_closed():
    for case in HM["tamper_cases"]:
        verified = _verify_hmac(
            case["content_hash"], case["signer"], case["signature_hex"], case["key"]
        )
        assert verified is case["verifies"] is False, case["reason"]
