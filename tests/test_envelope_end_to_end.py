"""End-to-end: the valid envelope vector verifies from content to signature."""

from __future__ import annotations

import hashlib

from conftest import VECTORS, canonical_bytes, load_json
from cryptography.hazmat.primitives.asymmetric import ed25519

ENVELOPE = load_json(VECTORS / "evidence-ref" / "valid-envelope.json")
NOTES = load_json(VECTORS / "evidence-ref" / "valid-envelope.notes.json")


def test_content_hash_recomputes_from_signed_content():
    encoded = canonical_bytes(NOTES["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == NOTES["expected_content_hash"]
    assert ENVELOPE["evidence"][0]["content_hash"] == NOTES["expected_content_hash"]


def test_envelope_signature_verifies_against_trust_store():
    ref = ENVELOPE["evidence"][0]
    entry = NOTES["trust_store"][ref["signer"]]
    assert entry["alg"] == "ed25519"
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)  # raises on failure


def test_signer_binding_blocks_cross_signer_replay():
    """The signer id is inside the signed message — a replayed signature under a
    different signer identity must not verify, even with the right public key."""
    import pytest
    from cryptography.exceptions import InvalidSignature

    ref = ENVELOPE["evidence"][0]
    entry = NOTES["trust_store"][ref["signer"]]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    forged = canonical_bytes({"content_hash": ref["content_hash"], "signer": "evil-signer"})
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(ref["signature"]), forged)
