"""Conformance for the ADR-0002 parents convention and ikigov T-B4.

Two append-only golden vectors, each a parents-bearing payload wrapped in the
frozen evidence-ref@1 envelope: a presidio-hardened/training-run@1 Layer-0
record and the presidio-hardened/workshop-attestation@1 schema freeze. Beyond
the usual content-hash/signature checks, this pins the provenance DAG edge —
the attestation's ``attests``/``parents`` point at the training-run payload.
"""

from __future__ import annotations

import hashlib

import pytest
from conftest import VECTORS, canonical_bytes, load_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

TRAINING = "training-run"
ATTESTATION = "workshop-attestation"


def _load(kind: str) -> tuple[dict, dict]:
    envelope = load_json(VECTORS / kind / "valid-envelope.json")
    notes = load_json(VECTORS / kind / "valid-envelope.notes.json")
    return envelope, notes


@pytest.mark.parametrize("kind", [TRAINING, ATTESTATION])
def test_content_hash_recomputes_from_signed_content(kind: str) -> None:
    envelope, notes = _load(kind)
    encoded = canonical_bytes(notes["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    assert envelope["evidence"][0]["content_hash"] == notes["expected_content_hash"]
    # The Layer-0 producer record binds the same content and hash.
    reading = notes["layer0_reading"]
    assert reading["attested_content"] == notes["signed_content"]
    assert reading["content_hash"] == notes["expected_content_hash"]


@pytest.mark.parametrize("kind", [TRAINING, ATTESTATION])
def test_envelope_signature_verifies_against_trust_store(kind: str) -> None:
    envelope, notes = _load(kind)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    assert entry["alg"] == "ed25519"
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)  # raises on failure


@pytest.mark.parametrize("kind", [TRAINING, ATTESTATION])
def test_signer_binding_blocks_cross_signer_replay(kind: str) -> None:
    envelope, notes = _load(kind)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    forged = canonical_bytes({"content_hash": ref["content_hash"], "signer": "evil-signer"})
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(ref["signature"]), forged)


@pytest.mark.parametrize("kind", [TRAINING, ATTESTATION])
def test_parents_live_inside_the_signed_content(kind: str) -> None:
    """ADR-0002 P1/P2: parents are inside the hashed content and follow the
    family lowercase-hex discipline; rewiring them would break the hash."""
    _, notes = _load(kind)
    parents = notes["signed_content"]["parents"]
    assert isinstance(parents, list) and parents  # non-empty when present (P3)
    for parent in parents:
        assert 8 <= len(parent) <= 128
        assert all(c in "0123456789abcdef" for c in parent)


def test_attestation_parents_point_at_training_run_payload() -> None:
    """The provenance DAG edge (ADR-0002 / L-EV-6): the workshop attestation
    attests, and lists as its parent, the exact content hash of the
    training-run payload."""
    _, tr_notes = _load(TRAINING)
    _, wa_notes = _load(ATTESTATION)
    training_ch = tr_notes["expected_content_hash"]
    attested = wa_notes["signed_content"]
    assert attested["attests"] == training_ch
    assert attested["parents"] == [training_ch]
    assert wa_notes["attests_parent_content_hash"] == training_ch
