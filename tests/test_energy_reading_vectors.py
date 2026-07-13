"""Conformance for the reserved presidio-hardened/energy-reading@1 Layer-0 type.

Reservation for the pat Energy Arc v0.24.0 "Sign the watt" (arch-translucency
PRESIDIO-REQ L-EN-4): a key-less energy reading wrapped in the frozen
evidence-ref@1 envelope. Two golden vectors — one nominal (no parents) and one
carrying the ADR-0002 DAG edge onto the training-run payload.

Beyond the usual hash/signature checks this pins the two properties that make an
energy reading auditable rather than merely present:

* joules and watts cross the wire as decimal STRINGS, never floats (ADR-0001 D1),
  and the two figures agree with the window they describe; and
* ``energy_chain_head`` — the head of pat's chained energy_observations store
  (pat ADR-0011 §2) — is inside the signed content, so a reading attests the
  unrewritten history behind it.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from decimal import Decimal

import pytest
from conftest import VECTORS, canonical_bytes, load_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

KIND = "energy-reading"
NOMINAL = "valid-envelope"
PARENTS = "valid-envelope-parents"
SCHEMA_ID = "presidio-hardened/energy-reading@1"
HEX = "0123456789abcdef"


def _load(stem: str) -> tuple[dict, dict]:
    envelope = load_json(VECTORS / KIND / f"{stem}.json")
    notes = load_json(VECTORS / KIND / f"{stem}.notes.json")
    return envelope, notes


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_content_hash_recomputes_from_signed_content(stem: str) -> None:
    envelope, notes = _load(stem)
    encoded = canonical_bytes(notes["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    assert envelope["evidence"][0]["content_hash"] == notes["expected_content_hash"]
    reading = notes["layer0_reading"]
    assert reading["schema"] == SCHEMA_ID
    assert reading["attested_content"] == notes["signed_content"]
    assert reading["content_hash"] == notes["expected_content_hash"]


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_envelope_signature_verifies_against_trust_store(stem: str) -> None:
    envelope, notes = _load(stem)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    assert entry["alg"] == "ed25519"
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)  # raises on failure


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_signer_binding_blocks_cross_signer_replay(stem: str) -> None:
    envelope, notes = _load(stem)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    forged = canonical_bytes({"content_hash": ref["content_hash"], "signer": "evil-signer"})
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(ref["signature"]), forged)


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_energy_quantities_are_decimal_strings_not_floats(stem: str) -> None:
    """ADR-0001 D1: the canonical profile rejects floats, so joules and watts
    travel as shortest-round-trip decimal strings. A bare float here would make
    the payload uncanonicalizable — and therefore unhashable — family-wide."""
    _, notes = _load(stem)
    content = notes["signed_content"]
    for field in ("energy_wh", "mean_power_w"):
        value = content[field]
        assert isinstance(value, str), f"{field} must be a string, got {type(value).__name__}"
        assert Decimal(value) > 0
        assert repr(float(value)) == value, f"{field} must be shortest round-trip"
    # The whole payload is float-free, so it canonicalizes at all.
    canonical_bytes(content)


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_mean_power_agrees_with_energy_over_the_window(stem: str) -> None:
    """The reading is internally consistent: mean_power_w == energy_wh / hours.
    A reading whose watts contradict its own joules is not evidence of anything."""
    _, notes = _load(stem)
    content = notes["signed_content"]
    start = datetime.fromisoformat(content["window_start"])
    end = datetime.fromisoformat(content["window_end"])
    seconds = Decimal((end - start).total_seconds())
    assert seconds == Decimal(notes["window_seconds"])
    hours = seconds / Decimal(3600)
    assert Decimal(content["mean_power_w"]) == Decimal(content["energy_wh"]) / hours


@pytest.mark.parametrize("stem", [NOMINAL, PARENTS])
def test_energy_chain_head_is_inside_the_signed_content(stem: str) -> None:
    """pat ADR-0011 §2 / the ADR-0010 anchoring deferral: the head of the chained
    energy_observations store is part of what gets signed, so a signed reading
    attests the unrewritten history behind it. The family pins only the hex
    discipline — the chain itself is pat's to walk."""
    _, notes = _load(stem)
    head = notes["signed_content"]["energy_chain_head"]
    assert len(head) == 64
    assert all(c in HEX for c in head)
    assert notes["energy_chain_head"] == head


def test_nominal_vector_omits_parents() -> None:
    """ADR-0002 P3: parents is omitted when empty, never emitted as []."""
    _, notes = _load(NOMINAL)
    assert "parents" not in notes["signed_content"]
    assert notes["parents_present"] is False


def test_parents_vector_points_at_the_training_run_payload() -> None:
    """The energy-axis DAG edge (ADR-0002): the reading names the training-run
    payload as its parent — 'these are the joules that run cost'. Lineage is
    inside the hashed content, so rewiring it breaks the hash and the signature."""
    _, tr_notes = _load_training_run()
    _, notes = _load(PARENTS)
    training_ch = tr_notes["expected_content_hash"]
    content = notes["signed_content"]
    assert content["parents"] == [training_ch]
    assert notes["parent_content_hash"] == training_ch
    for parent in content["parents"]:
        assert 8 <= len(parent) <= 128
        assert all(c in HEX for c in parent)
    # The edge is coherent: the window covers the run, and the layer is its strategy.
    tr_content = tr_notes["signed_content"]
    assert notes["window_seconds"] == tr_content["duration_s"]
    assert content["layer"] == tr_content["strategy"]


def _load_training_run() -> tuple[dict, dict]:
    envelope = load_json(VECTORS / "training-run" / "valid-envelope.json")
    notes = load_json(VECTORS / "training-run" / "valid-envelope.notes.json")
    return envelope, notes
