"""Conformance for the v0.23 energy-bearing presidio-hardened/training-run@1 vector.

``vectors/training-run/valid-envelope-energy`` is the family reference for the
optional ``energy_wh`` / ``mean_power_w`` fields (arch-translucency v0.23.0).
Beyond the usual hash/signature checks this pins the two properties that make the
optional fields safe:

* they are **additive & conditional** — a record without them re-hashes
  byte-identically to ``valid-envelope`` (ADR-0011), so the pre-v0.23 vector is
  untouched; and
* joules/watts cross the wire as decimal STRINGS (ADR-0001 D1) and agree with
  ``duration_s`` (840 Wh over 2 h == 420 W), so contradictory signable evidence
  cannot exist.

The expected content hash is byte-for-byte the value pat pins locally in
arch-translucency ``test_training.py::test_training_run_energy_bearing_self_pin``
— the L-EV-7 cross-repo contract.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal

import pytest
from conftest import VECTORS, canonical_bytes, load_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

KIND = "training-run"
ENERGY = "valid-envelope-energy"
NO_ENERGY = "valid-envelope"
SCHEMA_ID = "presidio-hardened/training-run@1"
HEX = "0123456789abcdef"

#: The cross-repo contract value: arch-translucency's local self-pin for this
#: exact content (test_training.py::test_training_run_energy_bearing_self_pin).
PAT_SELF_PIN = "d674a11562def33ba92b54ab946d7782b1d3a111ec6a8f8f22a541788a57ffb0"


def _load(stem: str) -> tuple[dict, dict]:
    envelope = load_json(VECTORS / KIND / f"{stem}.json")
    notes = load_json(VECTORS / KIND / f"{stem}.notes.json")
    return envelope, notes


def test_content_hash_recomputes_and_matches_pat_self_pin() -> None:
    envelope, notes = _load(ENERGY)
    encoded = canonical_bytes(notes["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    assert envelope["evidence"][0]["content_hash"] == notes["expected_content_hash"]
    reading = notes["layer0_reading"]
    assert reading["schema"] == SCHEMA_ID
    assert reading["attested_content"] == notes["signed_content"]
    assert reading["content_hash"] == notes["expected_content_hash"]
    # L-EV-7: this family vector IS pat's self-pin, byte for byte.
    assert notes["expected_content_hash"] == PAT_SELF_PIN


def test_envelope_signature_verifies_against_trust_store() -> None:
    envelope, notes = _load(ENERGY)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    assert entry["alg"] == "ed25519"
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)  # raises on failure


def test_signer_binding_blocks_cross_signer_replay() -> None:
    envelope, notes = _load(ENERGY)
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    forged = canonical_bytes({"content_hash": ref["content_hash"], "signer": "evil-signer"})
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(ref["signature"]), forged)


def test_energy_quantities_are_decimal_strings_not_floats() -> None:
    """ADR-0001 D1: joules and watts are shortest-round-trip decimal strings; a
    bare float would make the payload uncanonicalizable and therefore unhashable."""
    _, notes = _load(ENERGY)
    content = notes["signed_content"]
    for field in ("energy_wh", "mean_power_w"):
        value = content[field]
        assert isinstance(value, str), f"{field} must be a string, got {type(value).__name__}"
        assert Decimal(value) > 0
        assert repr(float(value)) == value, f"{field} must be shortest round-trip"
    canonical_bytes(content)  # float-free, so it canonicalizes at all


def test_mean_power_agrees_with_energy_over_the_duration() -> None:
    """mean_power_w == energy_wh / (duration_s / 3600). A training-run's energy
    claim that contradicts its own duration is not evidence of anything."""
    _, notes = _load(ENERGY)
    content = notes["signed_content"]
    hours = Decimal(content["duration_s"]) / Decimal(3600)
    assert Decimal(content["mean_power_w"]) == Decimal(content["energy_wh"]) / hours


def test_energy_fields_are_additive_over_the_no_energy_vector() -> None:
    """ADR-0011: the optional fields are the ONLY difference from valid-envelope.
    Strip them and the payload re-hashes byte-identically to the pre-v0.23 vector,
    so adding energy left that published vector untouched."""
    _, energy_notes = _load(ENERGY)
    _, base_notes = _load(NO_ENERGY)
    stripped = {
        k: v
        for k, v in energy_notes["signed_content"].items()
        if k not in ("energy_wh", "mean_power_w")
    }
    assert stripped == base_notes["signed_content"]
    stripped_hash = hashlib.sha256(canonical_bytes(stripped)).hexdigest()
    assert stripped_hash == base_notes["expected_content_hash"]
    assert stripped_hash == energy_notes["no_energy_content_hash"]


def test_parents_preserved_inside_the_signed_content() -> None:
    """The energy fields are additive to a parents-bearing payload; lineage stays
    inside the hashed content (ADR-0002)."""
    _, notes = _load(ENERGY)
    parents = notes["signed_content"]["parents"]
    assert isinstance(parents, list) and parents
    for parent in parents:
        assert 8 <= len(parent) <= 128
        assert all(c in HEX for c in parent)
