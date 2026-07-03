"""Conformance for the consumer-coverage vectors (2026-07-03 arc).

One golden vector per consumer surface that previously had none:

- ``workshop-leavebehind/`` — ikigov-assess T-B4: an OWNER-signed manifest.
  Pins two profiles: the manifest's canonical sha256 (the value a
  ``workshop-attestation@1`` ``attests`` references — the ADR-0002 DAG edge
  target) and the owner signature over the RAW canonical manifest bytes
  (the manifest.sig profile, deliberately not the family
  ``{content_hash, signer}`` message).
- ``slo-reading/`` — x402: a ``slo-reading@1`` Layer-0 degradation reading
  signed into an ``evidence-ref@1`` envelope (the pat → bridge → SLO payment
  broker chain).
- ``treasury-checkpoint/`` — treasury: Layer 0 ONLY (ADR-0001 D1), checkpoint
  identity as content addressing over the canonical envelope (nulls, i64
  nanosecond timestamps, no signature by design).
"""

from __future__ import annotations

import hashlib

import pytest
from conftest import VECTORS, canonical_bytes, load_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# ── workshop-leavebehind (ikigov T-B4) ────────────────────────────────────────


def _leavebehind() -> tuple[dict, dict]:
    manifest = load_json(VECTORS / "workshop-leavebehind/valid-manifest.json")
    notes = load_json(VECTORS / "workshop-leavebehind/valid-manifest.notes.json")
    return manifest, notes


def test_leavebehind_manifest_hash_is_the_dag_edge_target() -> None:
    manifest, notes = _leavebehind()
    encoded = canonical_bytes(manifest)
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    assert notes["attestation_would_attest"] == notes["expected_content_hash"]


def test_leavebehind_owner_signature_over_raw_manifest_bytes() -> None:
    manifest, notes = _leavebehind()
    # Owner pubkey lives INSIDE the signed content (owner-consistency check).
    assert manifest["owner"]["public_key"] == notes["verifies_with_public_key_hex"]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(notes["verifies_with_public_key_hex"])
    )
    pk.verify(bytes.fromhex(notes["owner_signature"]), canonical_bytes(manifest))

    # Deterministic Ed25519: the customer test fixture reproduces the signature.
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(notes["customer_private_key_hex_test_fixture"])
    )
    assert sk.sign(canonical_bytes(manifest)).hex() == notes["owner_signature"]


def test_leavebehind_tamper_fails_closed() -> None:
    manifest, notes = _leavebehind()
    pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(notes["verifies_with_public_key_hex"])
    )
    tampered = dict(manifest)
    tampered["risk_class"] = "low"
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(notes["owner_signature"]), canonical_bytes(tampered))


def test_leavebehind_owner_block_is_additive_within_at1() -> None:
    manifest, _ = _leavebehind()
    # T-B3 required fields all present (no removals, no type changes — D5);
    # `owner` is the additive optional block.
    for field in (
        "schema",
        "tool",
        "tool_version",
        "use_case_id",
        "cell",
        "risk_class",
        "lang",
        "generated_at",
        "pack",
        "artifacts",
        "signed",
        "UNSIGNED",
    ):
        assert field in manifest, field
    assert manifest["schema"] == "presidio-hardened/workshop-leavebehind@1"
    assert manifest["signed"] is True and manifest["UNSIGNED"] is False


# ── slo-reading (x402 SLO payment broker) ────────────────────────────────────


def _slo() -> tuple[dict, dict]:
    envelope = load_json(VECTORS / "slo-reading/valid-envelope.json")
    notes = load_json(VECTORS / "slo-reading/valid-envelope.notes.json")
    return envelope, notes


def test_slo_content_hash_recomputes_and_binds_envelope() -> None:
    envelope, notes = _slo()
    encoded = canonical_bytes(notes["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    assert envelope["evidence"][0]["content_hash"] == notes["expected_content_hash"]
    reading = notes["layer0_reading"]
    assert reading["attested_content"] == notes["signed_content"]
    assert reading["schema"] == "presidio-hardened/slo-reading@1"


def test_slo_degradation_semantics() -> None:
    _, notes = _slo()
    content = notes["signed_content"]
    assert content["value"] > content["threshold"]
    assert notes["degraded"] is True


def test_slo_signature_verifies_and_replay_fails() -> None:
    envelope, notes = _slo()
    ref = envelope["evidence"][0]
    entry = notes["trust_store"][ref["signer"]]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)
    # Cross-signer replay fails closed.
    replayed = canonical_bytes({"content_hash": ref["content_hash"], "signer": "not-the-signer"})
    with pytest.raises(InvalidSignature):
        pk.verify(bytes.fromhex(ref["signature"]), replayed)


def test_slo_ref_matches_arch_translucency_producer_contract() -> None:
    envelope, _ = _slo()
    ref = envelope["evidence"][0]
    # Pinned to arch-translucency build_slo_evidence output (byte-identity
    # cross-checked against the producer at vector creation).
    assert ref["item_id"] == "SLO-DEGRADED"
    assert ref["ledger_ref"] == "arch-translucency:obs"
    assert ref["signer"] == "presidio-hardened-arch-translucency"


# ── treasury-checkpoint (Layer 0 only) ───────────────────────────────────────


def _checkpoint() -> tuple[dict, dict]:
    envelope = load_json(VECTORS / "treasury-checkpoint/valid-checkpoint.json")
    notes = load_json(VECTORS / "treasury-checkpoint/valid-checkpoint.notes.json")
    return envelope, notes


def test_checkpoint_id_is_content_address_of_canonical_envelope() -> None:
    envelope, notes = _checkpoint()
    encoded = canonical_bytes(envelope)
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_checkpoint_id"]


def test_checkpoint_is_layer_zero_only_by_design() -> None:
    envelope, notes = _checkpoint()
    assert notes["layer"] == 0
    assert notes["signature"] is None
    # Null-valued optionals are part of the addressed content.
    for optional in ("supersedes", "reason", "materiality_memo"):
        assert optional in envelope and envelope[optional] is None
    # Nanosecond timestamps stay within i64 (Rust serde_json compatibility).
    assert 0 < envelope["as_of"] < 2**63
    assert 0 < envelope["sealed_at"] < 2**63


def test_checkpoint_floats_rejected_by_strict_profile() -> None:
    envelope, _ = _checkpoint()
    bad = dict(envelope)
    bad["as_of"] = 1.5
    with pytest.raises(ValueError, match="floats are not permitted"):
        canonical_bytes(bad)
