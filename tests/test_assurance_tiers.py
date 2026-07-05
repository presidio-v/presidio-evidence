"""Conformance for evidence-ref@2 assurance tiers (ADR-0003, Accepted).

The verifier accepts @1 and @2 and fails closed on anything else; the tier is
exposed to consumers with the "attested" default; and — critically — declaring
a tier does NOT change what is signed (still canonical({content_hash, signer})).
Covers the new @2 golden vectors under vectors/evidence-ref-v2/.
"""

from __future__ import annotations

import hashlib

import pytest
from conftest import VECTORS, canonical_bytes, load_json
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_evidence import (
    ASSURANCE_TIERS,
    DEFAULT_ASSURANCE_TIER,
    EVIDENCE_REF_SCHEMA_ID,
    EVIDENCE_REF_SCHEMA_ID_V2,
    EVIDENCE_REF_SCHEMA_IDS,
    EvidenceError,
    EvidenceRef,
    build_envelope,
    load_trust_store,
    parse_document,
    verify_ref,
)

V2 = VECTORS / "evidence-ref-v2"


def _load(name: str) -> dict:
    return load_json(V2 / name)


# ── constants ────────────────────────────────────────────────────────────────


def test_tier_constants() -> None:
    assert ASSURANCE_TIERS == ("attested", "optimistic", "zk")
    assert DEFAULT_ASSURANCE_TIER == "attested"
    assert EVIDENCE_REF_SCHEMA_ID_V2 == "presidio-hardened/evidence-ref@2"
    assert EVIDENCE_REF_SCHEMA_IDS == (EVIDENCE_REF_SCHEMA_ID, EVIDENCE_REF_SCHEMA_ID_V2)


# ── valid-tiers: one ref per explicit tier ───────────────────────────────────


def test_v2_explicit_tiers_parse_and_expose() -> None:
    doc = _load("valid-tiers.json")
    assert doc["schema"] == EVIDENCE_REF_SCHEMA_ID_V2
    refs = parse_document(doc)
    tiers = [r.assurance_tier for r in refs]
    assert tiers == ["attested", "optimistic", "zk"]
    # `tier` mirrors the declared value when present.
    assert [r.tier for r in refs] == ["attested", "optimistic", "zk"]


def test_v2_tier_is_not_part_of_the_signed_message() -> None:
    """Signature unchanged: it covers canonical({content_hash, signer}) only, so
    every explicit-tier ref (and the @1 golden) verifies with the same key."""
    doc = _load("valid-tiers.json")
    notes = _load("valid-tiers.notes.json")
    # content_hash still recomputes from the signed content.
    encoded = canonical_bytes(notes["signed_content"])
    assert hashlib.sha256(encoded).hexdigest() == notes["expected_content_hash"]
    trust = load_trust_store(notes["trust_store"])
    for ref in parse_document(doc):
        assert ref.content_hash == notes["expected_content_hash"]
        assert verify_ref(ref, trust) is True
    # The signed message is tier-independent by construction.
    signer = doc["evidence"][0]["signer"]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(notes["verifies_with_public_key_hex"])
    )
    message = canonical_bytes({"content_hash": notes["expected_content_hash"], "signer": signer})
    for ref in doc["evidence"]:
        pk.verify(bytes.fromhex(ref["signature"]), message)
    assert notes["tier_default_when_absent"] == DEFAULT_ASSURANCE_TIER


# ── valid-tier-absent: the default ───────────────────────────────────────────


def test_v2_absent_tier_resolves_to_attested() -> None:
    doc = _load("valid-tier-absent.json")
    notes = _load("valid-tier-absent.notes.json")
    (ref,) = parse_document(doc)
    assert ref.assurance_tier is None  # absent on the wire
    assert ref.tier == "attested"  # resolved default
    assert notes["resolved_assurance_tier"] == DEFAULT_ASSURANCE_TIER
    trust = load_trust_store(notes["trust_store"])
    assert verify_ref(ref, trust) is True


# ── invalid @2 documents fail closed ─────────────────────────────────────────


def test_v2_unknown_tier_rejected() -> None:
    doc = _load("invalid-unknown-tier.json")["document"]
    with pytest.raises(EvidenceError, match="assurance_tier"):
        parse_document(doc)


def test_v2_wrong_schema_id_rejected() -> None:
    # A schema id outside {@1, @2} is rejected fail-closed (ADR-0001 D4/D5).
    doc = dict(_load("valid-tier-absent.json"), schema="presidio-hardened/evidence-ref@3")
    with pytest.raises(EvidenceError, match="unsupported evidence schema"):
        parse_document(doc)


# ── extra-field finding: @1 tolerates assurance_tier ─────────────────────────


def test_v1_record_with_tier_is_tolerated_and_reads_as_attested() -> None:
    """ADR-0003 extra-field finding: @1 has no additionalProperties:false and the
    verifier ignores unknown keys, so an @1 ref carrying assurance_tier parses
    (extra field is not an @1-freeze violation). The field is inert unless the
    envelope declares @2, so @1 policy still reads the default."""
    doc = _load("valid-v1-with-extra-tier.json")
    assert doc["schema"] == EVIDENCE_REF_SCHEMA_ID
    (ref,) = parse_document(doc)
    # Option 1 / founder decision: @2 is the contract boundary. A tier attached
    # to @1 is tolerated as an extra field but is inert, so policy sees attested.
    assert ref.assurance_tier is None
    assert ref.tier == "attested"


def test_schema_absent_record_with_tier_is_tolerated_and_reads_as_attested() -> None:
    doc = _load("valid-v1-with-extra-tier.json")
    del doc["schema"]
    (ref,) = parse_document(doc)
    assert ref.assurance_tier is None
    assert ref.tier == DEFAULT_ASSURANCE_TIER


# ── EvidenceRef / build_envelope round-trip ──────────────────────────────────


def _ref(**overrides: str) -> EvidenceRef:
    base = dict(
        item_id="D1",
        source="s",
        source_version="v",
        ledger_ref="l",
        content_hash="abc123def456",
        signer="sig",
        signature="abc123def456",
        claimed_at="2026-01-01T00:00:00+00:00",
    )
    base.update(overrides)
    return EvidenceRef(**base)


def test_evidence_ref_default_tier_and_to_dict_omits_absent() -> None:
    ref = _ref()
    assert ref.assurance_tier is None
    assert ref.tier == "attested"
    # An undeclared tier is NOT emitted — @1 envelopes stay byte-identical.
    assert "assurance_tier" not in ref.to_dict()


def test_evidence_ref_declared_tier_round_trips() -> None:
    ref = _ref(assurance_tier="zk")
    assert ref.tier == "zk"
    assert ref.to_dict()["assurance_tier"] == "zk"


def test_build_envelope_v2_emits_schema_and_tier() -> None:
    env = build_envelope([_ref(assurance_tier="optimistic")], schema=EVIDENCE_REF_SCHEMA_ID_V2)
    assert env["schema"] == EVIDENCE_REF_SCHEMA_ID_V2
    assert env["evidence"][0]["assurance_tier"] == "optimistic"
    # Parses back to an equivalent tier.
    (parsed,) = parse_document(env)
    assert parsed.tier == "optimistic"


def test_build_envelope_defaults_to_v1() -> None:
    env = build_envelope([_ref()])
    assert env["schema"] == EVIDENCE_REF_SCHEMA_ID
    assert "assurance_tier" not in env["evidence"][0]


def test_build_envelope_rejects_unknown_schema() -> None:
    with pytest.raises(EvidenceError, match="unsupported evidence schema"):
        build_envelope([_ref()], schema="presidio-hardened/evidence-ref@9")


@pytest.mark.parametrize(
    "field,value",
    [
        ("use_case", ""),
        ("source", "x\x00y"),
        ("source_version", "x" * 513),
        ("generated_at", 123),
    ],
)
def test_parse_document_rejects_malformed_envelope_metadata(field: str, value: object) -> None:
    doc = _load("valid-tier-absent.json")
    doc[field] = value
    with pytest.raises(EvidenceError, match=f"evidence envelope field '{field}'"):
        parse_document(doc)
