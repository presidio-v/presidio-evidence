"""Conformance for ADR-0006: gate-certificate@1 identity and schema registration.

The identity of a gate certificate is sha256 over canonical-json@1 of the
document minus ``signature`` -- the bytes the issuer signs. The vector under
``vectors/gate-certificate/`` was cross-checked at creation against
ikigov-assess v0.28.0 (``signing_bytes``, ``build_certificate``,
``verify_certificate``); these tests pin it from this side.
"""

from __future__ import annotations

import copy
import hashlib

import pytest
from conftest import SCHEMAS, VECTORS, canonical_bytes, load_json
from cryptography.hazmat.primitives.asymmetric import ed25519
from jsonschema import Draft202012Validator

from presidio_evidence import (
    GATE_CERTIFICATE_SCHEMA_ID,
    EvidenceError,
    gate_certificate_identity,
    gate_certificate_signing_bytes,
    signing_message,
)

KIND = VECTORS / "gate-certificate"
CERT = load_json(KIND / "valid-certificate.json")
NOTES = load_json(KIND / "valid-certificate.notes.json")
CHILD = load_json(KIND / "child-training-run.json")
CHILD_NOTES = load_json(KIND / "child-training-run.notes.json")

#: The identity hash pinned by this vector (ADR-0006).
GOLDEN_IDENTITY = "dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a"


def _pub(signer: str) -> ed25519.Ed25519PublicKey:
    entry = NOTES["trust_store"][signer]
    assert entry["alg"] == "ed25519"
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))


def test_identity_is_sha256_of_the_signed_bytes() -> None:
    signed = gate_certificate_signing_bytes(CERT)
    assert signed.decode("utf-8") == NOTES["signing_bytes_canonical"]
    assert hashlib.sha256(signed).hexdigest() == NOTES["identity"] == GOLDEN_IDENTITY
    assert gate_certificate_identity(CERT) == GOLDEN_IDENTITY


def test_identity_does_not_depend_on_the_signature() -> None:
    unsigned = {k: v for k, v in CERT.items() if k != "signature"}
    assert gate_certificate_identity(unsigned) == GOLDEN_IDENTITY
    resigned = dict(CERT, signature={"alg": "hmac-sha256", "signer": "x", "sig": "00" * 32})
    assert gate_certificate_identity(resigned) == GOLDEN_IDENTITY


def test_issuer_signature_verifies_over_the_identity_bytes() -> None:
    sig = CERT["signature"]
    assert sig["signer"] == CERT["issuer"]
    _pub(sig["signer"]).verify(bytes.fromhex(sig["sig"]), gate_certificate_signing_bytes(CERT))


def test_embedded_refs_verify_and_bind_one_item_each() -> None:
    seen: set[tuple[str, str]] = set()
    for entry in CERT["affirmation_set"]:
        ref = entry["evidence_ref"]
        assert ref["item_id"] == entry["id"]
        key = (ref["signer"], ref["content_hash"])
        assert key not in seen, "one ref, one item (ikigov GHSA-376h-xg26-xf2j)"
        seen.add(key)
        message = signing_message(ref["content_hash"], ref["signer"])
        _pub(ref["signer"]).verify(bytes.fromhex(ref["signature"]), message)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("decision", "BLOCKED"),
        ("assessed_at", "2026-07-02T00:00:01Z"),
        ("issuer", "someone-else"),
        ("not_after", "2028-07-02T00:00:00Z"),
    ],
)
def test_any_change_to_the_issuance_changes_the_identity(field: str, value: str) -> None:
    assert gate_certificate_identity(dict(CERT, **{field: value})) != GOLDEN_IDENTITY


def test_identity_is_not_the_predicate_hash() -> None:
    """Two issuances under one rule share framework_content_hash and nothing
    else: the predicate hash names the rule, the identity names the decision."""
    assert CERT["framework_content_hash"] == NOTES["predicate_content_hash"]
    assert GOLDEN_IDENTITY != CERT["framework_content_hash"]
    other = copy.deepcopy(CERT)
    other["affirmation_set"][0]["status"] = "skipped"
    assert other["framework_content_hash"] == CERT["framework_content_hash"]
    assert gate_certificate_identity(other) != GOLDEN_IDENTITY


def test_training_run_parent_is_the_certificate_identity() -> None:
    """The ADR-0002 edge from a training run to the gate decision that admitted it."""
    content = CHILD_NOTES["signed_content"]
    assert content["parents"][0] == GOLDEN_IDENTITY
    assert CHILD_NOTES["parent_certificate_identity"] == GOLDEN_IDENTITY
    ch = hashlib.sha256(canonical_bytes(content)).hexdigest()
    ref = CHILD["evidence"][0]
    assert ch == CHILD_NOTES["expected_content_hash"] == ref["content_hash"]
    pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(CHILD_NOTES["trust_store"][ref["signer"]]["public_key"])
    )
    pk.verify(bytes.fromhex(ref["signature"]), signing_message(ref["content_hash"], ref["signer"]))


@pytest.mark.parametrize(
    "bad",
    [
        ["not", "a", "mapping"],
        {"schema": "presidio-hardened/evidence-ref@1"},
        {"decision": "OPEN"},
        {"schema": GATE_CERTIFICATE_SCHEMA_ID, "score": 1.5},
        {"schema": GATE_CERTIFICATE_SCHEMA_ID, "blob": object()},
    ],
    ids=["non-mapping", "foreign-schema", "no-schema", "float", "unencodable"],
)
def test_identity_fails_closed(bad: object) -> None:
    with pytest.raises(EvidenceError):
        gate_certificate_identity(bad)  # type: ignore[arg-type]


# ── schema registration (ADR-0006) ──────────────────────────────────────────


@pytest.fixture(scope="module")
def certificate_schema() -> dict:
    schema = load_json(SCHEMAS / "gate-certificate.v1.schema.json")
    Draft202012Validator.check_schema(schema)
    return schema


@pytest.fixture(scope="module")
def training_run_schema() -> dict:
    schema = load_json(SCHEMAS / "training-run.v1.schema.json")
    Draft202012Validator.check_schema(schema)
    return schema


def test_certificate_vector_matches_schema(certificate_schema: dict) -> None:
    Draft202012Validator(certificate_schema).validate(CERT)
    assert certificate_schema["properties"]["schema"]["const"] == GATE_CERTIFICATE_SCHEMA_ID


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("signature"),
        lambda d: d.update(decision="MAYBE"),
        lambda d: d.update(assurance_tier="zk"),
        lambda d: d.update(parents=[]),
        lambda d: d.update(not_after="2027-07-02T00:00:00+00:00"),
        lambda d: d["affirmation_set"][0]["evidence_ref"].update(content_hash="ABCDEF12"),
        lambda d: d["predicate"].pop("strict"),
    ],
    ids=[
        "unsigned",
        "unknown-decision",
        "non-attested-tier",
        "empty-parents",
        "non-z-instant",
        "uppercase-hex",
        "predicate-incomplete",
    ],
)
def test_certificate_schema_rejects(certificate_schema: dict, mutate) -> None:
    doc = copy.deepcopy(CERT)
    mutate(doc)
    assert list(Draft202012Validator(certificate_schema).iter_errors(doc))


@pytest.mark.parametrize(
    "path",
    [
        VECTORS / "training-run" / "valid-envelope.notes.json",
        VECTORS / "training-run" / "valid-envelope-energy.notes.json",
        KIND / "child-training-run.notes.json",
    ],
    ids=lambda p: f"{p.parent.name}/{p.stem}",
)
def test_training_run_vectors_match_schema(training_run_schema: dict, path) -> None:
    reading = load_json(path)["layer0_reading"]
    Draft202012Validator(training_run_schema).validate(reading)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("degree", 0),
        ("strategy", "magic"),
        ("duration_s", 7200.5),
        ("energy_wh", "840"),
        ("energy_wh", 840),
        ("run_id", "bad\nid"),
        ("run_id", "   "),
        ("parents", []),
    ],
)
def test_training_run_schema_rejects(training_run_schema: dict, field: str, value) -> None:
    reading = copy.deepcopy(
        load_json(VECTORS / "training-run" / "valid-envelope-energy.notes.json")["layer0_reading"]
    )
    reading["attested_content"][field] = value
    assert list(Draft202012Validator(training_run_schema).iter_errors(reading))


def test_training_run_schema_accepts_the_ieee_exponent_form(training_run_schema: dict) -> None:
    """The grandfathered energy form includes repr's exponent spelling."""
    reading = copy.deepcopy(
        load_json(VECTORS / "training-run" / "valid-envelope-energy.notes.json")["layer0_reading"]
    )
    reading["attested_content"]["energy_wh"] = "1e-05"
    Draft202012Validator(training_run_schema).validate(reading)
