"""evidence-ref@3 (ADR-0004): the signature binds the subject and the tier.

Every vector's expectations live in ``vectors/evidence-ref-v3/expectations.json``
so the Rust lane asserts the same table.
"""

from __future__ import annotations

import json

import pytest
from conftest import SCHEMAS, VECTORS, load_json
from jsonschema import Draft202012Validator

from presidio_evidence import (
    EVIDENCE_REF_SCHEMA_ID,
    EVIDENCE_REF_SCHEMA_ID_V2,
    EVIDENCE_REF_SCHEMA_ID_V3,
    EvidenceError,
    build_envelope,
    content_hash,
    load_trust_store,
    parse_document,
    reused_refs,
    sign_evidence_v3,
    signing_message_v3,
    verify_envelope,
    verify_ref,
)
from presidio_evidence._cli import main

V3 = VECTORS / "evidence-ref-v3"
EXPECT = load_json(V3 / "expectations.json")
TRUST = load_trust_store(EXPECT["trust_store"])
FRAMEWORK = EXPECT["expected_framework"]
SCHEMA_FILES = {
    EVIDENCE_REF_SCHEMA_ID: "evidence-ref.v1.schema.json",
    EVIDENCE_REF_SCHEMA_ID_V2: "evidence-ref.v2.schema.json",
    EVIDENCE_REF_SCHEMA_ID_V3: "evidence-ref.v3.schema.json",
}


def _validator(doc: dict) -> Draft202012Validator:
    schema_id = doc.get("schema", EVIDENCE_REF_SCHEMA_ID)
    return Draft202012Validator(load_json(SCHEMAS / SCHEMA_FILES[schema_id]))


def test_expectations_cover_every_envelope_vector():
    on_disk = {p.name for p in V3.glob("*.json") if p.name.startswith(("valid-", "tampered-"))}
    assert on_disk == set(EXPECT["files"])


def test_v3_schema_is_valid():
    Draft202012Validator.check_schema(load_json(SCHEMAS / "evidence-ref.v3.schema.json"))


@pytest.mark.parametrize("name", sorted(EXPECT["files"]))
def test_envelope_vectors_are_schema_valid(name):
    doc = load_json(V3 / name)
    _validator(doc).validate(doc)


@pytest.mark.parametrize("path", sorted(V3.glob("invalid-*.json")), ids=lambda p: p.stem)
def test_invalid_vectors_fail_schema_and_parser(path):
    doc = load_json(path)["document"]
    assert list(_validator(doc).iter_errors(doc))
    with pytest.raises(EvidenceError, match="framework"):
        parse_document(doc)


@pytest.mark.parametrize("name", sorted(EXPECT["files"]))
def test_vector_expectations(name):
    doc = load_json(V3 / name)
    rows = EXPECT["files"][name]
    refs = parse_document(doc)
    results = verify_envelope(doc, TRUST)
    assert len(refs) == len(rows) == len(results)
    for ref, row, result in zip(refs, rows, results, strict=True):
        assert verify_ref(ref, TRUST) is row["signature_verifies"]
        assert verify_ref(ref, TRUST, expected_framework=FRAMEWORK) is row["verifies_for_framework"]
        assert result.verified is row["envelope_verifies"]
        if "envelope_reason" in row:
            assert result.reason.startswith(row["envelope_reason"])


@pytest.mark.parametrize("name", ["ed25519-golden-v3.json", "hmac-sha256-golden-v3.json"])
def test_signing_goldens_reproduce(name):
    golden = load_json(VECTORS / "signing" / name)
    key = golden.get("private_key_hex") or golden["key"]
    for case in golden["cases"]:
        args = (case["content_hash"], case["signer"], case["framework"], case["item_id"])
        message = signing_message_v3(*args, case["assurance_tier"])
        assert message.decode() == case["message_canonical"]
        sig = sign_evidence_v3(
            *args, key=key, alg=golden["algorithm"], assurance_tier=case["assurance_tier"]
        )
        assert sig == case["signature_hex"]


def test_v3_message_never_equals_v1_message():
    golden = load_json(VECTORS / "signing" / "ed25519-golden-v3.json")
    for case in golden["cases"]:
        assert set(json.loads(case["message_canonical"])) == {
            "assurance_tier",
            "content_hash",
            "framework",
            "item_id",
            "signer",
        }


def test_signing_message_v3_rejects_unknown_tier():
    with pytest.raises(EvidenceError, match="assurance_tier"):
        signing_message_v3("ab", "s", "iki-gov", "D1", "gold")


def test_same_content_two_items_is_not_reuse():
    refs = parse_document(load_json(V3 / "valid-same-content-two-items.json"))
    assert refs[0].content_hash == refs[1].content_hash
    assert refs[0].signature != refs[1].signature
    assert reused_refs(refs) == frozenset()


def test_v2_reuse_floor():
    doc = load_json(VECTORS / "evidence-ref-v2" / "reused-ref.json")
    notes = load_json(VECTORS / "evidence-ref-v2" / "reused-ref.notes.json")
    trust = load_trust_store(notes["trust_store"])
    refs = parse_document(doc)
    assert [verify_ref(r, trust) for r in refs] == notes["signature_verifies"]
    results = verify_envelope(doc, trust)
    assert [r.verified for r in results] == notes["envelope_verifies"]
    assert all(r.reason == notes["envelope_reason"] for r in results)
    assert reused_refs(refs) == {(refs[0].signer, refs[0].content_hash)}


def test_binding_demand_rejects_v2_refs():
    doc = load_json(VECTORS / "evidence-ref-v2" / "valid-tier-absent.json")
    notes = load_json(VECTORS / "evidence-ref-v2" / "valid-tier-absent.notes.json")
    trust = load_trust_store(notes["trust_store"])
    results = verify_envelope(doc, trust, expected_framework=FRAMEWORK)
    assert not any(r.verified for r in results)
    assert results[0].reason == "subject binding required (evidence-ref@3)"


def test_framework_mismatch_reason():
    doc = load_json(V3 / "valid-signature-foreign-framework.json")
    (result,) = verify_envelope(doc, TRUST, expected_framework=FRAMEWORK)
    assert result.reason == "framework 'other-checklist' is not 'iki-gov'"


# ── bare mappings: the schema argument decides, never field presence ─────────


def _v3_ref() -> dict:
    return load_json(V3 / "valid-envelope.json")["evidence"][0]


def test_mapping_with_framework_defaults_to_v1_message():
    assert verify_ref(_v3_ref(), TRUST) is False
    assert verify_ref(_v3_ref(), TRUST, schema=EVIDENCE_REF_SCHEMA_ID_V3) is True


@pytest.mark.parametrize(
    "change",
    [
        {"framework": "Bad Framework"},
        {"framework": None},
        {"item_id": 7},
        {"assurance_tier": "gold"},
        {"content_hash": None},
        {"signature": None},
        {"signer": "nobody"},
    ],
)
def test_malformed_v3_mappings_fail_closed(change):
    ref = dict(_v3_ref(), **change)
    assert verify_ref(ref, TRUST, schema=EVIDENCE_REF_SCHEMA_ID_V3) is False


def test_non_mapping_ref_fails_closed():
    assert verify_ref(["not", "a", "ref"], TRUST) is False


# ── producer side ────────────────────────────────────────────────────────────


def test_build_envelope_enforces_framework_by_schema():
    ref = _v3_ref()
    env = build_envelope([ref], schema=EVIDENCE_REF_SCHEMA_ID_V3)
    assert parse_document(env)[0].framework == FRAMEWORK
    with pytest.raises(EvidenceError, match="framework"):
        build_envelope([ref], schema=EVIDENCE_REF_SCHEMA_ID_V2)
    without = {k: v for k, v in ref.items() if k != "framework"}
    with pytest.raises(EvidenceError, match="framework"):
        build_envelope([without], schema=EVIDENCE_REF_SCHEMA_ID_V3)


def test_parsed_ref_round_trips():
    doc = load_json(V3 / "valid-tier-optimistic.json")
    (ref,) = parse_document(doc)
    assert ref.subject_bound and ref.tier == "optimistic"
    assert build_envelope([ref], schema=EVIDENCE_REF_SCHEMA_ID_V3)["evidence"] == doc["evidence"]


# ── CLI ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def trust_file(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(EXPECT["trust_store"]), encoding="utf-8")
    return str(path)


def test_cli_require_subject_binding(trust_file, capsys):
    valid = str(V3 / "valid-envelope.json")
    assert main(["verify", valid, "--trust", trust_file]) == 0
    assert (
        main(["verify", valid, "--trust", trust_file, "--require-subject-binding", "iki-gov"]) == 0
    )
    foreign = str(V3 / "valid-signature-foreign-framework.json")
    assert (
        main(["verify", foreign, "--trust", trust_file, "--require-subject-binding", "iki-gov"])
        == 1
    )
    assert "is not 'iki-gov'" in capsys.readouterr().err


def test_cli_reports_reuse(capsys, tmp_path):
    notes = load_json(VECTORS / "evidence-ref-v2" / "reused-ref.notes.json")
    trust = tmp_path / "t.json"
    trust.write_text(json.dumps(notes["trust_store"]), encoding="utf-8")
    envelope = str(VECTORS / "evidence-ref-v2" / "reused-ref.json")
    assert main(["verify", envelope, "--trust", str(trust)]) == 1
    assert "reused under 2 items" in capsys.readouterr().err


def test_cli_invalid_envelope_json(tmp_path, trust_file, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["verify", str(bad), "--trust", trust_file]) == 1
    assert "invalid evidence JSON" in capsys.readouterr().err


# ── scoutsuite consumer vector (cloud-posture) ───────────────────────────────


def test_scoutsuite_vector_verifies_and_legacy_fails():
    doc = load_json(VECTORS / "cloud-posture" / "valid-envelope.json")
    notes = load_json(VECTORS / "cloud-posture" / "valid-envelope.notes.json")
    trust = load_trust_store(notes["trust_store"])
    _validator(doc).validate(doc)
    refs = parse_document(doc)
    assert all(r.verified for r in verify_envelope(doc, trust))
    for ref in refs:
        claim = notes["claims"][ref.item_id]
        assert content_hash(claim["claim_subject"]) == ref.content_hash
        legacy = dict(ref.to_dict(), signature=notes["legacy_signatures"][ref.item_id])
        assert verify_ref(legacy, trust) is False
