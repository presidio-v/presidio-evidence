"""Every vector must agree with the JSON Schemas: valid passes, invalid fails."""

from __future__ import annotations

import pytest
from conftest import VECTORS, load_json
from jsonschema import Draft202012Validator

EVIDENCE_VALID = sorted((VECTORS / "evidence-ref").glob("valid-*.json"))
EVIDENCE_INVALID = sorted((VECTORS / "evidence-ref").glob("invalid-*.json"))
TRUST_INVALID = sorted((VECTORS / "trust-store").glob("invalid-*.json"))

# evidence-ref@2 (ADR-0003). The v1-with-extra-tier vector is validated against
# the @1 schema (the extra-field boundary case), not the @2 schema.
V2_VALID = sorted(
    p
    for p in (VECTORS / "evidence-ref-v2").glob("valid-*.json")
    if not p.name.startswith("valid-v1-")
)
V2_INVALID = sorted((VECTORS / "evidence-ref-v2").glob("invalid-*.json"))


def test_schemas_are_themselves_valid(evidence_ref_schema, trust_store_schema):
    Draft202012Validator.check_schema(evidence_ref_schema)
    Draft202012Validator.check_schema(trust_store_schema)


@pytest.mark.parametrize("path", EVIDENCE_VALID, ids=lambda p: p.stem)
def test_valid_evidence_vectors_pass(path, evidence_ref_schema):
    if path.name.endswith(".notes.json"):
        pytest.skip("companion notes file, not an envelope")
    Draft202012Validator(evidence_ref_schema).validate(load_json(path))


@pytest.mark.parametrize("path", EVIDENCE_INVALID, ids=lambda p: p.stem)
def test_invalid_evidence_vectors_fail(path, evidence_ref_schema):
    doc = load_json(path)["document"]
    errors = list(Draft202012Validator(evidence_ref_schema).iter_errors(doc))
    assert errors, f"{path.name} unexpectedly passed schema validation"


def test_valid_trust_store_passes(trust_store_schema):
    doc = load_json(VECTORS / "trust-store" / "valid.json")
    Draft202012Validator(trust_store_schema).validate(doc)


@pytest.mark.parametrize("path", TRUST_INVALID, ids=lambda p: p.stem)
def test_invalid_trust_stores_fail(path, trust_store_schema):
    doc = load_json(path)["document"]
    errors = list(Draft202012Validator(trust_store_schema).iter_errors(doc))
    assert errors, f"{path.name} unexpectedly passed schema validation"


def test_contract_constants_match_schema(evidence_ref_schema):
    from presidio_evidence import EVIDENCE_REF_FIELDS, EVIDENCE_REF_SCHEMA_ID

    ref_schema = evidence_ref_schema["$defs"]["evidenceRef"]
    assert set(ref_schema["required"]) == set(EVIDENCE_REF_FIELDS)
    assert evidence_ref_schema["properties"]["schema"]["const"] == EVIDENCE_REF_SCHEMA_ID


# ── evidence-ref@2 schema conformance (ADR-0003) ─────────────────────────────


@pytest.mark.parametrize("path", V2_VALID, ids=lambda p: p.stem)
def test_valid_v2_vectors_pass(path, evidence_ref_schema_v2):
    if path.name.endswith(".notes.json"):
        pytest.skip("companion notes file, not an envelope")
    Draft202012Validator(evidence_ref_schema_v2).validate(load_json(path))


@pytest.mark.parametrize("path", V2_INVALID, ids=lambda p: p.stem)
def test_invalid_v2_vectors_fail(path, evidence_ref_schema_v2):
    doc = load_json(path)["document"]
    errors = list(Draft202012Validator(evidence_ref_schema_v2).iter_errors(doc))
    assert errors, f"{path.name} unexpectedly passed @2 schema validation"


def test_v1_record_with_assurance_tier_is_valid_under_v1_schema(evidence_ref_schema):
    """Extra-field finding (ADR-0003): @1 sets no additionalProperties:false, so
    an @1 record carrying assurance_tier is VALID under the @1 schema — an extra
    field is not an @1-freeze violation (ADR-0001 D5)."""
    doc = load_json(VECTORS / "evidence-ref-v2" / "valid-v1-with-extra-tier.json")
    Draft202012Validator(evidence_ref_schema).validate(doc)
    assert doc["evidence"][0]["assurance_tier"] == "optimistic"


def test_v2_contract_constants_match_schema(evidence_ref_schema_v2):
    from presidio_evidence import (
        ASSURANCE_TIERS,
        EVIDENCE_REF_FIELDS,
        EVIDENCE_REF_SCHEMA_ID_V2,
    )

    ref_schema = evidence_ref_schema_v2["$defs"]["evidenceRef"]
    assert set(ref_schema["required"]) == set(EVIDENCE_REF_FIELDS)
    assert evidence_ref_schema_v2["properties"]["schema"]["const"] == EVIDENCE_REF_SCHEMA_ID_V2
    # @2 makes the envelope `schema` field required (no grandfathering).
    assert "schema" in evidence_ref_schema_v2["required"]
    assert tuple(evidence_ref_schema_v2["$defs"]["assuranceTier"]["enum"]) == ASSURANCE_TIERS
