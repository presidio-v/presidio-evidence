"""Every vector must agree with the JSON Schemas: valid passes, invalid fails."""

from __future__ import annotations

import pytest
from conftest import VECTORS, load_json
from jsonschema import Draft202012Validator

EVIDENCE_VALID = sorted((VECTORS / "evidence-ref").glob("valid-*.json"))
EVIDENCE_INVALID = sorted((VECTORS / "evidence-ref").glob("invalid-*.json"))
TRUST_INVALID = sorted((VECTORS / "trust-store").glob("invalid-*.json"))


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
