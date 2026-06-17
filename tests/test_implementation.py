"""Unit coverage for the v0.2.0 implementation (Layer 0/1 + refs + trust).

Layer-0 conformance is already exercised via ``conftest.canonical_bytes`` in
``test_canonical_json.py``; this file covers the rest of the public API and every
fail-closed branch. Ed25519 paths use ``cryptography`` (a dev dependency), the
same convention as ``test_signing_vectors.py``.
"""

from __future__ import annotations

import pytest
from conftest import VECTORS, load_json

import presidio_evidence as E
from presidio_evidence import EvidenceError, EvidenceRef

ED = load_json(VECTORS / "signing" / "ed25519-golden.json")
HM = load_json(VECTORS / "signing" / "hmac-sha256-golden.json")
CH, SIGNER = ED["content_hash"], ED["signer"]


# ── Layer 0 ──────────────────────────────────────────────────────────────────
def test_sha256_hex_and_content_hash():
    assert E.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # content_hash == sha256_hex(canonical_bytes(payload))
    payload = {"b": 2, "a": "x"}
    assert E.content_hash(payload) == E.sha256_hex(E.canonical_bytes(payload))


def test_canonical_rejects_floats_nested_in_list():
    with pytest.raises(ValueError):
        E.canonical_bytes([1, {"a": 3.14}])  # list → dict → float
    assert E.canonical_bytes([1, 2, "x"]) == b'[1,2,"x"]'


# ── Layer 1: signing & verification ──────────────────────────────────────────
def test_signing_message_is_signer_bound():
    assert E.signing_message(CH, SIGNER).decode("utf-8") == ED["message_canonical"]


def test_hmac_sign_and_verify_golden():
    assert E.sign_hmac(HM["content_hash"], HM["signer"], HM["key"]) == HM["signature_hex"]
    assert E.verify_hmac(HM["content_hash"], HM["signer"], HM["signature_hex"], HM["key"]) is True
    assert E.verify_hmac(HM["content_hash"], HM["signer"], HM["signature_hex"], "wrong") is False


def test_sign_evidence_dispatch_and_unknown_alg():
    assert (
        E.sign_evidence(HM["content_hash"], HM["signer"], key=HM["key"], alg="hmac-sha256")
        == (HM["signature_hex"])
    )
    with pytest.raises(EvidenceError):
        E.sign_evidence(CH, SIGNER, key="k", alg="rsa")


def test_ed25519_sign_verify_and_tamper():
    assert E.sign_ed25519(CH, SIGNER, ED["private_key_hex"]) == ED["signature_hex"]
    assert (
        E.sign_evidence(CH, SIGNER, key=ED["private_key_hex"], alg="ed25519")
        == (ED["signature_hex"])
    )
    assert E.verify_ed25519(CH, SIGNER, ED["signature_hex"], ED["public_key_hex"]) is True
    # tamper: wrong content_hash → fail-closed False (not an exception)
    assert E.verify_ed25519("dead" * 4, SIGNER, ED["signature_hex"], ED["public_key_hex"]) is False


def test_ed25519_invalid_private_key_raises():
    with pytest.raises(EvidenceError):
        E.sign_ed25519(CH, SIGNER, "not-hex")


# ── refs & envelopes ─────────────────────────────────────────────────────────
def _ref_dict(**over):
    base = {
        "item_id": "T5",
        "source": "presidio-hardened-scoutsuite",
        "source_version": "0.2.0",
        "ledger_ref": "presidio-report-manifest:sha256/" + "a" * 64,
        "content_hash": HM["content_hash"],
        "signer": HM["signer"],
        "signature": HM["signature_hex"],
        "claimed_at": "2026-06-17T00:00:00Z",
    }
    base.update(over)
    return base


def test_evidence_ref_to_dict_roundtrips():
    ref = EvidenceRef(**_ref_dict())
    assert ref.to_dict() == _ref_dict()


def test_parse_and_load_document():
    doc = {"schema": E.EVIDENCE_REF_SCHEMA_ID, "evidence": [_ref_dict()]}
    refs = E.parse_document(doc)
    assert len(refs) == 1 and refs[0].item_id == "T5"
    import json

    assert E.load_evidence(json.dumps(doc))[0].signer == HM["signer"]


@pytest.mark.parametrize(
    "doc",
    [
        {"no_evidence": []},
        {"schema": "other@2", "evidence": []},
        {"evidence": "nope"},
        {"evidence": [_ref_dict(content_hash="NOTHEX")]},
        {"evidence": [_ref_dict(signature="ZZ")]},
        {"evidence": [_ref_dict(item_id="")]},  # empty string
        {"evidence": [_ref_dict(ledger_ref="x\x00y")]},  # null byte
        {"evidence": [_ref_dict(source="a" * 513)]},  # oversize
        {"evidence": [{k: v for k, v in _ref_dict().items() if k != "claimed_at"}]},  # missing
        {"evidence": ["not-an-object"]},
    ],
)
def test_parse_document_rejects_malformed(doc):
    with pytest.raises(EvidenceError):
        E.parse_document(doc)


def test_load_evidence_bad_json():
    with pytest.raises(EvidenceError):
        E.load_evidence("{not json")


def test_build_envelope_with_and_without_metadata():
    full = E.build_envelope(
        [EvidenceRef(**_ref_dict())],
        source="s",
        source_version="0.2.0",
        use_case="audit",
        generated_at="2026-06-17T00:00:00Z",
    )
    assert full["schema"] == E.EVIDENCE_REF_SCHEMA_ID
    assert full["use_case"] == "audit" and full["source"] == "s"
    assert E.parse_document(full)  # round-trips back through validation
    # a mapping ref (not an EvidenceRef) is accepted too; minimal metadata
    minimal = E.build_envelope([_ref_dict()])
    assert set(minimal) == {"schema", "evidence"}


# ── trust store ──────────────────────────────────────────────────────────────
def test_load_trust_store_shapes():
    trust = E.load_trust_store(
        {
            "bare": "sekret",
            "obj": {"alg": "hmac-sha256", "key": ["k1", "k2"]},
        }
    )
    assert trust["bare"] == {"alg": "hmac-sha256", "keys": ["sekret"]}
    assert trust["obj"]["keys"] == ["k1", "k2"]


def test_load_trust_store_from_json_text():
    import json

    trust = E.load_trust_store(json.dumps({"s": "x"}))
    assert trust["s"]["alg"] == "hmac-sha256"


@pytest.mark.parametrize(
    "doc",
    [
        {"s": ""},  # empty HMAC secret
        {"s": {"alg": "rsa", "key": "x"}},  # unknown alg
        {"s": {"alg": "hmac-sha256"}},  # missing key material
        {"s": {"alg": "hmac-sha256", "key": []}},  # empty list
        {"s": 123},  # neither string nor object
    ],
)
def test_load_trust_store_rejects(doc):
    with pytest.raises(EvidenceError):
        E.load_trust_store(doc)


def test_load_trust_store_bad_json_and_non_mapping():
    with pytest.raises(EvidenceError):
        E.load_trust_store("{not json")
    with pytest.raises(EvidenceError):
        E.load_trust_store("[1,2,3]")  # valid JSON, wrong shape
    with pytest.raises(EvidenceError):
        E.load_trust_store(123)  # neither str nor mapping


def test_ed25519_key_fallback_and_rotation():
    # 'public_key' fallback via the generic 'key' field is accepted (mirrors consumers)
    trust = E.load_trust_store({SIGNER: {"alg": "ed25519", "key": ED["public_key_hex"]}})
    assert trust[SIGNER]["keys"] == [ED["public_key_hex"]]


# ── verify_ref ───────────────────────────────────────────────────────────────
def test_verify_ref_hmac_ref_and_mapping_and_rotation():
    ref = EvidenceRef(**_ref_dict())
    # normalised trust entry (from load_trust_store), with rotation
    trust = E.load_trust_store({HM["signer"]: {"alg": "hmac-sha256", "key": ["stale", HM["key"]]}})
    assert E.verify_ref(ref, trust) is True
    # a Mapping ref and a raw (un-normalised) bare-string trust entry
    assert E.verify_ref(_ref_dict(), {HM["signer"]: HM["key"]}) is True


def test_verify_ref_fail_closed_cases():
    ref = EvidenceRef(**_ref_dict())
    assert E.verify_ref(ref, {}) is False  # unknown signer
    assert E.verify_ref("not-a-ref", {}) is False  # wrong type
    # non-str fields fail closed
    assert E.verify_ref({"content_hash": 1, "signer": "s", "signature": "x"}, {}) is False
    assert E.verify_ref(EvidenceRef(**_ref_dict(signer="evil")), {HM["signer"]: HM["key"]}) is False


def test_verify_ref_ed25519():
    ref = EvidenceRef(**_ref_dict(content_hash=CH, signer=SIGNER, signature=ED["signature_hex"]))
    trust = E.load_trust_store({SIGNER: {"alg": "ed25519", "public_key": ED["public_key_hex"]}})
    assert E.verify_ref(ref, trust) is True
