"""Regressions for the pre-publication security audit of 2026-10-25.

Four low-severity findings, each pinned here so it cannot come back:

1. CLI output: producer-controlled ``item_id``/``signer`` could forge verdict
   lines or terminal escapes.
2. ``verify_message``: a non-ASCII signature raised ``TypeError`` instead of
   returning ``False``.
3. Trust store: ``public_key`` without ``alg`` (or under ``hmac-sha256``) was used
   as an HMAC secret, so anyone holding the public key could forge evidence.
4. A lone surrogate in a signer or item id raised ``UnicodeEncodeError`` instead
   of failing closed.
"""

from __future__ import annotations

import json

import pytest
from conftest import VECTORS, load_json

from presidio_evidence import (
    EVIDENCE_REF_SCHEMA_ID_V3,
    EvidenceError,
    load_trust_store,
    parse_document,
    sign_hmac,
    verify_envelope,
    verify_hmac,
    verify_ref,
)
from presidio_evidence._cli import main
from presidio_evidence._signing import verify_message

GOLDEN = load_json(VECTORS / "signing" / "hmac-sha256-golden.json")
HMAC_TRUST = load_trust_store({GOLDEN["signer"]: {"alg": "hmac-sha256", "key": GOLDEN["key"]}})


def _hmac_ref(**change) -> dict:
    ref = {
        "item_id": "D1",
        "source": "s",
        "source_version": "1",
        "ledger_ref": "l",
        "content_hash": GOLDEN["content_hash"],
        "signer": GOLDEN["signer"],
        "signature": GOLDEN["signature_hex"],
        "claimed_at": "2026-10-25T00:00:00Z",
    }
    ref.update(change)
    return ref


# ── 1. CLI output cannot be forged ───────────────────────────────────────────


@pytest.mark.parametrize("bad", ["D1\nok   D2 forged", "D1\x1b[32m", "D1\x85"])
def test_control_characters_in_identifiers_are_rejected(bad):
    with pytest.raises(EvidenceError, match="control character"):
        parse_document({"evidence": [_hmac_ref(item_id=bad)]})
    with pytest.raises(EvidenceError, match="control character"):
        parse_document({"evidence": [_hmac_ref(signer=bad)]})


def test_cli_escapes_identifiers(tmp_path, capsys):
    trust = tmp_path / "t.json"
    trust.write_text(json.dumps({GOLDEN["signer"]: GOLDEN["key"]}), encoding="utf-8")
    env = tmp_path / "e.json"
    env.write_text(json.dumps({"evidence": [_hmac_ref(item_id='D1 "x" ü')]}), encoding="utf-8")
    assert main(["verify", str(env), "--trust", str(trust)]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and json.dumps('D1 "x" ü') in out


def test_cli_rejects_control_characters_cleanly(tmp_path, capsys):
    trust = tmp_path / "t.json"
    trust.write_text(json.dumps({GOLDEN["signer"]: GOLDEN["key"]}), encoding="utf-8")
    env = tmp_path / "e.json"
    env.write_text(json.dumps({"evidence": [_hmac_ref(item_id="D1\nok forged")]}))
    assert main(["verify", str(env), "--trust", str(trust)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error:")


# ── 2. malformed signatures return False ─────────────────────────────────────


@pytest.mark.parametrize("sig", ["é" * 64, "\ud800" * 64, GOLDEN["signature_hex"] + "\n", "", 7])
def test_malformed_signature_is_false_not_an_exception(sig):
    assert verify_ref(_hmac_ref(signature=sig), HMAC_TRUST) is False
    assert verify_message(b"m", sig, "k", alg="hmac-sha256") is False
    assert verify_message(b"m", sig, "00" * 32, alg="ed25519") is False


def test_verify_hmac_non_ascii_signature_is_false():
    assert verify_hmac(GOLDEN["content_hash"], GOLDEN["signer"], "é" * 64, GOLDEN["key"]) is False


def test_unencodable_hmac_key_is_false():
    sig = sign_hmac("ab", "s", "k")
    assert verify_message(b"m", sig, "\ud800", alg="hmac-sha256") is False


# ── 3. public_key is never an HMAC secret ────────────────────────────────────


def test_public_key_under_hmac_is_rejected():
    doc = load_json(VECTORS / "trust-store" / "rejected-hmac-with-public-key.json")["document"]
    with pytest.raises(EvidenceError, match="not an HMAC secret"):
        load_trust_store(doc)


def test_public_key_without_alg_is_ed25519():
    vec = load_json(VECTORS / "trust-store" / "public-key-implies-ed25519.json")
    trust = load_trust_store(vec["document"])
    assert trust[vec["signer"]]["alg"] == "ed25519"
    ref = {"content_hash": vec["content_hash"], "signer": vec["signer"]}
    assert verify_ref(dict(ref, signature=vec["verifies"]["signature_hex"]), trust) is True
    assert verify_ref(dict(ref, signature=vec["must_not_verify"]["signature_hex"]), trust) is False


def test_ed25519_public_key_under_key_still_loads():
    vec = load_json(VECTORS / "trust-store" / "public-key-implies-ed25519.json")
    pub = vec["document"][vec["signer"]]["public_key"]
    trust = load_trust_store({vec["signer"]: {"alg": "ed25519", "key": pub}})
    ref = {"content_hash": vec["content_hash"], "signer": vec["signer"]}
    assert verify_ref(dict(ref, signature=vec["verifies"]["signature_hex"]), trust) is True


# ── 4. lone surrogates fail closed ───────────────────────────────────────────


def test_surrogate_signer_is_rejected_at_parse():
    with pytest.raises(EvidenceError, match="not valid UTF-8"):
        parse_document({"evidence": [_hmac_ref(signer="s\ud800")]})


def test_surrogate_item_id_under_v3_fails_closed():
    ref = dict(_hmac_ref(item_id="D\ud800"), framework="iki-gov")
    with pytest.raises(EvidenceError, match="not valid UTF-8"):
        verify_envelope({"schema": EVIDENCE_REF_SCHEMA_ID_V3, "evidence": [ref]}, HMAC_TRUST)
    assert verify_ref(ref, HMAC_TRUST, schema=EVIDENCE_REF_SCHEMA_ID_V3) is False


def test_surrogate_signer_on_bare_mapping_is_false():
    assert verify_ref(_hmac_ref(signer="s\ud800"), {"s\ud800": "k"}) is False
