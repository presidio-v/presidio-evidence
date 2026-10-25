"""ADR-0001 D4: the ``presidio-evidence`` CLI exits 0 iff verification succeeds.

Driven through ``main(argv)`` (and once through ``python -m`` via runpy) so the
coverage gate sees every branch. Golden vectors supply the inputs.
"""

from __future__ import annotations

import json
import runpy
import sys

import pytest
from conftest import VECTORS, load_json

from presidio_evidence._cli import main

ENVELOPE = VECTORS / "evidence-ref" / "valid-envelope.json"
NOTES = load_json(VECTORS / "evidence-ref" / "valid-envelope.notes.json")
V2_TIERS = VECTORS / "evidence-ref-v2" / "valid-tiers.json"
V2_ABSENT = VECTORS / "evidence-ref-v2" / "valid-tier-absent.json"


@pytest.fixture
def trust_file(tmp_path):
    p = tmp_path / "trust.json"
    p.write_text(json.dumps(NOTES["trust_store"]))
    return str(p)


def test_verify_golden_envelope_exits_0(trust_file, capsys):
    assert main(["verify", str(ENVELOPE), "--trust", trust_file]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ok ")
    assert any(json.dumps(signer) in out for signer in NOTES["trust_store"])


def test_verify_v2_absent_tier_is_attested_and_exits_0(trust_file):
    assert main(["verify", str(V2_ABSENT), "--trust", trust_file]) == 0


def test_verify_non_attested_tiers_fail_closed_even_with_valid_signature(trust_file, capsys):
    # valid-tiers.json reuses the @1 golden signature for attested/optimistic/zk
    assert main(["verify", str(V2_TIERS), "--trust", trust_file]) == 1
    err = capsys.readouterr().err
    assert "'optimistic'" in err and "'zk'" in err and "not verifiable by this verifier" in err


def test_verify_unknown_signer_exits_1(tmp_path, capsys):
    trust = tmp_path / "t.json"
    trust.write_text(json.dumps({"someone-else": {"alg": "hmac-sha256", "key": "k"}}))
    assert main(["verify", str(ENVELOPE), "--trust", str(trust)]) == 1
    assert "signature not verified" in capsys.readouterr().err


def test_verify_tampered_signature_exits_1(tmp_path, trust_file):
    doc = load_json(ENVELOPE)
    doc["evidence"][0]["signature"] = "00" * 64
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    assert main(["verify", str(bad), "--trust", trust_file]) == 1


def test_verify_empty_envelope_exits_1(tmp_path, trust_file, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"schema": "presidio-hardened/evidence-ref@1", "evidence": []}))
    assert main(["verify", str(empty), "--trust", trust_file]) == 1
    assert "no evidence refs" in capsys.readouterr().err


@pytest.mark.parametrize(
    "envelope_text, trust_text",
    [
        ("{not json", "{}"),
        ('{"evidence": "nope"}', "{}"),
        ('{"schema": "presidio-hardened/evidence-ref@1", "evidence": []}', "[1]"),
    ],
)
def test_verify_malformed_inputs_exit_1(tmp_path, envelope_text, trust_text, capsys):
    e, t = tmp_path / "e.json", tmp_path / "t.json"
    e.write_text(envelope_text)
    t.write_text(trust_text)
    assert main(["verify", str(e), "--trust", str(t)]) == 1
    assert capsys.readouterr().err.startswith("error: ")


def test_verify_unreadable_file_exits_1(tmp_path, trust_file, capsys):
    assert main(["verify", str(tmp_path / "missing.json"), "--trust", trust_file]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_usage_error_exits_2():
    with pytest.raises(SystemExit) as exc:
        main(["verify"])  # missing --trust
    assert exc.value.code == 2


# ── keygen ───────────────────────────────────────────────────────────────────
def test_keygen_writes_0600_and_prints_only_public_half(tmp_path, capsys):
    import presidio_evidence as E

    out = tmp_path / "signer.key"
    assert main(["keygen", "--out", str(out)]) == 0
    pub = capsys.readouterr().out.strip()
    priv = E.load_private_key(out)
    assert out.stat().st_mode & 0o077 == 0
    assert E.public_key_hex(priv) == pub and priv not in pub


def test_keygen_signer_prints_trust_store_entry(tmp_path, capsys):
    import presidio_evidence as E

    out = tmp_path / "signer.key"
    assert main(["keygen", "--out", str(out), "--signer", "acme"]) == 0
    entry = json.loads(capsys.readouterr().out)
    assert entry == {
        "acme": {"alg": "ed25519", "public_key": E.public_key_hex(E.load_private_key(out))}
    }
    assert E.load_trust_store(entry)["acme"]["keys"] == [entry["acme"]["public_key"]]


def test_keygen_refuses_existing_file(tmp_path, capsys):
    out = tmp_path / "signer.key"
    out.write_text("precious")
    assert main(["keygen", "--out", str(out)]) == 1
    assert out.read_text() == "precious"
    assert "cannot create" in capsys.readouterr().err


# ── python -m presidio_evidence ──────────────────────────────────────────────
def test_module_entry_point(monkeypatch, trust_file):
    monkeypatch.setattr(
        sys, "argv", ["presidio-evidence", "verify", str(ENVELOPE), "--trust", trust_file]
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("presidio_evidence", run_name="__main__", alter_sys=True)
    assert exc.value.code == 0
