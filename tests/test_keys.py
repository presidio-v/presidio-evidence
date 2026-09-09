"""ADR-0001 D3 key helpers: generation, derivation, and fail-closed loading.

The loader must enforce ``0600`` on files, accept env vars, reject anything
that is not a 64-char hex key, and never echo key material in an error.
"""

from __future__ import annotations

import os

import pytest
from conftest import VECTORS, load_json

import presidio_evidence as E
from presidio_evidence import EvidenceError

ED = load_json(VECTORS / "signing" / "ed25519-golden.json")
PRIV, PUB = ED["private_key_hex"], ED["public_key_hex"]


def test_public_key_hex_matches_family_golden_key():
    assert E.public_key_hex(PRIV) == PUB


def test_public_key_hex_rejects_malformed_without_echo():
    with pytest.raises(EvidenceError) as exc:
        E.public_key_hex("zz")
    assert "zz" not in str(exc.value)


def test_generate_keypair_roundtrips_through_sign_verify():
    priv, pub = E.generate_ed25519_keypair()
    assert len(priv) == 64 and len(pub) == 64
    assert priv == priv.lower() and pub == pub.lower()
    assert E.public_key_hex(priv) == pub
    sig = E.sign_ed25519(ED["content_hash"], ED["signer"], priv)
    assert E.verify_ed25519(ED["content_hash"], ED["signer"], sig, pub) is True
    assert E.generate_ed25519_keypair()[0] != priv  # fresh randomness each call


# ── load_private_key: file source ────────────────────────────────────────────
def test_load_from_0600_file_trims_and_lowercases(tmp_path):
    p = tmp_path / "key"
    p.write_text("  " + PRIV.upper() + "\n")
    p.chmod(0o600)
    assert E.load_private_key(p) == PRIV
    assert E.load_private_key(str(p)) == PRIV  # str path accepted too


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o700, 0o610, 0o601])
def test_load_rejects_permissive_modes(tmp_path, mode):
    p = tmp_path / "key"
    p.write_text(PRIV)
    p.chmod(mode)
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(p)
    msg = str(exc.value)
    assert "too permissive" in msg and PRIV not in msg


def test_load_accepts_0400(tmp_path):
    p = tmp_path / "key"
    p.write_text(PRIV)
    p.chmod(0o400)
    assert E.load_private_key(p) == PRIV


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(tmp_path / "absent")
    assert "absent" in str(exc.value)


def test_load_rejects_non_regular_file(tmp_path):
    d = tmp_path / "dir"
    d.mkdir(mode=0o700)
    with pytest.raises(EvidenceError):
        E.load_private_key(d)  # a directory opens but is not a regular file


def test_load_rejects_oversize_file_unread(tmp_path):
    p = tmp_path / "key"
    p.write_bytes(b"a" * 4096)
    p.chmod(0o600)
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(p)
    assert "too large" in str(exc.value)


def test_load_rejects_non_ascii_and_bad_hex_without_echo(tmp_path):
    p = tmp_path / "key"
    p.write_bytes("ü".encode() * 40)
    p.chmod(0o600)
    with pytest.raises(EvidenceError):
        E.load_private_key(p)
    p.write_text("not-a-key-SECRET")
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(p)
    assert "SECRET" not in str(exc.value)


# ── load_private_key: env source ─────────────────────────────────────────────
def test_load_from_env(monkeypatch):
    monkeypatch.setenv("PE_TEST_KEY", " " + PRIV.upper() + " ")
    assert E.load_private_key(env="PE_TEST_KEY") == PRIV


def test_load_env_missing_or_malformed(monkeypatch):
    monkeypatch.delenv("PE_TEST_KEY", raising=False)
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(env="PE_TEST_KEY")
    assert "PE_TEST_KEY" in str(exc.value)
    monkeypatch.setenv("PE_TEST_KEY", "SECRET-but-not-hex")
    with pytest.raises(EvidenceError) as exc:
        E.load_private_key(env="PE_TEST_KEY")
    assert "SECRET" not in str(exc.value)


def test_load_requires_exactly_one_source(tmp_path):
    with pytest.raises(EvidenceError):
        E.load_private_key()
    with pytest.raises(EvidenceError):
        E.load_private_key(tmp_path / "k", env="X")


# ── write_private_key ────────────────────────────────────────────────────────
def test_write_creates_0600_and_refuses_overwrite(tmp_path):
    p = tmp_path / "key"
    E.write_private_key(p, PRIV.upper())
    assert oct(p.stat().st_mode & 0o777) == oct(0o600)
    assert p.read_text() == PRIV + "\n"
    assert E.load_private_key(p) == PRIV  # what we write, we can load
    with pytest.raises(EvidenceError) as exc:
        E.write_private_key(p, PRIV)
    assert "cannot create" in str(exc.value)


def test_write_rejects_malformed_before_touching_disk(tmp_path):
    p = tmp_path / "key"
    with pytest.raises(EvidenceError):
        E.write_private_key(p, "nope")
    assert not p.exists()


def test_write_honours_umask_independence(tmp_path):
    # mode is set explicitly at creation; a permissive umask must not widen it
    old = os.umask(0o000)
    try:
        p = tmp_path / "key"
        E.write_private_key(p, PRIV)
        assert p.stat().st_mode & 0o077 == 0
    finally:
        os.umask(old)
