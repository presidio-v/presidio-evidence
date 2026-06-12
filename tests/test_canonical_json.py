"""Layer-0 conformance: canonical encoding reproduces vectors byte-for-byte."""

from __future__ import annotations

import hashlib

import pytest
from conftest import VECTORS, canonical_bytes, load_json

DOC = load_json(VECTORS / "canonical-json" / "vectors.json")


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["name"])
def test_canonical_encoding_matches(case):
    encoded = canonical_bytes(case["payload"])
    assert encoded.decode("utf-8") == case["canonical"]
    assert hashlib.sha256(encoded).hexdigest() == case["sha256_hex"]


@pytest.mark.parametrize("case", DOC["rejected"], ids=lambda c: c["name"])
def test_strict_profile_rejects(case):
    with pytest.raises(ValueError):
        canonical_bytes(case["payload"])


def test_unicode_is_not_ascii_escaped():
    encoded = canonical_bytes({"k": "ß"})
    assert b"\\u" not in encoded  # ensure_ascii=False is part of the wire format
    assert "ß".encode() in encoded
