# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris coverage-guided fuzz harness for presidio-evidence.

Drives the consumer path on arbitrary bytes: JSON text through
``load_evidence`` / ``verify_envelope`` against a fixed trust store, plus
``canonical_bytes`` and ``is_decimal_string`` on whatever parses. Seed it with
the published vectors (``fuzz/make_corpus.py``) so it starts from real
envelopes. The invariant
under test is the fail-closed contract: malformed input raises only
``EvidenceError`` (or a ``ValueError`` from the strict canonicaliser), and
nothing else escapes.

Linux only (Atheris ships no macOS wheel); CI runs it on Python 3.12.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from presidio_evidence import (
        EvidenceError,
        canonical_bytes,
        is_decimal_string,
        load_evidence,
        load_trust_store,
        verify_envelope,
    )

# Well-known published test keys (see SECURITY.md): an Ed25519 public key and
# an HMAC secret, so both verification paths are reachable.
TRUST = load_trust_store(
    {
        "presidio-hardened-ai": {
            "alg": "ed25519",
            "public_key": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        },
        "presidio-hmac-producer": {"alg": "hmac-sha256", "key": "shared-key"},
    }
)

# Verify each envelope without a framework and bound to one registered
# framework id, so both branches of the @3 subject binding are exercised.
FRAMEWORKS = (None, "iki-gov")


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")

    try:
        load_evidence(text)
    except EvidenceError:
        pass

    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return
    for framework in FRAMEWORKS:
        try:
            results = verify_envelope(doc, TRUST, expected_framework=framework)
        except EvidenceError:
            continue
        for result in results:
            assert isinstance(result.verified, bool)
            assert result.verified == (result.reason == "ok")

    try:
        canonical_bytes(doc)
    except (ValueError, RecursionError):
        pass
    if isinstance(doc, str):
        assert isinstance(is_decimal_string(doc), bool)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
