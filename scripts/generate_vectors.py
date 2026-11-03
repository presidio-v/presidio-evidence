#!/usr/bin/env python3
"""Regenerate the golden test vectors under vectors/.

Vectors are append-only (ADR-0001 D5): this script must remain byte-stable for
already-published vectors. Run with --check to verify the committed vectors match
regeneration exactly (CI does this); run without flags to (re)write them.

Requires: cryptography>=42.
"""

from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = pathlib.Path(__file__).resolve().parent.parent
V = ROOT / "vectors"

# Cross-repo constants — pinned by the consumers' tests (ikigov-assess
# tests/test_evidence.py, x402, presidio-hardened-ai). Do not change within @1.
PRIV = "01" * 32
EXPECTED_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
EXPECTED_SIG = (
    "a0dc8599958734457f194ebce15c60ec097754b59897ab5dc758f73abadafe36"
    "97874049d9f7736de4e3a9cc28b2fb4d76b15d8bce7fa0b26c8434bebbba590a"
)
EXPECTED_HSIG = "2e7af6d2882dd53847dcf3032e1fe36e58c5a879c224ea97b505b3e3b626b87a"
CH, SIGNER, KEY = "abc123def456", "presidio-hardened-ai", "shared-key"

# energy-reading@1 frozen vocabulary (PR #14 maintainer decision, 2026-07-13).
# Kept next to the generator rather than in the runtime package: this repository
# reserves and tests the wire contract; the producer owns runtime validation.
ENERGY_METERS = ("rapl", "kepler", "dcgm")
ENERGY_LAYERS = ("container", "pod", "deployment", "node")


def _validate_energy_content(content: dict) -> None:
    """Fail closed before an energy-reading@1 vector enters the contract."""
    if "reading" in content:
        raise RuntimeError("energy-reading@1 carries no payload-internal type id")
    if "source" in content:
        raise RuntimeError("energy-reading@1 uses meter; source is wrapper metadata")
    meter = content.get("meter")
    if meter not in ENERGY_METERS:
        raise RuntimeError(f"meter must be one of {ENERGY_METERS}: {meter!r}")
    if ("layer" in content) == ("strategy" in content):
        raise RuntimeError("energy-reading@1 requires exactly one of layer / strategy")
    if "layer" in content and content["layer"] not in ENERGY_LAYERS:
        raise RuntimeError(f"layer must be one of {ENERGY_LAYERS}: {content['layer']!r}")


def cb(payload: object) -> bytes:
    """Canonical JSON bytes — must byte-match every producer/consumer."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def build() -> dict[pathlib.Path, dict]:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIV))
    pub = sk.public_key().public_bytes_raw().hex()
    msg = cb({"content_hash": CH, "signer": SIGNER})
    sig = sk.sign(msg).hex()
    hsig = hmaclib.new(KEY.encode(), msg, hashlib.sha256).hexdigest()
    if pub != EXPECTED_PUB:
        raise RuntimeError("Ed25519 public-key derivation drifted")
    if sig != EXPECTED_SIG:
        raise RuntimeError("Ed25519 wire format drifted")
    if hsig != EXPECTED_HSIG:
        raise RuntimeError("HMAC wire format drifted")

    out: dict[pathlib.Path, dict] = {}

    out[V / "signing/ed25519-golden.json"] = {
        "description": (
            "Cross-repo Ed25519 golden vector. Pins the wire format: detached "
            "signature over canonical_json({content_hash, signer}). Matches the "
            "vectors committed in presidio-hardened-ai, x402, and ikigov-assess."
        ),
        "algorithm": "ed25519",
        "private_key_hex": PRIV,
        "public_key_hex": pub,
        "content_hash": CH,
        "signer": SIGNER,
        "message_canonical": msg.decode(),
        "signature_hex": sig,
        "tamper_cases": [
            {
                "reason": "wrong public key",
                "public_key_hex": "00" * 32,
                "content_hash": CH,
                "signer": SIGNER,
                "signature_hex": sig,
                "verifies": False,
            },
            {
                "reason": "tampered content_hash",
                "public_key_hex": pub,
                "content_hash": "tampered",
                "signer": SIGNER,
                "signature_hex": sig,
                "verifies": False,
            },
            {
                "reason": "tampered signer (cross-signer replay)",
                "public_key_hex": pub,
                "content_hash": CH,
                "signer": "evil-signer",
                "signature_hex": sig,
                "verifies": False,
            },
            {
                "reason": "malformed signature hex",
                "public_key_hex": pub,
                "content_hash": CH,
                "signer": SIGNER,
                "signature_hex": "zz" + sig[2:],
                "verifies": False,
            },
        ],
    }

    out[V / "signing/hmac-sha256-golden.json"] = {
        "description": (
            "Cross-repo HMAC-SHA256 golden vector (back-compat algorithm). "
            "Matches ikigov-assess tests/test_evidence.py GOLDEN_SIG."
        ),
        "algorithm": "hmac-sha256",
        "key": KEY,
        "content_hash": CH,
        "signer": SIGNER,
        "message_canonical": msg.decode(),
        "signature_hex": hsig,
        "tamper_cases": [
            {
                "reason": "wrong key",
                "key": "wrong",
                "content_hash": CH,
                "signer": SIGNER,
                "signature_hex": hsig,
                "verifies": False,
            },
            {
                "reason": "tampered signer",
                "key": KEY,
                "content_hash": CH,
                "signer": "evil-signer",
                "signature_hex": hsig,
                "verifies": False,
            },
        ],
    }

    cases = []
    for name, payload in [
        ("key-sorting", {"b": "2", "a": "1", "z": "26", "m": "13"}),
        ("nested-objects", {"outer": {"y": ["s", "t"], "x": {"k": "v"}}, "alpha": "first"}),
        ("unicode-preserved", {"name": "Käfer-Prüfung", "city": "München", "sz": "ß"}),
        ("integers-allowed", {"count": 42, "zero": 0, "negative": -7}),
        ("booleans-null", {"flag": True, "off": False, "none": None}),
        ("empty-structures", {"obj": {}, "arr": [], "s": ""}),
        ("signing-message-shape", {"content_hash": CH, "signer": SIGNER}),
    ]:
        enc = cb(payload)
        cases.append(
            {
                "name": name,
                "payload": payload,
                "canonical": enc.decode(),
                "sha256_hex": hashlib.sha256(enc).hexdigest(),
            }
        )
    out[V / "canonical-json/vectors.json"] = {
        "description": (
            'Layer-0 canonical JSON profile: sorted keys, separators (",", ":"), '
            "UTF-8, ensure_ascii=False. sha256_hex is the content hash over the "
            "canonical bytes. Strict profile (ADR-0001 D1): floats are REJECTED by "
            "conforming canonicalizers; payloads under 'rejected' must error."
        ),
        "cases": cases,
        "rejected": [
            {
                "name": "float-top-level",
                "payload": {"amount": 1.5},
                "reason": "floats rejected (treasury-strict profile)",
            },
            {
                "name": "float-nested",
                "payload": {"a": {"b": [1.0]}},
                "reason": "floats rejected (treasury-strict profile)",
            },
        ],
    }

    content = {"records": ["r1", "r2"], "use_case": "fraud-scoring"}
    real_ch = hashlib.sha256(cb(content)).hexdigest()
    real_sig = sk.sign(cb({"content_hash": real_ch, "signer": SIGNER})).hex()
    ref = {
        "item_id": "D1",
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "ledger_ref": "pai-ledger:seq/1",
        "content_hash": real_ch,
        "signer": SIGNER,
        "signature": real_sig,
        "claimed_at": "2026-06-12T00:00:00+00:00",
    }
    out[V / "evidence-ref/valid-envelope.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "fraud-scoring",
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "generated_at": "2026-06-12T00:00:00+00:00",
        "evidence": [ref],
    }
    out[V / "evidence-ref/valid-envelope.notes.json"] = {
        "description": (
            "Companion to valid-envelope.json: evidence[0] is end-to-end verifiable. "
            "content_hash = sha256(canonical(signed_content)); signature = "
            "ed25519(priv 01*32) over canonical({content_hash, signer})."
        ),
        "signed_content": content,
        "expected_content_hash": real_ch,
        "verifies_with_public_key_hex": pub,
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": pub}},
    }
    out[V / "evidence-ref/valid-minimal.json"] = {"evidence": []}
    ref_hmac = dict(
        ref, signature=hsig, content_hash=CH, ledger_ref="pai-ledger:head", item_id="O5"
    )
    out[V / "evidence-ref/valid-hmac-ref.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "evidence": [ref_hmac],
    }

    invalid = [
        (
            "invalid-missing-field",
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "evidence": [{k: v for k, v in ref.items() if k != "ledger_ref"}],
            },
            "evidence ref missing required field ledger_ref",
        ),
        (
            "invalid-wrong-schema-id",
            {"schema": "presidio-hardened/evidence-ref@2", "evidence": []},
            "unknown schema major must be rejected (fail-closed)",
        ),
        (
            "invalid-uppercase-hex",
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "evidence": [dict(ref, content_hash=real_ch.upper())],
            },
            "content_hash must be lowercase hex",
        ),
        (
            "invalid-empty-field",
            {"schema": "presidio-hardened/evidence-ref@1", "evidence": [dict(ref, signer="")]},
            "fields must be non-empty",
        ),
        (
            "invalid-null-byte",
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "evidence": [dict(ref, source="a\x00b")],
            },
            "null bytes forbidden",
        ),
        (
            "invalid-oversize-field",
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "evidence": [dict(ref, item_id="x" * 513)],
            },
            "fields must be ≤512 chars",
        ),
        (
            "invalid-evidence-not-array",
            {"schema": "presidio-hardened/evidence-ref@1", "evidence": {}},
            "'evidence' must be an array",
        ),
        (
            "invalid-non-hex-signature",
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "evidence": [dict(ref, signature="not-hex!")],
            },
            "signature must be lowercase hex",
        ),
    ]
    for name, doc, why in invalid:
        out[V / f"evidence-ref/{name}.json"] = {"_reason": why, "document": doc}

    out[V / "trust-store/valid.json"] = {
        "presidio-hardened-ai": {"alg": "ed25519", "public_key": pub},
        "rotating-signer": {"alg": "ed25519", "public_key": [pub, "aa" * 32]},
        "legacy-hmac-bare": "shared-key",
        "hmac-object": {"alg": "hmac-sha256", "key": ["shared-key", "old-key"]},
    }
    for name, doc, why in [
        ("invalid-unknown-alg", {"s": {"alg": "rsa-pss", "public_key": pub}}, "unknown alg"),
        (
            "invalid-empty-keylist",
            {"s": {"alg": "ed25519", "public_key": []}},
            "key list must be non-empty",
        ),
        ("invalid-missing-key", {"s": {"alg": "ed25519"}}, "key material required"),
    ]:
        out[V / f"trust-store/{name}.json"] = {"_reason": why, "document": doc}

    # Schema-valid trust stores the verifier must still read safely (audit
    # 2026-10-25): public_key is Ed25519 material and never an HMAC secret.
    # A forger who knows the public key computes HMAC(public_key, message).
    forged = hmaclib.new(pub.encode(), msg, hashlib.sha256).hexdigest()
    out[V / "trust-store/rejected-hmac-with-public-key.json"] = {
        "_reason": (
            "public_key under alg hmac-sha256 is rejected at load: a published public "
            "key must never act as a shared HMAC secret"
        ),
        "document": {SIGNER: {"alg": "hmac-sha256", "public_key": pub}},
    }
    out[V / "trust-store/public-key-implies-ed25519.json"] = {
        "_reason": (
            "an entry with public_key and no alg is Ed25519: the golden Ed25519 "
            "signature verifies, and an HMAC forged with the public key as secret does not"
        ),
        "document": {SIGNER: {"public_key": pub}},
        "content_hash": CH,
        "signer": SIGNER,
        "verifies": {"signature_hex": sig},
        "must_not_verify": {"signature_hex": forged},
    }

    # ------------------------------------------------------------------
    # Provenance-parents convention (ADR-0002, Accepted 2026-07-02) and the
    # ikigov-assess T-B4 workshop-attestation. Two append-only golden vectors
    # that also demonstrate the DAG edge: the attestation's `parents` (and
    # `attests`) point at the training-run payload's content hash. Both wrap a
    # parents-bearing payload in the frozen evidence-ref@1 envelope (untouched;
    # lineage lives inside the signed attested_content per ADR-0002 P1), signed
    # with the family test key (PRIV 01*32). Signer identity is a per-producer
    # label bound into the signed message; the key is the shared test fixture.
    ATX_SIGNER = "presidio-hardened-arch-translucency"
    ASSESSOR_SIGNER = "presidio-hardened-ikigov-assess"
    GOLDEN_PARENT = "a" * 64  # matches arch-translucency test _PARENT

    # (a) presidio-hardened/training-run@1 Layer-0 payload, parents-bearing.
    # attested_content shape and key set match arch-translucency's
    # build_training_run_reading + its test_training_run_content_hash_is_stable
    # golden-ish vector (evidence_producer.py); this vector supersedes that
    # self-generated hash test as the family reference.
    tr_content = {
        "run_id": "golden-run",
        "strategy": "pipeline",
        "degree": 4,
        "samples_per_second": 250,
        "duration_s": 7200,
        "device_count": 4,
        "parents": [GOLDEN_PARENT],
    }
    tr_ch = hashlib.sha256(cb(tr_content)).hexdigest()
    tr_sig = sk.sign(cb({"content_hash": tr_ch, "signer": ATX_SIGNER})).hex()
    tr_reading = {
        "schema": "presidio-hardened/training-run@1",
        "attested_content": tr_content,
        "content_hash": tr_ch,
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
    }
    tr_ref = {
        "item_id": "training-run/golden-run",
        "source": ATX_SIGNER,
        "source_version": "test",
        "ledger_ref": "atx-ledger:seq/1",
        "content_hash": tr_ch,
        "signer": ATX_SIGNER,
        "signature": tr_sig,
        "claimed_at": "2026-07-02T00:00:00+00:00",
    }
    out[V / "training-run/valid-envelope.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "training-run-provenance",
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
        "evidence": [tr_ref],
    }
    out[V / "training-run/valid-envelope.notes.json"] = {
        "description": (
            "Companion to training-run/valid-envelope.json. ADR-0002 "
            "parents-bearing presidio-hardened/training-run@1 Layer-0 payload "
            "(shape per arch-translucency build_training_run_reading). "
            "layer0_reading is the unsigned producer record; signed_content is "
            "its attested_content, whose canonical sha256 is expected_content_hash "
            "= evidence[0].content_hash. `parents` is inside the hashed content, "
            "so rewiring lineage breaks both the hash and the signature."
        ),
        "layer0_reading": tr_reading,
        "signed_content": tr_content,
        "expected_content_hash": tr_ch,
        "verifies_with_public_key_hex": pub,
        "trust_store": {ATX_SIGNER: {"alg": "ed25519", "public_key": pub}},
    }

    # (a.energy) The v0.23 energy-bearing shape of training-run@1: the OPTIONAL
    # energy_wh / mean_power_w fields added to the (a) payload and NOTHING else.
    # Producer claims under the v0.18 trust boundary (PRESIDIO-REQ Energy Arc
    # E1a), never observation-chain readings. Additive & conditional (ADR-0011):
    # a record WITHOUT these fields re-hashes byte-identically to (a) — absent
    # fields never perturb the canonical bytes — so the existing vector stays the
    # no-energy pin and this is purely additive. String-decimals on the wire
    # (ADR-0001 D1: floats rejected; shortest IEEE-754 round-trip). Physically
    # coherent with duration_s: 7200 s == 2 h at 420 W == 840 Wh (the v0.23.0
    # release audit fixed an earlier incoherent draft). Byte-for-byte cross-check
    # against arch-translucency test_training.py::
    # test_training_run_energy_bearing_self_pin (content hash d674a115…): pat
    # swaps its local self-pin for THIS family vector (L-EV-7).
    tr_energy_content = dict(tr_content)
    tr_energy_content["energy_wh"] = "840.0"
    tr_energy_content["mean_power_w"] = "420.0"
    tr_energy_ch = hashlib.sha256(cb(tr_energy_content)).hexdigest()
    tr_energy_sig = sk.sign(cb({"content_hash": tr_energy_ch, "signer": ATX_SIGNER})).hex()
    tr_energy_reading = {
        "schema": "presidio-hardened/training-run@1",
        "attested_content": tr_energy_content,
        "content_hash": tr_energy_ch,
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
    }
    tr_energy_ref = {
        "item_id": "training-run/golden-run-energy",
        "source": ATX_SIGNER,
        "source_version": "test",
        "ledger_ref": "atx-ledger:seq/1",
        "content_hash": tr_energy_ch,
        "signer": ATX_SIGNER,
        "signature": tr_energy_sig,
        "claimed_at": "2026-07-02T00:00:00+00:00",
    }
    out[V / "training-run/valid-envelope-energy.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "training-run-provenance",
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
        "evidence": [tr_energy_ref],
    }
    out[V / "training-run/valid-envelope-energy.notes.json"] = {
        "description": (
            "Companion to training-run/valid-envelope-energy.json. The v0.23 "
            "energy-bearing shape of presidio-hardened/training-run@1: the "
            "OPTIONAL energy_wh / mean_power_w fields (producer claims under the "
            "v0.18 trust boundary, PRESIDIO-REQ Energy Arc E1a) added to the "
            "training-run/valid-envelope payload and nothing else. Additive & "
            "conditional (ADR-0011): a record WITHOUT them re-hashes "
            "byte-identically to training-run/valid-envelope — absent fields "
            "never perturb the canonical bytes — so `no_energy_content_hash` "
            "here equals that vector's hash. energy_wh / mean_power_w are "
            "shortest-round-trip decimal STRINGS, never floats (ADR-0001 D1), and "
            "physically coherent with duration_s (7200 s == 2 h at 420 W == 840 "
            "Wh). Byte-for-byte cross-checked against arch-translucency "
            "test_training.py::test_training_run_energy_bearing_self_pin (content "
            "hash d674a115…): pat swaps its local self-pin for THIS family vector "
            "(L-EV-7)."
        ),
        "layer0_reading": tr_energy_reading,
        "signed_content": tr_energy_content,
        "expected_content_hash": tr_energy_ch,
        "energy_fields_are_additive_optional": True,
        "no_energy_content_hash": tr_ch,
        "verifies_with_public_key_hex": pub,
        "trust_store": {ATX_SIGNER: {"alg": "ed25519", "public_key": pub}},
    }

    # (b) presidio-hardened/workshop-attestation@1 — the schema freeze for @1
    # (ikigov-assess PRESIDIO-REQ v0.22.0 T-B4). ASCII-only, float-free, no
    # integers. `attests` and `parents[0]` both point at (a)'s content hash,
    # activating the provenance DAG (edge documents, evidence backlog L-EV-6).
    wa_content = {
        "role": "assessor",
        "attests": tr_ch,
        "parents": [tr_ch],
        "engagement": "eng-golden-001",
        "scope": "facilitation + methodology conformance",
        "workshop_date": "2026-07-02",
    }
    wa_ch = hashlib.sha256(cb(wa_content)).hexdigest()
    wa_sig = sk.sign(cb({"content_hash": wa_ch, "signer": ASSESSOR_SIGNER})).hex()
    wa_reading = {
        "schema": "presidio-hardened/workshop-attestation@1",
        "attested_content": wa_content,
        "content_hash": wa_ch,
        "source": ASSESSOR_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
    }
    wa_ref = {
        "item_id": "workshop-attestation/eng-golden-001",
        "source": ASSESSOR_SIGNER,
        "source_version": "test",
        "ledger_ref": "iga-ledger:seq/1",
        "content_hash": wa_ch,
        "signer": ASSESSOR_SIGNER,
        "signature": wa_sig,
        "claimed_at": "2026-07-02T00:00:00+00:00",
    }
    out[V / "workshop-attestation/valid-envelope.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "workshop-attestation",
        "source": ASSESSOR_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
        "evidence": [wa_ref],
    }
    out[V / "workshop-attestation/valid-envelope.notes.json"] = {
        "description": (
            "Companion to workshop-attestation/valid-envelope.json. Schema freeze "
            "for presidio-hardened/workshop-attestation@1 (ikigov-assess T-B4): a "
            "presidio-as-assessor countersignature. `attests` and `parents[0]` are "
            "the content_hash of training-run/valid-envelope.json's payload — the "
            "DAG edge (ADR-0002). signed_content's canonical sha256 is "
            "expected_content_hash = evidence[0].content_hash. ASCII-only, "
            "float-free, no integers."
        ),
        "layer0_reading": wa_reading,
        "signed_content": wa_content,
        "expected_content_hash": wa_ch,
        "attests_parent_content_hash": tr_ch,
        "verifies_with_public_key_hex": pub,
        "trust_store": {ASSESSOR_SIGNER: {"alg": "ed25519", "public_key": pub}},
    }

    # ------------------------------------------------------------------
    # Consumer coverage arc (2026-07-03): one golden vector per consumer
    # surface that previously had none. Appended after the Rust lane's first
    # green run (ADR-0001 D2 satisfied — both suites gate every vector).
    # All payloads stay inside the proven conformance envelope: ASCII-only,
    # float-free, integers within i64.
    # ------------------------------------------------------------------

    # (c) ikigov-assess: presidio-hardened/workshop-leavebehind@1, OWNER-signed
    # (T-B4 R1). Two profiles coexist by design and this vector pins both:
    #   - the manifest's canonical sha256 (what a workshop-attestation@1
    #     `attests`/`parents[0]` references — the DAG edge target), and
    #   - the OWNER signature: Ed25519 over the RAW canonical manifest bytes
    #     (T-B3 manifest.sig profile; NOT the family {content_hash, signer}
    #     message — the manifest is a document the customer signs whole,
    #     not an evidence ref).
    # The customer key is a second well-known test fixture: priv 02*32.
    CUSTOMER_PRIV = "02" * 32
    csk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(CUSTOMER_PRIV))
    customer_pub = csk.public_key().public_bytes_raw().hex()
    wl_manifest = {
        "schema": "presidio-hardened/workshop-leavebehind@1",
        "tool": "presidio-hardened-ikigov-assess",
        "tool_version": "test",
        "use_case_id": "golden-uc",
        "cell": "T2-L3",
        "risk_class": "high",
        "lang": "de",
        "generated_at": "2026-07-02T00:00:00Z",
        "pack": {
            "framework_id": "iki-gov",
            "version": "test",
            "content_hash": "b" * 64,
        },
        "artifacts": {
            "report.de.md": {"sha256": hashlib.sha256(b"golden report md").hexdigest()},
            "report.json": {"sha256": hashlib.sha256(b"golden report json").hexdigest()},
        },
        "signed": True,
        "UNSIGNED": False,
        "owner": {
            "signer": "Golden Customer GmbH",
            "public_key": customer_pub,
            "signed_at": "2026-07-02T00:00:00+00:00",
        },
    }
    wl_bytes = cb(wl_manifest)
    wl_ch = hashlib.sha256(wl_bytes).hexdigest()
    wl_owner_sig = csk.sign(wl_bytes).hex()
    out[V / "workshop-leavebehind/valid-manifest.json"] = wl_manifest
    out[V / "workshop-leavebehind/valid-manifest.notes.json"] = {
        "description": (
            "Companion to workshop-leavebehind/valid-manifest.json. Owner-signed "
            "presidio-hardened/workshop-leavebehind@1 manifest (ikigov-assess "
            "T-B4 R1: customer anchors). The `owner` block is additive-optional "
            "within @1 (ADR-0001 D5) and lives INSIDE the signed content. Two "
            "profiles pinned: expected_content_hash is the canonical sha256 of "
            "the manifest (the value a workshop-attestation@1 `attests` would "
            "carry — the ADR-0002 DAG edge target); owner_signature is Ed25519 "
            "over the RAW canonical manifest bytes (manifest.sig profile, not "
            "the family {content_hash, signer} message). Customer test key: "
            "priv 02*32 — a cross-repo fixture, not a secret."
        ),
        "expected_content_hash": wl_ch,
        "owner_signature": wl_owner_sig,
        "manifest_sig_file": {
            "alg": "ed25519",
            "role": "owner",
            "signer": "Golden Customer GmbH",
            "signature": wl_owner_sig,
        },
        "owner_signs_message": "raw canonical manifest bytes",
        "verifies_with_public_key_hex": customer_pub,
        "customer_private_key_hex_test_fixture": CUSTOMER_PRIV,
        "attestation_would_attest": wl_ch,
    }

    # (d) x402: presidio-hardened/slo-reading@1 Layer-0 degradation reading +
    # its signed evidence-ref@1 envelope — the pat -> signing-bridge -> x402
    # SLO payment broker chain (v0.17.0/v0.7.0). item_id and ledger_ref match
    # arch-translucency build_slo_evidence exactly; x402's
    # ArchTranslucencyAdapter verifies this envelope fail-closed before paying.
    slo_content = {
        "slo": "p99_latency_ms",
        "value": 420,
        "threshold": 200,
        "window": "5m",
    }
    slo_ch = hashlib.sha256(cb(slo_content)).hexdigest()
    slo_sig = sk.sign(cb({"content_hash": slo_ch, "signer": ATX_SIGNER})).hex()
    slo_reading = {
        "schema": "presidio-hardened/slo-reading@1",
        "attested_content": slo_content,
        "content_hash": slo_ch,
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
    }
    slo_ref = {
        "item_id": "SLO-DEGRADED",
        "source": ATX_SIGNER,
        "source_version": "test",
        "ledger_ref": "arch-translucency:obs",
        "content_hash": slo_ch,
        "signer": ATX_SIGNER,
        "signature": slo_sig,
        "claimed_at": "2026-07-02T00:00:00+00:00",
    }
    out[V / "slo-reading/valid-envelope.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "slo-degradation",
        "source": ATX_SIGNER,
        "source_version": "test",
        "generated_at": "2026-07-02T00:00:00+00:00",
        "evidence": [slo_ref],
    }
    out[V / "slo-reading/valid-envelope.notes.json"] = {
        "description": (
            "Companion to slo-reading/valid-envelope.json. The x402 consumer "
            "vector: a presidio-hardened/slo-reading@1 Layer-0 degradation "
            "reading (key-less, emitted by `pat evidence-emit`; degraded means "
            "value > threshold) signed into an evidence-ref@1 envelope by the "
            "bridge sidecar. item_id SLO-DEGRADED and ledger_ref match "
            "arch-translucency build_slo_evidence; presidio-hardened-x402's "
            "SLO payment broker verifies this envelope fail-closed (wrong key "
            "or tamper => reject, do not pay) before purchasing capacity."
        ),
        "layer0_reading": slo_reading,
        "signed_content": slo_content,
        "expected_content_hash": slo_ch,
        "degraded": True,
        "verifies_with_public_key_hex": pub,
        "trust_store": {ATX_SIGNER: {"alg": "ed25519", "public_key": pub}},
    }

    # (e) treasury: treasury-close/checkpoint/v1 — LAYER 0 ONLY by design
    # (ADR-0001 D1: no Ed25519 grafted onto the keyless dual-control model;
    # "no secrets to steal"). Pins content addressing: the checkpoint id is
    # the sha256 of the canonical envelope, including null-valued optional
    # fields and integer-nanosecond timestamps (within i64).
    ckpt_envelope = {
        "schema": "treasury-close/checkpoint/v1",
        "tenant": "acme",
        "period": "2026Q2",
        "as_of": 1780000000000000000,
        "sealed_at": 1780000000000000100,
        "state_root": "05" * 32,
        "supersedes": None,
        "reason": None,
        "materiality_memo": None,
    }
    ckpt_id = hashlib.sha256(cb(ckpt_envelope)).hexdigest()
    out[V / "treasury-checkpoint/valid-checkpoint.json"] = ckpt_envelope
    out[V / "treasury-checkpoint/valid-checkpoint.notes.json"] = {
        "description": (
            "Companion to treasury-checkpoint/valid-checkpoint.json. The "
            "treasury consumer vector, Layer 0 ONLY (ADR-0001 D1): "
            "treasury-close/checkpoint/v1 checkpoint identity = sha256 over "
            "the canonical envelope (sorted keys, compact separators, floats "
            "rejected, nulls preserved, i64 nanosecond timestamps). No "
            "signature by design — treasury's trust model is content "
            "addressing + dual-control approval (preparer != approver), not "
            "key material. Shape matches treasury-close checkpoint.rs "
            "compute_id."
        ),
        "expected_checkpoint_id": ckpt_id,
        "layer": 0,
        "signature": None,
    }

    # ------------------------------------------------------------------
    # evidence-ref@2 — assurance tiers (ADR-0003, Accepted). Additive to @1:
    # the envelope `schema` field is now REQUIRED (no grandfathering in @2) and
    # each evidenceRef MAY carry an optional `assurance_tier` in
    # ("attested", "optimistic", "zk"); absent means "attested" (the implicit
    # @1 tier). What gets SIGNED is unchanged — the detached signature still
    # covers canonical({content_hash, signer}); the tier is not part of that
    # message. The @2 refs below reuse the @1 golden content/signature (CH,
    # real_sig over the fraud-scoring content) verbatim to make that explicit.
    # Append-only: these are new files; no @1 vector is touched.
    # ------------------------------------------------------------------
    v2_base_ref = {
        "item_id": "D1",
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "ledger_ref": "pai-ledger:seq/1",
        "content_hash": real_ch,
        "signer": SIGNER,
        "signature": real_sig,
        "claimed_at": "2026-06-12T00:00:00+00:00",
    }

    def v2_envelope(refs: list[dict]) -> dict:
        return {
            "schema": "presidio-hardened/evidence-ref@2",
            "use_case": "fraud-scoring",
            "source": "presidio-hardened-ai",
            "source_version": "0.30.0",
            "generated_at": "2026-06-12T00:00:00+00:00",
            "evidence": refs,
        }

    # One valid @2 envelope carrying one ref per explicit tier value.
    out[V / "evidence-ref-v2/valid-tiers.json"] = v2_envelope(
        [
            dict(v2_base_ref, item_id="D1-attested", assurance_tier="attested"),
            dict(v2_base_ref, item_id="D2-optimistic", assurance_tier="optimistic"),
            dict(v2_base_ref, item_id="D3-zk", assurance_tier="zk"),
        ]
    )
    out[V / "evidence-ref-v2/valid-tiers.notes.json"] = {
        "description": (
            "Companion to valid-tiers.json (ADR-0003). One valid "
            "presidio-hardened/evidence-ref@2 envelope carrying one ref per "
            "explicit assurance_tier value (attested, optimistic, zk). Every "
            "ref reuses the @1 golden content_hash/signature verbatim: the "
            "signature covers canonical({content_hash, signer}) exactly as in "
            "@1, so declaring a tier does not change what is signed. "
            "optimistic and zk name an assurance TARGET; fraud-proof and "
            "ZK-proof verification are out of scope of this repo (ADR-0003)."
        ),
        "signed_content": content,
        "expected_content_hash": real_ch,
        "verifies_with_public_key_hex": pub,
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": pub}},
        "tier_default_when_absent": "attested",
    }

    # A valid @2 envelope whose single ref OMITS assurance_tier — documents the
    # default ("attested"), and pins that the field is genuinely optional in @2.
    out[V / "evidence-ref-v2/valid-tier-absent.json"] = v2_envelope([dict(v2_base_ref)])
    out[V / "evidence-ref-v2/valid-tier-absent.notes.json"] = {
        "description": (
            "Companion to valid-tier-absent.json (ADR-0003). A valid "
            "evidence-ref@2 envelope whose evidence[0] omits assurance_tier. "
            "assurance_tier is OPTIONAL in @2; when absent the tier is "
            "'attested' — identical assurance to every @1 record. Consumers "
            "read the tier through the library default, not the wire bytes."
        ),
        "signed_content": content,
        "expected_content_hash": real_ch,
        "resolved_assurance_tier": "attested",
        "verifies_with_public_key_hex": pub,
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": pub}},
    }

    # ------------------------------------------------------------------
    # (f) arch-translucency: presidio-hardened/energy-reading@1 — RESERVATION
    # for the pat Energy Arc v0.24.0 "Sign the watt" (pat PRESIDIO-REQ L-EN-4).
    # Key-less Layer-0 reading under the frozen evidence-ref@1 envelope (the
    # v0.17 pattern: producer emits unsigned, sidecar signs). Purely additive —
    # no envelope change, no existing vector touched.
    #
    # `energy_chain_head` is the head of pat's chained energy_observations store
    # (pat ADR-0011 §2, a parallel chain with the ADR-0010 discipline). It is
    # the discharge of the ADR-0010 external-anchoring deferral: each signed
    # reading attests the unrewritten history behind it. The family treats it as
    # an OPAQUE lowercase-hex sha256 — this repo pins the hex discipline, not
    # pat's chain semantics. The golden value below is a deterministic
    # placeholder built with the ADR-0010 record-hash shape
    # (sha256(canonical({content, prev_hash, seq})), genesis prev_hash "0"*64).
    #
    # Float discipline: joules/watts never cross the wire as floats (ADR-0001
    # D1 rejects them). energy_wh / mean_power_w are shortest-round-trip decimal
    # STRINGS. Payload is ASCII-only, float-free and integer-free.
    #
    # Field shape settled by the maintainer on PR #14 (2026-07-13):
    #   - no payload-internal type id: the Layer-0 wrapper's `schema` is
    #     authoritative, and no other family payload repeats its own type inside
    #     the signed content (a duplicate invites skew between the two);
    #   - `meter` (not `source`) names the measuring device, so it cannot collide
    #     with the family `source` (= producer repo) at the wrapper/envelope
    #     levels. Enum is MEASURED sources only — "analytic" was removed: per pat
    #     invariant E1a ("pat never signs a watt it did not measure"), modelled
    #     energy is never a *reading*;
    #   - `layer` XOR `strategy`: two optional fields, exactly one present,
    #     validated fail-closed in both lanes. `layer` is a pat serving layer;
    #     `strategy` is a training strategy, reusing training-run@1's name.
    ENERGY_GENESIS = "0" * 64
    energy_chain_head = hashlib.sha256(
        cb({"content": {"golden": "energy-observation"}, "prev_hash": ENERGY_GENESIS, "seq": 1})
    ).hexdigest()

    def energy_vectors(
        stem: str,
        item_id: str,
        use_case: str,
        content: dict,
        description: str,
        extra_notes: dict | None = None,
    ) -> None:
        # Fail closed at generation: a vector that violates the settled shape is
        # never written, so the contract cannot drift in through the generator.
        _validate_energy_content(content)

        ch = hashlib.sha256(cb(content)).hexdigest()
        sig = sk.sign(cb({"content_hash": ch, "signer": ATX_SIGNER})).hex()
        reading = {
            "schema": "presidio-hardened/energy-reading@1",
            "attested_content": content,
            "content_hash": ch,
            "source": ATX_SIGNER,
            "source_version": "test",
            "generated_at": "2026-07-02T00:00:00+00:00",
        }
        ref = {
            "item_id": item_id,
            "source": ATX_SIGNER,
            "source_version": "test",
            "ledger_ref": "atx-energy-ledger:seq/1",
            "content_hash": ch,
            "signer": ATX_SIGNER,
            "signature": sig,
            "claimed_at": "2026-07-02T00:00:00+00:00",
        }
        out[V / f"energy-reading/{stem}.json"] = {
            "schema": "presidio-hardened/evidence-ref@1",
            "use_case": use_case,
            "source": ATX_SIGNER,
            "source_version": "test",
            "generated_at": "2026-07-02T00:00:00+00:00",
            "evidence": [ref],
        }
        notes = {
            "description": description,
            "layer0_reading": reading,
            "signed_content": content,
            "expected_content_hash": ch,
            "energy_chain_head": content["energy_chain_head"],
            "energy_chain_head_is_opaque_to_family": True,
            "verifies_with_public_key_hex": pub,
            "trust_store": {ATX_SIGNER: {"alg": "ed25519", "public_key": pub}},
        }
        notes.update(extra_notes or {})
        out[V / f"energy-reading/{stem}.notes.json"] = notes

    # (f.1) Nominal: a 5-minute Kepler-sourced serving-layer reading, no parents.
    # 12.5 Wh over 300 s == 150.0 W mean — the two figures agree by construction,
    # and the conformance suites re-derive one from the other.
    energy_vectors(
        stem="valid-envelope",
        item_id="energy-reading/golden-window",
        use_case="energy-reading",
        content={
            "window_start": "2026-07-02T00:00:00+00:00",
            "window_end": "2026-07-02T00:05:00+00:00",
            "energy_wh": "12.5",
            "mean_power_w": "150.0",
            "meter": "kepler",
            "layer": "pod",
            "energy_chain_head": energy_chain_head,
        },
        description=(
            "Nominal presidio-hardened/energy-reading@1 Layer-0 reading (pat "
            "Energy Arc v0.24 'Sign the watt', L-EN-4) — RESERVED, not yet "
            "emitted by a shipped producer. A 5-minute serving-layer window "
            "measured by Kepler, key-lessly emitted by pat and signed into the "
            "frozen evidence-ref@1 envelope by the bridge sidecar (v0.17 "
            "pattern). Carries `layer` (a pat serving layer) and NOT `strategy` — "
            "exactly one of the two is always present. `parents` is absent — "
            "ADR-0002 P3 omits it when empty. The payload carries no type id of "
            "its own: the Layer-0 wrapper's `schema` is authoritative. `meter` "
            "names the measuring device and is deliberately distinct from the "
            "family `source` (= producer repo) at the wrapper/envelope levels. "
            "energy_wh and mean_power_w are shortest-round-trip decimal STRINGS, "
            "never floats (ADR-0001 D1): 12.5 Wh over 300 s == 150.0 W, and the "
            "conformance suites re-derive the mean power from the energy and the "
            "window. `energy_chain_head` is the head of pat's chained "
            "energy_observations store (pat ADR-0011 §2) — opaque here; this "
            "repo pins only the lowercase-hex discipline."
        ),
        extra_notes={"parents_present": False, "window_seconds": 300},
    )

    # (f.2) Parents-bearing: the ADR-0002 DAG edge. This reading covers exactly
    # the golden training run's window (duration_s 7200 == 2 h) and names its
    # payload as parent — "these are the joules that run cost". 4800 Wh over 2 h
    # == 2400.0 W == 4 devices (training-run device_count) at 600 W each.
    energy_vectors(
        stem="valid-envelope-parents",
        item_id="energy-reading/golden-training-window",
        use_case="energy-reading",
        content={
            "window_start": "2026-07-02T00:00:00+00:00",
            "window_end": "2026-07-02T02:00:00+00:00",
            "energy_wh": "4800.0",
            "mean_power_w": "2400.0",
            "meter": "dcgm",
            "strategy": "pipeline",
            "energy_chain_head": energy_chain_head,
            "parents": [tr_ch],
        },
        description=(
            "Parents-bearing presidio-hardened/energy-reading@1 (pat Energy Arc "
            "v0.24, L-EN-4) — RESERVED. The ADR-0002 DAG edge for the energy "
            "axis: `parents[0]` is the content hash of the training-run/ golden "
            "payload, so this reading says 'these are the joules that run cost'. "
            "This is a TRAINING window, so it carries `strategy` (not `layer`) — "
            "the same field name training-run@1 uses, holding the same value "
            "('pipeline'). The window matches that run exactly (duration_s 7200 "
            "== 2 h); 4800 Wh over 2 h == 2400.0 W == the run's 4 devices at 600 "
            "W each. Lineage lives inside the hashed content (ADR-0002 P1), so "
            "rewiring it breaks both the content hash and the signature. "
            "DCGM-metered (the accelerator device, per the v0.23 'Train the watt' "
            "theme)."
        ),
        extra_notes={
            "parents_present": True,
            "window_seconds": 7200,
            "parent_content_hash": tr_ch,
            "parent_vector": "vectors/training-run/valid-envelope.json",
        },
    )

    v2_invalid = [
        (
            "invalid-unknown-tier",
            v2_envelope([dict(v2_base_ref, assurance_tier="quantum")]),
            "assurance_tier must be one of attested/optimistic/zk (unknown value rejected)",
        ),
        (
            "invalid-missing-schema",
            {
                "use_case": "fraud-scoring",
                "source": "presidio-hardened-ai",
                "source_version": "0.30.0",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "evidence": [dict(v2_base_ref)],
            },
            "schema field is REQUIRED in @2 (no grandfathering) — envelope without it rejected",
        ),
        (
            "invalid-wrong-schema-id",
            dict(v2_envelope([dict(v2_base_ref)]), schema="presidio-hardened/evidence-ref@1"),
            "@2 validator rejects any schema id other than evidence-ref@2 (fail-closed)",
        ),
    ]
    for name, doc, why in v2_invalid:
        out[V / f"evidence-ref-v2/{name}.json"] = {"_reason": why, "document": doc}

    # An @1 record carrying assurance_tier. ADR-0001 D5 freezes @1 but the @1
    # schema sets no additionalProperties:false and the @1 verifier ignores
    # unknown keys, so an extra field is TOLERATED under @1 (it is neither a
    # field removal, a type/constraint change, nor a new required field). This
    # vector is validated against evidence-ref.v1.schema.json and PASSES; it
    # documents that the tier is silently ignored by @1 consumers (they read
    # the implicit "attested"). Filed under evidence-ref-v2/ as a v1-vs-v2
    # boundary case; the finding is recorded in ADR-0003.
    out[V / "evidence-ref-v2/valid-v1-with-extra-tier.json"] = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "fraud-scoring",
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "generated_at": "2026-06-12T00:00:00+00:00",
        "evidence": [dict(v2_base_ref, assurance_tier="optimistic")],
    }
    out[V / "evidence-ref-v2/valid-v1-with-extra-tier.notes.json"] = {
        "description": (
            "Boundary case (ADR-0003 extra-field finding). An "
            "evidence-ref@1 envelope whose ref carries assurance_tier. The @1 "
            "schema declares no additionalProperties:false and the @1 verifier "
            "ignores unknown keys, so this document is VALID under "
            "evidence-ref.v1.schema.json — an extra field is not a field "
            "removal, type/constraint change, or new required field, so it "
            "does not violate the @1 freeze (ADR-0001 D5). @1 consumers ignore "
            "the tier and read the implicit 'attested'. Producers that want the "
            "tier honoured emit @2. Validated against the @1 schema, expected "
            "to PASS."
        ),
        "validated_against": "evidence-ref.v1.schema.json",
        "expected": "valid (extra field tolerated under @1)",
        "tier_visible_to_v1_consumer": False,
        "resolved_assurance_tier_for_v1_consumer": "attested",
    }

    out.update(_numeric_encoding_vectors())
    out.update(_gate_certificate_vectors(sk, pub, ATX_SIGNER, ASSESSOR_SIGNER))
    out.update(_cloud_posture_vectors(sk, pub))
    out.update(_v3_vectors(sk, pub))

    return out


# ----------------------------------------------------------------------
# (g) Numeric payload encoding (ADR-0005, Proposed). Non-integer numbers in
# signed payloads are decimal strings in plain notation. The expected results
# below are written out by hand, not computed by the library, so the vectors
# judge the implementation rather than echo it.
# ----------------------------------------------------------------------
NUMERIC_PRECISION = 6


def _numeric_encoding_vectors() -> dict[pathlib.Path, dict]:
    p = NUMERIC_PRECISION

    def case(name: str, value: object, valid: bool, reason: str, **extra: object) -> dict:
        entry = {"name": name, "value": value, "precision": extra.pop("precision", p)}
        entry.update(extra)
        entry.update({"valid": valid, "reason": reason})
        return entry

    validate = [
        case("small-fraction", "0.00001", True, "plain notation, 5 fractional digits <= 6"),
        case("integral", "12", True, "integral value: no point, no fraction"),
        case("zero", "0", True, "the one spelling of zero"),
        case("negative-fraction", "-12.5", True, "leading '-' allowed"),
        case("negative-below-one", "-0.5", True, "one digit '0' before the point"),
        case("at-precision", "3.141593", True, "6 fractional digits == precision"),
        case("precision-zero-integral", "42", True, "precision 0 admits integers", precision=0),
        case(
            "sentinel-declared",
            "unbounded",
            True,
            "schema-declared sentinel (ADR-0005)",
            sentinels=["unbounded"],
        ),
        case("exponent-lower", "1e-05", False, "exponent notation (Python repr of 1e-05)"),
        case("exponent-upper", "1E+16", False, "exponent notation"),
        case("trailing-zero", "12.0", False, "trailing zero (the one spelling is 12)"),
        case("trailing-zeros-fraction", "0.50", False, "trailing zero in the fraction"),
        case("trailing-point", "5.", False, "trailing decimal point"),
        case("no-leading-digit", ".5", False, "at least one digit before the point"),
        case("leading-zero", "01.5", False, "leading zero before a non-zero integer part"),
        case("plus-sign", "+1", False, "only '-' is allowed as a sign"),
        case(
            "negative-zero",
            "-0",
            False,
            "negative zero is not a canonical spelling; zero is '0' (ADR-0005 defines this)",
        ),
        case("negative-zero-fraction", "-0.0", False, "negative zero with a trailing zero"),
        case("bare-minus", "-", False, "no digits"),
        case("empty", "", False, "no digits"),
        case("nan", "NaN", False, "NaN is rejected"),
        case("infinity", "Infinity", False, "Infinity is rejected; use a declared sentinel"),
        case("neg-infinity", "-Infinity", False, "-Infinity is rejected"),
        case("inf-short", "inf", False, "IEEE special spelling is not a number"),
        case(
            "sentinel-undeclared",
            "unbounded",
            False,
            "a sentinel is admitted only where the schema declares it",
        ),
        case("too-precise", "0.0000001", False, "7 fractional digits > precision 6"),
        case(
            "precision-zero-fraction", "0.5", False, "precision 0 admits no fraction", precision=0
        ),
        case("comma-separator", "1,5", False, "only '.' separates the fraction"),
        case("leading-space", " 1", False, "no surrounding whitespace"),
        case("trailing-newline", "1\n", False, "no surrounding whitespace"),
        case("fullwidth-digit", "１", False, "ASCII digits only"),
        case("json-number", 12, False, "a decimal field is a JSON string, never a number"),
        case(
            "grandfathered-ieee-repr",
            "840.0",
            False,
            "the shortest-round-trip IEEE form of training-run@1 energy_wh; valid only in the "
            "grandfathered fields named in ADR-0005, never in a new field",
        ),
        case("over-length", "1" * 513, False, "longer than the 512-char family string bound"),
    ]
    encode = [
        {"input": "0.00001", "precision": 6, "expected": "0.00001"},
        {"input": "1e-05", "precision": 6, "expected": "0.00001"},
        {"input": "12.0", "precision": 6, "expected": "12"},
        {"input": 12, "precision": 2, "expected": "12"},
        {"input": "840.0", "precision": 2, "expected": "840"},
        {"input": "0.125", "precision": 2, "expected": "0.12"},
        {"input": "0.135", "precision": 2, "expected": "0.14"},
        {"input": "2.5", "precision": 0, "expected": "2"},
        {"input": "3.5", "precision": 0, "expected": "4"},
        {"input": "-1.005", "precision": 2, "expected": "-1"},
        {"input": "-0.001", "precision": 2, "expected": "0"},
        {"input": "-0", "precision": 6, "expected": "0"},
        {"input": "1e-7", "precision": 6, "expected": "0"},
        {"input": "1E+3", "precision": 6, "expected": "1000"},
        {"input": "123456789.987654321", "precision": 6, "expected": "123456789.987654"},
        {"input": "0.0000005", "precision": 6, "expected": "0"},
        {"input": "0.0000015", "precision": 6, "expected": "0.000002"},
    ]
    encode_rejected = [
        {"input": "NaN", "reason": "NaN is rejected at the producer"},
        {"input": "Infinity", "reason": "Infinity is rejected; use a declared sentinel"},
        {"input": "-Infinity", "reason": "-Infinity is rejected"},
        {"input": "sNaN", "reason": "signalling NaN is rejected"},
        {"input": "twelve", "reason": "not a number"},
    ]
    return {
        V / "numeric-encoding/vectors.json": {
            "description": (
                "ADR-0005 numeric payload encoding. Non-integer numeric values in signed "
                "payloads are decimal strings in plain notation: no exponent, no trailing "
                "zeros, no trailing point, optional leading '-', at least one ASCII digit "
                "before the point, no leading zeros, no negative zero. Each schema declares "
                "a precision per field (maximum fractional digits); producers round "
                "half-even to it before encoding. 'validate' cases are verifier-side: a "
                "byte-wise grammar check, never a float parse. 'encode' cases are "
                "producer-side: input -> canonical string. 'encode_rejected' inputs must "
                "fail at the producer. canonical-json@1 is unchanged."
            ),
            "grammar": "-?(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?, excluding '-0'",
            "max_length": 512,
            "recommended_unbounded_sentinel": "unbounded",
            "validate": validate,
            "encode": encode,
            "encode_rejected": encode_rejected,
        }
    }


# ----------------------------------------------------------------------
# (h) gate-certificate@1 identity (ADR-0006, Proposed). A sample certificate as
# presidio-hardened-ikigov-assess build_certificate() + sign() emit it, signed
# with the family test key. Its identity is sha256 over canonical-json@1 of the
# document minus `signature` -- the bytes the issuer signs. A second vector is a
# training-run@1 reading whose parents[0] is that identity: the ADR-0002 edge
# from a training run to the gate decision that admitted it.
#
# Cross-checked at creation (2026-10-18) against ikigov-assess v0.28.0:
# build_certificate() with these inputs yields this document minus `signature`
# byte for byte, sha256(certificate.signing_bytes(doc)) equals the identity,
# and verify_certificate(doc, trust, now=2026-07-03) returns ok.
# ----------------------------------------------------------------------
#: ikigov-assess v0.28.0 gate_predicate_content_hash(). Opaque here: ikigov
#: hashes float risk weights with a non-strict canonicaliser, so this repo cannot
#: recompute it (open point in ADR-0005/ADR-0006).
IKIGOV_PREDICATE_HASH = "c359f71130ecdfc34e7b90e835ad02453360721ef330f3479868f5dd7b9773ef"


def _gate_certificate_vectors(
    sk: ed25519.Ed25519PrivateKey, pub: str, atx_signer: str, issuer: str
) -> dict[pathlib.Path, dict]:
    ref_signer = "presidio-hardened-ai"
    gate_items = ["S1", "S2", "S3"]
    affirmation_set = []
    for seq, item_id in enumerate(gate_items, start=1):
        content = {"item_id": item_id, "artefact": f"golden-{item_id.lower()}"}
        ch = hashlib.sha256(cb(content)).hexdigest()
        affirmation_set.append(
            {
                "id": item_id,
                "status": "affirmed",
                "evidence_ref": {
                    "content_hash": ch,
                    "signer": ref_signer,
                    "signature": sk.sign(cb({"content_hash": ch, "signer": ref_signer})).hex(),
                    "claimed_at": "2026-07-02T00:00:00+00:00",
                    "item_id": item_id,
                    "source": ref_signer,
                    "source_version": "0.30.0",
                    "ledger_ref": f"pai-ledger:seq/{seq}",
                    "assurance_tier": "attested",
                },
            }
        )
    classification_parent = "b" * 64  # placeholder eai-classification@1 payload hash
    unsigned = {
        "schema": "presidio-hardened/gate-certificate@1",
        "use_case": "golden-training-gate",
        "framework_content_hash": IKIGOV_PREDICATE_HASH,
        "gate": "G0",
        "risk_class": "medium",
        "decision": "OPEN",
        "assurance_tier": "attested",
        "grounding": "evidence-verified",
        "affirmation_set": affirmation_set,
        "predicate": {
            "gate_items": gate_items,
            "risk_class": "medium",
            "strict": False,
            "strict_effective": False,
            "predicate_content_hash": IKIGOV_PREDICATE_HASH,
        },
        "assessed_at": "2026-07-02T00:00:00Z",
        "issuer": issuer,
        "parents": [classification_parent],
        "not_after": "2027-07-02T00:00:00Z",
        "require_evidence": True,
    }
    signing_bytes = cb(unsigned)
    identity = hashlib.sha256(signing_bytes).hexdigest()
    certificate = dict(
        unsigned,
        signature={"alg": "ed25519", "signer": issuer, "sig": sk.sign(signing_bytes).hex()},
    )
    trust = {
        issuer: {"alg": "ed25519", "public_key": pub},
        ref_signer: {"alg": "ed25519", "public_key": pub},
    }

    run_content = {
        "run_id": "golden-gated-run",
        "strategy": "pipeline",
        "degree": 4,
        "samples_per_second": 250,
        "duration_s": 7200,
        "device_count": 4,
        "parents": [identity],
    }
    run_ch = hashlib.sha256(cb(run_content)).hexdigest()
    run_ref = {
        "item_id": "training-run/golden-gated-run",
        "source": atx_signer,
        "source_version": "test",
        "ledger_ref": "atx-ledger:seq/2",
        "content_hash": run_ch,
        "signer": atx_signer,
        "signature": sk.sign(cb({"content_hash": run_ch, "signer": atx_signer})).hex(),
        "claimed_at": "2026-07-02T00:00:00+00:00",
    }
    return {
        V / "gate-certificate/valid-certificate.json": certificate,
        V / "gate-certificate/valid-certificate.notes.json": {
            "description": (
                "Companion to gate-certificate/valid-certificate.json (ADR-0006). A "
                "presidio-hardened/gate-certificate@1 as ikigov-assess emits it: gate G0, "
                "all three items affirmed by Ed25519-signed evidence-refs, issuer-signed "
                "with the family test key (priv 01*32). identity = sha256(canonical-json@1 "
                "(document minus `signature`)) -- exactly the bytes the issuer signs "
                "(ikigov certificate.signing_bytes). A provenance parent that refers to "
                "this gate decision carries `identity`, not framework_content_hash: the "
                "predicate hash names the rule, the identity names the issuance. "
                "framework_content_hash is ikigov's value, opaque here. parents[0] is a "
                "placeholder eai-classification@1 hash. Cross-checked at creation against "
                "ikigov-assess v0.28.0 build_certificate/signing_bytes/verify_certificate."
            ),
            "signing_bytes_canonical": signing_bytes.decode("utf-8"),
            "identity": identity,
            "identity_excludes_signature": True,
            "predicate_content_hash": IKIGOV_PREDICATE_HASH,
            "verify_at": "2026-07-03T00:00:00Z",
            "cross_checked_against": "presidio-hardened-ikigov-assess v0.28.0",
            "trust_store": trust,
        },
        V / "gate-certificate/child-training-run.json": {
            "schema": "presidio-hardened/evidence-ref@1",
            "use_case": "training-run-provenance",
            "source": atx_signer,
            "source_version": "test",
            "generated_at": "2026-07-02T00:00:00+00:00",
            "evidence": [run_ref],
        },
        V / "gate-certificate/child-training-run.notes.json": {
            "description": (
                "A presidio-hardened/training-run@1 reading whose parents[0] is the "
                "identity of gate-certificate/valid-certificate.json: the ADR-0002 edge "
                "from a training run to the gate decision that admitted it (ADR-0006). "
                "The producer does not resolve the parent (ADR-0002 P4); it MAY verify "
                "the certificate before adding its identity."
            ),
            "layer0_reading": {
                "schema": "presidio-hardened/training-run@1",
                "attested_content": run_content,
                "content_hash": run_ch,
                "source": atx_signer,
                "source_version": "test",
                "generated_at": "2026-07-02T00:00:00+00:00",
            },
            "signed_content": run_content,
            "expected_content_hash": run_ch,
            "parent_certificate_identity": identity,
            "parent_vector": "vectors/gate-certificate/valid-certificate.json",
            "verifies_with_public_key_hex": pub,
            "trust_store": {atx_signer: {"alg": "ed25519", "public_key": pub}},
        },
    }


V3_SCHEMA = "presidio-hardened/evidence-ref@3"
V3_FRAMEWORK = "iki-gov"
V3_HMAC_SIGNER = "presidio-hmac-producer"


def _v3_message(ch: str, signer: str, framework: str, item_id: str, tier: str | None) -> bytes:
    """ADR-0004 D2, written out independently of the library."""
    return cb(
        {
            "assurance_tier": tier or "attested",
            "content_hash": ch,
            "framework": framework,
            "item_id": item_id,
            "signer": signer,
        }
    )


def _v3_vectors(sk, pub: str) -> dict[pathlib.Path, dict]:
    """evidence-ref@3 (ADR-0004): subject- and tier-bound signatures."""
    d = V / "evidence-ref-v3"
    ch = hashlib.sha256(cb({"item_id": "D1", "status": "evidence-present"})).hexdigest()
    claimed = "2026-10-25T00:00:00+00:00"

    def ref(item, *, framework=V3_FRAMEWORK, tier=None, signer=SIGNER, alg="ed25519", ch=ch):
        message = _v3_message(ch, signer, framework, item, tier)
        if alg == "ed25519":
            sig = sk.sign(message).hex()
        else:
            sig = hmaclib.new(KEY.encode(), message, hashlib.sha256).hexdigest()
        out = {
            "item_id": item,
            "source": "presidio-hardened-ai",
            "source_version": "test",
            "ledger_ref": "ledger:golden",
            "content_hash": ch,
            "signer": signer,
            "signature": sig,
            "claimed_at": claimed,
            "framework": framework,
        }
        if tier is not None:
            out["assurance_tier"] = tier
        return out

    def env(refs, schema=V3_SCHEMA):
        doc = {"schema": schema, "source": "presidio-hardened-ai", "generated_at": claimed}
        if schema is None:
            del doc["schema"]
        doc["evidence"] = refs
        return doc

    def strip(r, *keys):
        return {k: v for k, v in r.items() if k not in keys}

    d1 = ref("D1")
    d2_hmac = ref("D2", signer=V3_HMAC_SIGNER, alg="hmac-sha256")
    optimistic = ref("D3", tier="optimistic")
    v2_golden = {
        "item_id": "D1",
        "source": "presidio-hardened-ai",
        "source_version": "test",
        "ledger_ref": "ledger:golden",
        "content_hash": CH,
        "signer": SIGNER,
        "signature": EXPECTED_SIG,
        "claimed_at": claimed,
    }

    files = {
        "valid-envelope.json": env([d1, d2_hmac]),
        "valid-tier-optimistic.json": env([optimistic]),
        "valid-same-content-two-items.json": env([d1, ref("D2")]),
        "valid-signature-foreign-framework.json": env([ref("D1", framework="other-checklist")]),
        "tampered-relabelled-item.json": env([dict(d1, item_id="D4")]),
        "tampered-relabelled-framework.json": env([dict(d1, framework="iki-gov-2")]),
        "tampered-relabelled-tier.json": env([strip(optimistic, "assurance_tier")]),
        "tampered-v2-signature-as-v3.json": env([dict(v2_golden, framework=V3_FRAMEWORK)]),
        "tampered-v3-signature-as-v2.json": env(
            [strip(d1, "framework")], schema="presidio-hardened/evidence-ref@2"
        ),
        "tampered-v3-refs-schema-absent.json": env([d1], schema=None),
    }
    out: dict[pathlib.Path, dict] = {d / name: doc for name, doc in files.items()}
    out[d / "invalid-missing-framework.json"] = {
        "_reason": "@3 requires 'framework' on every ref",
        "document": env([strip(d1, "framework")]),
    }
    out[d / "invalid-framework-pattern.json"] = {
        "_reason": "framework must match ^[a-z0-9][a-z0-9._-]{0,63}$",
        "document": env([dict(d1, framework="IKI Gov")]),
    }

    def expect(sig, framework_ok, envelope_ok, reason=None):
        row = {
            "signature_verifies": sig,
            "verifies_for_framework": framework_ok,
            "envelope_verifies": envelope_ok,
        }
        if reason:
            row["envelope_reason"] = reason
        return row

    out[d / "expectations.json"] = {
        "description": (
            "Expectations for every evidence-ref-v3 vector, asserted identically by "
            "the Python and Rust lanes. signature_verifies: the ref's signature under "
            "the message its envelope schema selects. verifies_for_framework: the same "
            "with expected_framework 'iki-gov' (subject binding demanded). "
            "envelope_verifies: verify_envelope without a framework demand, i.e. the "
            "CLI default (tier, reuse floor, signature)."
        ),
        "expected_framework": V3_FRAMEWORK,
        "trust_store": {
            SIGNER: {"alg": "ed25519", "public_key": pub},
            V3_HMAC_SIGNER: {"alg": "hmac-sha256", "key": KEY},
        },
        "files": {
            "valid-envelope.json": [expect(True, True, True), expect(True, True, True)],
            "valid-tier-optimistic.json": [
                expect(True, True, False, "assurance tier 'optimistic'")
            ],
            "valid-same-content-two-items.json": [
                expect(True, True, True),
                expect(True, True, True),
            ],
            "valid-signature-foreign-framework.json": [expect(True, False, True)],
            "tampered-relabelled-item.json": [expect(False, False, False)],
            "tampered-relabelled-framework.json": [expect(False, False, False)],
            "tampered-relabelled-tier.json": [expect(False, False, False)],
            "tampered-v2-signature-as-v3.json": [expect(False, False, False)],
            "tampered-v3-signature-as-v2.json": [expect(False, False, False)],
            "tampered-v3-refs-schema-absent.json": [expect(False, False, False)],
        },
    }

    escaped_signer = 'presidio "quoted", signer'
    for alg, name in (
        ("ed25519", "ed25519-golden-v3.json"),
        ("hmac-sha256", "hmac-sha256-golden-v3.json"),
    ):
        cases = []
        for signer, tier in ((SIGNER, None), (SIGNER, "zk"), (escaped_signer, None)):
            message = _v3_message(CH, signer, V3_FRAMEWORK, "D1", tier)
            if alg == "ed25519":
                sig = sk.sign(message).hex()
            else:
                sig = hmaclib.new(KEY.encode(), message, hashlib.sha256).hexdigest()
            cases.append(
                {
                    "content_hash": CH,
                    "signer": signer,
                    "framework": V3_FRAMEWORK,
                    "item_id": "D1",
                    "assurance_tier": tier,
                    "message_canonical": message.decode(),
                    "signature_hex": sig,
                }
            )
        key_fields = (
            {"private_key_hex": PRIV, "public_key_hex": pub} if alg == "ed25519" else {"key": KEY}
        )
        out[V / "signing" / name] = {
            "description": (
                "evidence-ref@3 golden signatures (ADR-0004 D2): the message is "
                "canonical({assurance_tier, content_hash, framework, item_id, signer}) "
                "with assurance_tier resolved ('attested' when absent, shown as null "
                "here). The quoted signer pins canonical escaping, so a 5-key @3 "
                "message can never collide with a 2-key @1/@2 message."
            ),
            "algorithm": alg,
            **key_fields,
            "cases": cases,
        }

    reused = env(
        [dict(v2_golden, item_id="D1"), dict(v2_golden, item_id="D2")],
        schema="presidio-hardened/evidence-ref@2",
    )
    out[V / "evidence-ref-v2/reused-ref.json"] = reused
    out[V / "evidence-ref-v2/reused-ref.notes.json"] = {
        "description": (
            "The ADR-0004 D5 floor for @1/@2: one genuine golden ref cloned under items "
            "D1 and D2. Each copy's signature verifies on its own; the envelope fails "
            "for both, because the @2 message does not say which item the producer meant."
        ),
        "signature_verifies": [True, True],
        "envelope_verifies": [False, False],
        "envelope_reason": "reused under 2 items",
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": pub}},
    }
    return out


SCOUTSUITE = "presidio-hardened-scoutsuite"
# Rule sets exactly as scoutsuite's aws.evidence.json maps them to O5 and T5.
SCOUTSUITE_RULES = {
    "O5": [
        "cloudtrail-no-encryption-with-kms.json",
        "cloudtrail-no-global-services-logging.json",
        "cloudtrail-no-log-file-validation.json",
        "cloudtrail-no-logging.json",
        "cloudtrail-not-configured.json",
        "config-recorder-not-configured.json",
        "s3-bucket-no-logging.json",
        "vpc-subnet-without-flow-log.json",
    ],
    "T5": [
        "ec2-default-security-group-in-use.json",
        "ec2-default-security-group-with-rules.json",
        "ec2-ebs-default-encryption-disabled.json",
        "ec2-ebs-volume-not-encrypted.json",
        "ec2-instance-with-user-data-secrets.json",
        "ec2-security-group-opens-all-ports-to-all.json",
        "ec2-security-group-opens-known-port-to-all.json",
        "iam-inline-policy-allows-NotActions.json",
        "iam-managed-policy-allows-full-privileges.json",
        "iam-password-policy-minimum-length.json",
        "iam-password-policy-no-expiration.json",
        "iam-password-policy-reuse-enabled.json",
        "iam-root-account-no-hardware-mfa.json",
        "iam-root-account-no-mfa.json",
        "iam-root-account-used-recently.json",
        "iam-root-account-with-active-keys.json",
        "iam-user-no-key-rotation.json",
        "iam-user-with-multiple-access-keys.json",
        "iam-user-with-password-and-key.json",
        "iam-user-without-mfa.json",
        "kms-cmk-rotation-disabled.json",
        "rds-instance-publicly-accessible.json",
        "s3-bucket-allowing-cleartext.json",
        "s3-bucket-no-default-encryption.json",
        "s3-bucket-no-versioning.json",
        "s3-bucket-world-acl.json",
    ],
}


def _cloud_posture_vectors(sk, pub: str) -> dict[pathlib.Path, dict]:
    """scoutsuite consumer vector: clean cloud controls as evidence-ref@2 refs.

    presidio-hardened-scoutsuite 0.30.0 signs the family message
    ``canonical({content_hash, signer})``; releases up to 0.29.x signed every
    ref field instead, which ``presidio-evidence verify`` rejects. The notes pin
    that legacy signature as a must-fail case, so a regression back to it shows.
    """
    digest = hashlib.sha256(b"presidio-evidence golden scoutsuite report").hexdigest()
    claimed = "2026-10-18T00:00:00+00:00"
    ledger_ref = f"presidio-report-manifest:sha256/{digest}"
    refs, subjects, legacy = [], {}, {}
    for item, rules in SCOUTSUITE_RULES.items():
        subject = {
            "item_id": item,
            "provider": "aws",
            "rules": sorted(rules),
            "status": "clean",
            "report_manifest_digest": digest,
        }
        chash = hashlib.sha256(cb(subject)).hexdigest()
        ref = {
            "item_id": item,
            "source": SCOUTSUITE,
            "source_version": "test",
            "ledger_ref": ledger_ref,
            "content_hash": chash,
            "signer": SCOUTSUITE,
            "signature": sk.sign(cb({"content_hash": chash, "signer": SCOUTSUITE})).hex(),
            "claimed_at": claimed,
        }
        legacy_fields = {k: v for k, v in ref.items() if k != "signature"}
        subjects[item] = {"claim_subject": subject, "expected_content_hash": chash}
        legacy[item] = sk.sign(cb(legacy_fields)).hex()
        refs.append(ref)
    envelope = {
        "schema": "presidio-hardened/evidence-ref@2",
        "source": SCOUTSUITE,
        "source_version": "test",
        "generated_at": claimed,
        "evidence": refs,
    }
    return {
        V / "cloud-posture/valid-envelope.json": envelope,
        V / "cloud-posture/valid-envelope.notes.json": {
            "description": (
                "Companion to cloud-posture/valid-envelope.json. The scoutsuite "
                "consumer vector: clean AWS controls mapped to IKI-Gov items O5 and "
                "T5, one Ed25519-signed evidence-ref@2 ref each, built the way "
                "presidio-hardened-scoutsuite 0.30.0 build_evidence builds them "
                "(claim_subject -> content_hash, family signing message). "
                "legacy_signatures are what 0.29.x would have signed (every ref field "
                "but the signature); they must NOT verify."
            ),
            "claims": subjects,
            "report_manifest_digest": digest,
            "verifies_with_public_key_hex": pub,
            "trust_store": {SCOUTSUITE: {"alg": "ed25519", "public_key": pub}},
            "legacy_signatures": legacy,
        },
    }


def render(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    built = build()
    bad = 0
    for path, obj in built.items():
        text = render(obj)
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                print(f"DRIFT: {path.relative_to(ROOT)}")
                bad += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if check and bad:
        print(f"{bad} vector file(s) drifted from regeneration")
        return 1
    print("vectors OK" if check else "vectors generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
