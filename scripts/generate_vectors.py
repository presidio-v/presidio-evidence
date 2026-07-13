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

# Cross-repo constants — pinned by presidio-hardened-ai tests/test_ed25519.py,
# ikigov-assess tests/test_evidence.py, and x402. Do not change within @1.
PRIV = "01" * 32
EXPECTED_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
EXPECTED_SIG = (
    "a0dc8599958734457f194ebce15c60ec097754b59897ab5dc758f73abadafe36"
    "97874049d9f7736de4e3a9cc28b2fb4d76b15d8bce7fa0b26c8434bebbba590a"
)
EXPECTED_HSIG = "2e7af6d2882dd53847dcf3032e1fe36e58c5a879c224ea97b505b3e3b626b87a"
CH, SIGNER, KEY = "abc123def456", "presidio-hardened-ai", "shared-key"


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
            "reading": "energy-reading@1",
            "window_start": "2026-07-02T00:00:00+00:00",
            "window_end": "2026-07-02T00:05:00+00:00",
            "energy_wh": "12.5",
            "mean_power_w": "150.0",
            "source": "kepler",
            "layer": "pod",
            "energy_chain_head": energy_chain_head,
        },
        description=(
            "Nominal presidio-hardened/energy-reading@1 Layer-0 reading (pat "
            "Energy Arc v0.24 'Sign the watt', L-EN-4) — RESERVED, not yet "
            "emitted by a shipped producer. A 5-minute serving-layer window "
            "measured by Kepler, key-lessly emitted by pat and signed into the "
            "frozen evidence-ref@1 envelope by the bridge sidecar (v0.17 "
            "pattern). `parents` is absent — ADR-0002 P3 omits it when empty. "
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
            "reading": "energy-reading@1",
            "window_start": "2026-07-02T00:00:00+00:00",
            "window_end": "2026-07-02T02:00:00+00:00",
            "energy_wh": "4800.0",
            "mean_power_w": "2400.0",
            "source": "dcgm",
            "layer": "pipeline",
            "energy_chain_head": energy_chain_head,
            "parents": [tr_ch],
        },
        description=(
            "Parents-bearing presidio-hardened/energy-reading@1 (pat Energy Arc "
            "v0.24, L-EN-4) — RESERVED. The ADR-0002 DAG edge for the energy "
            "axis: `parents[0]` is the content hash of the training-run/ golden "
            "payload, so this reading says 'these are the joules that run cost'. "
            "The window matches that run exactly (duration_s 7200 == 2 h) and "
            "`layer` matches its `strategy` ('pipeline'); 4800 Wh over 2 h == "
            "2400.0 W == the run's 4 devices at 600 W each. Lineage lives inside "
            "the hashed content (ADR-0002 P1), so rewiring it breaks both the "
            "content hash and the signature. DCGM-sourced (the accelerator meter, "
            "per the v0.23 'Train the watt' theme)."
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

    return out


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
