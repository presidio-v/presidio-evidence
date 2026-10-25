//! Cross-language conformance: this Rust toolchain must reproduce the golden
//! vectors byte-for-byte. Layer 0 (canonical JSON, SHA-256 content addressing,
//! the signer-bound signing message) is exercised through the crate's public
//! API — extracted from this file in v0.3.0 after the vectors had pinned it
//! (conformance tests before library code, ADR-0001). Signing/verification
//! stays test-local: the crate has no signature layer by design (D1).

use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use presidio_evidence::{canonical_string, sha256_hex, signing_message};
use serde_json::Value;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load(rel: &str) -> Value {
    let text = fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn canonical_json_vectors_reproduce() {
    let doc = load("vectors/canonical-json/vectors.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let encoded = canonical_string(&case["payload"]).unwrap();
        assert_eq!(encoded, case["canonical"].as_str().unwrap(), "case {name}");
        assert_eq!(
            sha256_hex(encoded.as_bytes()),
            case["sha256_hex"].as_str().unwrap(),
            "case {name}"
        );
    }
    for case in doc["rejected"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(
            canonical_string(&case["payload"]).is_err(),
            "case {name} must be rejected"
        );
    }
}

#[test]
fn ed25519_golden_vector_reproduces_and_verifies() {
    let v = load("vectors/signing/ed25519-golden.json");
    let priv_bytes: [u8; 32] = hex::decode(v["private_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sk = SigningKey::from_bytes(&priv_bytes);
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        v["public_key_hex"].as_str().unwrap()
    );

    let msg = signing_message(
        v["content_hash"].as_str().unwrap(),
        v["signer"].as_str().unwrap(),
    );
    assert_eq!(msg, v["message_canonical"].as_str().unwrap());

    // Ed25519 is deterministic (RFC 8032) — the signature must match exactly.
    let sig = sk.sign(msg.as_bytes());
    assert_eq!(
        hex::encode(sig.to_bytes()),
        v["signature_hex"].as_str().unwrap()
    );

    sk.verifying_key()
        .verify(msg.as_bytes(), &sig)
        .expect("golden vector must verify");
}

/// Reference fail-closed verifier: any failure is `false`, never a panic/error.
fn verify_ed25519(
    content_hash: &str,
    signer: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> bool {
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(pk_array) = <[u8; 32]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_array) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_array);
    let msg = signing_message(content_hash, signer);
    pk.verify(msg.as_bytes(), &sig).is_ok()
}

#[test]
fn ed25519_tamper_cases_fail_closed() {
    let v = load("vectors/signing/ed25519-golden.json");
    for case in v["tamper_cases"].as_array().unwrap() {
        let verified = verify_ed25519(
            case["content_hash"].as_str().unwrap(),
            case["signer"].as_str().unwrap(),
            case["signature_hex"].as_str().unwrap(),
            case["public_key_hex"].as_str().unwrap(),
        );
        assert!(!verified, "tamper case must fail: {}", case["reason"]);
        assert!(!case["verifies"].as_bool().unwrap());
    }
}

#[test]
fn hmac_golden_vector_reproduces() {
    let v = load("vectors/signing/hmac-sha256-golden.json");
    let msg = signing_message(
        v["content_hash"].as_str().unwrap(),
        v["signer"].as_str().unwrap(),
    );
    assert_eq!(msg, v["message_canonical"].as_str().unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(v["key"].as_str().unwrap().as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    assert_eq!(
        hex::encode(mac.finalize().into_bytes()),
        v["signature_hex"].as_str().unwrap()
    );
}

#[test]
fn envelope_end_to_end_verifies() {
    let envelope = load("vectors/evidence-ref/valid-envelope.json");
    let notes = load("vectors/evidence-ref/valid-envelope.notes.json");
    let evidence_ref = &envelope["evidence"][0];

    // Content hash recomputes from the signed content.
    let content = canonical_string(&notes["signed_content"]).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(content.as_bytes()), expected_ch);
    assert_eq!(evidence_ref["content_hash"].as_str().unwrap(), expected_ch);

    // Signature verifies against the trust-store key; signer replay fails.
    let signer = evidence_ref["signer"].as_str().unwrap();
    let pub_hex = notes["trust_store"][signer]["public_key"].as_str().unwrap();
    let sig_hex = evidence_ref["signature"].as_str().unwrap();
    assert!(verify_ed25519(expected_ch, signer, sig_hex, pub_hex));
    assert!(!verify_ed25519(
        expected_ch,
        "evil-signer",
        sig_hex,
        pub_hex
    ));
}

/// Common Layer-0 reading checks for a `{dir}/{stem}(.notes).json` vector pair:
/// the content hash recomputes from the signed content, the envelope ref and the
/// producer record both bind it, the signature verifies against the trust store,
/// and signer replay fails closed. `parents` (ADR-0002) is checked when present —
/// it is optional per P3, so its absence is not a failure here.
fn assert_reading_vector_verifies(dir: &str, stem: &str) {
    let envelope = load(&format!("vectors/{dir}/{stem}.json"));
    let notes = load(&format!("vectors/{dir}/{stem}.notes.json"));
    let evidence_ref = &envelope["evidence"][0];

    // content_hash recomputes from the signed content; the Layer-0 producer
    // record binds the same content and hash.
    let content = canonical_string(&notes["signed_content"]).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(content.as_bytes()), expected_ch, "{dir} hash");
    assert_eq!(evidence_ref["content_hash"].as_str().unwrap(), expected_ch);
    assert_eq!(
        notes["layer0_reading"]["content_hash"].as_str().unwrap(),
        expected_ch
    );
    assert_eq!(
        notes["layer0_reading"]["attested_content"],
        notes["signed_content"]
    );

    // parents, when present, are inside the hashed content and follow the family
    // hex rule.
    if let Some(parents) = notes["signed_content"]["parents"].as_array() {
        assert!(
            !parents.is_empty(),
            "{dir} parents must be omitted, not empty"
        );
        for parent in parents {
            let p = parent.as_str().unwrap();
            assert!((8..=128).contains(&p.len()), "{dir} parent length");
            assert!(p
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }

    // Signature verifies against the trust-store key; signer replay fails.
    let signer = evidence_ref["signer"].as_str().unwrap();
    let pub_hex = notes["trust_store"][signer]["public_key"].as_str().unwrap();
    let sig_hex = evidence_ref["signature"].as_str().unwrap();
    assert!(
        verify_ed25519(expected_ch, signer, sig_hex, pub_hex),
        "{dir} verify"
    );
    assert!(!verify_ed25519(
        expected_ch,
        "evil-signer",
        sig_hex,
        pub_hex
    ));
}

/// ADR-0002 provenance-parents + ikigov T-B4: a parents-bearing payload wrapped
/// in the frozen evidence-ref@1 envelope must recompute its content hash and
/// verify, for both new golden vectors. These two vectors MUST carry parents.
fn assert_provenance_vector_verifies(kind: &str) {
    assert_reading_vector_verifies(kind, "valid-envelope");
    let notes = load(&format!("vectors/{kind}/valid-envelope.notes.json"));
    assert!(
        !notes["signed_content"]["parents"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{kind} must be parents-bearing"
    );
}

#[test]
fn training_run_provenance_vector_verifies() {
    assert_provenance_vector_verifies("training-run");
}

#[test]
fn workshop_attestation_provenance_vector_verifies() {
    assert_provenance_vector_verifies("workshop-attestation");
}

#[test]
fn attestation_parents_point_at_training_run_payload() {
    // The provenance DAG edge (ADR-0002 / L-EV-6): the workshop attestation
    // attests, and lists as its parent, the training-run payload's content hash.
    let tr_notes = load("vectors/training-run/valid-envelope.notes.json");
    let wa_notes = load("vectors/workshop-attestation/valid-envelope.notes.json");
    let training_ch = tr_notes["expected_content_hash"].as_str().unwrap();
    let attested = &wa_notes["signed_content"];
    assert_eq!(attested["attests"].as_str().unwrap(), training_ch);
    assert_eq!(attested["parents"], serde_json::json!([training_ch]));
    assert_eq!(
        wa_notes["attests_parent_content_hash"].as_str().unwrap(),
        training_ch
    );
}

#[test]
fn schema_constants_match_python_side() {
    assert_eq!(
        presidio_evidence::EVIDENCE_REF_SCHEMA_ID,
        "presidio-hardened/evidence-ref@1"
    );
    assert_eq!(presidio_evidence::EVIDENCE_REF_FIELDS.len(), 8);
    assert_eq!(
        presidio_evidence::SIGNING_ALGORITHMS,
        ["ed25519", "hmac-sha256"]
    );
}

// ── Consumer coverage arc (2026-07-03): ikigov / x402 / treasury vectors ─────

#[test]
fn slo_reading_vector_verifies() {
    // The x402 consumer chain: pat Layer-0 reading → bridge-signed
    // evidence-ref@1 envelope → SLO payment broker verify_ref.
    let envelope = load("vectors/slo-reading/valid-envelope.json");
    let notes = load("vectors/slo-reading/valid-envelope.notes.json");
    let evidence_ref = &envelope["evidence"][0];

    let content = canonical_string(&notes["signed_content"]).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(content.as_bytes()), expected_ch, "slo hash");
    assert_eq!(evidence_ref["content_hash"].as_str().unwrap(), expected_ch);
    assert_eq!(
        notes["layer0_reading"]["attested_content"],
        notes["signed_content"]
    );

    // Degradation semantics: value > threshold (the broker's precondition).
    let value = notes["signed_content"]["value"].as_i64().unwrap();
    let threshold = notes["signed_content"]["threshold"].as_i64().unwrap();
    assert!(value > threshold);
    assert_eq!(notes["degraded"], serde_json::json!(true));

    // Signature verifies against the trust-store key (family Layer-1 message).
    let signer = evidence_ref["signer"].as_str().unwrap();
    let pub_hex = notes["trust_store"][signer]["public_key"].as_str().unwrap();
    let vk_bytes: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
    let sig_bytes: [u8; 64] = hex::decode(evidence_ref["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    let message = signing_message(expected_ch, signer);
    vk.verify(message.as_bytes(), &sig).expect("slo signature");
    // Cross-signer replay must fail closed.
    let wrong = signing_message(expected_ch, "not-the-signer");
    assert!(vk.verify(wrong.as_bytes(), &sig).is_err());
}

#[test]
fn workshop_leavebehind_owner_signature_verifies() {
    // ikigov T-B4 R1 consumer vector. Two profiles pinned: the manifest's
    // canonical sha256 (the attestation DAG-edge target) and the OWNER
    // signature over the RAW canonical manifest bytes (manifest.sig profile,
    // deliberately NOT the family {content_hash, signer} message).
    let manifest = load("vectors/workshop-leavebehind/valid-manifest.json");
    let notes = load("vectors/workshop-leavebehind/valid-manifest.notes.json");

    let manifest_canonical = canonical_string(&manifest).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(manifest_canonical.as_bytes()), expected_ch);
    assert_eq!(
        notes["attestation_would_attest"].as_str().unwrap(),
        expected_ch
    );

    // Owner pubkey is attested INSIDE the signed content and must match the
    // verifying key (ikigov's owner-consistency check).
    let embedded_pub = manifest["owner"]["public_key"].as_str().unwrap();
    let notes_pub = notes["verifies_with_public_key_hex"].as_str().unwrap();
    assert_eq!(embedded_pub, notes_pub);

    let vk_bytes: [u8; 32] = hex::decode(notes_pub).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
    let sig_bytes: [u8; 64] = hex::decode(notes["owner_signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(manifest_canonical.as_bytes(), &sig)
        .expect("owner signature over raw manifest bytes");

    // The customer test fixture (priv 02*32) reproduces the signature —
    // deterministic Ed25519, so this pins the wire format end-to-end.
    let priv_hex = notes["customer_private_key_hex_test_fixture"]
        .as_str()
        .unwrap();
    let sk_bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
    let sk = SigningKey::from_bytes(&sk_bytes);
    assert_eq!(
        hex::encode(sk.sign(manifest_canonical.as_bytes()).to_bytes()),
        notes["owner_signature"].as_str().unwrap()
    );

    // Tampered manifest fails closed.
    let mut bad = manifest.clone();
    bad["risk_class"] = serde_json::json!("low");
    let bad_canonical = canonical_string(&bad).unwrap();
    assert!(vk.verify(bad_canonical.as_bytes(), &sig).is_err());
}

// ── evidence-ref@2 assurance tiers (ADR-0003) ────────────────────────────────

#[test]
fn v2_schema_constants_match_python_side() {
    assert_eq!(
        presidio_evidence::EVIDENCE_REF_SCHEMA_ID_V2,
        "presidio-hardened/evidence-ref@2"
    );
    assert_eq!(
        presidio_evidence::EVIDENCE_REF_SCHEMA_IDS,
        [
            "presidio-hardened/evidence-ref@1",
            "presidio-hardened/evidence-ref@2",
            "presidio-hardened/evidence-ref@3"
        ]
    );
    assert_eq!(
        presidio_evidence::ASSURANCE_TIERS,
        ["attested", "optimistic", "zk"]
    );
    assert_eq!(presidio_evidence::DEFAULT_ASSURANCE_TIER, "attested");
}

/// Resolve a ref's tier the way an @2-aware consumer does: declared values are
/// honored only under evidence-ref@2. Under @1, assurance_tier is an inert extra
/// field and policy reads the "attested" default (ADR-0003 Option 1).
fn resolved_tier(schema: &str, evidence_ref: &Value) -> String {
    if schema != presidio_evidence::EVIDENCE_REF_SCHEMA_ID_V2 {
        return presidio_evidence::DEFAULT_ASSURANCE_TIER.to_string();
    }
    evidence_ref["assurance_tier"]
        .as_str()
        .unwrap_or(presidio_evidence::DEFAULT_ASSURANCE_TIER)
        .to_string()
}

#[test]
fn v2_explicit_tiers_verify_and_signature_is_tier_independent() {
    // One valid @2 envelope, one ref per explicit tier. Declaring a tier does
    // NOT change what is signed — every ref reuses the @1 golden
    // content_hash/signature and verifies against the same key.
    let envelope = load("vectors/evidence-ref-v2/valid-tiers.json");
    let notes = load("vectors/evidence-ref-v2/valid-tiers.notes.json");
    let schema = envelope["schema"].as_str().unwrap();
    assert_eq!(schema, presidio_evidence::EVIDENCE_REF_SCHEMA_ID_V2);

    let content = canonical_string(&notes["signed_content"]).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(content.as_bytes()), expected_ch);

    let pub_hex = notes["verifies_with_public_key_hex"].as_str().unwrap();
    let seen: Vec<String> = envelope["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            assert_eq!(r["content_hash"].as_str().unwrap(), expected_ch);
            let signer = r["signer"].as_str().unwrap();
            let sig = r["signature"].as_str().unwrap();
            assert!(
                verify_ed25519(expected_ch, signer, sig, pub_hex),
                "tier {} must verify",
                resolved_tier(schema, r)
            );
            resolved_tier(schema, r)
        })
        .collect();
    assert_eq!(seen, ["attested", "optimistic", "zk"]);
    assert_eq!(
        notes["tier_default_when_absent"].as_str().unwrap(),
        presidio_evidence::DEFAULT_ASSURANCE_TIER
    );
}

#[test]
fn v2_absent_tier_resolves_to_attested_and_verifies() {
    let envelope = load("vectors/evidence-ref-v2/valid-tier-absent.json");
    let notes = load("vectors/evidence-ref-v2/valid-tier-absent.notes.json");
    let evidence_ref = &envelope["evidence"][0];
    assert!(
        evidence_ref["assurance_tier"].is_null(),
        "absent on the wire"
    );
    assert_eq!(
        resolved_tier(envelope["schema"].as_str().unwrap(), evidence_ref),
        "attested"
    );
    assert_eq!(
        notes["resolved_assurance_tier"].as_str().unwrap(),
        presidio_evidence::DEFAULT_ASSURANCE_TIER
    );

    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    let signer = evidence_ref["signer"].as_str().unwrap();
    let sig = evidence_ref["signature"].as_str().unwrap();
    let pub_hex = notes["verifies_with_public_key_hex"].as_str().unwrap();
    assert!(verify_ed25519(expected_ch, signer, sig, pub_hex));
}

#[test]
fn v2_invalid_vectors_are_rejectable() {
    // Unknown tier: not in the enum.
    let unknown = load("vectors/evidence-ref-v2/invalid-unknown-tier.json");
    let tier = unknown["document"]["evidence"][0]["assurance_tier"]
        .as_str()
        .unwrap();
    assert!(!presidio_evidence::ASSURANCE_TIERS.contains(&tier));

    // Missing schema: @2 requires it (no grandfathering).
    let missing = load("vectors/evidence-ref-v2/invalid-missing-schema.json");
    assert!(missing["document"]["schema"].is_null());

    // Wrong schema id: the @2 validator rejects anything but @2.
    let wrong = load("vectors/evidence-ref-v2/invalid-wrong-schema-id.json");
    assert_eq!(
        wrong["document"]["schema"].as_str().unwrap(),
        presidio_evidence::EVIDENCE_REF_SCHEMA_ID
    );
    assert_ne!(
        wrong["document"]["schema"].as_str().unwrap(),
        presidio_evidence::EVIDENCE_REF_SCHEMA_ID_V2
    );
}

#[test]
fn v1_record_with_assurance_tier_still_verifies() {
    // Extra-field finding (ADR-0003): an @1 envelope carrying assurance_tier is
    // tolerated (no additionalProperties:false in @1). The signed message is
    // unchanged, so the ref still verifies; the tier is inert unless the
    // envelope declares @2, and is ignored (read as "attested") by @1 consumers.
    let envelope = load("vectors/evidence-ref-v2/valid-v1-with-extra-tier.json");
    let schema = envelope["schema"].as_str().unwrap();
    assert_eq!(schema, presidio_evidence::EVIDENCE_REF_SCHEMA_ID);
    let evidence_ref = &envelope["evidence"][0];
    assert_eq!(
        evidence_ref["assurance_tier"].as_str().unwrap(),
        "optimistic"
    );
    assert_eq!(resolved_tier(schema, evidence_ref), "attested");

    // Reuses the @1 fraud-scoring golden content/signature; verifies unchanged.
    let notes = load("vectors/evidence-ref/valid-envelope.notes.json");
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    let pub_hex = notes["verifies_with_public_key_hex"].as_str().unwrap();
    let signer = evidence_ref["signer"].as_str().unwrap();
    let sig = evidence_ref["signature"].as_str().unwrap();
    assert_eq!(evidence_ref["content_hash"].as_str().unwrap(), expected_ch);
    assert!(verify_ed25519(expected_ch, signer, sig, pub_hex));
}

#[test]
fn treasury_checkpoint_id_reproduces() {
    // Treasury consumer vector — Layer 0 ONLY (ADR-0001 D1): checkpoint
    // identity is content addressing over the canonical envelope, including
    // null-valued optionals and i64 nanosecond timestamps. No signature.
    let envelope = load("vectors/treasury-checkpoint/valid-checkpoint.json");
    let notes = load("vectors/treasury-checkpoint/valid-checkpoint.notes.json");

    let canonical = canonical_string(&envelope).unwrap();
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        notes["expected_checkpoint_id"].as_str().unwrap()
    );
    assert!(notes["signature"].is_null());
    assert_eq!(notes["layer"], serde_json::json!(0));

    // The strict profile still rejects floats in checkpoint-shaped payloads.
    let mut bad = envelope.clone();
    bad["as_of"] = serde_json::json!(1.5);
    assert!(canonical_string(&bad).is_err());
}

// ── energy-reading@1 reservation (pat Energy Arc v0.24 "Sign the watt") ──────

#[test]
fn energy_reading_vectors_verify() {
    // Both reserved vectors are ordinary Layer-0 readings under the frozen
    // evidence-ref@1 envelope: nominal (parents omitted, ADR-0002 P3) and
    // parents-bearing (the energy-axis DAG edge).
    assert_reading_vector_verifies("energy-reading", "valid-envelope");
    assert_reading_vector_verifies("energy-reading", "valid-envelope-parents");
}

#[test]
fn energy_quantities_are_decimal_strings_not_floats() {
    // ADR-0001 D1: the canonical profile rejects floats, so joules and watts
    // travel as decimal strings. A bare float makes the payload uncanonicalizable
    // — and therefore unhashable — so the reading could not be evidence at all.
    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        let content = &notes["signed_content"];
        for field in ["energy_wh", "mean_power_w"] {
            let value = content[field].as_str().unwrap_or_else(|| {
                panic!("{stem}: {field} must be a string, not a number");
            });
            let parsed = value.parse::<f64>().unwrap();
            assert!(parsed.is_finite() && parsed > 0.0);
            assert_eq!(
                serde_json::to_string(&parsed).unwrap(),
                value,
                "{stem}: {field} must use the shortest round-trip decimal spelling"
            );
        }
        assert!(canonical_string(content).is_ok());

        let mut bad = content.clone();
        bad["energy_wh"] = serde_json::json!(12.5);
        assert!(
            canonical_string(&bad).is_err(),
            "{stem}: a float energy_wh must be rejected by the canonicalizer"
        );
    }
}

#[test]
fn energy_mean_power_agrees_with_rfc3339_utc_window() {
    // Independent Rust-side enforcement of the semantic relation pinned by the
    // Python lane: both endpoints are absolute RFC3339 UTC instants and
    // mean_power_w == energy_wh / window_hours.
    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        let content = &notes["signed_content"];
        let start =
            DateTime::<FixedOffset>::parse_from_rfc3339(content["window_start"].as_str().unwrap())
                .unwrap();
        let end =
            DateTime::<FixedOffset>::parse_from_rfc3339(content["window_end"].as_str().unwrap())
                .unwrap();
        assert_eq!(start.offset().local_minus_utc(), 0, "{stem}: start UTC");
        assert_eq!(end.offset().local_minus_utc(), 0, "{stem}: end UTC");

        let seconds = end.signed_duration_since(start).num_seconds();
        assert!(seconds > 0, "{stem}: window must be positive");
        assert_eq!(seconds, notes["window_seconds"].as_i64().unwrap());

        let energy_wh = content["energy_wh"]
            .as_str()
            .unwrap()
            .parse::<f64>()
            .unwrap();
        let actual_w = content["mean_power_w"]
            .as_str()
            .unwrap()
            .parse::<f64>()
            .unwrap();
        let expected_w = energy_wh / (seconds as f64 / 3600.0);
        assert!(
            (actual_w - expected_w).abs() <= f64::EPSILON * expected_w.abs().max(1.0),
            "{stem}: mean power disagrees with energy/window"
        );
    }
}

#[test]
fn energy_chain_head_is_inside_the_signed_content() {
    // pat ADR-0011 §2 / the ADR-0010 anchoring deferral: the head of the chained
    // energy_observations store is part of what gets signed, so a signed reading
    // attests the unrewritten history behind it. The family pins the hex
    // discipline only — walking the chain is pat's job.
    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        let head = notes["signed_content"]["energy_chain_head"]
            .as_str()
            .unwrap();
        assert_eq!(head.len(), 64, "{stem}: chain head must be sha256 hex");
        assert!(head
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(notes["energy_chain_head"].as_str().unwrap(), head);
    }
}

#[test]
fn energy_reading_parents_point_at_training_run_payload() {
    // The energy-axis DAG edge (ADR-0002): the reading names the training-run
    // payload as its parent — "these are the joules that run cost".
    let tr_notes = load("vectors/training-run/valid-envelope.notes.json");
    let notes = load("vectors/energy-reading/valid-envelope-parents.notes.json");
    let training_ch = tr_notes["expected_content_hash"].as_str().unwrap();

    assert_eq!(
        notes["signed_content"]["parents"],
        serde_json::json!([training_ch])
    );
    assert_eq!(notes["parent_content_hash"].as_str().unwrap(), training_ch);

    // The edge is coherent: the window covers the run, and the reading names the
    // same strategy the run does — the same field name, holding the same value.
    assert_eq!(
        notes["window_seconds"],
        tr_notes["signed_content"]["duration_s"]
    );
    assert_eq!(
        notes["signed_content"]["strategy"],
        tr_notes["signed_content"]["strategy"]
    );
}

/// The settled `layer` XOR `strategy` rule. A conforming producer/consumer fails
/// closed on both-present and on neither-present.
fn exactly_one_of_layer_or_strategy(content: &Value) -> bool {
    content.get("layer").is_some() != content.get("strategy").is_some()
}

const ENERGY_LAYERS: [&str; 4] = ["container", "pod", "deployment", "node"];

fn energy_layer_is_valid(content: &Value) -> bool {
    match content.get("layer") {
        None => true,
        Some(Value::String(layer)) => ENERGY_LAYERS.contains(&layer.as_str()),
        Some(_) => false,
    }
}

#[test]
fn energy_reading_payload_carries_no_type_id_of_its_own() {
    // The Layer-0 wrapper's `schema` is authoritative. No family payload repeats
    // its own type id inside the signed content — a duplicate could skew from the
    // wrapper, leaving two disagreeing answers to "what is this?" in one signature.
    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        assert!(
            notes["signed_content"]["reading"].is_null(),
            "{stem}: payload must not carry its own type id"
        );
        assert_eq!(
            notes["layer0_reading"]["schema"].as_str().unwrap(),
            "presidio-hardened/energy-reading@1"
        );
    }
}

#[test]
fn energy_meter_is_a_measured_source_and_does_not_collide_with_source() {
    // `meter` names the measuring device; `source` keeps its family meaning
    // (producer repo) at the wrapper/envelope levels. Measured sources only — an
    // "analytic" meter would let modelled energy masquerade as a reading, which
    // pat invariant E1a forbids.
    const METERS: [&str; 3] = ["rapl", "kepler", "dcgm"];
    assert!(!METERS.contains(&"analytic"));

    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let envelope = load(&format!("vectors/energy-reading/{stem}.json"));
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        let content = &notes["signed_content"];

        let meter = content["meter"].as_str().unwrap();
        assert!(METERS.contains(&meter), "{stem}: unknown meter {meter}");

        // `source` is NOT a payload field; it means the producer repo further out.
        assert!(
            content["source"].is_null(),
            "{stem}: source must not be a payload field"
        );
        assert_eq!(
            notes["layer0_reading"]["source"].as_str().unwrap(),
            "presidio-hardened-arch-translucency"
        );
        assert_eq!(
            envelope["evidence"][0]["source"].as_str().unwrap(),
            "presidio-hardened-arch-translucency"
        );
    }
}

#[test]
fn energy_reading_has_exactly_one_of_layer_or_strategy() {
    // Fail-closed: a serving reading carries `layer`, a training reading carries
    // `strategy` (training-run@1's name for it). Both or neither is rejected —
    // one field spanning two domains is what made the original `layer` ambiguous.
    for stem in ["valid-envelope", "valid-envelope-parents"] {
        let notes = load(&format!("vectors/energy-reading/{stem}.notes.json"));
        let content = &notes["signed_content"];
        assert!(exactly_one_of_layer_or_strategy(content), "{stem}: XOR");
        assert!(energy_layer_is_valid(content), "{stem}: serving layer");

        let mut both = content.clone();
        both["layer"] = serde_json::json!("pod");
        both["strategy"] = serde_json::json!("pipeline");
        assert!(!exactly_one_of_layer_or_strategy(&both), "{stem}: both");

        let mut neither = content.clone();
        neither.as_object_mut().unwrap().remove("layer");
        neither.as_object_mut().unwrap().remove("strategy");
        assert!(
            !exactly_one_of_layer_or_strategy(&neither),
            "{stem}: neither"
        );
    }

    // The serving vector uses `layer`; the training vector uses `strategy`.
    let nominal = load("vectors/energy-reading/valid-envelope.notes.json");
    assert_eq!(nominal["signed_content"]["layer"].as_str().unwrap(), "pod");
    assert!(ENERGY_LAYERS.contains(&nominal["signed_content"]["layer"].as_str().unwrap()));
    assert!(nominal["signed_content"]["strategy"].is_null());

    let parents = load("vectors/energy-reading/valid-envelope-parents.notes.json");
    assert_eq!(
        parents["signed_content"]["strategy"].as_str().unwrap(),
        "pipeline"
    );
    assert!(parents["signed_content"]["layer"].is_null());

    // The maintainer-frozen serving-layer vocabulary is fail-closed.
    let mut unknown_layer = nominal["signed_content"].clone();
    unknown_layer["layer"] = serde_json::json!("database");
    assert!(!energy_layer_is_valid(&unknown_layer));
}

#[test]
fn nominal_energy_reading_omits_parents() {
    // ADR-0002 P3: parents is omitted when empty, never emitted as [].
    let notes = load("vectors/energy-reading/valid-envelope.notes.json");
    assert!(notes["signed_content"]["parents"].is_null());
    assert_eq!(notes["parents_present"], serde_json::json!(false));
}

// ── Layer-0 reading-type registry (PR #14 decision 5) ────────────────────────

/// Every `layer0_reading.schema` committed under `vectors/`.
fn schema_ids_from_vectors_tree() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.to_string_lossy().ends_with(".notes.json") {
                let doc: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
                if let Some(schema) = doc["layer0_reading"]["schema"].as_str() {
                    out.push(schema.to_string());
                }
            }
        }
    }
    let mut ids = Vec::new();
    walk(&root().join("vectors"), &mut ids);
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn reading_registry_matches_the_committed_vectors_tree() {
    // The registry is only load-bearing if it cannot drift from what is actually
    // committed: a reading type added to the vectors tree but not to the constant
    // (or vice versa) fails here, in both lanes.
    assert_eq!(
        presidio_evidence::LAYER0_READING_SCHEMA_IDS.to_vec(),
        schema_ids_from_vectors_tree()
    );
}

#[test]
fn reading_registry_mirrors_python_side() {
    // Mirrors src/presidio_evidence/_constants.py LAYER0_READING_SCHEMA_IDS —
    // sorted, deduped, and boundary-checked: workshop-leavebehind@1 is an
    // owner-signed manifest, not a Layer-0 reading, so it is deliberately absent.
    assert_eq!(
        presidio_evidence::LAYER0_READING_SCHEMA_IDS,
        [
            "presidio-hardened/energy-reading@1",
            "presidio-hardened/slo-reading@1",
            "presidio-hardened/training-run@1",
            "presidio-hardened/workshop-attestation@1",
        ]
    );
    let mut sorted = presidio_evidence::LAYER0_READING_SCHEMA_IDS.to_vec();
    sorted.sort();
    assert_eq!(
        presidio_evidence::LAYER0_READING_SCHEMA_IDS.to_vec(),
        sorted
    );
    assert!(!presidio_evidence::LAYER0_READING_SCHEMA_IDS
        .contains(&"presidio-hardened/workshop-leavebehind@1"));
}

// ── training-run@1 energy-bearing vector (v0.23 optional energy fields) ───────

#[test]
fn training_run_energy_vector_verifies() {
    // Ordinary Layer-0 reading checks (hash recompute, envelope + producer
    // binding, signature, signer replay, parents-when-present).
    assert_reading_vector_verifies("training-run", "valid-envelope-energy");

    // L-EV-7: this family vector IS pat's local self-pin, byte for byte
    // (arch-translucency test_training.py::test_training_run_energy_bearing_self_pin).
    let notes = load("vectors/training-run/valid-envelope-energy.notes.json");
    assert_eq!(
        notes["expected_content_hash"].as_str().unwrap(),
        "d674a11562def33ba92b54ab946d7782b1d3a111ec6a8f8f22a541788a57ffb0"
    );
}

#[test]
fn training_run_energy_quantities_are_decimal_strings_not_floats() {
    // ADR-0001 D1: joules/watts are decimal strings; a float makes the payload
    // uncanonicalizable and therefore unhashable.
    let notes = load("vectors/training-run/valid-envelope-energy.notes.json");
    let content = &notes["signed_content"];
    for field in ["energy_wh", "mean_power_w"] {
        let value = content[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} must be a string, not a number"));
        assert!(value.parse::<f64>().unwrap() > 0.0);
    }
    assert!(canonical_string(content).is_ok());

    let mut bad = content.clone();
    bad["energy_wh"] = serde_json::json!(840.0);
    assert!(
        canonical_string(&bad).is_err(),
        "a float energy_wh must be rejected by the canonicalizer"
    );
}

#[test]
fn training_run_energy_fields_are_additive_over_the_no_energy_vector() {
    // ADR-0011: strip the optional fields and the payload re-hashes
    // byte-identically to the pre-v0.23 valid-envelope vector — adding energy
    // left that published vector untouched.
    let energy = load("vectors/training-run/valid-envelope-energy.notes.json");
    let base = load("vectors/training-run/valid-envelope.notes.json");

    let mut stripped = energy["signed_content"].clone();
    let obj = stripped.as_object_mut().unwrap();
    obj.remove("energy_wh");
    obj.remove("mean_power_w");
    assert_eq!(stripped, base["signed_content"]);

    let stripped_hash = sha256_hex(canonical_string(&stripped).unwrap().as_bytes());
    assert_eq!(
        stripped_hash,
        base["expected_content_hash"].as_str().unwrap()
    );
    assert_eq!(
        stripped_hash,
        energy["no_energy_content_hash"].as_str().unwrap()
    );
}

// ── ADR-0005: numeric payload encoding ──────────────────────────────────────

/// Reference verifier-side check for an ADR-0005 decimal string. Walks the
/// bytes; never parses to a float. `-0` is excluded, as is any fraction longer
/// than `precision`.
fn is_decimal_string(value: &Value, precision: u64, sentinels: &[&str]) -> bool {
    let Some(s) = value.as_str() else {
        return false;
    };
    if s.chars().count() > 512 {
        return false;
    }
    if sentinels.contains(&s) {
        return true;
    }
    if s == "-0" {
        return false;
    }
    let body = s.strip_prefix('-').unwrap_or(s);
    let (int_part, frac_part) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    let int_ok = int_part == "0"
        || (!int_part.is_empty()
            && int_part.bytes().all(|b| b.is_ascii_digit())
            && !int_part.starts_with('0'));
    if !int_ok {
        return false;
    }
    match frac_part {
        None => true,
        Some(f) => {
            !f.is_empty()
                && f.bytes().all(|b| b.is_ascii_digit())
                && !f.ends_with('0')
                && (f.len() as u64) <= precision
        }
    }
}

#[test]
fn numeric_encoding_validate_vectors() {
    let doc = load("vectors/numeric-encoding/vectors.json");
    for case in doc["validate"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sentinels: Vec<&str> = case["sentinels"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap()).collect())
            .unwrap_or_default();
        let got = is_decimal_string(
            &case["value"],
            case["precision"].as_u64().unwrap(),
            &sentinels,
        );
        assert_eq!(got, case["valid"].as_bool().unwrap(), "case {name}");
    }
    // Every producer-side expected output is itself a valid decimal string.
    for case in doc["encode"].as_array().unwrap() {
        assert!(
            is_decimal_string(&case["expected"], case["precision"].as_u64().unwrap(), &[]),
            "encode expected {}",
            case["expected"]
        );
    }
}

// ── ADR-0006: gate-certificate@1 identity ───────────────────────────────────

fn certificate_signing_bytes(doc: &Value) -> Vec<u8> {
    let mut stripped = doc.as_object().unwrap().clone();
    stripped.remove("signature");
    presidio_evidence::canonical_bytes(&Value::Object(stripped)).unwrap()
}

#[test]
fn gate_certificate_identity_reproduces() {
    let cert = load("vectors/gate-certificate/valid-certificate.json");
    let notes = load("vectors/gate-certificate/valid-certificate.notes.json");
    assert_eq!(cert["schema"], "presidio-hardened/gate-certificate@1");
    let signed = certificate_signing_bytes(&cert);
    assert_eq!(
        String::from_utf8(signed.clone()).unwrap(),
        notes["signing_bytes_canonical"].as_str().unwrap()
    );
    assert_eq!(sha256_hex(&signed), notes["identity"].as_str().unwrap());
    assert_eq!(
        notes["identity"].as_str().unwrap(),
        "dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a"
    );

    // The issuer signature covers exactly the identity bytes.
    let sig_block = &cert["signature"];
    let signer = sig_block["signer"].as_str().unwrap();
    assert_eq!(cert["issuer"].as_str().unwrap(), signer);
    let pk_hex = notes["trust_store"][signer]["public_key"].as_str().unwrap();
    let pk_bytes: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    let pk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
    let sig_bytes: [u8; 64] = hex::decode(sig_block["sig"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    pk.verify(&signed, &Signature::from_bytes(&sig_bytes))
        .expect("issuer signature must verify over the identity bytes");

    // Embedded refs verify under the family {content_hash, signer} message.
    for entry in cert["affirmation_set"].as_array().unwrap() {
        let r = &entry["evidence_ref"];
        assert_eq!(r["item_id"], entry["id"]);
        let ref_signer = r["signer"].as_str().unwrap();
        assert!(verify_ed25519(
            r["content_hash"].as_str().unwrap(),
            ref_signer,
            r["signature"].as_str().unwrap(),
            notes["trust_store"][ref_signer]["public_key"]
                .as_str()
                .unwrap(),
        ));
    }
}

#[test]
fn gate_certificate_identity_ignores_the_signature_only() {
    let cert = load("vectors/gate-certificate/valid-certificate.json");
    let identity = sha256_hex(&certificate_signing_bytes(&cert));
    let mut resigned = cert.clone();
    resigned["signature"]["sig"] = Value::String("00".repeat(64));
    assert_eq!(sha256_hex(&certificate_signing_bytes(&resigned)), identity);
    let mut other = cert.clone();
    other["decision"] = Value::String("BLOCKED".into());
    assert_ne!(sha256_hex(&certificate_signing_bytes(&other)), identity);
}

#[test]
fn training_run_parent_is_the_certificate_identity() {
    let cert = load("vectors/gate-certificate/valid-certificate.json");
    let identity = sha256_hex(&certificate_signing_bytes(&cert));
    let envelope = load("vectors/gate-certificate/child-training-run.json");
    let notes = load("vectors/gate-certificate/child-training-run.notes.json");
    let content = &notes["signed_content"];
    assert_eq!(content["parents"][0].as_str().unwrap(), identity);
    let ch = presidio_evidence::content_hash(content).unwrap();
    let r = &envelope["evidence"][0];
    assert_eq!(r["content_hash"].as_str().unwrap(), ch);
    let signer = r["signer"].as_str().unwrap();
    assert!(verify_ed25519(
        &ch,
        signer,
        r["signature"].as_str().unwrap(),
        notes["trust_store"][signer]["public_key"].as_str().unwrap(),
    ));
}

// ── evidence-ref@3 subject binding (ADR-0004) ────────────────────────────────

use presidio_evidence::signing_message_v3;

const V3: &str = "presidio-hardened/evidence-ref@3";

fn hmac_hex(key: &str, msg: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn ed25519_verifies(public_key_hex: &str, msg: &str, signature_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(public_key_hex), hex::decode(signature_hex)) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    pk.verify(msg.as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

fn is_framework_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// The message an envelope's schema selects for one ref (never field presence).
fn message_for(schema: &str, r: &Value) -> Option<String> {
    let ch = r["content_hash"].as_str()?;
    let signer = r["signer"].as_str()?;
    if schema != V3 {
        return Some(signing_message(ch, signer));
    }
    let framework = r["framework"].as_str().filter(|f| is_framework_id(f))?;
    let tier = r["assurance_tier"].as_str();
    if tier.is_some_and(|t| !presidio_evidence::ASSURANCE_TIERS.contains(&t)) {
        return None;
    }
    Some(signing_message_v3(
        ch,
        signer,
        framework,
        r["item_id"].as_str()?,
        tier,
    ))
}

fn signature_verifies(trust: &Value, schema: &str, r: &Value) -> bool {
    let Some(msg) = message_for(schema, r) else {
        return false;
    };
    let entry = &trust[r["signer"].as_str().unwrap_or("")];
    let sig = r["signature"].as_str().unwrap_or("");
    match entry["alg"].as_str() {
        Some("ed25519") => ed25519_verifies(entry["public_key"].as_str().unwrap(), &msg, sig),
        Some("hmac-sha256") => hmac_hex(entry["key"].as_str().unwrap(), &msg) == sig,
        _ => false,
    }
}

/// verify_envelope without a framework demand: tier, @1/@2 reuse floor, signature.
fn envelope_verdicts(trust: &Value, doc: &Value) -> Vec<bool> {
    let schema = doc["schema"]
        .as_str()
        .unwrap_or("presidio-hardened/evidence-ref@1");
    let refs = doc["evidence"].as_array().unwrap();
    let tiered = schema != "presidio-hardened/evidence-ref@1";
    refs.iter()
        .map(|r| {
            let tier = if tiered {
                r["assurance_tier"].as_str()
            } else {
                None
            };
            if tier.unwrap_or("attested") != "attested" {
                return false;
            }
            let reused = schema != V3
                && refs.iter().any(|o| {
                    o["signer"] == r["signer"]
                        && o["content_hash"] == r["content_hash"]
                        && o["item_id"] != r["item_id"]
                });
            !reused && signature_verifies(trust, schema, r)
        })
        .collect()
}

#[test]
fn v3_schema_constants_match_python_side() {
    assert_eq!(presidio_evidence::EVIDENCE_REF_SCHEMA_ID_V3, V3);
    assert_eq!(
        presidio_evidence::FRAMEWORK_PATTERN,
        "^[a-z0-9][a-z0-9._-]{0,63}$"
    );
}

#[test]
fn v3_signing_goldens_reproduce() {
    for (name, alg) in [
        ("vectors/signing/ed25519-golden-v3.json", "ed25519"),
        ("vectors/signing/hmac-sha256-golden-v3.json", "hmac-sha256"),
    ] {
        let golden = load(name);
        assert_eq!(golden["algorithm"], alg);
        for case in golden["cases"].as_array().unwrap() {
            let msg = signing_message_v3(
                case["content_hash"].as_str().unwrap(),
                case["signer"].as_str().unwrap(),
                case["framework"].as_str().unwrap(),
                case["item_id"].as_str().unwrap(),
                case["assurance_tier"].as_str(),
            );
            assert_eq!(msg, case["message_canonical"].as_str().unwrap());
            let sig = if alg == "ed25519" {
                let sk_bytes = hex::decode(golden["private_key_hex"].as_str().unwrap()).unwrap();
                let sk = SigningKey::from_bytes(&<[u8; 32]>::try_from(sk_bytes).unwrap());
                hex::encode(sk.sign(msg.as_bytes()).to_bytes())
            } else {
                hmac_hex(golden["key"].as_str().unwrap(), &msg)
            };
            assert_eq!(sig, case["signature_hex"].as_str().unwrap());
            let keys: Vec<String> = serde_json::from_str::<serde_json::Map<String, Value>>(&msg)
                .unwrap()
                .keys()
                .cloned()
                .collect();
            assert_eq!(keys.len(), 5, "an @3 message never has the @1/@2 key set");
        }
    }
}

#[test]
fn v3_vectors_meet_their_expectations() {
    let expect = load("vectors/evidence-ref-v3/expectations.json");
    let trust = &expect["trust_store"];
    let framework = expect["expected_framework"].as_str().unwrap();
    for (name, rows) in expect["files"].as_object().unwrap() {
        let doc = load(&format!("vectors/evidence-ref-v3/{name}"));
        let schema = doc["schema"]
            .as_str()
            .unwrap_or("presidio-hardened/evidence-ref@1");
        let refs = doc["evidence"].as_array().unwrap();
        let verdicts = envelope_verdicts(trust, &doc);
        let rows = rows.as_array().unwrap();
        assert_eq!(refs.len(), rows.len(), "{name}");
        for ((r, row), verdict) in refs.iter().zip(rows).zip(verdicts) {
            let sig_ok = signature_verifies(trust, schema, r);
            assert_eq!(
                sig_ok,
                row["signature_verifies"].as_bool().unwrap(),
                "{name}"
            );
            let bound = schema == V3 && r["framework"].as_str() == Some(framework) && sig_ok;
            assert_eq!(
                bound,
                row["verifies_for_framework"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(
                verdict,
                row["envelope_verifies"].as_bool().unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn v3_invalid_vectors_lack_a_valid_framework() {
    for name in ["invalid-missing-framework", "invalid-framework-pattern"] {
        let doc = load(&format!("vectors/evidence-ref-v3/{name}.json"));
        let r = &doc["document"]["evidence"][0];
        assert!(
            !r["framework"].as_str().is_some_and(is_framework_id),
            "{name}"
        );
    }
}

#[test]
fn v2_reuse_floor_fails_cloned_refs() {
    let doc = load("vectors/evidence-ref-v2/reused-ref.json");
    let notes = load("vectors/evidence-ref-v2/reused-ref.notes.json");
    let trust = &notes["trust_store"];
    for r in doc["evidence"].as_array().unwrap() {
        assert!(signature_verifies(
            trust,
            "presidio-hardened/evidence-ref@2",
            r
        ));
    }
    let expected: Vec<bool> = notes["envelope_verifies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_bool().unwrap())
        .collect();
    assert_eq!(envelope_verdicts(trust, &doc), expected);
}

#[test]
fn scoutsuite_cloud_posture_vector_verifies_and_legacy_fails() {
    let doc = load("vectors/cloud-posture/valid-envelope.json");
    let notes = load("vectors/cloud-posture/valid-envelope.notes.json");
    let trust = &notes["trust_store"];
    assert!(envelope_verdicts(trust, &doc).into_iter().all(|ok| ok));
    for r in doc["evidence"].as_array().unwrap() {
        let item = r["item_id"].as_str().unwrap();
        let subject = canonical_string(&notes["claims"][item]["claim_subject"]).unwrap();
        assert_eq!(
            sha256_hex(subject.as_bytes()),
            r["content_hash"].as_str().unwrap()
        );
        let mut legacy = r.clone();
        legacy["signature"] = notes["legacy_signatures"][item].clone();
        assert!(!signature_verifies(
            trust,
            "presidio-hardened/evidence-ref@2",
            &legacy
        ));
    }
}
