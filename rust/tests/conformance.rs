//! Cross-language conformance: this Rust toolchain must reproduce the golden
//! vectors byte-for-byte. The reference canonicalizer lives in test code on
//! purpose (conformance tests before library code, ADR-0001).
//!
//! Canonicalization note: `serde_json::Value` objects are `BTreeMap`-backed by
//! default (the `preserve_order` feature is NOT enabled), so `to_string` yields
//! sorted-key, compact, non-ASCII-escaped JSON — the same profile as Python's
//! `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

/// Layer-0 strict canonical JSON (ADR-0001 D1): floats rejected.
fn canonical_string(value: &Value) -> Result<String, String> {
    reject_floats(value)?;
    // BTreeMap-backed objects serialize with sorted keys; compact by default.
    serde_json::to_string(value).map_err(|e| e.to_string())
}

fn reject_floats(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(n) if n.is_f64() => {
            Err("floats are not permitted in canonical payloads (strict profile)".into())
        }
        Value::Array(items) => items.iter().try_for_each(reject_floats),
        Value::Object(map) => map.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

fn signing_message(content_hash: &str, signer: &str) -> String {
    let payload = serde_json::json!({"content_hash": content_hash, "signer": signer});
    canonical_string(&payload).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
            "presidio-hardened/evidence-ref@2"
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
            assert!(value.parse::<f64>().unwrap() > 0.0);
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

    // The edge is coherent: the window covers the run, the layer is its strategy.
    assert_eq!(
        notes["window_seconds"],
        tr_notes["signed_content"]["duration_s"]
    );
    assert_eq!(
        notes["signed_content"]["layer"],
        tr_notes["signed_content"]["strategy"]
    );
}

#[test]
fn nominal_energy_reading_omits_parents() {
    // ADR-0002 P3: parents is omitted when empty, never emitted as [].
    let notes = load("vectors/energy-reading/valid-envelope.notes.json");
    assert!(notes["signed_content"]["parents"].is_null());
    assert_eq!(notes["parents_present"], serde_json::json!(false));
}
