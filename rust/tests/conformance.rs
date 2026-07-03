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

/// ADR-0002 provenance-parents + ikigov T-B4: a parents-bearing payload wrapped
/// in the frozen evidence-ref@1 envelope must recompute its content hash and
/// verify, for both new golden vectors.
fn assert_provenance_vector_verifies(kind: &str) {
    let envelope = load(&format!("vectors/{kind}/valid-envelope.json"));
    let notes = load(&format!("vectors/{kind}/valid-envelope.notes.json"));
    let evidence_ref = &envelope["evidence"][0];

    // content_hash recomputes from the signed content; the Layer-0 producer
    // record binds the same content and hash.
    let content = canonical_string(&notes["signed_content"]).unwrap();
    let expected_ch = notes["expected_content_hash"].as_str().unwrap();
    assert_eq!(sha256_hex(content.as_bytes()), expected_ch, "{kind} hash");
    assert_eq!(evidence_ref["content_hash"].as_str().unwrap(), expected_ch);
    assert_eq!(
        notes["layer0_reading"]["content_hash"].as_str().unwrap(),
        expected_ch
    );
    assert_eq!(
        notes["layer0_reading"]["attested_content"],
        notes["signed_content"]
    );

    // parents are inside the hashed content and follow the family hex rule.
    for parent in notes["signed_content"]["parents"].as_array().unwrap() {
        let p = parent.as_str().unwrap();
        assert!((8..=128).contains(&p.len()), "{kind} parent length");
        assert!(p
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    // Signature verifies against the trust-store key; signer replay fails.
    let signer = evidence_ref["signer"].as_str().unwrap();
    let pub_hex = notes["trust_store"][signer]["public_key"].as_str().unwrap();
    let sig_hex = evidence_ref["signature"].as_str().unwrap();
    assert!(
        verify_ed25519(expected_ch, signer, sig_hex, pub_hex),
        "{kind} verify"
    );
    assert!(!verify_ed25519(
        expected_ch,
        "evil-signer",
        sig_hex,
        pub_hex
    ));
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
    assert_eq!(notes["attestation_would_attest"].as_str().unwrap(), expected_ch);

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
