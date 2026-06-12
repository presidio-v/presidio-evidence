//! Cross-language conformance: this Rust toolchain must reproduce the golden
//! vectors byte-for-byte. The reference canonicalizer lives in test code on
//! purpose (conformance tests before library code, ADR-0001).
//!
//! Canonicalization note: `serde_json::Value` objects are `BTreeMap`-backed by
//! default (the `preserve_order` feature is NOT enabled), so `to_string` yields
//! sorted-key, compact, non-ASCII-escaped JSON — the same profile as Python's
//! `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn load(rel: &str) -> Value {
    let text = fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Layer-0 strict canonical JSON (ADR-0001 D1): floats rejected.
fn canonical_string(value: &Value) -> Result<String, String> {
    reject_floats(value)?;
    // BTreeMap-backed objects serialize with sorted keys; compact by default.
    Ok(serde_json::to_string(value).map_err(|e| e.to_string())?)
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
        assert!(canonical_string(&case["payload"]).is_err(), "case {name} must be rejected");
    }
}

#[test]
fn ed25519_golden_vector_reproduces_and_verifies() {
    let v = load("vectors/signing/ed25519-golden.json");
    let priv_bytes: [u8; 32] =
        hex::decode(v["private_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let sk = SigningKey::from_bytes(&priv_bytes);
    assert_eq!(hex::encode(sk.verifying_key().to_bytes()), v["public_key_hex"].as_str().unwrap());

    let msg = signing_message(v["content_hash"].as_str().unwrap(), v["signer"].as_str().unwrap());
    assert_eq!(msg, v["message_canonical"].as_str().unwrap());

    // Ed25519 is deterministic (RFC 8032) — the signature must match exactly.
    let sig = sk.sign(msg.as_bytes());
    assert_eq!(hex::encode(sig.to_bytes()), v["signature_hex"].as_str().unwrap());

    sk.verifying_key().verify(msg.as_bytes(), &sig).expect("golden vector must verify");
}

/// Reference fail-closed verifier: any failure is `false`, never a panic/error.
fn verify_ed25519(content_hash: &str, signer: &str, signature_hex: &str, public_key_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(public_key_hex) else { return false };
    let Ok(pk_array) = <[u8; 32]>::try_from(pk_bytes) else { return false };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_array) else { return false };
    let Ok(sig_bytes) = hex::decode(signature_hex) else { return false };
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else { return false };
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
        assert_eq!(case["verifies"].as_bool().unwrap(), false);
    }
}

#[test]
fn hmac_golden_vector_reproduces() {
    let v = load("vectors/signing/hmac-sha256-golden.json");
    let msg = signing_message(v["content_hash"].as_str().unwrap(), v["signer"].as_str().unwrap());
    assert_eq!(msg, v["message_canonical"].as_str().unwrap());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(v["key"].as_str().unwrap().as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    assert_eq!(hex::encode(mac.finalize().into_bytes()), v["signature_hex"].as_str().unwrap());
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
    assert!(!verify_ed25519(expected_ch, "evil-signer", sig_hex, pub_hex));
}

#[test]
fn schema_constants_match_python_side() {
    assert_eq!(presidio_evidence::EVIDENCE_REF_SCHEMA_ID, "presidio-hardened/evidence-ref@1");
    assert_eq!(presidio_evidence::EVIDENCE_REF_FIELDS.len(), 8);
    assert_eq!(presidio_evidence::SIGNING_ALGORITHMS, ["ed25519", "hmac-sha256"]);
}
