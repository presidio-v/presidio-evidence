//! presidio-evidence — shared evidence substrate (Rust side).
//!
//! The normative contract is the `schemas/` + `vectors/` trees at the repo
//! root; `tests/conformance.rs` proves this crate reproduces the cross-language
//! wire format byte-for-byte. As of v0.3.0 the crate ships the **Layer 0**
//! reference implementation (ADR-0001 D1, migration step 4) alongside the
//! contract constants:
//!
//! * [`canonical_string`] / [`canonical_bytes`] — strict canonical JSON
//!   (sorted keys, compact separators, UTF-8 preserved, **floats rejected**).
//! * [`sha256_hex`] / [`content_hash`] — SHA-256 content addressing.
//! * [`signing_message`] — the signer-bound Layer-1 message
//!   `canonical({content_hash, signer})` of `evidence-ref@1`/`@2`, and
//!   [`signing_message_v3`], the subject- and tier-bound message of
//!   `evidence-ref@3` (ADR-0004). This crate does not sign or verify
//!   (treasury is keyless by design — dual control instead, ADR-0001 D1).
//!
//! Canonicalization note: `serde_json::Value` objects are `BTreeMap`-backed
//! (the `preserve_order` feature is deliberately NOT enabled — enabling it
//! anywhere in a dependent's feature graph would silently break the contract),
//! so `to_string` yields sorted-key, compact, non-ASCII-escaped JSON — the same
//! profile as Python's `json.dumps(sort_keys=True, separators=(",", ":"),
//! ensure_ascii=False)`.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// Cross-repo signed-evidence schema id (frozen; ADR-0001 D1/D5).
pub const EVIDENCE_REF_SCHEMA_ID: &str = "presidio-hardened/evidence-ref@1";

/// Assurance-tier revision (ADR-0003, Accepted): optional per-ref
/// `assurance_tier`, required envelope `schema`; the signed message is
/// unchanged from @1.
pub const EVIDENCE_REF_SCHEMA_ID_V2: &str = "presidio-hardened/evidence-ref@2";

/// Subject-binding revision (ADR-0004): each ref names its `framework`, and the
/// signature covers `{assurance_tier, content_hash, framework, item_id, signer}`.
pub const EVIDENCE_REF_SCHEMA_ID_V3: &str = "presidio-hardened/evidence-ref@3";

/// Schema ids the verifier accepts (fail-closed on any other; ADR-0001 D4/D5).
pub const EVIDENCE_REF_SCHEMA_IDS: [&str; 3] = [
    EVIDENCE_REF_SCHEMA_ID,
    EVIDENCE_REF_SCHEMA_ID_V2,
    EVIDENCE_REF_SCHEMA_ID_V3,
];

/// An @3 `framework` id: one fixed item vocabulary, never reused (ADR-0004 D1).
pub const FRAMEWORK_PATTERN: &str = "^[a-z0-9][a-z0-9._-]{0,63}$";

/// Assurance tiers (ADR-0003), default first: signature-attested / trusted
/// execution, bonded optimistic assertion, succinct zero-knowledge proof.
pub const ASSURANCE_TIERS: [&str; 3] = ["attested", "optimistic", "zk"];

/// Tier assumed when a ref omits `assurance_tier` (every @1 ref is implicitly
/// this tier); ADR-0003.
pub const DEFAULT_ASSURANCE_TIER: &str = "attested";

/// Layer-0 reading schema ids — the payload types the family emits *inside* an
/// evidence-ref envelope (the producer's `layer0_reading.schema`). Reserving a
/// new reading type is a one-place change here, plus its golden vectors: both
/// conformance lanes assert this list, the generator's output, and the vectors
/// tree agree exactly. Mirrors `_constants.py`.
pub const LAYER0_READING_SCHEMA_IDS: [&str; 4] = [
    "presidio-hardened/energy-reading@1",
    "presidio-hardened/slo-reading@1",
    "presidio-hardened/training-run@1",
    "presidio-hardened/workshop-attestation@1",
];

/// Verifier-side trust-store schema id (ADR-0001 D3).
pub const TRUST_STORE_SCHEMA_ID: &str = "presidio-hardened/trust-store@1";

/// Supported detached-signature algorithms, default first (ADR-0001 D3).
pub const SIGNING_ALGORITHMS: [&str; 2] = ["ed25519", "hmac-sha256"];

/// Contract fields of one evidence ref, in producer emission order (frozen).
pub const EVIDENCE_REF_FIELDS: [&str; 8] = [
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
];

/// Why a payload could not be canonicalized. Both variants are fail-closed:
/// a payload that cannot be canonicalized cannot be hashed, and therefore
/// cannot be evidence at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A float (any `f64`-backed number, incl. NaN/inf) was found anywhere in
    /// the payload. The strict profile carries decimals as strings (ADR-0001 D1).
    FloatRejected,
    /// `serde_json` failed to serialize the value (not reachable for a
    /// well-formed `Value`, kept so the API never panics).
    Serialize(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloatRejected => {
                f.write_str("floats are not permitted in canonical payloads (strict profile)")
            }
            Self::Serialize(msg) => write!(f, "canonical serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Recursively reject floats anywhere in `value` (strict profile).
fn reject_floats(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Number(n) if n.is_f64() => Err(CanonicalError::FloatRejected),
        Value::Array(items) => items.iter().try_for_each(reject_floats),
        Value::Object(map) => map.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

/// Layer-0 strict canonical JSON of `value` as a `String` (ADR-0001 D1).
///
/// Sorted keys, compact separators, UTF-8 preserved, floats rejected. This is
/// the exact text content hashes and signatures are computed over; see
/// `vectors/canonical-json/` for the golden cases.
pub fn canonical_string(value: &Value) -> Result<String, CanonicalError> {
    reject_floats(value)?;
    serde_json::to_string(value).map_err(|e| CanonicalError::Serialize(e.to_string()))
}

/// [`canonical_string`] as UTF-8 bytes — the Python `canonical_bytes` twin.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    canonical_string(value).map(String::into_bytes)
}

/// SHA-256 of `data` as lowercase hex (64 chars) — the family hex discipline.
pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 (lowercase hex) over the canonical encoding of `value`.
pub fn content_hash(value: &Value) -> Result<String, CanonicalError> {
    canonical_string(value).map(|s| sha256_hex(s.as_bytes()))
}

/// The signer-bound Layer-1 message a detached signature covers:
/// `canonical({"content_hash": …, "signer": …})` (ADR-0001 D3). Binding the
/// signer into the message blocks cross-signer replay. Infallible: both
/// fields are strings, so the strict profile cannot reject it.
pub fn signing_message(content_hash: &str, signer: &str) -> String {
    let payload = serde_json::json!({"content_hash": content_hash, "signer": signer});
    canonical_string(&payload).expect("string-only payload is always canonicalizable")
}

/// The `evidence-ref@3` message (ADR-0004 D2): subject- and tier-bound,
/// `canonical({"assurance_tier", "content_hash", "framework", "item_id",
/// "signer"})`. `assurance_tier` is the resolved tier; `None` means
/// [`DEFAULT_ASSURANCE_TIER`], exactly as an absent wire field does. Checking
/// the tier against [`ASSURANCE_TIERS`] is the verifier's job, as it is for
/// every other field.
pub fn signing_message_v3(
    content_hash: &str,
    signer: &str,
    framework: &str,
    item_id: &str,
    assurance_tier: Option<&str>,
) -> String {
    let payload = serde_json::json!({
        "assurance_tier": assurance_tier.unwrap_or(DEFAULT_ASSURANCE_TIER),
        "content_hash": content_hash,
        "framework": framework,
        "item_id": item_id,
        "signer": signer,
    });
    canonical_string(&payload).expect("string-only payload is always canonicalizable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_are_rejected_at_any_depth() {
        assert_eq!(
            canonical_string(&json!(1.5)),
            Err(CanonicalError::FloatRejected)
        );
        assert_eq!(
            canonical_string(&json!([1, [2, 3.0]])),
            Err(CanonicalError::FloatRejected)
        );
        assert_eq!(
            canonical_string(&json!({"a": {"b": [{"c": 0.1}]}})),
            Err(CanonicalError::FloatRejected)
        );
        assert!(canonical_string(&json!({"a": "1.5", "b": 1, "c": null})).is_ok());
    }

    #[test]
    fn canonical_profile_sorts_keys_and_keeps_utf8() {
        let v = json!({"z": 1, "a": {"y": "ü", "b": [true, null]}});
        assert_eq!(
            canonical_string(&v).unwrap(),
            r#"{"a":{"b":[true,null],"y":"ü"},"z":1}"#
        );
        assert_eq!(
            canonical_bytes(&v).unwrap(),
            canonical_string(&v).unwrap().into_bytes()
        );
    }

    #[test]
    fn sha256_hex_is_lowercase_64_chars() {
        // SHA-256("") — well-known constant.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(content_hash(&json!({})).unwrap(), sha256_hex(b"{}"));
    }

    #[test]
    fn signing_message_is_sorted_and_signer_bound() {
        assert_eq!(
            signing_message("ab", "s"),
            r#"{"content_hash":"ab","signer":"s"}"#
        );
        assert_ne!(signing_message("ab", "s"), signing_message("ab", "t"));
    }

    #[test]
    fn signing_message_v3_binds_subject_and_resolved_tier() {
        assert_eq!(
            signing_message_v3("ab", "s", "iki-gov", "D1", None),
            r#"{"assurance_tier":"attested","content_hash":"ab","framework":"iki-gov","item_id":"D1","signer":"s"}"#
        );
        assert_eq!(
            signing_message_v3("ab", "s", "iki-gov", "D1", None),
            signing_message_v3("ab", "s", "iki-gov", "D1", Some("attested"))
        );
        assert_ne!(
            signing_message_v3("ab", "s", "iki-gov", "D1", None),
            signing_message_v3("ab", "s", "iki-gov", "D2", None)
        );
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            CanonicalError::FloatRejected.to_string(),
            "floats are not permitted in canonical payloads (strict profile)"
        );
        assert_eq!(
            CanonicalError::Serialize("x".into()).to_string(),
            "canonical serialization failed: x"
        );
    }
}
