//! presidio-evidence — shared evidence substrate (Rust side).
//!
//! Scope (ADR-0001): contract constants only. The normative contract is the
//! `schemas/` + `vectors/` trees at the repo root; `tests/conformance.rs` proves
//! this toolchain reproduces the cross-language wire format byte-for-byte.
//! Implementation code is extracted from the consumers in Q4 — conformance
//! tests exist before code, deliberately. Treasury (the Rust consumer) joins at
//! Layer 0 (canonical JSON + SHA-256 content addressing); it has no signature
//! layer by design (dual-control instead — ADR-0001 D1).

/// Cross-repo signed-evidence schema id (frozen; ADR-0001 D1/D5).
pub const EVIDENCE_REF_SCHEMA_ID: &str = "presidio-hardened/evidence-ref@1";

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
