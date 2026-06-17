"""Frozen contract constants (ADR-0001). Mirrored by ``rust/src/lib.rs``."""

from __future__ import annotations

#: Cross-repo signed-evidence schema id (frozen; ADR-0001 D1/D5).
EVIDENCE_REF_SCHEMA_ID = "presidio-hardened/evidence-ref@1"

#: Verifier-side trust-store schema id (ADR-0001 D3).
TRUST_STORE_SCHEMA_ID = "presidio-hardened/trust-store@1"

#: Supported detached-signature algorithms, default first (ADR-0001 D3).
SIGNING_ALGORITHMS = ("ed25519", "hmac-sha256")

#: Contract fields of one evidence ref, in producer emission order (frozen).
EVIDENCE_REF_FIELDS = (
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
)
