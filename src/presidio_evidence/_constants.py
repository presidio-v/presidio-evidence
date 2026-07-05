"""Frozen contract constants (ADR-0001). Mirrored by ``rust/src/lib.rs``."""

from __future__ import annotations

#: Cross-repo signed-evidence schema id (frozen; ADR-0001 D1/D5).
EVIDENCE_REF_SCHEMA_ID = "presidio-hardened/evidence-ref@1"

#: Assurance-tier revision of the evidence-ref schema (ADR-0003, Accepted).
#: Adds an optional per-ref ``assurance_tier`` and makes the envelope ``schema``
#: field required; what gets signed is unchanged from @1.
EVIDENCE_REF_SCHEMA_ID_V2 = "presidio-hardened/evidence-ref@2"

#: Schema ids the verifier accepts (fail-closed on any other; ADR-0001 D4/D5).
EVIDENCE_REF_SCHEMA_IDS = (EVIDENCE_REF_SCHEMA_ID, EVIDENCE_REF_SCHEMA_ID_V2)

#: Assurance tiers (ADR-0003), default first: signature-attested / trusted
#: execution ("attested"), bonded optimistic assertion ("optimistic"), succinct
#: zero-knowledge proof ("zk"). Computational Jurisprudence (Stantchev 2026).
ASSURANCE_TIERS = ("attested", "optimistic", "zk")

#: Tier assumed when a ref omits ``assurance_tier`` (every @1 ref is implicitly
#: this tier); ADR-0003.
DEFAULT_ASSURANCE_TIER = "attested"

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
