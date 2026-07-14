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

#: Layer-0 reading schema ids — the payload types the family emits *inside* an
#: evidence-ref envelope (the producer's ``layer0_reading.schema``). Reserving a
#: new reading type is a one-place change here, plus its golden vectors: both
#: conformance lanes assert this tuple, the generator's output, and the vectors
#: tree agree exactly, so a type added in one place and forgotten in another
#: fails the build. Not a hash surface — this list may grow (a reading type,
#: once published, is frozen by ADR-0001 D5 like any other vector).
#: Mirrored by ``rust/src/lib.rs``.
LAYER0_READING_SCHEMA_IDS = (
    "presidio-hardened/energy-reading@1",
    "presidio-hardened/slo-reading@1",
    "presidio-hardened/training-run@1",
    "presidio-hardened/workshop-attestation@1",
)

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
