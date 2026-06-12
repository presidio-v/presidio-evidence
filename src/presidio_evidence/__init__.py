"""presidio-evidence — shared evidence substrate for the presidio-hardened-* suite.

Scope (ADR-0001): this package currently ships **contract constants only**. The
normative contract is the ``schemas/`` + ``vectors/`` trees at the repo root,
enforced by the conformance suites (Python ``tests/``, Rust ``rust/tests/``).
Implementation code (canonicalization, signing, verification) is extracted from
the consumers in Q4 — conformance tests exist before code, deliberately.

Independent of Microsoft Presidio.
"""

from __future__ import annotations

__version__ = "0.1.0"

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

__all__ = [
    "EVIDENCE_REF_FIELDS",
    "EVIDENCE_REF_SCHEMA_ID",
    "SIGNING_ALGORITHMS",
    "TRUST_STORE_SCHEMA_ID",
    "__version__",
]
