"""presidio-evidence — shared evidence substrate for the presidio-hardened-* suite.

The normative contract is the ``schemas/`` + ``vectors/`` trees at the repo root,
enforced by the conformance suites (Python ``tests/``, Rust ``rust/tests/``). As
of **v0.2.0** this package also ships the reference **implementation** the
consumers migrate onto (ADR-0001 action item 5, Q4 extraction):

* Layer 0 — :func:`canonical_bytes`, :func:`sha256_hex`, :func:`content_hash`.
* Layer 1 — :func:`sign_evidence` (/ :func:`sign_ed25519` / :func:`sign_hmac`),
  :func:`verify_ed25519` / :func:`verify_hmac`, and the signer-bound
  :func:`signing_message`.
* Refs & trust — :class:`EvidenceRef`, :func:`parse_document` /
  :func:`load_evidence`, :func:`build_envelope`, :func:`load_trust_store`,
  :func:`verify_ref` (fail-closed).
* Keys (ADR-0001 D3) — :func:`generate_ed25519_keypair`, :func:`public_key_hex`,
  :func:`load_private_key` (``0600`` file or env var; never logged),
  :func:`write_private_key`. The ``presidio-evidence`` CLI (D4) exposes
  ``verify`` (exit 0/1) and ``keygen``.
* Numeric payload encoding (ADR-0005) — :func:`encode_decimal` (producer,
  half-even to a declared precision), :func:`is_decimal_string` (verifier,
  never parses to float), :func:`decimal_pattern` (JSON Schema pattern).
* Gate-certificate identity (ADR-0006) — :func:`gate_certificate_identity`,
  :func:`gate_certificate_signing_bytes`.

Ed25519 needs the optional ``cryptography`` dependency (``[crypto]`` extra);
HMAC-SHA256 and Layer 0 are pure stdlib. The wire format is unchanged from
v0.1.0 — the golden vectors prove it byte-for-byte. Independent of Microsoft
Presidio.
"""

from __future__ import annotations

from ._canonical import canonical_bytes, content_hash, sha256_hex
from ._constants import (
    ASSURANCE_TIERS,
    DEFAULT_ASSURANCE_TIER,
    EVIDENCE_REF_FIELDS,
    EVIDENCE_REF_SCHEMA_ID,
    EVIDENCE_REF_SCHEMA_ID_V2,
    EVIDENCE_REF_SCHEMA_IDS,
    LAYER0_READING_SCHEMA_IDS,
    SIGNING_ALGORITHMS,
    TRUST_STORE_SCHEMA_ID,
)
from ._errors import EvidenceError
from ._gate_certificate import (
    GATE_CERTIFICATE_SCHEMA_ID,
    gate_certificate_identity,
    gate_certificate_signing_bytes,
)
from ._keys import (
    generate_ed25519_keypair,
    load_private_key,
    public_key_hex,
    write_private_key,
)
from ._numeric import (
    DECIMAL_STRING_MAX_LEN,
    UNBOUNDED_SENTINEL,
    decimal_pattern,
    encode_decimal,
    is_decimal_string,
)
from ._refs import (
    EvidenceRef,
    build_envelope,
    load_evidence,
    load_trust_store,
    parse_document,
    verify_ref,
)
from ._signing import (
    sign_ed25519,
    sign_evidence,
    sign_hmac,
    signing_message,
    verify_ed25519,
    verify_hmac,
)

__version__ = "0.4.0"

__all__ = [
    # contract constants (frozen; ADR-0001) + assurance tiers (ADR-0003)
    "EVIDENCE_REF_FIELDS",
    "EVIDENCE_REF_SCHEMA_ID",
    "EVIDENCE_REF_SCHEMA_ID_V2",
    "EVIDENCE_REF_SCHEMA_IDS",
    "ASSURANCE_TIERS",
    "DEFAULT_ASSURANCE_TIER",
    "LAYER0_READING_SCHEMA_IDS",
    "SIGNING_ALGORITHMS",
    "TRUST_STORE_SCHEMA_ID",
    "__version__",
    # errors
    "EvidenceError",
    # Layer 0
    "canonical_bytes",
    "sha256_hex",
    "content_hash",
    # Layer 1
    "signing_message",
    "sign_evidence",
    "sign_ed25519",
    "sign_hmac",
    "verify_ed25519",
    "verify_hmac",
    # refs & trust
    "EvidenceRef",
    "parse_document",
    "load_evidence",
    "build_envelope",
    "load_trust_store",
    "verify_ref",
    # keys (ADR-0001 D3)
    "generate_ed25519_keypair",
    "public_key_hex",
    "load_private_key",
    "write_private_key",
    # numeric payload encoding (ADR-0005)
    "DECIMAL_STRING_MAX_LEN",
    "UNBOUNDED_SENTINEL",
    "decimal_pattern",
    "encode_decimal",
    "is_decimal_string",
    # gate-certificate identity (ADR-0006)
    "GATE_CERTIFICATE_SCHEMA_ID",
    "gate_certificate_identity",
    "gate_certificate_signing_bytes",
]
