"""Identity of a ``gate-certificate@1`` document (ADR-0006).

A gate certificate (issued by presidio-hardened-ikigov-assess) is signed whole:
the issuer signs the canonical-json@1 bytes of the document with its top-level
``signature`` field removed (ikigov ``certificate.signing_bytes``). ADR-0006
makes the SHA-256 of exactly those bytes the certificate's identity, the hash a
provenance parent (ADR-0002) uses when it points at a gate decision.

The identity covers the issuance: the decision, the affirmation set, the
embedded evidence-refs, the issuer and the timestamps. The predicate hash
(``framework_content_hash``) only names the rule; two certificates issued under
the same rule share it and still have different identities.
"""

from __future__ import annotations

from collections.abc import Mapping

from ._canonical import canonical_bytes, sha256_hex
from ._errors import EvidenceError

#: Schema id of the ikigov-assess gate certificate (ADR-0006).
GATE_CERTIFICATE_SCHEMA_ID = "presidio-hardened/gate-certificate@1"


def gate_certificate_signing_bytes(document: Mapping[str, object]) -> bytes:
    """canonical-json@1 bytes of ``document`` minus its top-level ``signature``.

    Byte-identical to ikigov-assess ``certificate.signing_bytes`` for every
    float-free certificate (all certificates ikigov emits are float-free).
    Fails closed on a non-mapping, a foreign schema id, or content the strict
    canonicaliser rejects.
    """
    if not isinstance(document, Mapping):
        raise EvidenceError("a gate certificate must be a JSON object")
    if document.get("schema") != GATE_CERTIFICATE_SCHEMA_ID:
        raise EvidenceError(f"not a {GATE_CERTIFICATE_SCHEMA_ID} document")
    stripped = {key: value for key, value in document.items() if key != "signature"}
    try:
        return canonical_bytes(stripped)
    except (TypeError, ValueError) as exc:
        raise EvidenceError("gate certificate is not canonical-json@1 encodable") from exc


def gate_certificate_identity(document: Mapping[str, object]) -> str:
    """The certificate's ``content_hash`` (ADR-0006): lowercase-hex SHA-256 of
    :func:`gate_certificate_signing_bytes`. Present or absent ``signature``
    yields the same identity, so a parent hash can be computed before or after
    signing."""
    return sha256_hex(gate_certificate_signing_bytes(document))
