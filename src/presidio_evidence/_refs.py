"""Evidence refs, envelopes, and fail-closed trust-store verification.

Structural validation of the wire contract only — ``item_id`` *domain* validation
(e.g. ikigov checklist membership) stays consumer-side by design (ADR-0001;
schema note on ``evidenceRef``). Ed25519 public-key well-formedness is enforced
fail-closed at verification time (a malformed key verifies to ``False``), not at
load, matching the consumers and the trust-store schema.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from ._constants import EVIDENCE_REF_FIELDS, EVIDENCE_REF_SCHEMA_ID, SIGNING_ALGORITHMS
from ._errors import EvidenceError
from ._signing import _require_crypto, verify_ed25519, verify_hmac

_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
_MAX_STR = 512


@dataclass(frozen=True)
class EvidenceRef:
    """One signed evidence reference (the 8 frozen contract fields, in order)."""

    item_id: str
    source: str
    source_version: str
    ledger_ref: str
    content_hash: str
    signer: str
    signature: str
    claimed_at: str

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in EVIDENCE_REF_FIELDS}


def _str_field(raw: Mapping[str, object], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value or len(value) > _MAX_STR:
        raise EvidenceError(f"evidence ref field '{name}' must be a non-empty string <={_MAX_STR}")
    if "\x00" in value:
        raise EvidenceError(f"evidence ref field '{name}' contains a null byte")
    return value


def _parse_ref(raw: object) -> EvidenceRef:
    if not isinstance(raw, Mapping):
        raise EvidenceError("each evidence entry must be an object")
    missing = [f for f in EVIDENCE_REF_FIELDS if f not in raw]
    if missing:
        raise EvidenceError(f"evidence ref missing field(s): {', '.join(missing)}")
    fields = {name: _str_field(raw, name) for name in EVIDENCE_REF_FIELDS}
    for hex_field in ("content_hash", "signature"):
        if not _HEX_RE.match(fields[hex_field]):
            raise EvidenceError(f"evidence ref {hex_field} must be lowercase hex (8-128 chars)")
    return EvidenceRef(**fields)


def parse_document(doc: object) -> list[EvidenceRef]:
    """Validate an evidence envelope and return its refs (fail-closed).

    Enforces the wire contract (the 8 fields, bounded strings, lowercase-hex
    hash/signature, optional schema id) but not ``item_id`` domain membership.
    """
    if not isinstance(doc, Mapping) or "evidence" not in doc:
        raise EvidenceError("evidence document must be an object with an 'evidence' array")
    schema = doc.get("schema")
    if schema is not None and schema != EVIDENCE_REF_SCHEMA_ID:
        raise EvidenceError(
            f"unsupported evidence schema: {schema!r} (expected {EVIDENCE_REF_SCHEMA_ID!r})"
        )
    entries = doc.get("evidence")
    if not isinstance(entries, list):
        raise EvidenceError("'evidence' must be an array")
    return [_parse_ref(entry) for entry in entries]


def load_evidence(text: str) -> list[EvidenceRef]:
    """Parse evidence-envelope JSON text into validated refs."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid evidence JSON: {exc.msg}") from exc
    return parse_document(doc)


def build_envelope(
    refs: list[EvidenceRef] | list[Mapping[str, str]],
    *,
    source: str | None = None,
    source_version: str | None = None,
    use_case: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Assemble an evidence envelope from refs plus optional metadata."""
    envelope: dict[str, object] = {"schema": EVIDENCE_REF_SCHEMA_ID}
    if use_case is not None:
        envelope["use_case"] = use_case
    if source is not None:
        envelope["source"] = source
    if source_version is not None:
        envelope["source_version"] = source_version
    if generated_at is not None:
        envelope["generated_at"] = generated_at
    envelope["evidence"] = [r.to_dict() if isinstance(r, EvidenceRef) else dict(r) for r in refs]
    return envelope


def _normalise_entry(signer: str, value: object) -> dict[str, object]:
    """Normalise a trust entry to ``{'alg', 'keys'}`` (``keys`` always a list).

    A bare string is an HMAC secret; an object declares ``alg`` and key material
    (``public_key``/``key``, single value or list for rotation).
    """
    if isinstance(value, str):
        if not value:
            raise EvidenceError(f"trust entry '{signer}': empty HMAC secret")
        return {"alg": "hmac-sha256", "keys": [value]}
    if isinstance(value, Mapping):
        alg = value.get("alg", "hmac-sha256")
        if alg not in SIGNING_ALGORITHMS:
            raise EvidenceError(f"trust entry '{signer}': unknown alg {alg!r}")
        raw = value.get("public_key") if alg == "ed25519" else value.get("key")
        raw = raw if raw is not None else (value.get("key") or value.get("public_key"))
        keys = [raw] if isinstance(raw, str) else raw
        if (
            not isinstance(keys, list)
            or not keys
            or not all(isinstance(k, str) and k for k in keys)
        ):
            raise EvidenceError(f"trust entry '{signer}': missing or invalid key material")
        return {"alg": alg, "keys": list(keys)}
    raise EvidenceError(f"trust entry '{signer}': must be a string or an object")


def load_trust_store(source: str | Mapping[str, object]) -> dict[str, dict[str, object]]:
    """Parse a trust store (JSON text or mapping) into normalised entries.

    Fails fast (clear message) if an Ed25519 entry is present without the
    ``cryptography`` dependency; otherwise key well-formedness is checked at
    verification time (fail-closed), matching the consumers.
    """
    if isinstance(source, str):
        try:
            data = json.loads(source)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"invalid trust-store JSON: {exc.msg}") from exc
    elif isinstance(source, Mapping):
        data = source
    else:
        raise EvidenceError("trust store must be a JSON string or mapping")
    if not isinstance(data, Mapping):
        raise EvidenceError("trust store must be a JSON object keyed by signer id")
    normalised = {signer: _normalise_entry(signer, value) for signer, value in data.items()}
    if any(entry["alg"] == "ed25519" for entry in normalised.values()):
        _require_crypto()  # fail fast with a clear message before verification
    return normalised


def verify_ref(ref: EvidenceRef | Mapping[str, object], trust: Mapping[str, object]) -> bool:
    """Verify a ref's signature against the trust store (fail-closed).

    Succeeds if the signature matches **any** key listed for the signer (key
    rotation); an unknown signer, malformed ref, or bad key returns ``False``.
    """
    if isinstance(ref, EvidenceRef):
        content_hash, signer, signature = ref.content_hash, ref.signer, ref.signature
    elif isinstance(ref, Mapping):
        content_hash = ref.get("content_hash")
        signer = ref.get("signer")
        signature = ref.get("signature")
    else:
        return False
    if not (
        isinstance(content_hash, str) and isinstance(signer, str) and isinstance(signature, str)
    ):
        return False
    entry = trust.get(signer)
    if entry is None:
        return False
    norm = (
        entry if isinstance(entry, Mapping) and "keys" in entry else _normalise_entry(signer, entry)
    )
    verify = verify_ed25519 if norm["alg"] == "ed25519" else verify_hmac
    return any(verify(content_hash, signer, signature, key) for key in norm["keys"])
