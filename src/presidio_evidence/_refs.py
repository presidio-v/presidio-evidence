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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ._constants import (
    ASSURANCE_TIERS,
    DEFAULT_ASSURANCE_TIER,
    EVIDENCE_REF_FIELDS,
    EVIDENCE_REF_SCHEMA_ID,
    EVIDENCE_REF_SCHEMA_ID_V3,
    EVIDENCE_REF_SCHEMA_IDS,
    FRAMEWORK_PATTERN,
    SIGNING_ALGORITHMS,
    TIERED_SCHEMA_IDS,
)
from ._errors import EvidenceError
from ._signing import _require_crypto, signing_message, signing_message_v3, verify_message

_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
_FRAMEWORK_RE = re.compile(FRAMEWORK_PATTERN)
_MAX_STR = 512


@dataclass(frozen=True)
class EvidenceRef:
    """One signed evidence reference (the 8 frozen contract fields, in order).

    ``assurance_tier`` is the additive optional field of ``evidence-ref@2``
    (ADR-0003); ``None`` on the wire (absent, or an @1 ref) resolves to the
    default ``"attested"`` via :attr:`tier`. Under @1/@2 it is metadata about the
    referenced evidence and NOT part of the signed message
    (``canonical({content_hash, signer})``).

    ``framework`` is the required @3 field naming the vocabulary of ``item_id``
    (ADR-0004); ``schema`` records which major the ref was parsed under. It is
    not a wire field: it selects the signed message (@3 binds subject and tier).
    """

    item_id: str
    source: str
    source_version: str
    ledger_ref: str
    content_hash: str
    signer: str
    signature: str
    claimed_at: str
    assurance_tier: str | None = None
    framework: str | None = None
    schema: str = EVIDENCE_REF_SCHEMA_ID

    @property
    def tier(self) -> str:
        """Resolved assurance tier: the declared value, or ``"attested"`` if absent."""
        return self.assurance_tier if self.assurance_tier is not None else DEFAULT_ASSURANCE_TIER

    @property
    def subject_bound(self) -> bool:
        """True iff the signature covers the subject (an ``evidence-ref@3`` ref)."""
        return self.schema == EVIDENCE_REF_SCHEMA_ID_V3

    def to_dict(self) -> dict[str, str]:
        """The 8 frozen contract fields, plus ``framework``/``assurance_tier`` iff set.

        Omitting an undeclared tier keeps @1 envelopes byte-identical and the
        content-hash/signing surface unchanged.
        """
        out = {name: getattr(self, name) for name in EVIDENCE_REF_FIELDS}
        if self.framework is not None:
            out["framework"] = self.framework
        if self.assurance_tier is not None:
            out["assurance_tier"] = self.assurance_tier
        return out


def _bounded_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_STR:
        raise EvidenceError(f"{label} must be a non-empty string <={_MAX_STR}")
    if "\x00" in value:
        raise EvidenceError(f"{label} contains a null byte")
    return value


def _str_field(raw: Mapping[str, object], name: str) -> str:
    return _bounded_str(raw.get(name), f"evidence ref field '{name}'")


def _optional_envelope_field(raw: Mapping[str, object], name: str) -> str | None:
    if name not in raw:
        return None
    return _bounded_str(raw.get(name), f"evidence envelope field '{name}'")


def _parse_ref(raw: object, *, schema: str | None) -> EvidenceRef:
    if not isinstance(raw, Mapping):
        raise EvidenceError("each evidence entry must be an object")
    missing = [f for f in EVIDENCE_REF_FIELDS if f not in raw]
    if missing:
        raise EvidenceError(f"evidence ref missing field(s): {', '.join(missing)}")
    fields = {name: _str_field(raw, name) for name in EVIDENCE_REF_FIELDS}
    for hex_field in ("content_hash", "signature"):
        if not _HEX_RE.match(fields[hex_field]):
            raise EvidenceError(f"evidence ref {hex_field} must be lowercase hex (8-128 chars)")
    tier = None
    if schema in TIERED_SCHEMA_IDS:
        tier = raw.get("assurance_tier")
        if tier is not None and tier not in ASSURANCE_TIERS:
            raise EvidenceError(
                "evidence ref assurance_tier must be one of "
                f"{ASSURANCE_TIERS} or absent, got {tier!r}"
            )
    framework = None
    if schema == EVIDENCE_REF_SCHEMA_ID_V3:
        framework = raw.get("framework")
        if not isinstance(framework, str) or not _FRAMEWORK_RE.match(framework):
            raise EvidenceError(f"evidence ref framework must match {FRAMEWORK_PATTERN}")
    return EvidenceRef(
        **fields,
        assurance_tier=tier,
        framework=framework,
        schema=schema or EVIDENCE_REF_SCHEMA_ID,
    )


def parse_document(doc: object) -> list[EvidenceRef]:
    """Validate an evidence envelope and return its refs (fail-closed).

    Enforces the wire contract (the 8 fields, bounded strings, lowercase-hex
    hash/signature, and — @2 only — the optional per-ref ``assurance_tier``) but
    not ``item_id`` domain membership. The verifier accepts ``evidence-ref@1``
    (schema optional, grandfathered) and ``evidence-ref@2`` (schema required,
    ADR-0003); any other schema is rejected fail-closed (ADR-0001 D4/D5). A
    schema-absent envelope is parsed under the @1 grandfathering rule. An @1 ref
    carrying ``assurance_tier`` is tolerated as an ignored extra field (not an
    @1 freeze violation) and resolves to the "attested" default like any other
    @1 ref; declared tiers are honored only under ``evidence-ref@2``.
    """
    if not isinstance(doc, Mapping) or "evidence" not in doc:
        raise EvidenceError("evidence document must be an object with an 'evidence' array")
    schema = doc.get("schema")
    if schema is not None and schema not in EVIDENCE_REF_SCHEMA_IDS:
        raise EvidenceError(
            f"unsupported evidence schema: {schema!r} (expected one of {EVIDENCE_REF_SCHEMA_IDS})"
        )
    for name in ("use_case", "source", "source_version", "generated_at"):
        _optional_envelope_field(doc, name)
    entries = doc.get("evidence")
    if not isinstance(entries, list):
        raise EvidenceError("'evidence' must be an array")
    return [_parse_ref(entry, schema=schema) for entry in entries]


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
    schema: str = EVIDENCE_REF_SCHEMA_ID,
) -> dict:
    """Assemble an evidence envelope from refs plus optional metadata.

    ``schema`` defaults to ``evidence-ref@1`` (unchanged); pass
    :data:`EVIDENCE_REF_SCHEMA_ID_V2` to emit an ``evidence-ref@2`` envelope
    whose refs may carry ``assurance_tier`` (ADR-0003). The envelope shape and
    the signed message are otherwise identical.
    """
    if schema not in EVIDENCE_REF_SCHEMA_IDS:
        raise EvidenceError(
            f"unsupported evidence schema: {schema!r} (expected one of {EVIDENCE_REF_SCHEMA_IDS})"
        )
    entries = [r.to_dict() if isinstance(r, EvidenceRef) else dict(r) for r in refs]
    for entry in entries:
        if (schema == EVIDENCE_REF_SCHEMA_ID_V3) != ("framework" in entry):
            raise EvidenceError(
                "evidence-ref@3 refs must carry 'framework'; @1/@2 refs must not (ADR-0004)"
            )
    envelope: dict[str, object] = {"schema": schema}
    if use_case is not None:
        envelope["use_case"] = use_case
    if source is not None:
        envelope["source"] = source
    if source_version is not None:
        envelope["source_version"] = source_version
    if generated_at is not None:
        envelope["generated_at"] = generated_at
    envelope["evidence"] = entries
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


def _ref_fields(ref: EvidenceRef | Mapping[str, object], schema: str) -> dict | None:
    if isinstance(ref, EvidenceRef):
        fields: dict[str, object] = dict(ref.to_dict())
        schema = ref.schema
    elif isinstance(ref, Mapping):
        fields = dict(ref)
    else:
        return None
    fields["_schema"] = schema
    return fields


def _message(fields: Mapping[str, object]) -> bytes | None:
    """The signed bytes for a ref; the schema decides, never field presence."""
    content_hash, signer = fields.get("content_hash"), fields.get("signer")
    if not (isinstance(content_hash, str) and isinstance(signer, str)):
        return None
    if fields["_schema"] != EVIDENCE_REF_SCHEMA_ID_V3:
        return signing_message(content_hash, signer)
    framework, item_id = fields.get("framework"), fields.get("item_id")
    tier = fields.get("assurance_tier")
    if not (isinstance(framework, str) and _FRAMEWORK_RE.match(framework)):
        return None
    if not isinstance(item_id, str) or (tier is not None and tier not in ASSURANCE_TIERS):
        return None
    return signing_message_v3(content_hash, signer, framework, item_id, tier)


def verify_ref(
    ref: EvidenceRef | Mapping[str, object],
    trust: Mapping[str, object],
    *,
    schema: str = EVIDENCE_REF_SCHEMA_ID,
    expected_framework: str | None = None,
) -> bool:
    """Verify a ref's signature against the trust store (fail-closed).

    Succeeds if the signature matches **any** key listed for the signer (key
    rotation); an unknown signer, malformed ref, or bad key returns ``False``.

    The message follows the ref's schema: an :class:`EvidenceRef` carries the
    schema it was parsed under; a bare mapping is read under ``schema`` (default
    @1), so a ``framework`` key on it never selects the @3 message by itself.
    With ``expected_framework`` the caller demands subject binding (ADR-0004
    D4): @1/@2 refs fail, and an @3 ref verifies only for that framework.
    """
    fields = _ref_fields(ref, schema)
    if fields is None:
        return False
    if expected_framework is not None and (
        fields["_schema"] != EVIDENCE_REF_SCHEMA_ID_V3
        or fields.get("framework") != expected_framework
    ):
        return False
    message = _message(fields)
    signer, signature = fields.get("signer"), fields.get("signature")
    if message is None or not isinstance(signature, str):
        return False
    entry = trust.get(signer)
    if entry is None:
        return False
    norm = (
        entry if isinstance(entry, Mapping) and "keys" in entry else _normalise_entry(signer, entry)
    )
    return any(verify_message(message, signature, key, alg=norm["alg"]) for key in norm["keys"])


def reused_refs(refs: Iterable[EvidenceRef]) -> frozenset[tuple[str, str]]:
    """``(signer, content_hash)`` pairs that @1/@2 refs claim for several items.

    The @1/@2 message does not cover ``item_id``, so one genuine ref can be
    copied under every item and still verify. A consumer cannot tell which item
    the producer meant, so such a ref verifies for none of them (ADR-0004 D5,
    from ikigov-assess). @3 refs are exempt: each claim signs its own subject.
    The rule works per envelope; claims split across envelopes evade it.
    """
    items: dict[tuple[str, str], set[str]] = {}
    for ref in refs:
        if not ref.subject_bound:
            items.setdefault((ref.signer, ref.content_hash), set()).add(ref.item_id)
    return frozenset(key for key, ids in items.items() if len(ids) > 1)


@dataclass(frozen=True)
class RefResult:
    """Outcome for one ref of :func:`verify_envelope`."""

    ref: EvidenceRef
    verified: bool
    reason: str


def verify_envelope(
    doc: object,
    trust: Mapping[str, object],
    *,
    expected_framework: str | None = None,
) -> list[RefResult]:
    """Parse an envelope and verify every ref, applying the full policy.

    Raises :class:`EvidenceError` on a malformed envelope (fail-closed). Per ref:
    a declared ``optimistic``/``zk`` tier is not verifiable here (ADR-0003 D6);
    with ``expected_framework`` only @3 refs for that framework can pass
    (ADR-0004 D4); @1/@2 refs reused across items fail (D5); then the signature.
    """
    refs = parse_document(doc)
    reused = reused_refs(refs)
    items: dict[tuple[str, str], set[str]] = {}
    for ref in refs:
        items.setdefault((ref.signer, ref.content_hash), set()).add(ref.item_id)
    results = []
    for ref in refs:
        key = (ref.signer, ref.content_hash)
        if ref.tier != DEFAULT_ASSURANCE_TIER:
            reason = (
                f"assurance tier {ref.tier!r} is not verifiable by this verifier "
                "(signature attestation only)"
            )
        elif expected_framework is not None and not ref.subject_bound:
            reason = "subject binding required (evidence-ref@3)"
        elif expected_framework is not None and ref.framework != expected_framework:
            reason = f"framework {ref.framework!r} is not {expected_framework!r}"
        elif key in reused:
            reason = f"reused under {len(items[key])} items"
        elif not verify_ref(ref, trust):
            reason = "signature not verified"
        else:
            results.append(RefResult(ref, True, "ok"))
            continue
        results.append(RefResult(ref, False, reason))
    return results
