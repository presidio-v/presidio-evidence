# ADR-0006: gate-certificate@1 identity and schema registration

**Status:** Proposed — awaiting founder sign-off
**Date:** 2026-10-18
**Deciders:** V.S. (founder, governing account)
**Founder sign-off:** pending.
**Source mandate:** provenance chain classify → gate → train (ADR-0002 adoption order); ikigov-assess `gate-certificate@1` (v0.23.0 T-B5, `certificate.py`); arch-translucency `training-run@1` (its ADR-0009). ADR-0004 is reserved for `evidence-ref@3` (issue #38).

## Context

ADR-0002 lets a payload name its upstream evidence by content hash in `parents`. The suite's flagship chain needs a training run to name the gate decision that admitted it. arch-translucency ADR-0009 says so in as many words ("hashes of upstream evidence payloads (classification, gate decision) are attested inside the signed content"). Nobody has said which hash *is* a gate decision's.

A `gate-certificate@1` (ikigov-assess `certificate.py`) carries two candidates:

- `framework_content_hash` (mirrored as `predicate.predicate_content_hash`): SHA-256 over the gate rule, i.e. the per-gate item mapping and the per-risk weights. Every certificate issued under the same checklist carries the same value.
- the hash of the certificate itself. ikigov signs the canonical bytes of the document with its top-level `signature` field removed (`signing_bytes`, lines 388–398), but it never names that hash or exposes it.

Neither `gate-certificate@1` nor `training-run@1` has a schema in this repo. Both are pinned only by producer code and, for `training-run@1`, by `vectors/training-run/`.

Forces:

1. **A parent must bind to one decision.** A training run is admitted by a specific issuance: this affirmation set, these embedded refs, this issuer, this validity window. A rule hash is shared by every issuance, OPEN and BLOCKED alike. A parent pointing at it would say "some gate under this checklist", which is no claim at all.
2. **The signed bytes already exist.** ikigov signs `canonical(document − signature)`. Hashing exactly those bytes needs no new canonicalisation, lets the identity be computed before or after signing, and makes "the hash I hold" and "the bytes the issuer vouched for" the same thing.
3. **The signature block is not content.** It records `{alg, signer, sig}`. Re-signing (key rotation, HMAC→Ed25519) must not change what a parent points at.
4. **Producers do not resolve parents** (ADR-0002 P4). The identity has to be computable by whoever holds the certificate, with no registry lookup.
5. **Registration describes, it does not change.** Both schemas are shipped. Registering them may not alter a single byte on the wire (ADR-0001 D5).

## Decision

- **G1 — Identity.** The identity (`content_hash`) of a `gate-certificate@1` document is SHA-256 over the canonical-json@1 bytes of the document minus its top-level `signature` field: exactly the bytes ikigov signs (`signing_bytes`). Lowercase hex, 64 characters. Reference: `presidio_evidence.gate_certificate_identity()` / `gate_certificate_signing_bytes()`; both fail closed on a non-object, a foreign schema id, or content canonical-json@1 rejects.
- **G2 — Parents use the identity.** A provenance parent (ADR-0002) that refers to a gate decision carries the G1 identity.
- **G3 — The predicate hash stays secondary.** `framework_content_hash` / `predicate.predicate_content_hash` keep their meaning: they identify the rule, not the issuance. They are never used as a parent. Rationale: a parent binds to the specific decision that admitted a run.
- **G4 — Resolution.** Producers do not resolve parents (P4). A producer MAY verify a certificate before adding its identity (e.g. a future arch-translucency `--gate-certificate` input that runs ikigov verification and refuses a certificate that does not verify, is expired or is not OPEN). Verifying is the producer's policy, never a condition of G1.
- **G5 — Schema registration.** `schemas/gate-certificate.v1.schema.json` and `schemas/training-run.v1.schema.json` are registered as descriptions of the shipped wire form, derived from ikigov-assess v0.28.0 `build_certificate`/`sign` and arch-translucency v0.24.2 `build_training_run_reading`. No `additionalProperties: false`, matching the family posture (ADR-0003 extra-field finding). The `training-run@1` energy fields carry the ADR-0005 N8 grandfathered form. `gate-certificate@1` is signed whole, like `workshop-leavebehind@1`, so it is not a Layer-0 reading and is not added to `LAYER0_READING_SCHEMA_IDS`.

### Vectors (append-only)

`vectors/gate-certificate/`:

- `valid-certificate.json`: gate G0, three items affirmed by Ed25519-signed refs, `grounding: evidence-verified`, `require_evidence: true`, one placeholder classification parent, `not_after`, issuer-signed with the family test key. Companion notes carry the canonical signing bytes and the identity:
  **`dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a`**.
- `child-training-run.json`: a `training-run@1` reading whose `parents[0]` is that identity, signed into an `evidence-ref@1` envelope. This is the ADR-0002 edge from a run to its gate.

Cross-checked at creation against ikigov-assess v0.28.0 (read-only): `build_certificate()` with the same inputs yields the document minus `signature` byte for byte; `sha256(certificate.signing_bytes(doc))` equals the identity; `verify_certificate(doc, trust, now=2026-07-03)` returns `ok`. The Python and Rust suites both recompute the identity, verify the issuer signature over the identity bytes, verify every embedded ref, and check the child's parent link. The two existing `training-run/` vectors and the new child validate against the new `training-run@1` schema.

## Options considered

**A — Identity = SHA-256 of the signed bytes (chosen).** No new canonicalisation, computable before or after signing, independent of the signature algorithm, and it binds the exact issuance.

**B — `framework_content_hash` as the parent.** Already present, already a hash. Rejected (G3): it names the rule and is shared by every certificate under it, including BLOCKED ones.

**C — SHA-256 over the whole document, signature included.** Binds the signature too, so a re-signed certificate would get a new identity and existing parents would stop resolving. It also cannot be computed until signing is done. Rejected.

**D — A new `certificate_id` field set by the issuer.** Readable, but it is a claim inside the content rather than a property of it, and it needs `gate-certificate@2` or an optional field that verifiers would have to cross-check. Rejected.

## Consequences

- Easier: the classify → gate → train chain is now a hash chain end to end; an auditor holding a run, its certificate and a trust store can walk it with no service in the path.
- Easier: consumers in other languages validate certificates and training runs against a schema instead of reading Python.
- Harder: a certificate that ikigov re-issues (new `assessed_at`) has a new identity, so a run admitted by the earlier issuance keeps pointing at that one. That is the intended reading of "the decision that admitted it".
- Not changed: ikigov's wire format and signing rule, arch-translucency's wire format, every published vector.

## Open points (for founder review)

1. **`--gate-certificate` does not exist yet.** arch-translucency main (v0.24.2) has no such option; G4 names it as the intended example. Building it is an arch-translucency change.
2. **`framework_content_hash` cannot be recomputed here.** ikigov hashes float risk weights with a non-strict canonicaliser (ADR-0005 open point 2), so the vector treats the value as opaque. Identity (G1) is unaffected: the certificate document itself is float-free.
3. **Fields the schemas could not pin** without inventing a constraint ikigov does not enforce:
   - `gate` is a pattern `^G[0-9]+$`, not ikigov's current enum G0–G5;
   - affirmation `id` and `predicate.gate_items` are free bounded strings; ikigov's checklist vocabulary and the sorted order of `gate_items` are verifier-side checks;
   - `assessed_at` is a bounded string. ikigov requires the strict `YYYY-MM-DDTHH:MM:SSZ` form only when `not_after` is set, and otherwise accepts what the caller passes;
   - `require_evidence` is a boolean, although ikigov writes it only when true;
   - embedded-ref `assurance_tier` is optional in the schema, although ikigov always writes it;
   - `training-run@1` `model_hash` / `dataset_hash` come from producer code; no vector exercises them yet. The IEEE round-trip property of the energy fields is producer-enforced and cannot be expressed in JSON Schema;
   - semantic rules (decision recomputation, predicate identity, issuer = `signature.signer`, one ref per item) stay verifier-side.
4. **Interaction with issue #38 / ADR-0004.** The identity covers the embedded refs and their `item_id`s, so a parent pins which ref backed which item at issuance. It does not close the relabelling gap of `evidence-ref@1`/`@2`, which is what ADR-0004 is reserved for.
5. **ikigov does not expose the identity.** Recommended follow-up: ikigov adds `certificate_identity()` (or imports this library's), and `iga certify` prints it, so a producer can copy it into `parents` without recomputing.

## Action items

1. [ ] Founder sign-off on G1–G5.
2. [x] Reference helper, both schemas, `vectors/gate-certificate/`, Python and Rust conformance (this PR).
3. [ ] ikigov-assess: expose the identity (open point 5).
4. [ ] arch-translucency: optional `--gate-certificate` verify-then-parent input (open point 1).
