# ADR-0003: Assurance tiers — evidence-ref@2 and proof-carrying-transaction vocabulary

**Status:** Accepted
**Date:** 2026-07-05
**Deciders:** V.S. (founder, governing account)
**Founder sign-off:** Accepted by V.S. on 2026-07-05.
**Source mandate:** Computational Jurisprudence (Stantchev, arXiv 2026, position paper), three-tier assurance regime for runtime compliance evidence; Computational Jurisprudence alignment.

## Context

The "Computational Jurisprudence" (CJ) research program frames a compliant runtime as a **proof-carrying transaction (PCT)**: an action carries, at execution time, the evidence that it satisfies the governing norm — **pre-hoc authorization-with-evidence** rather than **post-hoc monitoring**. CJ defines a three-tier **assurance** regime for that evidence:

- **attested** — trusted-execution / signature-attested: a signer vouches for the content (the family's current model).
- **optimistic** — a bonded assertion, presumed valid unless a fraud proof lands within a dispute window (**optimistic compliance**).
- **zk** — a succinct zero-knowledge proof of the norm predicate.

Today every `evidence-ref` is *implicitly* tier **attested**: an Ed25519/HMAC signature over `canonical({content_hash, signer})` is exactly a signature-attestation. The record has no place to say so, and no way for a producer to declare a stronger regime or for a verifier to demand a minimum tier. Declaring the tier in the record lets producers upgrade assurance without schema churn and lets verifiers express a policy ("this gate requires at least `optimistic`").

Forces:

1. **`evidence-ref@1` is frozen** (ADR-0001 D5: no field removals, no type/constraint changes, no new required fields within @1). Adding a field to the record is an `@2` concern by construction — Option B in ADR-0001 already reserved `@2` for exactly this kind of additive envelope change.
2. **The signed surface must not move.** The detached signature covers `canonical({content_hash, signer})` and is byte-pinned across five consumers and the golden vectors. The tier is *metadata about* the referenced evidence, not part of the authenticator; it must not enter the signed message.
3. **The tier names a target, not a capability.** `optimistic` and `zk` describe the assurance regime a producer *claims*; verifying a fraud proof or a ZK proof is a different machine entirely and is **not** in this repo's scope (extraction + conformance only, ADR-0001).
4. **Extra-field behaviour under @1 must be stated, not assumed.** Some consumer may already attach ad-hoc keys; the `@2` decision has to be consistent with how `@1` actually treats them.

### Extra-field finding (@1)

`schemas/evidence-ref.v1.schema.json` declares **no `additionalProperties: false`** — not on the envelope, not on `evidenceRef`, not on `$defs`. The Python verifier (`_parse_ref` / `parse_document`) reads only the known fields and **ignores unknown keys**; the Rust conformance path likewise indexes named fields. Therefore **an `@1` record carrying `assurance_tier` is valid under `@1`** and is silently ignored by `@1` consumers (they read the implicit `attested`). This is *consistent with the freeze*: an extra field is neither a field removal, a type/constraint change, nor a new required field, so it does not violate ADR-0001 D5. The golden vector `vectors/evidence-ref-v2/valid-v1-with-extra-tier.json` pins this (validated against the `@1` schema, expected **valid**). The consequence: attaching a tier to an `@1` record is *harmless but inert* — producers that want the tier honoured emit `@2`.

## Decision

Ship **`evidence-ref@2`** (`schemas/evidence-ref.v2.schema.json`, id `presidio-hardened/evidence-ref@2`) as an additive revision of `@1`, under the same freeze discipline (ADR-0001 D5 applies verbatim to `@2`).

- **D1 — Two differences from @1, nothing else.** (a) The envelope `schema` field is **required** and must be `presidio-hardened/evidence-ref@2` — no grandfathering in `@2` (unlike `@1`, where `schema` is optional). (b) Each `evidenceRef` gains one **optional** field `assurance_tier` with enum `["attested", "optimistic", "zk"]`. The eight `@1` fields, their types, bounds, and the lowercase-hex discipline are carried over unchanged.
- **D2 — @1 stays frozen and untouched.** `evidence-ref.v1.schema.json` is not edited; no `@1` vector is modified or deleted (append-only, ADR-0001 D5). Producers dual-emit during migration; `@2` ships alongside `@1`.
- **D3 — Default is `attested`.** When `assurance_tier` is absent, the resolved tier is `attested` — identical assurance to every `@1` record. The library exposes the resolved tier (`EvidenceRef.tier`, `DEFAULT_ASSURANCE_TIER`); the wire stays minimal (an undeclared tier is not emitted, so `@1` envelopes remain byte-identical).
- **D4 — Verifier accepts both, fails closed on anything else.** `parse_document` accepts `evidence-ref@1` and `evidence-ref@2` (`EVIDENCE_REF_SCHEMA_IDS`); an unknown schema major, or an out-of-enum tier under `@2`, is rejected fail-closed (ADR-0001 D4/D5). An `assurance_tier` field on `@1` remains an ignored extra field and resolves to `attested`; declared tiers are honored only under `@2`. Rust constants mirror the Python side.
- **D5 — The signed message is unchanged.** The detached signature still covers `canonical({content_hash, signer})` exactly as in `@1`. `assurance_tier` is **not** part of that message; it is signed only insofar as a producer content-hashes it into the *referenced* payload. The `@2` golden vectors reuse the `@1` golden `content_hash`/`signature` verbatim across all three tiers to make this explicit — declaring a tier changes nothing about verification.
- **D6 — `optimistic`/`zk` are targets, not implementations.** The enum reserves the CJ vocabulary so producers can *declare* an assurance regime. **Verification of fraud proofs (optimistic) or ZK proofs (zk) is explicitly OUT of scope** of this repo and this ADR. A verifier that only knows how to check `attested` signatures MUST treat an `optimistic`/`zk` ref as *unverified-by-this-verifier* and apply its own policy (e.g. fail closed), not as *verified*.

## Options considered

**A — envelope-level `min_assurance` only, no per-ref tier.** Lets a verifier demand a floor but gives producers nowhere to *declare* per-item assurance (a bundle can mix tiers). Rejected: the tier is a property of each referenced evidence item, not the envelope.

**B — reuse `@1`, put the tier in a free-form extra field.** The extra-field finding shows `@1` tolerates it — but it would be inert (ignored by `@1` consumers) and unvalidated (no enum). That is a convention, not a contract. Kept only as the documented back-compat path (a tier on an `@1` record is harmless), not the mechanism.

**C — `@2` with a required `schema` and an optional enum'd `assurance_tier` (chosen).** Additive, validated, signed-surface-preserving, and consistent with ADR-0001's reservation of `@2` for envelope-level additions. Making `schema` required in `@2` closes the one looseness `@1` grandfathered, at no cost to `@1`.

## Consequences

- **Consumer migration is opt-in.** Nothing breaks: `@1` producers and verifiers keep working; `@2`-aware verifiers accept both. A consumer adopts `@2` only when it wants to declare or require a tier.
- **Producers may declare tiers today.** The vocabulary and schema exist now; a producer emitting `attested` gains an explicit, machine-checkable statement of what was already true.
- **`optimistic`/`zk` name a roadmap, not a claim.** No fraud-proof or ZK-proof verifier ships here; a ref that declares those tiers is not "more verified" by this substrate. This boundary is load-bearing and is asserted by the code (the signed message is tier-independent) and by the vectors (all tiers reuse the `@1` signature).
- **Extra-field discipline is now recorded** (finding above): `@1` tolerates unknown fields by design; `@2` constrains the one field it adds via an enum but likewise sets no `additionalProperties: false`, matching `@1`'s posture.
- **Harder:** a future third tier or a tier-policy engine (min-assurance gates) is a further `@2` addition or an `@3`; not built now.

## Action items

1. [x] Founder sign-off on D1–D6 — **Accepted by V.S. on 2026-07-05**.
2. [x] `schemas/evidence-ref.v2.schema.json` + append-only `@2` golden vectors (`vectors/evidence-ref-v2/`), both suites green (Python 116 passed/3 skipped, 100% coverage; Rust conformance green — see gate).
3. [x] Python + Rust constants (`EVIDENCE_REF_SCHEMA_ID_V2`, `EVIDENCE_REF_SCHEMA_IDS`, `ASSURANCE_TIERS`, `DEFAULT_ASSURANCE_TIER`); verifier accepts `@1`+`@2`, tier exposed with the `attested` default.
4. [x] **Release gate (founder):** macOS local rerun completed 2026-07-05 after Option 1 remediation: vector stability OK, Python ruff OK, Python 116 passed / 3 skipped with 100% coverage, Rust fmt/clippy OK, `cargo test --locked` 17 passed, `pip-audit` clean, `cargo audit` clean, `uv build` produced 0.2.2 sdist/wheel. Any signed tag remains a founder release step.
5. [ ] Record adoption order once a producer declares a non-`attested` tier (candidate: x402 optimistic-compliance audit entries).
