# ADR-0004: evidence-ref@3 — bind the subject into the signed message

**Status:** Proposed
**Date:** 2026-10-25
**Deciders:** V.S. (founder, governing account)
**Founder sign-off:** pending.
**Source mandate:** issue #1 (carried over from the development repository); ikigov-assess security audit 2026-09-30, finding C-1, and its consumer-side mitigation (ikigov-assess PR #60, `reused_refs`).

## Context

The detached signature on an `evidence-ref@1`/`@2` record covers `canonical({content_hash, signer})` (ADR-0001 D3, unchanged by ADR-0003 D5). It proves who vouched for which bytes. It does not say what those bytes are evidence *for*: `item_id` travels next to the signature, not inside it.

Whoever assembles an evidence envelope can therefore copy one genuine ref under any number of item ids, and every copy verifies. The 2026-09-30 ikigov-assess audit showed the consequence: one HMAC-signed ref from a trusted producer, cloned under all 25 checklist ids, made `iga assess --require-evidence` count 25 of 25 items as evidence-verified and open every gate.

ikigov-assess closed the hole consumer-side without touching the wire: a `(signer, content_hash)` pair claimed for more than one item verifies for none of them. That is fail-closed, and it has a price: a producer can no longer let one artefact back two items honestly, because identical content yields an identical ref. The rule also lives in one consumer; the others still accept a relabelled ref.

ADR-0001 already made this argument once: `signer` sits inside the signed message so a signature cannot be replayed under another signer. The subject deserves the same treatment.

Forces:

1. **@1 and @2 are frozen** (ADR-0001 D5, ADR-0003 D2). Their signed message cannot change; a subject-bound message is a new major, `@3`.
2. **`item_id` is consumer vocabulary.** `S1`–`I5` mean something in the IKI-Gov checklist and nothing elsewhere. A producer that signs a bare `item_id` commits to one consumer's vocabulary without saying which.
3. **The binding must not be strippable.** If a verifier could be talked into checking an @3 ref under the @2 message (or the reverse), the binding would be decorative.
4. **Scope discipline.** This repo extracts and conforms; it does not add capabilities (ADR-0001). This change is a security fix to a demonstrated fail-open in the shared contract, which is why it is in scope.

## Decision

Ship **`evidence-ref@3`** (`schemas/evidence-ref.v3.schema.json`, id `presidio-hardened/evidence-ref@3`).

- **D1 — Record shape.** The envelope `schema` field is required and must be the @3 id. Each ref carries the eight @1 fields, one new **required** field `framework`, and the optional `assurance_tier` with the @2 enum. `framework` names the vocabulary `item_id` belongs to: lowercase, `^[a-z0-9][a-z0-9._-]{0,63}$` (for example `iki-gov`). A framework id names one fixed item vocabulary and is never reused: a renumbered checklist registers a new id (`iki-gov-2`).
- **D2 — Signed message.** `canonical({"assurance_tier", "content_hash", "framework", "item_id", "signer"})`, where `assurance_tier` is the resolved tier (`"attested"` when the field is absent). The signature names its subject `(framework, item_id)` and the regime it vouches for.
- **D3 — The schema chooses the message, never field presence.** The parser records each ref's schema; `verify_ref` on a bare mapping takes an explicit `schema` argument (default @1) and builds the @1/@2 message unless it is @3, ignoring any `framework` key otherwise. `build_envelope` rejects `framework` under @1/@2 and requires it under @3. A schema-absent envelope is @1 (ADR-0001 grandfathering), so @3-shaped refs in it fail. The @1/@2 and @3 messages have different key sets, so a signature made for one never verifies as the other; canonical escaping keeps that true for signer strings containing `"` or `,`.
- **D4 — Verifier policy.** `verify_ref` accepts all three majors. A gate that needs the guarantee calls it with `expected_framework=...` (CLI `verify --require-subject-binding FRAMEWORK`): @1/@2 refs then fail closed, and an @3 ref verifies only if its `framework` equals the expected one. The default stays permissive so existing @1/@2 producers keep working.
- **D5 — Reuse rule as the floor for @1/@2.** The library ships ikigov's rule as `reused_refs(refs)`: among @1/@2 refs, a `(signer, content_hash)` pair claimed for more than one `item_id` verifies for none of them (the framework is implicit in the verifier for these majors). @3 refs are exempt: one artefact may back several items honestly, because each claim carries its own signature over its own subject. `verify_envelope(doc, trust, *, expected_framework=None)` applies parse, signature, binding policy and the floor, returns a per-ref result with a reason, and is what the CLI uses, so consumers do not re-implement the floor. Known limit: the floor works per envelope; claims split across envelopes evade it, which is the case for demanding @3.
- **D6 — @3 fixes the tier parse trap.** The parser reads `assurance_tier` under @2 and @3. Under @3 the tier is signed, so relabelling it (for example stripping `optimistic` to pass an attested-only verifier) breaks the signature. Under @2 that relabel remains possible; this is recorded as a known @2 limitation and is another reason to demand @3.
- **D7 — Rust.** The crate mirrors the constants and adds `signing_message_v3(content_hash, signer, framework, item_id, assurance_tier)`. It still does not sign or verify (treasury is keyless, ADR-0001 D1). Crate version 0.3.0.
- **D8 — Rollout.** Substrate and vectors first (this repo, 0.5.0). Then producers dual-emit @2 and @3 (presidio-hardened-ai `pai ingest --evidence-out`, scoutsuite, arch-translucency). Then consumers demand @3 per gate (ikigov-assess first). @1 and @2 stay accepted; their removal is not planned.

### Vectors (append-only)

`vectors/evidence-ref-v3/`. `valid-*` and `tampered-*` files are schema-valid envelopes; `invalid-*` files are schema-invalid. `expectations.json` states, for every ref, whether its signature verifies, whether it verifies for `expected_framework "iki-gov"`, and the CLI verdict, so both conformance lanes assert the same table.

- `valid-envelope.json` — one Ed25519 and one HMAC ref under `framework "iki-gov"`.
- `valid-tier-optimistic.json` — a ref declaring `optimistic`: the signature verifies, the attested-only verdict fails.
- `valid-same-content-two-items.json` — one artefact backing two items: same `content_hash`, two subjects, two signatures; both verify, nothing reused.
- `valid-signature-foreign-framework.json` — a genuine ref signed for another framework; verifies on its own, fails for `iki-gov`.
- `tampered-relabelled-item.json`, `tampered-relabelled-framework.json`, `tampered-relabelled-tier.json` — genuine refs changed after signing (the tier one strips `optimistic`); must not verify.
- `tampered-v2-signature-as-v3.json` — the @2 golden ref wrapped as @3 with a `framework` added; must not verify.
- `tampered-v3-signature-as-v2.json` — a genuine @3 ref with `framework` stripped, wrapped as @2; must not verify.
- `tampered-v3-refs-schema-absent.json` — an @3 ref in an envelope without `schema`; read as @1, must not verify.
- `invalid-missing-framework.json`, `invalid-framework-pattern.json` — schema-invalid; the parser rejects them.

`vectors/signing/ed25519-golden-v3.json` and `hmac-sha256-golden-v3.json` pin `message_canonical` and the signatures for the @3 message, including a declared tier and a signer containing `"` and `,`. `vectors/evidence-ref-v2/reused-ref.json` pins the floor: the golden ref cloned under two items verifies per ref and fails as an envelope.

## Options considered

**A — Keep the consumer-side reuse rule only.** No wire change, but it forbids honest reuse, protects only consumers that implement it, and leaves the signature subject-free. Rejected as the end state; kept as the @1/@2 floor (D5).

**B — Bind the bare `item_id`.** Simplest message. It makes the producer commit to an unnamed consumer vocabulary, and the same id in two frameworks (`D1` in IKI-Gov, `D1` elsewhere) would be indistinguishable. Rejected.

**C — Bind a nested subject object `{"framework", "item"}`.** Equivalent security; it renames `item_id` inside the message only, so the wire field and the signed field would differ in name. Rejected for the flat form (D2), which keeps one name per concept.

**D — Leave `assurance_tier` unsigned, as in @2.** Rejected. Stripping a declared `optimistic` or `zk` tier turns a ref an attested-only verifier must refuse (ADR-0003 D6) into one it accepts, so the relabel gains an attacker an upgrade. ADR-0003 kept the tier out of the message to keep one message across @1 and @2; @3 changes the message anyway.

## Consequences

- A relabelled @3 ref fails verification in every consumer that uses this library, with no consumer-side bookkeeping.
- Honest reuse becomes possible again under @3: one artefact, several subjects, several signatures.
- Producers must know the framework at signing time. Evidence produced without a known consumer stays @2 until it is assigned.
- The CLI's `verify` now fails an @1/@2 envelope that claims one ref for several items and reports "reused under N items". That is a behaviour change for such envelopes, recorded in the changelog; it matches what ikigov-assess already does.
- Gates name their framework. A consumer that demands binding without naming its framework is rejected by the API rather than half-protected.
- Nothing about @1/@2 bytes, schemas or vectors changes.

## Open points (for founder review)

1. The `framework` registry: start with `iki-gov` in `vectors/README.md`; other producers register their vocabulary when they adopt @3.
2. Whether `require_subject_binding` should become the default in a later major of the library (not of the wire format).

## Action items

1. [ ] Founder sign-off on D1–D8.
2. [ ] `schemas/evidence-ref.v3.schema.json` and the vectors above; both conformance lanes green.
3. [ ] Python: constants, `EvidenceRef.framework`/`.schema`, `signing_message_v3`, schema-driven `verify_ref` with `expected_framework`, `reused_refs`, `verify_envelope`, CLI flag. Rust: constants and `signing_message_v3`.
4. [ ] Producer and consumer follow-ups filed in their repos (D7).
