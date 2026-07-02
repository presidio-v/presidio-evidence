# ADR-0002: Provenance-parents convention — evidence as a DAG, inside signed payloads

**Status:** Accepted — founder-signed 2026-07-02, Vladimir Stantchev (V.S.)
**Date:** 2026-07-02
**Deciders:** V.S. (founder, governing account)
**Source mandate:** suite-strategy deliberation 2026-07-02 (evidence as the
fundament of the presidio suite). First adopter:
`presidio-hardened-arch-translucency` `training-run@1` (its ADR-0009).

## Context

Every family producer emits *isolated* evidence: an `eai-classification@1`
result, an ikigov gate decision, an `slo-reading@1`, an x402 screening audit
entry, a `training-run@1` record. Each is individually canonical, hashed, and
(at Layer 1) signed — but nothing attests *how they relate*. The suite's
strategic claim — classify → govern → build → operate → prove, as one
compliant implementation environment — is only checkable if the relationships
themselves are evidence: which classification a training run was authorized
under, which gate decision cleared a deployment, which degradation reading
triggered a payment.

Forces:

1. **`evidence-ref@1` is frozen** (ADR-0001 D5: @1 is immutable; no new
   required fields, no constraint changes). Any envelope-level lineage field
   means `evidence-ref@2`, dual-emit migration, and verifier churn across five
   consumers.
2. **Content addressing already gives us stable node identity.** Every payload
   has a canonical SHA-256 content hash; referencing a payload by hash is
   already the family idiom (the envelope's own `content_hash` field).
3. **Lineage must be tamper-evident, not advisory.** A lineage claim outside
   the signed content could be edited after signing; the entire value of the
   provenance graph for Annex IV / Art. 12 traceability is that it cannot be
   quietly rewired.
4. **Acyclicity comes for free.** A payload can only reference the content
   hash of evidence that already exists at signing time; a hash cannot refer
   to a future payload (that would require inverting SHA-256). Parent links
   therefore form a DAG *by construction* — no cycle checking needed.

## Decision

Adopt a **payload-level convention**, not an envelope change: any family
payload schema MAY carry a field

```json
"parents": ["<content_hash>", "..."]
```

inside its `attested_content`, where each entry is the canonical content hash
of an upstream evidence payload.

- **P1 — Placement.** `parents` lives inside the signed/hashed content, never
  in the envelope. The `evidence-ref@1` envelope is untouched; the convention
  is additive and immediately available to every producer.
- **P2 — Hash discipline.** Each parent entry conforms to the family hex rule
  (lowercase hex, `^[0-9a-f]{8,128}$`, mirroring `content_hash`). Producers
  MUST fail closed on malformed entries (reject, do not emit).
- **P3 — Presence.** `parents` is omitted when empty (matching the family's
  optional-field minimalism). When present it is a non-empty JSON array of
  strings, order-preserving (order is producer-meaningful, e.g. primary
  authorization first).
- **P4 — Verification semantics.** Verifying a payload's signature attests
  that the producer *claimed* these parents at signing time. Resolving a
  parent hash to its payload, and verifying that payload in turn, is the
  consumer's walk — the library does not mandate a graph store. A consumer
  that requires lineage (e.g. an audit-pack exporter) fails closed on an
  unresolvable parent, per D4 semantics.
- **P5 — Naming.** New payload schemas SHOULD reserve `parents` for this
  convention and not overload the name.

### Options considered

**A — envelope field in `evidence-ref@2`.** Clean single location, but forces
a major-version migration across five consumers for a feature only some
payloads need, and violates the "@2 only when @1 cannot express it" bar. @1
*can* express lineage — inside the content it already signs. Rejected.

**B — external link documents (separate "edge" evidence).** Keeps payloads
untouched and models edges as first-class evidence, but doubles artifact count,
and an edge document signed by a different party than the child payload
weakens the claim ("who says this training run used that classification?").
Kept as a *complement* for third-party attestations (an assessor countersigning
a relationship), not the base mechanism. Not adopted now.

**C — parents inside signed payloads (chosen).** Additive, tamper-evident
(rewiring lineage changes the content hash and breaks the signature),
acyclic by construction, zero envelope churn.

## Consequences

- Easier: the suite's provenance graph (classification → gate → training run →
  deployment posture → payment) becomes a queryable, verifiable data
  structure — Annex IV traceability as a DAG rather than as process
  documentation. No competitor-visible equivalent as of the 2026-07-02 survey.
- Easier: adoption is per-payload-schema and incremental; `training-run@1`
  ships it first, `slo-reading@2`/ikigov manifests/x402 audit entries can
  follow without coordination.
- Harder: cross-repo hash resolution needs a shared lookup discipline
  eventually (content-addressed store or per-repo ledgers + an index); until
  then, DAG walks are engagement-local.
- Revisit: (a) a `vectors/` golden vector for a parents-bearing payload once
  the first schema is founder-signed; (b) Option B edge documents for
  third-party countersigned relationships (workshop dual-signature model);
  (c) graph-walk helper (`walk_parents()`) in the library once two consumers
  need it.

## Action items

1. [x] Founder sign-off on P1–P5 (2026-07-02).
2. [x] Add a parents-bearing golden vector (append-only) referencing the
   arch-translucency `training-run@1` shape (2026-07-02: `vectors/training-run/`,
   both suites green; the `workshop-attestation@1` edge document lands alongside
   per L-EV-6 revisit item, `vectors/workshop-attestation/`).
3. [ ] Record adoption order: arch-translucency (done, MVP) → ikigov workshop
   manifests → x402 audit entries.
