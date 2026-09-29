# Migration map — consumers onto presidio-evidence

Order is risk-ordered, not alphabetical: the repo that ships the customer loop first, the x402 surface late, the keyless system last and schema-only. Each step is independently shippable and reversible; no consumer ever depends on an unreleased state of another. Q4 execution (ADR-0001 action item 5).

## Invariant for every step

Zero wire-format change. The library reproduces today's bytes (proved by the golden vectors before any code lands). A consumer migration that would change any signed byte is a defect, not a migration.

## 1. ikigov-assess (first — it ships the customer loop)

> **Blocked while this library is private, recorded 2026-09-17.**
> This library is `Private :: Do Not Upload` (ADR-0001 D6) while ikigov-assess
> ships on PyPI. A public wheel cannot depend on a private package, so "add
> presidio-evidence as dependency" below cannot ship before the library is public, whatever
> the visibility decision's "the other consumers may use the private library now" permits in
> principle. Until then ikigov conforms **by vectors only**: it keeps its local
> canonicalisation/signing mirror and pins the family golden vectors
> (`workshop-attestation`, `workshop-leavebehind`, and now the `evidence-ref-v2`
> tier semantics it implements consumer-side — ikigov v0.26.0 T-B6 Decision 7). The
> import swap is re-sequenced to *after* step 3's precondition clears, at which point
> steps 1 and 3 can share one release train. Nothing in this section is otherwise
> changed.

What changes:
- `src/presidio_ikigov_assess/evidence.py`: `_canonical`, `_hmac_hex`, `_verify_ed25519`, `verify_ref`, `load_trust_store` re-export from `presidio_evidence`; `EvidenceRef` dataclass imports the contract (consumer keeps its `VALID_ITEM_IDS` domain check — that is consumer-side by design).
- Workshop leave-behind signing (`workshop.py`) moves onto library canonicalization + signing; `workshop-leavebehind@1` schema stays in ikigov (product-specific), only the crypto substrate is shared.
- Tests: point the existing golden-vector tests at `vectors/` in this repo (path or copied fixture pinned by hash) — they must pass **before** the import swap, then unchanged after.

Order within the step: add presidio-evidence as dependency → run ikigov's own test suite against library functions in parallel (shadow assertions) → swap imports → delete local copies.
Rollback: revert the import commit; local copies are deleted only in a separate, later commit.

## 2. hardened-ai (producer side)

What changes:
- `evidence.py` (`sign_evidence`, `sign_ed25519`, `verify_ed25519`, `export_evidence` envelope), `hashing.py` (`canonical_bytes`, `sha256_hex`) re-export from the library.
- `ledger.py` HMAC chain stays in-repo for now (ledger ≠ evidence; chained-ledger extraction is a recorded non-goal, L-EV ledger).
- The producer/consumer contract test (`test_evidence_ref_matches_contract`) now asserts against `presidio_evidence.EVIDENCE_REF_FIELDS`.

Gate: ikigov (step 1) green in CI for one release cycle first — producer changes are verified by the already-migrated consumer.

## 3. x402 + x402-mcp (customer-facing surface)

What changes:
- Screening pipeline's canonicalization/signing/audit-record hashing re-exports from the library; `check_payment_policy` / `check_payment_replay` gating logic stays in x402 (product logic, not substrate).
- **Precondition (RESOLVED 2026-07-04, founder decision): defer.** No x402 code moves into the shared library for now; the library stays private meanwhile. Until then x402 conforms via vectors only (like treasury). The other three consumers (steps 1, 2, 4) proceed now.
- Session-3 review trigger: if the OEM-kit session changed the screening surface, re-survey before this step.

## 4. treasury (last, schema-only — Layer 0)

What changes:
- **No Rust implementation dependency initially.** treasury adds a conformance test consuming `vectors/canonical-json/` (its float-rejecting canonicalizer must reproduce the vectors — it is the *origin* of the strict profile, so this is a regression pin, not a change).
- Optionally later: depend on the `presidio-evidence` crate for Layer-0 helpers once it has an implementation (v0.3.0).
- Explicit non-goal: no Ed25519, no trust store, no signature layer in treasury (ADR-0001 D1; its dual-control model is the security argument).

## Sequencing summary

| Step | Repo | Precondition | Risk if skipped-ahead |
|---|---|---|---|
| 1 | ikigov-assess | **once this library is public** — public PyPI package cannot depend on this private library; vectors-only until then | packaging failure on every `pip install` |
| 2 | hardened-ai | step 1 green one cycle | producer drift undetected by consumer |
| 3 | x402 (+mcp) | a founder decision on the x402 roadmap; session-3 review | churn on a customer-shipped surface |
| 4 | treasury | none (vectors exist now) | n/a — can run any time after v0.1.0 |

Step 4 has no dependency on steps 1–3 and may be done first if convenient; it is listed last only because it delivers the least de-duplication.
