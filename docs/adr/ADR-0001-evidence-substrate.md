# ADR-0001: presidio-evidence — the shared evidence substrate

**Status:** Accepted — founder-signed 2026-06-12, Vladimir Stantchev (V.S.)
**Date:** 2026-06-12
**Deciders:** V.S. (founder, governing account)
**Source mandate:** development-plan.md §6; session-4-evidence-library-adr.md
**Precondition note:** Session 2 done (parts 1–2), session 3 **not started** at survey time. The x402 surface was surveyed as committed in-repo (v0.4.0 screening API). **Review trigger:** if session 3 changes the x402 screening evidence surface, revisit §D1/§D4 before extraction (Q4).

## Context

Four repos independently implement the same pattern — *pre-execution gating + signed evidence + fail-closed verification*:

| Consumer | Evidence artefact | Signing | Canonicalization | Status |
|---|---|---|---|---|
| ikigov-assess | `presidio-hardened/evidence-ref@1` (consumer/verifier); `workshop-leavebehind@1` manifests | Ed25519 + HMAC-SHA256, trust store w/ key lists | sorted-keys compact JSON, UTF-8, `ensure_ascii=False` | shipped (v0.21.0) |
| hardened-ai | `evidence-ref@1` (producer, `pai ingest --evidence-out`); HMAC-chained JSONL ledger | Ed25519 + HMAC-SHA256, hex, detached | identical (`hashing.canonical_bytes`) | shipped (v0.30.0) |
| x402 (+ mcp) | screening audit pipeline (`POST /v1/screen` → ScreenResponse, audit_token); HMAC-chained JSONL audit log | Ed25519 + HMAC-SHA256, identical golden vector | identical | shipped (v0.4.0) |
| treasury | `treasury-close/checkpoint/v1` (Rust): content-addressed checkpoints, RFC 6962 Merkle heads | **none** — SHA-256 content addressing + dual-control (ActorId, preparer≠approver) | float-rejecting canonical JSON, depth-validated, sorted keys | shipped |

Survey findings that shape the decision:

1. **Three of four already share a byte-identical wire format.** ikigov, hardened-ai, and x402 use the same 8-field `EvidenceRef`, the same canonical JSON profile, the same detached signature over `canonical({"content_hash", "signer"})`, and the *same committed golden vector* (priv `01`×32 → pub `8a88e3dd…6f5c`, sig `a0dc8599…590a`; independently recomputed 2026-06-12, byte-identical). The schema is already unified de facto; the risk is silent drift, not divergence today.
2. **Treasury is intentionally different, not lagging.** Its trust model is content addressing + dual-control approval (no key material at all). Forcing Ed25519 into it would *add* a key-management attack surface to a system whose security argument is "no secrets to steal". Treasury's canonical JSON is also strictly stricter (rejects floats, validates nesting depth).
3. **Signer identity is bound into the signed message** (`{content_hash, signer}`), preventing cross-signer signature replay. Trust stores already support key lists per signer (rotation) on the consumer side; the producer has no rotation concept.
4. **The x402 audit pipeline is a shipped, customer-facing surface.** Extraction must not change its signed bytes or its release timing.

## Decision

Extract **one internal library, `presidio-evidence`**, structured as *schema + golden test vectors first, implementations second*, with a layered conformance model instead of a single mandatory crypto profile.

### D1 — Schema: `evidence-ref@1` frozen as the base; layered conformance

`presidio-hardened/evidence-ref@1` is adopted **verbatim and frozen** (8 required string fields ≤512 chars, no null bytes; `content_hash`/`signature` lowercase hex `^[0-9a-f]{8,128}$`; envelope with optional-but-strict `schema` field). This repo's JSON Schema + vectors are the single normative definition; consumer copies become conformance-tested mirrors, then imports.

Conformance is layered so treasury joins without distorting its trust model:

- **Layer 0 — Canonical substrate (all four):** canonical JSON (sorted keys, `(",", ":")` separators, UTF-8, no ASCII escaping, **floats rejected**, bounded nesting depth) + SHA-256 content addressing. Float rejection adopts treasury's stricter profile; it is backward-compatible for every signed message in production (all existing signed payloads are string-only).
- **Layer 1 — Signed evidence (ikigov, hardened-ai, x402):** detached signature over `canonical({"content_hash", "signer"})`; algorithms `ed25519` (default) and `hmac-sha256` (back-compat); hex encoding; trust-store verification.
- **Layer 2 — Approval semantics (treasury):** dual-control (preparer≠approver), supersession rules. **Out of library scope**; treasury conforms at Layer 0 + schema-shape only, keeping its checkpoint schema. A future `evidence-ref@2` may add an optional approval block — recorded as ledger entry, not built now.

### D2 — Language strategy: Python lib + Rust crate, vectors as the contract (founder-selected 2026-06-12)

One repo, two implementations: Python package `presidio_evidence` (root `pyproject.toml`, src layout) and Rust crate `presidio-evidence` (`rust/`). **The contract is the `schemas/` + `vectors/` trees, not either implementation.** Both run the identical vector suite; a vector change requires both suites green. Treasury consumes the Rust crate (or schema-only until then); ikigov/hardened-ai/x402 consume the Python package.

### D3 — Key management and rotation

Keys are 32-byte raw Ed25519, hex-encoded (64 chars), matching every producer. Private keys load from file (mode 0600 enforced) or env var; never from the repo, never logged. Trust store format is ikigov's normalised form, adopted as `trust-store@1`: `{signer: {"alg": "ed25519"|"hmac-sha256", "public_key"|"key": "<hex>" | ["<hex>", …]}}` (bare string = HMAC back-compat). **Rotation = append the new key to the signer's list, re-sign forward, retire the old key after the verification window.** Signer identity stays bound inside the signed message. Key generation/custody remains out-of-band (founder-held, per Humboldt root-of-trust); the library ships generation helpers but no key storage.

### D4 — Verification semantics: fail-closed, uniformly

`verify()` returns `bool`, never raises to the caller; any failure (unknown signer, malformed hex, wrong key, tampered content) is `False`. Unknown/absent schema major → reject. Missing evidence where required → not affirmed. CLI verify exits 0/1. Gating call sites (ikigov `--require-evidence`, x402 payment policy, treasury `ScopeGate`) keep their own gate placement; the library guarantees only that *verification itself can never fail open*. Timing-safe comparison for HMAC (`compare_digest`).

### D5 — Evidence-format versioning policy

Schema IDs are `presidio-hardened/<name>@<major>`, **major-only**. Within a major: no field removals, no type/constraint changes, no new required fields — i.e. @1 is immutable. Anything else is @2 under a new ID, shipped alongside @1 (producers dual-emit during migration; verifiers reject majors they don't know — fail-closed extends to versioning). Vectors are append-only: a vector, once published, is never edited — superseded vectors move to `vectors/retired/` with a reason.

### D6 — Repo visibility: private until the founder clears it

**Default: private repo.** Visibility is revisited only on a recorded founder decision.

## Options Considered

### Option A: evidence-ref@1 as frozen base + layered conformance (chosen)

| Dimension | Assessment |
|---|---|
| Complexity | Low — codifies what 3/4 repos already do |
| Migration risk | Minimal — zero wire-format change for shipped consumers |
| Treasury fit | Clean — Layer 0 only, trust model intact |
| Drift protection | Strong — vectors are the contract, CI-enforced in both languages |

**Pros:** no flag-day; golden vectors already cross-validated in production; treasury's stricter canonicalization improves the core. **Cons:** @1's loose hex bound (`{8,128}`) is grandfathered (tightening it is a @2 concern); Layer 2 unification deferred.

### Option B: new unified evidence-ref@2 now (all four, optional approval block)

| Dimension | Assessment |
|---|---|
| Complexity | High — new schema + 4 migrations + dual-emit window |
| Migration risk | High — invalidates a shipped cross-repo contract and workshop artefacts already in customer hands |
| Treasury fit | Forced — Ed25519 grafted onto a keyless design |

**Pros:** one schema everywhere. **Cons:** violates session scope ("extraction + conformance only, no new capability"); churns the customer-shipped x402 surface; rejected.

### Option C: Python-only library, treasury via schema document alone

| Dimension | Assessment |
|---|---|
| Complexity | Lowest |
| Drift protection | Weak for treasury — no executable conformance on the Rust side |

**Pros:** smallest repo. **Cons:** treasury conformance untested at CI time; founder explicitly selected Python+Rust; rejected.

## Trade-off Analysis

The decisive observation: **the unification already happened in the wire format; what is missing is a single normative home.** Option A converts an implicit, test-pinned contract into an explicit, vector-enforced one at near-zero migration cost. The cost accepted is living with @1's grandfathered looseness and postponing treasury's deeper integration — both bounded, both reversible via @2. Option B buys schema elegance with flag-day risk on a customer-shipped surface; that trade is not worth it.

## Consequences

- Easier: adding a fifth consumer (arch-translucency runtime posture evidence is the named candidate) — implement against vectors, done.
- Easier: algorithm rotation (alg lives in the trust store, not the schema — already true, now documented and tested).
- Harder: changing `evidence-ref@1` in any consumer unilaterally — CI in this repo breaks, by design.
- Revisit: Layer 2 approval block (@2), hex-bound tightening (@2), x402 surface after session 3, visibility on a founder decision.

## Action Items

1. [x] Scaffold repo: schemas + golden vectors + conformance tests in both languages as first commit (this session).
2. [x] Migration map per consumer (`docs/MIGRATION.md`, this session).
3. [x] Visibility question put to the founder (decision recorded in item 4).
4. [x] Founder signed this ADR (Accepted, 2026-06-12). Still open: record the visibility decision.
5. [ ] Q4 extraction in migration-map order: ikigov → hardened-ai → x402 → treasury (schema-only).
6. [x] Rust CI lane promoted from manual trigger to push/PR — validated green locally (fmt + clippy `-D warnings` + 6/6 conformance tests, 2026-06-12) and green on first push run.
7. [ ] **Protect `main` (block force-push + deletion).** Blocked 2026-06-12: branch protection and rulesets both require a paid plan for **private** repos, and `presidio-v` is on Free. D6 keeps the repo private, so this cannot be applied server-side now. Apply after either (a) org upgrade to Team/Pro, or (b) the repo goes public on founder clearance — whichever comes first. (Session-1 root-of-trust carry.)
