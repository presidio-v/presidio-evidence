# PRESIDIO-REQ — presidio-evidence

Requirement and deliberation ledger (template rule: every future-version deliberation persists here).

## v0.1.0 — ADR + scaffold (session 4, 2026-06-12)

Mandate: development-plan.md §6; session-4-evidence-library-adr.md. Scope discipline: extraction + conformance only, no new capability.

Requirements:

- R1 ADR deciding schema unification, language strategy, key management/rotation, verification semantics, versioning policy — **Delivered:** docs/adr/ADR-0001 (**Accepted, founder-signed 2026-06-12**). Founder pre-selected Python lib + Rust crate (2026-06-12).
- R2 Schema + golden test vectors as the first commit; conformance tests before code — **Delivered:** schemas/ (evidence-ref@1 verbatim-frozen, trust-store@1), vectors/ (generated + byte-stability-checked by scripts/generate_vectors.py), Python suite green; Rust suite written, first run pending toolchain (see Open).
- R3 CI to family standard (SAST, coverage gate, SBOM) — **Delivered:** ci.yml (ruff incl. S rules, pytest --cov fail_under=100, pip-audit, CycloneDX SBOM artifact, vector --check), codeql.yml (public-gated, family precedent), ci-rust.yml (manual until first green run, ci-zk precedent), dependabot (pip/cargo/actions).
- R4 Migration map per consumer — **Delivered:** docs/MIGRATION.md (ikigov → hardened-ai → x402 → treasury schema-only).
- R5 Repo private by default — **Delivered:** "Private :: Do Not Upload" classifier + `publish = false` guard against accidental publication.

Scoping decisions:

- Treasury joins at Layer 0 only; no Ed25519 grafted onto its keyless dual-control model (ADR-0001 D1, Option B rejected).
- Strict canonical profile adopts treasury's float rejection — backward-compatible because all shipped signed payloads are string-only.
- evidence-ref@1 grandfathered as-is (loose hex bound `{8,128}`, optional envelope `schema` field); tightening is an @2 concern.
- Vectors are append-only; supersession goes to vectors/retired/ with a reason (none yet).

Rejected "while we're at it" items (recorded, not built):

- L-EV-1: optional approval block (preparer/approver) in evidence-ref@2 — treasury Layer-2 unification.
- L-EV-2: tighten content_hash/signature to exact-length lowercase hex in @2.
- L-EV-3: arch-translucency as fifth consumer (runtime posture evidence) — after Q4 extraction.
- L-EV-4: key-rotation tooling (trust-store editing CLI) — Q4 at the earliest, founder key custody unchanged.

## Open / founder gates

- [x] Founder signed ADR-0001 (Accepted, 2026-06-12).
- [x] Founder signed ADR-0002 (provenance-parents convention, Accepted 2026-07-02).
- [x] Append the parents-bearing golden vector (R1) **and** the workshop-attestation vector (T-B4 R5) — **Delivered 2026-07-02**, both suites green (ADR-0001 D2: Python 81 passed/1 skipped, 100% coverage; Rust 9/9 conformance). Landed together with the Rust lane's first green run (gate above); no founder waiver needed.
- [x] Visibility decision recorded 2026-07-04: keep `presidio-evidence` private and defer x402 code movement (migration step 3) for now; closes ADR-0001 D6 + action item 4.
- [x] Rust lane first green run (2026-07-02): full lane green on a Rust-equipped runner — `cargo fmt --check` OK, `cargo clippy --all-targets -- -D warnings` clean, `cargo test --locked` 6/6 conformance tests pass (canonical-json, ed25519 golden + tamper-fail-closed, hmac golden, envelope end-to-end, schema constants), no divergence from committed vectors. Toolchain: rustc/cargo 1.95.0 (stable). ci-rust.yml already carries push/PR triggers (committed 2026-06-12, ADR-0001 item 6); no promotion change needed — this run closes the "awaits first green run" gate that R3/this list still showed open.
- [ ] Session 3 review trigger: if the x402 OEM-kit session changes the screening evidence surface, revisit ADR-0001 D1/D4 before Q4 extraction.

## v0.2.0 — extraction (delivered)

Python implementation extracted from hardened-ai/ikigov and shipped in the package, wire-format unchanged (golden vectors prove it byte-for-byte):

- **Layer 0** — `canonical_bytes` (strict: sorted keys, `(",",":")`, UTF-8, floats rejected), `sha256_hex`, `content_hash`.
- **Layer 1** — `signing_message` (signer-bound), `sign_evidence`/`sign_ed25519`/`sign_hmac`, `verify_ed25519`/`verify_hmac` (fail-closed). Ed25519 behind the optional `[crypto]` extra; HMAC + Layer 0 are stdlib-only (runtime `dependencies = []`).
- **Refs & trust** — `EvidenceRef`, `parse_document`/`load_evidence`, `build_envelope`, `load_trust_store` (bare-string + object entries, key rotation), `verify_ref`. `item_id` domain validation stays consumer-side by design.
- Conformance suite re-pointed at the library (`conftest.canonical_bytes` is now the shipped function); 100% coverage gate retained.

Consumers migrate per docs/MIGRATION.md (ikigov first, then hardened-ai). First proof point: `presidio-hardened-scoutsuite` (a producer) emits envelopes that ikigov-assess verifies via this contract; its 0.29.0 interop golden cross-checks the same wire format.

Deferred to a follow-up (not blocking consumers, which vendor their own copies today): shipping `schemas/` + `vectors/` as importable package data, and the Rust Layer-0 implementation (v0.3.0, for treasury).

## v0.3.0 (planned) — x402 binding + Rust Layer 0

x402 imports the library at the screening pipeline boundary (gated on a founder decision); Rust crate implements Layer 0 for treasury's schema conformance.

## Provenance-parents convention (deliberated 2026-07-02, session: suite strategy)

Strategy context: the suite claim — classify (eai-classificator → ikigov) → govern (ikigov gates) → build/train (arch-translucency training domain) → operate (pat posture, x402) → **prove** — is only checkable if the *relationships between* evidence payloads are themselves evidence. Decision drafted as **ADR-0002 (Proposed)**: any family payload MAY carry `parents: [<content_hash>, …]` **inside** its `attested_content` — lineage inside the signed bytes, envelope `evidence-ref@1` untouched (stays frozen per ADR-0001 D5). Family hex discipline for entries; fail-closed producer validation; omitted when empty; acyclic by construction (a hash cannot reference a future payload). Consumer graph-walk semantics stay out of library scope for now.

Requirements (gated on founder sign-off of ADR-0002):

- R1 Parents-bearing golden vector (append-only), shape-matched to arch-translucency `training-run@1` — the first adopter (its ADR-0009, MVP implemented 2026-07-02). **Delivered 2026-07-02:** `vectors/training-run/valid-envelope.json` (+ `.notes.json`) — a parents-bearing `training-run@1` Layer-0 payload (`run_id "golden-run"`, `strategy "pipeline"`, `parents ["a"×64]`, content hash `9173…b378`), wrapped in a signed `evidence-ref@1` envelope (family test key `01`×32). Shape and hash byte-match arch-translucency `build_training_run_reading` / `test_training_run_content_hash_is_stable`. Conformance in both suites (`tests/test_provenance_vectors.py`, `rust/tests/conformance.rs`). Follow-up **owed by arch-translucency, not this session:** swap its self-generated golden-ish hash test for this family vector.
- R2 Adoption order recorded: arch-translucency → ikigov workshop manifests → x402 audit entries.
- R3 Backlog: `walk_parents()` helper once two consumers need graph walks (L-EV-5).
- R4 **L-EV-6 activated (2026-07-02, O5 resolution):** edge documents for third-party countersigned relationships are now scheduled — first instance `workshop-attestation@1` (presidio-as-assessor countersigning a customer-signed workshop manifest via `attests` + `parents`; standard `evidence-ref@1` envelope, no new envelope). Spec and requirements live in ikigov-assess PRESIDIO-REQ v0.22.0 T-B4. **Delivered 2026-07-02 (T-B4 R5 cross-ref):** `vectors/workshop-attestation/valid-envelope.json` (+ `.notes.json`) — the **schema freeze** for `workshop-attestation@1` (`role "assessor"`, `engagement "eng-golden-001"`, `scope "facilitation + methodology conformance"`, `workshop_date "2026-07-02"`; ASCII-only, float-free, no integers). Its `attests` and `parents[0]` both point at the training-run payload's content hash `9173…b378`, exercising the ADR-0002 DAG edge in both suites. Follow-up **owed by ikigov-assess, not this session:** implement `iga workshop attest` (T-B4 R2) against this vector.

## v0.2.1 — Consumer vector coverage (2026-07-03, "golden vectors for every consumer")

Founder mandate (task queue 2026-07-03): golden vectors for IKI GOV, x402, and treasury. Every consumer surface now has a normative anchor in `vectors/`; all payloads stay inside the proven conformance envelope (ASCII-only, float-free, integers within i64) established by the 2026-07-02 first-green-run session.

Delivered (append-only; no pre-existing vector touched — `--check` + git status verified):

- R1 **ikigov — `vectors/workshop-leavebehind/`**: OWNER-signed `workshop-leavebehind@1` manifest (T-B4 R1 shape, additive `owner` block). Pins BOTH profiles: the manifest's canonical sha256 (the `attests` target of a workshop attestation — the ADR-0002 DAG edge) and the owner Ed25519 signature over raw canonical manifest bytes (manifest.sig profile, distinct from the family `{content_hash, signer}` message — documented in the vector notes). Second well-known test fixture introduced: customer key `02`×32. **Cross-checked at creation against ikigov's own `_verify_manifest_ed25519` (incl. tamper fail-closed).**
- R2 **x402 — `vectors/slo-reading/`**: `slo-reading@1` Layer-0 degradation reading (`p99 420 > 200`) + signed `evidence-ref@1` envelope — the pat → signing-bridge → SLO-payment-broker chain. **Cross-checked at creation: byte-identical (content hash AND deterministic signature) to arch-translucency `build_slo_evidence` / `build_layer0_reading` output**; `item_id "SLO-DEGRADED"`, `ledger_ref "arch-translucency:obs"` pinned.
- R3 **treasury — `vectors/treasury-checkpoint/`**: `treasury-close/checkpoint/v1` identity as Layer-0 content addressing over the canonical envelope (nulls preserved, i64 nanosecond timestamps, no signature — ADR-0001 D1 respected; shape per treasury `checkpoint.rs compute_id`).
- R4 **Conformance in both suites**: Python `tests/test_consumer_vectors.py` (11 tests: hash recompute, signature verify + cross-signer replay, tamper fail-closed, D5 additive-field check, degradation semantics, float rejection) — **92 passed, 100% coverage retained**; Rust `rust/tests/conformance.rs` +3 tests (`slo_reading_vector_verifies`, `workshop_leavebehind_owner_signature_verifies` incl. deterministic-signature reproduction from the `02`×32 fixture, `treasury_checkpoint_id_reproduces`).
- R5 `vectors/README.md` rows + two-fixture key note; version bumped to 0.2.1.

**Release gate (founder):** run `cargo test --locked` in `rust/` on a Rust-equipped machine (sandbox has no toolchain — Rust tests are written but their run is the ADR-0001 D2 both-suites gate), then signed tag `v0.2.1`.

## Assurance tiers — evidence-ref@2 (deliberated 2026-07-05, Computational Jurisprudence alignment)

Strategy context: the Computational Jurisprudence position paper (Stantchev, arXiv 2026) frames a compliant runtime as a **proof-carrying transaction (PCT)** — **pre-hoc authorization-with-evidence** vs **post-hoc monitoring** — with a three-tier **assurance** regime: *attested* (signature-attested), *optimistic* (bonded assertion / **optimistic compliance**, valid unless a fraud proof lands in a dispute window), *zk* (succinct proof of the norm predicate). Every `evidence-ref` is implicitly *attested* today; declaring the tier lets producers upgrade assurance without schema churn and lets verifiers demand a minimum tier. **ADR-0003 accepted by V.S. on 2026-07-05**: additive `evidence-ref@2` — envelope `schema` now REQUIRED (no grandfathering in @2), each ref gains an OPTIONAL enum `assurance_tier` (default *attested* when absent); @1 frozen and untouched; verifier accepts @1+@2 and fails closed on anything else; declared tiers are honored only under @2 (an @1 `assurance_tier` remains an inert extra and resolves to *attested*); the signed message is UNCHANGED (`canonical({content_hash, signer})` — the tier is not signed). *optimistic*/*zk* name a TARGET; fraud-proof and ZK-proof verification are explicitly OUT of scope of this repo.

**Extra-field finding (recorded):** `evidence-ref.v1.schema.json` sets no `additionalProperties: false` and the @1 verifier ignores unknown keys, so an @1 record carrying `assurance_tier` is VALID under @1 and silently ignored (read as *attested*). Consistent with the freeze (ADR-0001 D5): an extra field is not a removal, a type/constraint change, or a new required field. Vector `vectors/evidence-ref-v2/valid-v1-with-extra-tier.json` pins it (validated against the @1 schema, PASSES).

Requirements (gated on founder sign-off of ADR-0003):

- R1 `schemas/evidence-ref.v2.schema.json` (@2, `schema` required, optional enum `assurance_tier`) — **Delivered.** @1 schema untouched; trust-store schema untouched.
- R2 Append-only @2 golden vectors under `vectors/evidence-ref-v2/` — **Delivered:** `valid-tiers` (one ref per explicit tier), `valid-tier-absent` (documents the default), `invalid-unknown-tier`, `invalid-missing-schema`, `invalid-wrong-schema-id`, `valid-v1-with-extra-tier` (the finding). Generator `scripts/generate_vectors.py` extended; `--check` byte-stable for all pre-existing vectors (verified — only new files written).
- R3 Python: `EVIDENCE_REF_SCHEMA_ID_V2`, `EVIDENCE_REF_SCHEMA_IDS`, `ASSURANCE_TIERS`, `DEFAULT_ASSURANCE_TIER`; `parse_document` accepts @1+@2; `EvidenceRef.assurance_tier` + `.tier` (attested default); `build_envelope(..., schema=…)`. Signature path unchanged. Rust crate mirrors the constants. — **Delivered.**
- R4 Conformance in both suites: Python `tests/test_assurance_tiers.py` + `tests/test_schema_conformance.py` @2 cases — **116 passed, 3 skipped, 100% coverage retained** after Option 1 remediation; Rust `rust/tests/conformance.rs` +5 tests (constants, explicit tiers verify + tier-independence of the signature, absent-tier default, invalid-vector rejectability, @1-with-tier still verifies). **macOS release-gate rerun 2026-07-05:** Rust fmt/clippy clean, `cargo test --locked` 17/17 passed, `pip-audit` clean, `cargo audit` clean, `uv build` produced 0.2.2 sdist/wheel.
- R5 `vectors/README.md` row + README Layers/consumers note. Version NOT bumped (release mechanics are founder-signed).

**Release gate (founder):** ADR-0003 signed/accepted by V.S. (2026-07-05); local remediation gate green on macOS (2026-07-05); any signed tag remains a founder release step.

## Consumer posture note — ikigov import migration blocked by visibility (2026-09-17)

Recorded during the CJ ↔ ikigov synergies session. `docs/MIGRATION.md` step 1
assumed ikigov-assess could add this library as a dependency now (visibility decision:
"the other consumers may use the private library now"). It cannot: ikigov
ships on PyPI and this package is `Private :: Do Not Upload`, so the dependency
would break every public install. Step 1 is re-sequenced to after the
library goes public, alongside step 3; until then ikigov conforms
by golden vectors only (it already pins `workshop-attestation` and
`workshop-leavebehind`, and as of its v0.26.0 T-B6 implements the `evidence-ref@2`
tier semantics of ADR-0003 consumer-side, honouring declared tiers only under `@2`
and treating an `@1` extra tier as inert, exactly as
`vectors/evidence-ref-v2/valid-v1-with-extra-tier` pins). No schema, vector or code
change here; MIGRATION.md carries the amendment. **Founder gate unchanged:** any
visibility change remains a founder-signed release step.

Two follow-ons this session identified for the roadmap, neither started:

- **`capability-grant@1` golden vector.** ikigov's governance-ceiling design (its
  T-B6 Decision 6) derives an x402 capability grant from a `G3 OPEN` gate
  certificate (`parents[0]` = certificate hash). It is blocked until the grant
  format has a normative vector here, because the schema lives in x402 and a grant
  that does not byte-match the x402 verifier must not be issued. Fits the 0.3.0
  "x402 binding" line, and inherits its timing (the x402 roadmap).
- **`gate-certificate@1` golden vector.** ikigov now emits `parents`, `not_after`,
  `grounding` and `assurance_tier` in the certificate; a vector here would freeze
  that shape the way `workshop-attestation` froze T-B4. Append-only, no envelope
  change; can land any time.

## energy-reading@1 — reservation for the pat Energy Arc (2026-07-13, cross-repo)

Cross-repo reservation requested by `presidio-hardened-arch-translucency` (its
PRESIDIO-REQ "Energy Arc", **L-EN-4**, targeting pat v0.24.0 "Sign the watt").
pat will emit a new key-less Layer-0 reading type under the **unchanged**
`evidence-ref@1` envelope (the v0.17 pattern: producer emits unsigned, sidecar
signs). The family side is reserved *now* because the golden vector has the
longest lead time — the L-EV-7 precedent is that pat pins a presidio-evidence
vector byte-for-byte, so the vector is the contract, not a description of one.

**Status: RESERVED, not yet emitted.** No shipped producer writes an
`energy-reading@1` today. The vectors below are what pat v0.24 must reproduce.

Delivered (append-only; **no pre-existing vector touched** — generator `--check`
+ `git status` verified; the `evidence-ref@1` envelope is untouched):

- R1 **`vectors/energy-reading/valid-envelope.json`** (+ `.notes.json`) — nominal:
  a 5-minute Kepler-sourced serving-layer window, `parents` **omitted** (ADR-0002
  P3). `energy_wh "12.5"` over 300 s == `mean_power_w "150.0"`.
- R2 **`vectors/energy-reading/valid-envelope-parents.json`** (+ `.notes.json`) —
  the **energy-axis DAG edge** (ADR-0002): `parents[0]` is the `training-run/`
  golden payload's content hash `9173…b378`, so the reading says *"these are the
  joules that run cost"*. Window matches that run exactly (`duration_s 7200` ==
  2 h), `strategy` matches its `strategy` (`"pipeline"`), and `4800.0` Wh over 2 h
  == `2400.0` W == its 4 devices at 600 W each. DCGM-sourced.
- R3 **Float discipline (ADR-0001 D1).** Joules and watts never cross the wire as
  floats: `energy_wh` / `mean_power_w` are shortest-round-trip decimal **strings**.
  Both payloads are ASCII-only, float-free and integer-free. Both suites assert a
  float `energy_wh` is *rejected* by the canonicalizer — an unhashable reading
  cannot be evidence at all.
- R4 **`energy_chain_head`** — lowercase-hex SHA-256 head of pat's chained
  `energy_observations` store (pat ADR-0011 §2, a parallel chain with the ADR-0010
  discipline). It lives **inside the signed content**, so each signed reading
  attests the unrewritten history behind it; this is pat's discharge of the
  ADR-0010 external-anchoring deferral. The family treats it as **opaque** and
  pins only the hex discipline — walking the chain is pat's job, not ours.
- R5 **Conformance in both suites:** Python `tests/test_energy_reading_vectors.py`
  and Rust `rust/tests/conformance.rs` independently check hash/signature binding,
  decimal-string spelling, RFC3339 UTC windows, the energy/mean-power equation,
  chain-head placement, `parents`, the DAG edge, the `layer`/`strategy` XOR, and
  the frozen serving-layer vocabulary. **Remediation gate 2026-07-14:** Python
  **148 passed, 3 skipped** with 100% coverage; Rust **28 passed**, fmt + clippy
  clean. The shared
  `assert_provenance_vector_verifies` helper was generalised to
  `assert_reading_vector_verifies` so `parents` is checked *when present* (P3
  makes it optional); the two provenance vectors still assert it is non-empty.
- R6 `vectors/README.md` row. Version NOT bumped (release mechanics are
  founder-signed).

**Field shape settled by maintainer decision on PR #14 (2026-07-13).** Merging
freezes these choices under ADR-0001 D5:

1. The payload carries no internal type id. The Layer-0 wrapper's `schema` is
   authoritative, avoiding two potentially divergent type declarations inside
   one signed reading.
2. `meter` is exactly `"rapl" | "kepler" | "dcgm"`. `source` remains wrapper and
   envelope metadata naming the producer repository. `"analytic"` is excluded:
   modelled energy is not a measured reading (pat invariant E1a).
3. Exactly one of `layer` or `strategy` is present. `layer` is exactly
   `"container" | "pod" | "deployment" | "node"`; `strategy` reuses the
   training-run vocabulary. The generator and both conformance lanes reject an
   unknown serving layer and both/neither field combinations.
4. `window_start` and `window_end` are RFC3339 UTC instants inside the signed
   content. Both conformance lanes require a positive window and independently
   re-derive `mean_power_w` from `energy_wh` and the window duration.
5. `LAYER0_READING_SCHEMA_IDS` is the central registry, mirrored in Python and
   Rust. The declared registry, generator output, and committed vectors tree must
   agree exactly in both lanes. `workshop-leavebehind@1` remains outside because
   it is an owner-signed manifest, not a Layer-0 reading.
