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
- [ ] Visibility decision recorded.
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
