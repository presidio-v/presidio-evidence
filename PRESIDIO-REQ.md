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
- [ ] Visibility decision recorded.
- [ ] Rust lane first green run on a Rust-equipped runner, then promote ci-rust.yml to push/PR triggers.
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
