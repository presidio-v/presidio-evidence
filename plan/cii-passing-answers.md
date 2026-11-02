---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — passing level
project_url: https://github.com/presidio-v/presidio-evidence
---

# CII Best Practices — passing-level answer sheet

Answers for <https://www.bestpractices.dev> (passing level), filled from the
evidence in this repository on 2026-11-02. Every cited URL must resolve on `main`
before the answers are submitted.

## Before you start

1. **Register the URL as exactly** `https://github.com/presidio-v/presidio-evidence`.
   Scorecard does a literal DB string match. A trailing slash, `www.`, or the
   PyPI URL returns `NotFound` → score 0 despite a real badge.
2. **Log in with GitHub but decline the org grant.** BadgeApp requests `read:org`
   and no code path consumes it.
3. **Merge the hardening PR first** — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
   `GOVERNANCE.md`, `ARCHITECTURE.md`, `ASSURANCE.md`, `SEMVER.md`,
   `allowed_signers`, `.github/workflows/scorecard.yml` and
   `.github/workflows/fuzz.yml` must be on `main`.
4. **Merge the Python 3.11 change (PR #8, release 0.5.1) first.** The answers
   below describe the project as it stands after it: Python 3.11+, the full gate
   on 3.11 plus the test suite on 3.12 and 3.13, and the hash-pinned CI
   toolchain (`.github/constraints/ci-toolchain.txt`) that `fuzz.yml` installs.
5. **Align `CONTRIBUTING.md` with `SECURITY.md`** on the acknowledgement time
   (CONTRIBUTING says 5 business days, SECURITY says 72 hours) before submitting.
6. Record the badge id in `hardening.toml` (`[badge] bestpractices_id`) once the
   project is created; it is not registered yet.

Shorthand below: `REPO` = `https://github.com/presidio-v/presidio-evidence`.

---

## Basics — project website content

| Criterion | Status | Justification / URL |
|---|---|---|
| `description_good` | **Met** | `REPO#readme` — the README opens with what the project is (the signed-evidence substrate of the presidio-hardened-* family: canonical JSON and SHA-256 content addressing, detached Ed25519 or HMAC-SHA256 signatures, fail-closed verification against a trust store) and the problem it solves (one evidence contract, extracted from four production implementations before they could drift apart). |
| `interact` | **Met** | `REPO#readme` — README covers obtaining the software (`pip install presidio-evidence`, PyPI), and links `CONTRIBUTING.md` (issues, bug reports, contributing) and `SECURITY.md` (vulnerability reports); issues at `REPO/issues`. |
| `contribution` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md` — documents the fork → branch → PR flow against `main`. |
| `contribution_requirements` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — ruff style config, test and coverage policy, security-sensitive-change rules, dependency bar. |

## Basics — FLOSS license

| Criterion | Status | Justification / URL |
|---|---|---|
| `floss_license` | **Met** | `MIT`. |
| `floss_license_osi` | **Met** | `MIT` is OSI-approved. |
| `license_location` | **Met** | URL: `REPO/blob/main/LICENSE` |

## Basics — documentation

| Criterion | Status | Justification / URL |
|---|---|---|
| `documentation_basics` | **Met** | README (Install, Use, CLI, The contract, Verify a checkout), the architecture decision records in `docs/adr/`, the per-consumer migration plan `docs/MIGRATION.md`, `vectors/README.md` for the golden vectors, and `SEMVER.md` (including how to verify an installation). |
| `documentation_interface` | **Met** | The external interface is every name in `presidio_evidence.__all__` (each public function carries a docstring), the `presidio-evidence` CLI (`verify`, `keygen`, exit codes) and the shipped JSON Schemas; enumerated in `REPO/blob/main/SEMVER.md#what-is-the-public-api`, with usage in the README "Use" and "CLI" sections. |

## Basics — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `sites_https` | **Met** | The project site is the GitHub repository and the package is on PyPI, both HTTPS only. The project runs no other hosted site or service. |
| `discussion` | **Met** | GitHub Issues: `REPO/issues` — searchable, URL-addressable, open, no proprietary client. |
| `english` | **Met** | All docs and issue handling in English. |
| `maintained` | **Met** | Releases 0.5.1 and 0.5.0 on 2026-11-02 (`REPO/releases`, PyPI), 0.4.0 on 2026-10-18 (`CHANGELOG.md`); pull requests merged through 2026-11-02; CI and Dependabot active. |

## Change control — repository

| Criterion | Status | Justification / URL |
|---|---|---|
| `repo_public` | **Met** | `REPO` |
| `repo_track` | **Met** | git. |
| `repo_interim` | **Met** | Every change lands through a pull request from a pushed branch (direct pushes to `main` are blocked by branch protection); interim work is visible between versions. |
| `repo_distributed` | **Met** | git. |

## Change control — versioning

| Criterion | Status | Justification / URL |
|---|---|---|
| `version_unique` | **Met** | One version in `pyproject.toml` per release; `publish.yml` refuses to build when the tag does not match it; `CHANGELOG.md` records one entry per version. |
| `version_semver` | **Met** | URL: `REPO/blob/main/SEMVER.md` — Semantic Versioning with the documented pre-1.0 profile; wire schemas are versioned separately per schema id. |
| `version_tags` | **Met** | Releases are tagged `vX.Y.Z` (`v0.2.0` through `v0.5.1`, `REPO/tags`); every tag is an annotated, SSH-signed tag that GitHub shows as Verified. |

## Change control — release notes

| Criterion | Status | Justification / URL |
|---|---|---|
| `release_notes` | **Met** | URL: `REPO/blob/main/CHANGELOG.md` — Keep a Changelog format, hand-written per version with "why it matters" lines, not VCS log output. Earlier notes are in the GitHub releases. |
| `release_notes_vulns` | **N/A** | No publicly known vulnerability (CVE, GHSA or similar) has been fixed in any release; no security advisory exists for this repository. The four low-severity findings of the pre-publication audit, fixed before the code was public, are still listed under "Security" in the 0.5.0 entry. |

## Reporting — bug reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `report_process` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#reporting-bugs-and-requesting-features` |
| `report_tracker` | **Met** | GitHub Issues. |
| `report_responses` | **Met** | Met by the documented process. The repository became public on 2026-11-02 and no bug report from outside the project has been received yet; the issues on file (#1, #3) were opened by the maintainer as tracked work, and #3 was fixed and closed by PR #4. |
| `enhancement_responses` | **Met** | Met by the documented process. No enhancement request from outside the project has been received yet; #1 (tighten the `training-run@1` and `gate-certificate@1` schemas) is a maintainer-filed enhancement tracked in the open and linked from the README roadmap. |
| `report_archive` | **Met** | URL: `REPO/issues?q=is%3Aissue` — public and searchable. |

## Reporting — vulnerability reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerability_report_process` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` |
| `vulnerability_report_private` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory (`REPO/security/advisories/new`) or security@presidio-group.eu; acknowledgement within 72 hours, fix target 30 days. |
| `vulnerability_report_response` | **N/A** | No vulnerability reports have been received in the last 6 months: no security advisory, draft or published, exists for this repository, which was private until 2026-11-02. |

## Quality — build system

| Criterion | Status | Justification / URL |
|---|---|---|
| `build` | **Met** | Standard PEP 517 build with the `hatchling` backend: `python -m build` (or `uv build`) rebuilds the sdist and wheel from source. The Rust conformance crate builds with `cargo build --manifest-path rust/Cargo.toml`. |
| `build_common_tools` | **Met** | pip, `build` and `hatchling` (release builds use a hash-pinned set, `.github/constraints/release-build.txt`); `cargo` for the Rust crate. |
| `build_floss_tools` | **Met** | The entire toolchain is FLOSS. |

## Quality — automated test suite

| Criterion | Status | Justification / URL |
|---|---|---|
| `test` | **Met** | 20 pytest modules under `tests/` (about 420 tests: canonical JSON, signing, envelopes end to end, schema conformance, consumer vectors, CLI, key handling, audit regressions, vector byte-stability), a Rust conformance suite (`rust/tests/conformance.rs`, 41 tests, plus 6 unit tests) over the same golden vectors, and `scripts/generate_vectors.py --check` for vector stability. Licensed with the project. How to run: `CONTRIBUTING.md#local-verification`. |
| `test_invocation` | **Met** | `pytest tests/` (Python) and `cargo test --manifest-path rust/Cargo.toml` (Rust). |
| `test_most` | **Met** | CI enforces 100% statement coverage (`[tool.coverage.report] fail_under = 100` in `pyproject.toml`, applied by `pytest --cov=presidio_evidence` in `.github/workflows/ci.yml`). Branch coverage is not gated; measured locally at 195 of 196 branches on 2026-11-02. |
| `test_continuous_integration` | **Met** | GitHub Actions on every push to `main` and every PR: `.github/workflows/ci.yml` (ruff, vector check, tests with the coverage gate, `pip-audit`, SBOM on Python 3.11; the test suite on 3.12 and 3.13) and `.github/workflows/ci-rust.yml` (fmt, clippy, conformance tests). `conformance` and `conformance-rust` are required checks on `main`. |

## Quality — new functionality testing

| Criterion | Status | Justification / URL |
|---|---|---|
| `test_policy` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#tests` — functional changes ship with tests; fixes ship with regression tests; wire-format changes add vectors and never edit a published one. |
| `tests_are_added` | **Met** | Example: PR #2 (`REPO/pull/2`, merged 2026-10-25) fixed four audit findings (a trust-store `public_key` usable as an HMAC secret, `TypeError` on a non-ASCII signature, a lone surrogate aborting an envelope, forgeable CLI output) and added `tests/test_audit_2026_10_25.py` plus the vectors `vectors/trust-store/rejected-hmac-with-public-key.json` and `public-key-implies-ed25519.json` in the same change. |
| `tests_documented_added` | **Met** | The policy is stated in the contribution instructions themselves (`CONTRIBUTING.md#tests`). |

## Quality — warning flags

| Criterion | Status | Justification / URL |
|---|---|---|
| `warnings` | **Met** | `ruff check .` and `ruff format --check .` in CI (`ci.yml`); `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` for the Rust crate (`ci-rust.yml`). |
| `warnings_fixed` | **Met** | CI fails on any finding; `main` is clean. |
| `warnings_strict` | **Met** | ruff selects `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit security rules), beyond ruff's default `E`/`F` subset (`pyproject.toml` `[tool.ruff.lint]`). The only exclusion is `S101` (assert) in `tests/` and `fuzz/`; there are no `noqa` suppressions in `src/`. clippy runs with all warnings denied, and the crate has `#![forbid(unsafe_code)]`. |

## Security — secure development knowledge

| Criterion | Status | Justification / URL |
|---|---|---|
| `know_secure_design` | **Met** | The design is fail closed (bad evidence verifies as `False`, malformed input raises `EvidenceError`, never a pass), least privilege (no keys held, no state, no network, no logging), complete mediation (the whole envelope is parsed before any ref is verified; the CLI calls the same policy), defence in depth (signer binding, subject binding, reuse floor, tier check, key-type separation) and economy of mechanism (vetted primitives only, one canonical encoding). Argued in `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`. The pre-publication audit was run by the maintainer with tool assistance; there has been no independent review. |
| `know_common_errors` | **Met** | `REPO/blob/main/ASSURANCE.md` maps forgery, cross-signer replay, subject relabelling, downgrade, tier inflation, key confusion and hostile input to controls (section 1), and input validation, output injection, memory safety, crypto misuse, exposed secrets, TOCTOU file handling, unsafe deserialization, exceptions-as-pass and vulnerable dependencies to named countermeasures (section 4). |

## Security — cryptographic practices

| Criterion | Status | Justification / URL |
|---|---|---|
| `crypto_published` | **Met** | SHA-256 (FIPS 180-4) for content addressing, Ed25519 (RFC 8032) and HMAC-SHA256 (RFC 2104) for detached signatures. |
| `crypto_call` | **Met** | Ed25519 comes from `cryptography` (`Ed25519PrivateKey`/`Ed25519PublicKey`, optional `crypto` extra); SHA-256 and HMAC from the Python standard library (`hashlib.sha256`, `hmac.new`, `hmac.compare_digest`); the Rust crate uses `sha2`. No primitive is re-implemented. |
| `crypto_floss` | **Met** | `cryptography` (Apache-2.0/BSD), CPython's `hashlib`/`hmac` (PSF), `sha2` (MIT/Apache-2.0). |
| `crypto_keylength` | **Met** | The default is Ed25519 with 256-bit keys (about 128-bit security) and SHA-256 digests, above the NIST 2030 minimum of 112 bits. HMAC-SHA256 keys are supplied by the operator and the library does not enforce a minimum length; HMAC exists for back-compatibility and is documented as a shared-secret mode. |
| `crypto_working` | **Met** | No MD4, MD5, single DES, RC4 or Dual_EC_DRBG anywhere in the code. |
| `crypto_weaknesses` | **Met** | No SHA-1 and no CBC mode; the project does no encryption at all. |
| `crypto_pfs` | **N/A** | The project implements no key-agreement or network protocol and makes no network calls. |
| `crypto_password_storage` | **N/A** | Stores no passwords. |
| `crypto_random` | **Met** | The only security-relevant random value is a new Ed25519 private key in `generate_ed25519_keypair()` / `presidio-evidence keygen` (`src/presidio_evidence/_keys.py`), from `cryptography`'s `Ed25519PrivateKey.generate()`, which draws on the OS CSPRNG. Ed25519 signing is deterministic (RFC 8032) and needs no nonce. |

## Security — delivery

| Criterion | Status | Justification / URL |
|---|---|---|
| `delivery_mitm` | **Met** | Distributed over HTTPS from PyPI and GitHub. `publish.yml` publishes through PyPI Trusted Publishing (OIDC, no stored API token) after a required reviewer approves the `release` environment; PyPI files carry PEP 740 attestations. |
| `delivery_unsigned` | **Met** | No hash is fetched over plain HTTP. Release tags are SSH-signed and GitHub-verified; release assets carry build-provenance attestations. |

## Security — known vulnerabilities

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerabilities_fixed_60_days` | **Met** | No known unpatched medium+ vulnerabilities. `pip-audit` runs in CI on every push and PR (`ci.yml`); Dependabot alerts and security updates are enabled, with no open alerts. The runtime has no dependencies; `cryptography` is an optional extra. |
| `vulnerabilities_critical_fixed` | **Met** | No critical vulnerability has arisen in the project or its dependencies; `pip-audit` would fail CI on one. |

## Security — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `no_leaked_credentials` | **Met** | gitleaks 8.30.1 over the full history (all refs, 55 commits) on 2026-11-02: no leaks. The only key material in the tree is the published test fixtures documented in `SECURITY.md#test-keys-in-this-repository` (allowlisted in `.gitleaks.toml`). GitHub secret scanning with push protection is enabled. |

## Analysis — static

| Criterion | Status | Justification / URL |
|---|---|---|
| `static_analysis` | **Met** | CodeQL for Python (`.github/workflows/codeql.yml`, results in GitHub code scanning, required check `analyze`) and ruff with the `S` (flake8-bandit) rule set in CI; clippy with warnings denied on the Rust crate. |
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL's Python security queries, plus ruff's `S` rules (the bandit checks for injection, unsafe deserialization, weak hashes, hard-coded secrets and similar) as a required CI step. |
| `static_analysis_fixed` | **Met** | Findings are fixed before merge; CI blocks on ruff and clippy findings, and there are no open code-scanning alerts. |
| `static_analysis_often` | **Met** | CodeQL runs on every push and PR to `main`, plus a weekly scheduled run; ruff runs on every push and PR. |

## Analysis — dynamic

| Criterion | Status | Justification / URL |
|---|---|---|
| `dynamic_analysis` | **Met** | The automated suite exceeds 80% branch coverage (195 of 196 branches, measured 2026-11-02; branch coverage is measured, not gated) and is applied to every release through CI. An Atheris coverage-guided fuzz harness (`fuzz/fuzz_envelope.py`) drives arbitrary bytes through `load_evidence`, `verify_envelope`, `canonical_bytes` and `is_decimal_string`, asserting that only `EvidenceError` or `ValueError` can escape; `.github/workflows/fuzz.yml` runs it on PRs that touch `src/` or `fuzz/` and weekly. The fuzz job is newly added and has no results to report yet. |
| `dynamic_analysis_unsafe` | **N/A** | Python is memory-safe, and the Rust crate is safe Rust (`#![forbid(unsafe_code)]`). |
| `dynamic_analysis_enable_assertions` | **Met** | Tests are assertion-based (pytest) and run without `-O`; the fuzz harness also runs without `-O`, so its assertions are checked. |
| `dynamic_analysis_fixed` | **Met** | No unfixed medium+ findings. |

---

## Notes

- Any passing criterion not listed here is answerable **Met** by an existing
  artefact or **N/A** (library vs. website/app). Check `SECURITY.md`,
  `CONTRIBUTING.md` and `ci.yml` before writing anything new.
- Test counts and coverage figures are as of 2026-11-02; update them if the
  suite changes before submission.
