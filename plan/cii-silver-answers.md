---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — SILVER level (on top of passing)
project_url: https://github.com/presidio-v/presidio-evidence
related:
  - cii-passing-answers.md
---

# CII Best Practices — SILVER answer sheet

Answers for the **silver** tab at bestpractices.dev, filled from the evidence in
this repository on 2026-11-02. It covers only the criteria silver *adds* on top of
passing; passing answers carry over unchanged (see `cii-passing-answers.md`).

Before submitting silver: earn the passing badge first. The hardening PR is
merged, the project is registered as
[project 16243](https://www.bestpractices.dev/projects/16243), and the badge is
on the README.

Each row shows the **Status** to set in the dropdown and the **Justification** to
paste. `REPO` = `https://github.com/presidio-v/presidio-evidence`.

## Badge embed

Silver uses the **same** embed code as passing; the badge image renders the
current level. It is on the README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16243/badge)](https://www.bestpractices.dev/projects/16243)
```

## Backing docs

- `GOVERNANCE.md` — governance model, roles, continuity
- `ARCHITECTURE.md` — components, core flow, trust boundaries
- `ASSURANCE.md` — consolidated security assurance case (`assurance_case`)
- `allowed_signers` — public release signing key for local tag verification
- `CONTRIBUTING.md` — DCO sign-off requirement
- `SECURITY.md` — reporter credit, how to obtain signing keys, assurance-case link
- `README.md` — 12-month roadmap + links to GOVERNANCE/ARCHITECTURE/ASSURANCE

---

## Governance & continuity

| Criterion | Status | Justification to paste |
|---|---|---|
| `dco` | **Met** | Contributions must carry a DCO `Signed-off-by` line (`git commit -s`), documented at `REPO/blob/main/CONTRIBUTING.md#licensing-and-developer-certificate-of-origin-dco`; checked in review (there is no automated DCO check). Inbound = outbound `MIT`. The requirement was adopted in November 2026; earlier commits by the maintainer predate it. |
| `code_of_conduct` | **Met** | Contributor Covenant at `REPO/blob/main/CODE_OF_CONDUCT.md` (standard location). |
| `governance` | **Met** | Maintainer-led, single-steward model documented at `REPO/blob/main/GOVERNANCE.md`: ordinary changes decided on the PR, security-relevant changes (the listed security-sensitive modules, schemas and vectors) need a written rationale and may not weaken a default, API changes follow `SEMVER.md`, disagreements escalate to PRESIDIO Group. |
| `roles_responsibilities` | **Met** | Key roles (steward org, maintainer, security contact, release manager, contributor) documented at `REPO/blob/main/GOVERNANCE.md#roles-and-responsibilities`. |
| `access_continuity` | **Met** | Continuity rests on the steward organisation: the repository is owned by the `presidio-v` GitHub organisation, not a personal account; PyPI publishing uses Trusted Publishing bound to this repository and the `release` environment, so no personal API token exists; the release signing key is held in the organisation password manager, with its public half in `allowed_signers`; PRESIDIO Group's access policy provides emergency access (Bitwarden Emergency Access) so a designated trustee can take over the owner credentials and signing key and reassign ownership, code-owner review and `release` approval; the release procedure is written down (`SECURITY.md`, `.github/workflows/publish.yml`); and a second person (`ceoofcyber`) holds write access, code-owner review and `release`-environment approval. URL: `REPO/blob/main/GOVERNANCE.md#project-continuity`. |
| `bus_factor` (SHOULD) | **Met** | Two people review, merge and approve releases (`vstantch`, `ceoofcyber`, both code owners and `release`-environment reviewers); repository ownership, the signing key and the release flow are organisation-held, documented, and covered by the emergency-access policy. See `REPO/blob/main/GOVERNANCE.md#project-continuity`. |

## Documentation

| Criterion | Status | Justification to paste |
|---|---|---|
| `documentation_roadmap` | **Met** | `REPO#roadmap` — next 12 months to 2027-Q4: now (consumers move from vendored code to the PyPI package, OpenSSF silver), next (producers dual-emit `evidence-ref@2` and `@3`, consumers then demand `@3` per gate; tighter `training-run@1` and `gate-certificate@1` schemas, issue #1), later (a `capability-grant@1` vector once its producer exists; the remaining consumers onto the package). |
| `documentation_architecture` | **Met** | `REPO/blob/main/ARCHITECTURE.md` — components (Layer 0, Layer 1, keys, CLI, Rust crate, contract trees), producer and consumer flows, trust boundaries; linked from the README. |
| `documentation_security` | **Met** | `REPO/blob/main/SECURITY.md` (threat model, invariants, reporting, release verification), `REPO/blob/main/ASSURANCE.md` (threat table, out-of-scope assumptions, design and weakness arguments), `REPO/blob/main/ARCHITECTURE.md#trust-boundaries`, and the design rationale in `docs/adr/` (ADR-0001 to ADR-0006). |
| `documentation_quick_start` | **Met** | README "Install" (`pip install presidio-evidence`, or `[crypto]` for Ed25519), "Use" (a complete sign-then-verify example) and "CLI" (`verify`, `keygen`); `SEMVER.md#verifying-an-installation` runs the shipped golden vectors against an installed package. |
| `documentation_current` | **Met** | Docs are updated in the same PR as the code they describe (`CHANGELOG.md` per version, `SEMVER.md` public API, ADRs, `PRESIDIO-REQ.md` delivery status), and the README, `SECURITY.md` and `SEMVER.md` describe the current 0.5 line. |
| `documentation_achievements` | **Met** | The README front page shows and links the OpenSSF Best Practices badge (`REPO#presidio-evidence`, project 16243) next to the OpenSSF Scorecard badge; the badge image renders the current level, so a newly earned level appears without an edit. |

## Change control & reporting

| Criterion | Status | Justification to paste |
|---|---|---|
| `contribution_requirements` | **Met** | `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style, tests, security-change rules, dependency bar. |
| `report_tracker` | **Met** | GitHub Issues: `REPO/issues`. |
| `maintenance_or_update` | **Met** | `REPO/blob/main/SECURITY.md#supported-versions` states which lines are supported (0.5.x current; 0.4.x security fixes only while consumers move); `REPO/blob/main/SEMVER.md` documents the upgrade path, what counts as a breaking change and the per-schema wire stability rules. |
| `vulnerability_report_credit` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — reporters are credited in the advisory and the `CHANGELOG.md` entry for the fix unless they ask not to be. No external report has been received yet. |
| `vulnerability_response_process` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory or email intake, acknowledgement within 72 hours, fix target 30 days, fixes to the wire contract coordinated with consumers before disclosure. |

## Quality & testing

| Criterion | Status | Justification to paste |
|---|---|---|
| `tests_documented_added` | **Met** | `REPO/blob/main/CONTRIBUTING.md#tests` states the policy that changes adding/modifying functionality ship with tests in the same PR. |
| `test_policy_mandated` | **Met** | Formal written policy at `REPO/blob/main/CONTRIBUTING.md#tests`: functionality changes ship with tests; bug fixes include a regression test; wire-format changes add vectors. Enforced in review and by the 100% statement-coverage gate. |
| `automated_integration_testing` | **Met** | `REPO/blob/main/.github/workflows/ci.yml` runs the full suite on every push and PR (full gate on Python 3.11, tests on 3.12 and 3.13), including `tests/test_envelope_end_to_end.py`, the consumer vectors (one per conforming family repository, `tests/test_consumer_vectors.py`) and the vector byte-stability check; `ci-rust.yml` runs the Rust conformance suite over the same vectors. |
| `regression_tests_added50` | **Met** | Policy requires a regression test with every bug fix. In the last 6 months the product-code defect fixes were the four audit findings fixed in PR #2 (`REPO/pull/2`), and all four carry regression tests (`tests/test_audit_2026_10_25.py`) or vectors (`vectors/trust-store/`). The only other fix in that period concerned CI configuration (the SBOM command flag). |
| `test_statement_coverage80` | **Met** | CI gate: 100% statement coverage (`[tool.coverage.report] fail_under = 100` in `pyproject.toml`, applied by `pytest --cov=presidio_evidence` in `.github/workflows/ci.yml`). |
| `warnings_strict` | **Met** | ruff with `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit), only `S101` excused in `tests/` and `fuzz/`; clippy `--all-targets -- -D warnings` on the Rust crate. CI fails on any finding. |
| `coding_standards` | **Met** | `REPO/blob/main/CONTRIBUTING.md#style` — ruff (lint and format, configured in `pyproject.toml`: line length 100, target Python 3.11) and `cargo fmt` / `cargo clippy` for the Rust crate. |
| `coding_standards_enforced` | **Met** | `ruff check`, `ruff format --check`, `cargo fmt --check` and clippy run in CI on every PR, inside the required checks `conformance` and `conformance-rust`. |
| `installation_common` | **Met** | `pip install presidio-evidence` (or `pip install 'presidio-evidence[crypto]'` for Ed25519) from PyPI. |
| `installation_development_quick` | **Met** | `REPO/blob/main/CONTRIBUTING.md#local-verification` — create a venv, `pip install -e ".[dev]"`, then the ruff and pytest commands; `cargo` commands for the Rust lane. |
| `build_repeatable` (SHOULD) | **Met** | The wheel is bit-for-bit reproducible: rebuilding `v0.5.0` from the tagged source (`git archive v0.5.0`, `uv build --wheel`) on 2026-11-02 gave a wheel whose SHA-256 (`81203afc…ddc9a`) matches the PyPI file exactly, and two rebuilds matched each other. Release builds use a hash-pinned backend (`.github/constraints/release-build.txt`, `python -m build --no-isolation`) and SHA-pinned Actions; the package is pure Python with no runtime dependencies. The sdist was not compared. |
| `build_standard_variables` | **N/A** | A pure-Python package built by `hatchling`; no compiler or linker is invoked. The Rust crate is a non-distributed conformance lane (`publish = false`) with no `build.rs`. |
| `build_preserve_debug` | **N/A** | No compiled artefacts are distributed; the wheel is pure Python (`py3-none-any`). |
| `build_non_recursive` | **N/A** | A single PEP 517 build; there is no make or subdirectory build. |
| `installation_standard_variables` | **N/A** | Installed via pip; `DESTDIR`-style conventions do not apply. |

## Dependencies & components

| Criterion | Status | Justification to paste |
|---|---|---|
| `external_dependencies` | **Met** | Listed machine-readably in `pyproject.toml` (no runtime dependencies; optional `crypto` = `cryptography>=42`; `dev` and `fuzz` extras) and `rust/Cargo.toml`; release and CI toolchains are hash-pinned in `.github/constraints/*.txt`. A CycloneDX SBOM of the installed wheel with its `crypto` extra is generated, attested and attached to each release by `publish.yml`. |
| `updateable_reused_components` | **Met** | All reused components are PyPI or crates.io packages installed by the package manager (no vendored copies); Dependabot tracks pip, cargo and GitHub Actions updates. |
| `interfaces_current` | **Met** | Dependencies are kept current by Dependabot (pip, cargo, Actions) with security updates enabled; ruff's `UP` rules flag outdated Python idioms; clippy with `-D warnings` fails on deprecated Rust APIs. |

## Security

| Criterion | Status | Justification to paste |
|---|---|---|
| `assurance_case` | **Met** (URL required) | URL: `REPO/blob/main/ASSURANCE.md`. Threat model with out-of-scope assumptions and known limitations, five trust boundaries matching `ARCHITECTURE.md#trust-boundaries`, the secure-design-principles argument and the common-weakness argument. It states that the pre-publication audit was run by the maintainer and is not an independent review. |
| `implement_secure_design` | **Met** | Fail-safe defaults: every verification path returns `False` or raises `EvidenceError`; none returns `True` by default, and `optimistic`/`zk` tiers fail closed. Complete mediation: `verify_envelope` parses the whole envelope before verifying any ref and applies every check to every ref; the CLI uses the same function. Least privilege: no keys held, no state, no network, no logging. Defence in depth: signer binding, `@3` subject binding, the `@1`/`@2` reuse floor, the tier check and key-type separation are independent. Economy of mechanism: Ed25519 from `cryptography`, SHA-256/HMAC from the stdlib, no bespoke crypto. See `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`. |
| `input_validation` | **Met** | Envelopes are untrusted: `parse_document` (`src/presidio_evidence/_refs.py`) checks a known schema id, each field as a bounded string (≤ 512 chars, no NUL, valid UTF-8), lowercase-hex hashes and signatures, no control characters in `item_id`/`signer`, and the `framework` pattern under `@3`, and raises `EvidenceError` before anything is verified. Trust-store entries are normalised and `public_key` under `hmac-sha256` is rejected; key files are size-bounded. See `ARCHITECTURE.md#trust-boundaries`. |
| `hardening` | **Met** | `load_private_key` accepts only regular `0600`/`0400` files checked with `fstat` on the opened descriptor, reads at most 256 bytes and never echoes key material; `write_private_key` creates `0600` with `O_EXCL`; HMAC comparison is constant-time; CLI output is JSON-escaped; the Rust crate forbids `unsafe`. Supply chain: SHA-pinned GitHub Actions with least-privilege `permissions:`, hash-pinned release toolchains, Trusted Publishing behind a reviewer-gated environment, secret scanning with push protection. |
| `crypto_weaknesses` | **Met** | Security functions use SHA-256, Ed25519 and HMAC-SHA256 only; no MD5, SHA-1 or DES. |
| `crypto_algorithm_agility` (SHOULD) | **Met** | The signature algorithm is a per-signer trust-store field (`alg`: `ed25519` or `hmac-sha256`, `trust-store@1`), so an operator moves a signer to another algorithm by configuration, and a new algorithm is an additive schema change. The content-hash function (SHA-256) is fixed by the wire format; replacing it would be a new schema major with new vectors (`SEMVER.md#schemawire-stability`), not a runtime switch. |
| `crypto_credential_agility` | **Met** | No key is in the source tree (the published test fixtures in `vectors/` are documented as such). Private keys are supplied at run time from a `0600` file or an environment variable (`load_private_key(path)` / `env=`); trust stores are operator-supplied JSON, and each signer may list several keys, so keys rotate by appending to the list without a new release. |
| `crypto_used_network` | **N/A** | The project makes no network calls. |
| `crypto_tls12` | **N/A** | No network communication. |
| `crypto_certificate_verification` | **N/A** | No TLS client. |
| `crypto_verification_private` | **N/A** | No network communication. |
| `signed_releases` | **Met** | Wheel, sdist and CycloneDX SBOM carry GitHub build-provenance attestations (`gh attestation verify <file> --repo presidio-v/presidio-evidence`), PyPI files carry PEP 740 attestations from Trusted Publishing, and release tags are SSH-signed with the public key in `REPO/blob/main/allowed_signers`. Documented at `REPO/blob/main/SECURITY.md#verifying-releases-and-obtaining-public-signing-keys`. Checked for `v0.5.0` and `v0.5.1` on 2026-11-02 (wheel, sdist and SBOM attestations and the tag signatures all verify). |
| `version_tags_signed` | **Met** | Every release tag (`v0.2.0` through `v0.5.1`) is SSH-signed with the organisation release key and shown as Verified on GitHub; `git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag <tag>` checks it locally. |
| `sites_password_security` | **N/A** | The project runs no site and stores no passwords. |

## Analysis & monitoring

| Criterion | Status | Justification to paste |
|---|---|---|
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL for Python (`REPO/blob/main/.github/workflows/codeql.yml`) on every push/PR and weekly, and ruff's `S` (flake8-bandit) security rules as a required CI step; OpenSSF Scorecard (`scorecard.yml`) weekly and on every push to `main` for supply-chain posture. |
| `dynamic_analysis_unsafe` | **N/A** | Python is memory-safe and the Rust crate is safe Rust (`#![forbid(unsafe_code)]`). The Atheris harness (`fuzz/fuzz_envelope.py`, `fuzz.yml`) runs regardless, seeded from `vectors/`; its 60 s PR run on 2026-11-02 executed 583,156 inputs with no failure in the library. |
| `dependency_monitoring` | **Met** | Dependabot (pip, cargo, GitHub Actions) with security updates enabled; `pip-audit` on every push and PR (`ci.yml`); OpenSSF Scorecard weekly. |

## Accessibility & internationalization

| Criterion | Status | Justification to paste |
|---|---|---|
| `accessibility_best_practices` | **N/A** | A library and a command-line tool with no graphical or end-user UI; CLI output is plain text, one line per ref. |
| `internationalization` | **N/A** | No user-facing localizable UI; CLI messages are short English diagnostics for developers and operators. |

---

## Notes

- Any silver criterion **not** listed here carries over unchanged from the passing
  sheet.
- `bus_factor`, `build_repeatable` and `crypto_algorithm_agility` are SHOULD
  criteria.
