# Contributing to presidio-evidence

Thanks for your interest. This project is held to a stricter bar than a typical library — the
checklist below is what a change needs to clear before it can be merged.

## Reporting a security vulnerability

**Do not open a public issue for a security vulnerability.** Use the private reporting
process in [SECURITY.md](SECURITY.md) — GitHub Security Advisories, via the repository's
"Security" tab, or contact security@presidio-group.eu. You will get an acknowledgement
within 72 hours.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/presidio-v/presidio-evidence/issues). Search existing issues first.
For a bug, include:

- the installed version (`pip show presidio_evidence`) and language-runtime version
- what you expected to happen, and what happened instead
- a minimal reproduction if you can produce one

Please strip any secrets, credentials, or personal data from anything you paste into a
public issue.

## New to the project?

Issues labelled [`good first issue`](https://github.com/presidio-v/presidio-evidence/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are scoped to be approachable without deep knowledge of the codebase and are a good place to
start.

## How changes are made

All changes go through a pull request against `main`. Direct pushes to `main` are blocked by
branch protection, and every PR must pass the required status checks before it can merge.

1. Fork the repository and create a branch off `main`.
2. Make your change, with tests (see the test policy below).
3. Run the local verification block until it is clean.
4. Update `CHANGELOG.md` under `## [Unreleased]`.
5. Open a PR describing what changed and why.

## Code review

Every pull request — including a maintainer's own — is reviewed before it merges. This is
not advisory: `main` requires an approving review from a code owner
([CODEOWNERS](.github/CODEOWNERS)) who is **not** the author of the change, enforced by
branch protection (required review, code-owner review, stale-approval dismissal, and
last-push re-approval; admins are included).

What a reviewer confirms before approving:

- **Tests** — new or changed functionality ships with tests; bug fixes include a regression
  test; the coverage floors hold.
- **Security reasoning** — for changes to a security-sensitive area (see below), the PR
  explains the reasoning, and no existing default is weakened without an explicit rationale.
- **Compatibility** — changes to the public API surface, event/record shapes, or exception
  types follow [SEMVER.md](SEMVER.md); breaking changes are called out.
- **Style and scope** — the linter is clean, the change is focused, and `CHANGELOG.md` is
  updated.

Reviewers approve via GitHub's review flow. A change that needs rework is returned with
specific requested changes rather than merged with caveats.

## Requirements for acceptable contributions

A change is merged when it meets all of the following.

### Style

Formatting and linting are enforced by the project linter and are not a matter of taste — CI
rejects anything that does not conform.

The linter and formatter is **ruff**, configured in `pyproject.toml`: line length
100, target Python 3.11, rule sets `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit
security rules; `S101` is allowed in tests). The Rust crate uses `cargo fmt` and
`cargo clippy` with warnings denied.

Each module uses a single consistent import (or include) style. Do not mix conventions for
the same dependency within one module.

### Tests

**Test policy: any change that adds or modifies functionality must ship with tests in the
same pull request.** Bug fixes must include a regression test that fails before the fix and
passes after it. This is enforced in review, and by the coverage gate.

Coverage: CI runs `pytest --cov=presidio_evidence` and fails below **100%
statement coverage** (`[tool.coverage.report] fail_under = 100` in
`pyproject.toml`). Untestable lines need a `# pragma: no cover` with a reason in the
same line. Golden vectors are part of the test bar: a change to the wire format
adds new vectors and never edits a published one (`scripts/generate_vectors.py
--check` enforces this).


### Security-sensitive changes

This project's security controls are the product. If your change touches any of the
security-sensitive modules, then the reviewer bar above applies in full:

- `src/presidio_evidence/_canonical.py`, `_numeric.py`, `_gate_certificate.py`:
  canonical bytes and content hashes (byte-stability contracts)
- `src/presidio_evidence/_signing.py`: the signed messages and signature checks
- `src/presidio_evidence/_refs.py`: envelope parsing, trust stores, the
  verification policy
- `src/presidio_evidence/_keys.py`: key loading and writing
- `src/presidio_evidence/_cli.py`: the verdict and exit code
- `rust/src/`: the Rust Layer 0 and signing messages
- `schemas/`, `vectors/`, `scripts/generate_vectors.py`: the contract

- explain the security reasoning in the PR description, not only the mechanics
- do not weaken a default. New controls are opt-in; relaxations of existing controls need
  an explicit rationale
- never re-implement cryptographic primitives — call a vetted standard library or crypto
  dependency instead
- functions that produce a stable serialized or digest output are byte-stability contracts.
  Changing their output for existing input is a breaking change even if no signature changes

### Public API and compatibility

The public API surface and what counts as a breaking change are defined in
[SEMVER.md](SEMVER.md). Read it before changing anything exported from the public API, and
note that the schemas, the signed messages, the golden vectors and the exception type are
part of the contract that downstream consumers depend on.

### Dependencies

New runtime dependencies are a high bar for a security-focused library and need justification
in the PR. Prefer the standard library. Optional functionality belongs in an optional
dependency group rather than the core dependency set.

## Local verification

Run this before opening a PR, and fix anything it reports:

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m ruff check . \
  && .venv/bin/python -m ruff format --check . \
  && .venv/bin/python -m pytest tests/ -x -q --tb=short
```

Also check the contract and the Rust lane:

```bash
.venv/bin/python scripts/generate_vectors.py --check
cargo fmt --manifest-path rust/Cargo.toml --check \
  && cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings \
  && cargo test --manifest-path rust/Cargo.toml
```

CI runs the full gate (lint, vectors, coverage, `pip-audit`) on Python 3.11 and the test suite
on every other supported version (3.12, 3.13). A change must pass on all of them.

## Commit messages

Write in the imperative mood ("add TTL bound", not "added" or "adds"). Explain *why* the
change is being made where that is not obvious from the diff.

## Licensing and Developer Certificate of Origin (DCO)

The project is MIT licensed, and contributions are accepted under the same
terms (inbound = outbound).

To assert that you have the right to submit your contribution, every commit must
be **signed off** under the [Developer Certificate of Origin](https://developercertificate.org/)
1.1. Signing off means adding a `Signed-off-by` line to the commit message with
your real name and email:

```
Signed-off-by: Jane Developer <jane@example.com>
```

`git commit -s` adds this line for you. By signing off you certify the DCO —
in short, that you wrote the change or otherwise have the right to submit it
under the project's MIT license. Pull requests whose commits are not signed off
will be asked to amend before merge.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
