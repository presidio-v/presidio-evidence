# presidio-evidence

[![CI](https://github.com/presidio-v/presidio-evidence/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-v/presidio-evidence/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/presidio-v/presidio-evidence/badge)](https://scorecard.dev/viewer/?uri=github.com/presidio-v/presidio-evidence)
[![PyPI](https://img.shields.io/pypi/v/presidio-evidence.svg)](https://pypi.org/project/presidio-evidence/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The signed-evidence substrate of the presidio-hardened-* family. Every component that gates an action on evidence, or produces evidence for someone else to check, uses one contract: canonical JSON and SHA-256 content addressing, detached Ed25519 or HMAC-SHA256 signatures, fail-closed verification against a trust store, and provenance parents that chain payloads into a verifiable graph. Independent of Microsoft Presidio.

The library was extracted from four production implementations before they could drift apart. Seven family repositories now conform to it. Provenance parents (ADR-0002) chain classification → gate decision → training run → runtime posture → payment into one DAG, so regulatory traceability is a data structure rather than process documentation.

**The contract is `schemas/` + `vectors/`, not the code.** The Python package and the Rust crate both prove conformance against the same golden vectors, and both trees ship inside the Python package. A consumer migrates by pointing its existing tests at the vectors first and swapping imports second.

## Install

```bash
pip install presidio-evidence             # Layer 0 + HMAC, stdlib only
pip install 'presidio-evidence[crypto]'   # adds Ed25519 (cryptography)
```

Python 3.11+. The runtime has no dependencies; Ed25519 needs the `crypto` extra.

## Use

```python
from presidio_evidence import (
    EVIDENCE_REF_SCHEMA_ID_V3,
    build_envelope,
    content_hash,
    load_trust_store,
    sign_evidence_v3,
    verify_envelope,
)

ch = content_hash({"item_id": "D1", "status": "evidence-present"})  # Layer 0
sig = sign_evidence_v3(ch, "my-signer", "iki-gov", "D1", key=priv_hex)  # Layer 1, @3
ref = {
    "item_id": "D1",
    "framework": "iki-gov",
    "source": "my-tool",
    "source_version": "1.0",
    "ledger_ref": "run-42",
    "content_hash": ch,
    "signer": "my-signer",
    "signature": sig,
    "claimed_at": "2026-10-25T00:00:00Z",
}
envelope = build_envelope([ref], schema=EVIDENCE_REF_SCHEMA_ID_V3)

trust = load_trust_store({"my-signer": {"alg": "ed25519", "public_key": pub_hex}})
results = verify_envelope(envelope, trust, expected_framework="iki-gov")
assert all(r.verified for r in results)
```

Verification never raises on bad evidence: a wrong key, tampered content, a relabelled subject or an unknown signer verifies as `False`, with a reason per ref. A malformed envelope raises `EvidenceError`.

Keys (ADR-0001 D3): `generate_ed25519_keypair()` and `public_key_hex(priv)` produce trust-store entries; `load_private_key(path)` requires mode `0600` (or reads an environment variable with `env="VAR"`) and never echoes key material. Key custody stays with the operator; the library stores nothing.

The contract trees are package data: `schemas_dir()`, `vectors_dir()`, `schema_ids()` and `load_schema("presidio-hardened/evidence-ref@3")`.

## CLI

```bash
presidio-evidence verify envelope.json --trust trust-store.json
presidio-evidence verify envelope.json --trust trust-store.json --require-subject-binding iki-gov
presidio-evidence keygen --out signer.key --signer my-signer   # 0600 file; prints the trust-store entry
```

`verify` exits 0 only if every ref verifies. It fails closed on malformed input, on refs that declare an `optimistic` or `zk` tier (this verifier checks signature attestations only, ADR-0003 D6), and on an `@1`/`@2` ref claimed for more than one item.

## The contract

| Schema | What it pins |
|---|---|
| `evidence-ref@1` | The envelope and its eight ref fields; signature over `canonical({content_hash, signer})`. Frozen. |
| `evidence-ref@2` | Adds an optional per-ref `assurance_tier` (`attested` / `optimistic` / `zk`, ADR-0003); same signed message. |
| `evidence-ref@3` | Adds a required `framework` and signs the subject and the tier: `canonical({assurance_tier, content_hash, framework, item_id, signer})` (ADR-0004). A ref copied under another item, framework or tier no longer verifies. |
| `trust-store@1` | Signer → algorithm and keys, with rotation lists. |
| `training-run@1`, `gate-certificate@1` | Layer-0 payloads the family's producers emit (ADR-0005 numeric encoding, ADR-0006 certificate identity). |

Layers (ADR-0001 D1): **0** canonical JSON (strict: floats rejected) and SHA-256 content addressing · **1** detached signatures and trust-store verification · **2** approval semantics, out of scope (treasury keeps its dual control).

Every schema change is append-only (ADR-0001 D5): a published vector is never edited, and a new wire format is a new major. Verifiers accept `@1`, `@2` and `@3`; a gate that needs subject binding demands `@3` for its framework.

## Consumers

| Repository | Evidence | Layer |
|---|---|---|
| [presidio-hardened-ikigov-assess](https://github.com/presidio-v/presidio-hardened-ikigov-assess) | `evidence-ref@1`/`@2` verifier, gate certificates, workshop leave-behinds | 0 + 1 |
| [presidio-hardened-x402](https://github.com/presidio-v/presidio-hardened-x402) | screening audit pipeline; SLO readings via `evidence-bridge` | 0 + 1 |
| [presidio-hardened-x402-mcp](https://github.com/presidio-v/presidio-hardened-x402-mcp) | signed `payment-decision@1` records in `evidence-ref@1` envelopes | 0 + 1 |
| [presidio-hardened-arch-translucency](https://github.com/presidio-v/presidio-hardened-arch-translucency) | signed SLO envelopes; `training-run@1` and `energy-reading@1` readings | 0 + 1 |
| [presidio-hardened-scoutsuite](https://github.com/presidio-v/presidio-hardened-scoutsuite) | clean cloud controls as `evidence-ref@2` refs (0.30.0+) | 0 + 1 |
| [presidio-hardened-treasury](https://github.com/presidio-v/presidio-hardened-treasury) | close checkpoints (Rust, dual control, keyless) | 0 |
| a private producer | `evidence-ref@1` producer | 0 + 1 |

Each consumer has a golden vector here, so a regression in any of them fails this repository's CI as well as its own.

## Verify a checkout

```bash
pip install -e ".[dev]"
python scripts/generate_vectors.py --check   # vectors byte-stable
pytest tests/ -q                             # Python conformance, 100% coverage gate
cargo test --manifest-path rust/Cargo.toml   # Rust conformance
```

## Layout

```
schemas/    JSON Schemas (normative)
vectors/    golden test vectors, append-only, generated by scripts/generate_vectors.py
src/        Python package: Layer 0/1, refs and envelopes, keys, CLI
rust/       Rust crate: Layer 0 and the signing messages, plus conformance tests
tests/      Python conformance suite
docs/adr/   architecture decision records
docs/       MIGRATION.md (per-consumer plan)
```

## Roadmap

| Version | Scope | Status |
|---|---|---|
| 0.1.0 – 0.4.0 | ADR-0001; schemas and vectors; Python reference implementation; consumer vectors; `evidence-ref@2` tiers; Rust Layer 0; key helpers and CLI; numeric encoding and gate-certificate identity | delivered |
| 0.5.0 | First public release: `evidence-ref@3` subject binding (ADR-0004), contract trees as package data, scoutsuite consumer vector | delivered |
| 0.5.1 | Requires Python 3.11+ (3.10 is end of life); CI on every supported Python | current |

Next 12 months (to 2027-Q4), planned work only:

- **Now (2026-Q4)** — consumers move from vendored code to the PyPI package, starting with ikigov-assess ([MIGRATION.md](docs/MIGRATION.md) step 1); OpenSSF Best Practices silver for this repository.
- **Next (2027-H1)** — producers dual-emit `@2` and `@3`, then consumers demand `@3` per gate (ADR-0004 D8); tighter `training-run@1` and `gate-certificate@1` schemas ([#1](https://github.com/presidio-v/presidio-evidence/issues/1)).
- **Later (under evaluation)** — a `capability-grant@1` vector once its producer exists; moving the remaining consumers onto the package in migration-map order.

Design rationale: [ADR-0001](docs/adr/ADR-0001-evidence-substrate.md). Requirements ledger: [PRESIDIO-REQ.md](PRESIDIO-REQ.md). Migration order: [docs/MIGRATION.md](docs/MIGRATION.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## Governance, architecture, security

- [Governance](GOVERNANCE.md): roles, decision process, continuity, and how to become a maintainer.
- [Architecture](ARCHITECTURE.md): components, the verification flow and the trust boundaries.
- [Assurance case](ASSURANCE.md): the threat model and the argument that the security requirements are met.
- [Security policy](SECURITY.md): supported versions, how to report a vulnerability, and how to verify a release.
- [Stability and semver](SEMVER.md): the public API and the guarantees integrators can rely on.
- [Contributing](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

MIT
