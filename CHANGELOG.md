# Changelog

Release notes up to v0.3.0 live in the GitHub releases and in PRESIDIO-REQ.md.
From here on, changes are recorded in this file first. Pull-request and issue
numbers in the history up to v0.5.0 refer to the private development
repositories this history was published from.

## [0.5.0] — 2026-10-25

First public release. The repository and its history are public, and the
package is published on PyPI as `presidio-evidence`. Rust crate 0.3.0
(`publish = false`).

### Added
- **`evidence-ref@3` (ADR-0004): the signature binds the subject.**
  Each ref carries a required `framework`; the signed message is
  `canonical({assurance_tier, content_hash, framework, item_id, signer})`. A ref
  copied under another item, framework or tier no longer verifies. The envelope
  schema selects the message, never field presence. New: `signing_message_v3`,
  `sign_evidence_v3`, `verify_ref(..., schema=, expected_framework=)`,
  `verify_envelope`, `RefResult`, `reused_refs`, `EVIDENCE_REF_SCHEMA_ID_V3`,
  `FRAMEWORK_PATTERN`; CLI `verify --require-subject-binding FRAMEWORK`; Rust
  `signing_message_v3`. Vectors under `vectors/evidence-ref-v3/` and
  `vectors/signing/*-golden-v3.json`. **Why it matters:** one genuine signed ref
  could be copied under every checklist item and open every gate (ikigov-assess
  audit 2026-09-30); under `@3` it opens exactly the one it was signed for.
- **Contract trees as package data.** The wheel ships `schemas/` and `vectors/`;
  `schemas_dir()`, `vectors_dir()`, `schema_ids()`, `load_schema()`.
- **scoutsuite consumer vector** (`vectors/cloud-posture/`): clean cloud controls
  as scoutsuite 0.30.0 signs them, with the 0.29.x legacy signatures as
  must-fail cases.
- `vectors/evidence-ref-v2/reused-ref.json` pins the `@1`/`@2` reuse floor.

### Changed
- **CLI `verify` fails an `@1`/`@2` envelope that claims one ref for several
  items**, reporting "reused under N items" (ADR-0004 D5; the rule ikigov-assess
  already applies). **Why it matters:** those messages do not cover the item, so
  the copy is indistinguishable from the original.
- `verify_ref` reads `assurance_tier` under `@3` as well as `@2`.
- Package metadata: the `Private :: Do Not Upload` classifier is gone; project
  URLs and Python 3.10–3.13 classifiers added.

### Security
Fixes from the pre-publication security audit of 2026-10-25 (Cloudflare
security-audit skill, two passes; four low-severity findings, all fixed):
- **Trust store: a `public_key` could act as an HMAC secret.** An entry with
  `public_key` and no `alg` defaulted to `hmac-sha256` and used the public key as
  the shared secret, so anyone holding the public key could forge verified
  evidence. `public_key` now implies Ed25519, and `public_key` under
  `hmac-sha256` is rejected. Vectors: `trust-store/rejected-hmac-with-public-key`,
  `trust-store/public-key-implies-ed25519`.
- **`verify_ref` / `verify_hmac` raised `TypeError` on a non-ASCII signature**
  instead of returning `False`. Signatures that are not lowercase hex now verify
  as `False` before any comparison.
- **A lone surrogate in a signer or item id raised `UnicodeEncodeError`** and
  aborted the whole envelope. The parser now rejects such strings with
  `EvidenceError`; bare-mapping verification returns `False`.
- **CLI output could be forged** with newlines or terminal escapes in
  `item_id`/`signer`. Control characters in those fields are rejected, and the
  CLI prints them JSON-escaped, one line per ref.
- Known limitation, now documented: the `@2` tier is not signed and can be
  stripped by whoever assembles an envelope. Use `@3` where the tier matters.

## [0.4.0] - 2026-10-18

Minor, additive. ADR-0005 and ADR-0006 accepted by the founder on 2026-10-18.
Rust crate stays at 0.2.0 (conformance tests only, no crate API change).

### Added
- **ADR-0005 numeric payload encoding** (Accepted): non-integer numbers in
  signed payloads are decimal strings in plain notation, with a precision
  declared per field and half-even rounding at the producer. Reference
  functions `encode_decimal`, `is_decimal_string`, `decimal_pattern`,
  `UNBOUNDED_SENTINEL`; vectors under `vectors/numeric-encoding/`. The
  `training-run@1` and `energy-reading@1` energy fields keep their shipped
  form under the grandfather clause (N8). canonical-json@1 is unchanged.
- **ADR-0006 gate-certificate@1 identity** (Accepted): a gate certificate's
  identity is sha256 over canonical-json@1 of the document minus `signature`,
  and a provenance parent that names a gate decision uses it. Reference
  functions `gate_certificate_identity`, `gate_certificate_signing_bytes`,
  `GATE_CERTIFICATE_SCHEMA_ID`; vectors under `vectors/gate-certificate/`
  (identity `dbb7c6a3…3ebd4a`, cross-checked against ikigov-assess v0.28.0).
- Schemas `training-run.v1.schema.json` and `gate-certificate.v1.schema.json`,
  describing what the shipped producers already emit.
- Rust conformance tests for both vector sets (no crate API change).

### Changed
- None. No published vector, schema or wire format changed.
