# Changelog

Release notes up to v0.3.0 live in the GitHub releases and in PRESIDIO-REQ.md.
From here on, changes are recorded in this file first.

## [Unreleased]

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
