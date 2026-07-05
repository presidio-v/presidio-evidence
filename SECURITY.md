# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ current |
| 0.1.x | security fixes only while internal consumers finish migration |

## Reporting a vulnerability

This repository is private (internal library; ADR-0001 D6). Report issues directly to the founder/governing account: vladimir@presidio-group.eu. Do not open public issues. Target acknowledgement: 48 h.

## Threat model

The repo ships the **contract artefacts** (schemas, golden vectors), dual conformance tests, and the Python Layer-0/1 reference implementation. The security-relevant invariants enforced here:

- **Wire-format pinning:** golden vectors pin the exact canonicalization and signature bytes shared by ikigov-assess, hardened-ai, and x402. Any drift breaks CI in both languages (`scripts/generate_vectors.py --check` + dual conformance suites).
- **Fail-closed verification:** tamper vectors assert that wrong keys, tampered content, cross-signer replay, and malformed input all verify as `false` — never as an exception that could be swallowed into fail-open behaviour.
- **Signer binding:** the signer id is inside the signed message; signature replay under another identity is covered by an explicit vector.
- **Assurance-tier boundary:** `evidence-ref@2` is the only schema that honors declared `assurance_tier`; the same field on `@1` is tolerated as an ignored extra and resolves to `attested`.
- **No key material:** this repo contains only the well-known test key (`01`×32) used as a cross-repo golden vector. Production keys are founder-held, out-of-band (Humboldt root-of-trust); the library will never store keys.
- **Publication guards:** `Private :: Do Not Upload` trove classifier (PyPI rejects server-side) and `publish = false` (cargo refuses) protect against accidental publication while the repository is private.

## Security event logging

Applies from v0.2.0 (extracted implementation): "Presidio hardening applied to ..." events per family standard.
