# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | ✅ current |
| 0.4.x | security fixes only, while consumers move to 0.5 |
| < 0.4 | not supported |

## Reporting a vulnerability

Report privately, not in a public issue:

- GitHub: [report a vulnerability](https://github.com/presidio-v/presidio-evidence/security/advisories/new) (private advisory), or
- email security@presidio-group.eu.

We acknowledge within 72 hours and aim to ship a fix within 30 days. Reporters are credited in the advisory unless they ask not to be. A flaw in the wire contract (a schema, a signing message or a vector) usually affects every consumer, so we coordinate the fix with them before disclosure.

## Threat model

This repository ships the contract artefacts (schemas, golden vectors), conformance suites in two languages, and the Python Layer-0/1 reference implementation. It does not hold or store keys, and it does not decide what evidence means for a consumer: `item_id` domain checks stay with the consumer.

Invariants enforced here:

- **Wire-format pinning.** Golden vectors pin the exact canonical bytes and signatures shared by every consumer. Any drift fails CI in both languages (`scripts/generate_vectors.py --check` and both conformance suites).
- **Fail-closed verification.** Wrong keys, tampered content, cross-signer replay and malformed refs verify as `False`, never as an exception that a caller could swallow into a pass.
- **Signer binding.** The signer id is inside every signed message; replay under another identity is covered by a vector.
- **Subject binding (`evidence-ref@3`, ADR-0004).** The signature covers `framework`, `item_id` and the resolved `assurance_tier`. A ref copied under another item, framework or tier fails. The envelope's schema selects the signed message; field presence never does, so a signature made for one major never verifies as another.
- **Reuse floor for `@1`/`@2`.** Those messages do not cover the item, so `verify_envelope` and the CLI fail every copy of a ref that one envelope claims for several items. The floor works per envelope; a gate that needs the guarantee across envelopes demands `@3`.
- **Assurance tiers.** This verifier checks signature attestations only. A ref declaring `optimistic` or `zk` is not verified here (ADR-0003 D6).
- **Known limitation of `@2`.** The `@2` tier is not signed, so whoever assembles an envelope can strip or change it. Under `@3` the tier is signed.
- **Trust stores.** `public_key` is Ed25519 material only. An entry with `public_key` and no `alg` is read as Ed25519; `public_key` under `hmac-sha256` is rejected at load. A published public key therefore never acts as a shared HMAC secret. HMAC secrets come only from `key` or a bare string.
- **Malformed input never raises past the API.** A signature that is not lowercase hex verifies as `False` before any decode; strings that are not valid UTF-8 (lone surrogates) and control characters in `item_id`/`signer` are rejected when the envelope is parsed, with `EvidenceError`. The CLI prints identifiers JSON-escaped, one line per ref, so a producer cannot forge verdict lines or terminal escapes.
- **Key handling.** `load_private_key` accepts only regular files with mode `0600`/`0400` (or an environment variable), reads with a size bound, opens before it checks (no TOCTOU), and never puts key material in an error message. `write_private_key` refuses to overwrite.

## Test keys in this repository

`vectors/` contains well-known test keys on purpose: the Ed25519 key `01`×32, the customer key `02`×32, and the HMAC key `shared-key`. They are published fixtures that make the vectors reproducible across repositories, not secrets. Secret scanners will flag them; they are allowlisted for the `vectors/` tree and the generator. Never use them outside tests.

## Security event logging

The library itself logs nothing. Consumers log verification outcomes per the family standard and never log key material, tokens or evidence content.
