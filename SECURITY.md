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

We acknowledge within 72 hours and aim to ship a fix within 30 days. Reporters are credited in the advisory and in the `CHANGELOG.md` entry for the fix unless they ask not to be. A flaw in the wire contract (a schema, a signing message or a vector) usually affects every consumer, so we coordinate the fix with them before disclosure.

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

The consolidated assurance case (threat model, trust boundaries, secure-design argument and how common implementation weaknesses are countered) is in [ASSURANCE.md](ASSURANCE.md); components and boundaries are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Test keys in this repository

`vectors/` contains well-known test keys on purpose: the Ed25519 key `01`×32, the customer key `02`×32, and the HMAC key `shared-key`. They are published fixtures that make the vectors reproducible across repositories, not secrets. Secret scanners will flag them; they are allowlisted for the `vectors/` tree and the generator. Never use them outside tests.

## Security event logging

The library itself logs nothing. Consumers log verification outcomes per the family standard and never log key material, tokens or evidence content.

## Software development lifecycle

This library is developed under the Presidio hardened-family SDLC, in the
**open-source baseline** tier: it is published on PyPI and PRESIDIO does not operate it
as a service. The public report (scope, standards mapping, threat-model gates,
supply-chain controls) is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>,
and this repository's measured controls are its row in the
[applicability matrix](https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/applicability.md).

## Verifying releases and obtaining public signing keys

Releases are cut from an SSH-signed `v*` tag by `.github/workflows/publish.yml`, which builds with a hash-pinned toolchain and publishes to PyPI through Trusted Publishing (OIDC, no stored API token) after a second reviewer approves the `release` environment. There is no key to fetch by hand for artefact verification.

- **PyPI files** carry PEP 740 attestations from that workflow; PyPI shows them on each file's page.
- **GitHub release assets** (wheel, sdist, CycloneDX SBOM) carry build-provenance attestations:

  ```bash
  gh attestation verify presidio_evidence-<version>-py3-none-any.whl --repo presidio-v/presidio-evidence
  gh attestation verify sbom.cdx.json --repo presidio-v/presidio-evidence
  ```

  Each asset's provenance bundle is also attached to the release as `<asset>.intoto.jsonl`, so it can be verified without querying GitHub's attestation store:

  ```bash
  gh attestation verify sbom.cdx.json --bundle sbom.cdx.json.intoto.jsonl --repo presidio-v/presidio-evidence
  ```

- **Release tags** are SSH-signed with the organisation's release key, registered as a signing key on the maintainer's GitHub account, so each tag shows as **Verified**:

  ```bash
  gh api repos/presidio-v/presidio-evidence/git/tags/<sha> --jq .verification.verified
  ```

  The public key is in [`allowed_signers`](allowed_signers). To verify a tag locally:

  ```bash
  git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag <tag>
  ```
