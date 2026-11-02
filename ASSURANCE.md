# Security Assurance Case

This document is the assurance case for `presidio-evidence`: an explicit argument
for why the project's security requirements are met. It has four parts, as
required by the OpenSSF Best Practices silver criterion `assurance_case`:

1. the threat model,
2. the trust boundaries,
3. the argument that secure design principles are applied, and
4. the argument that common implementation weaknesses are countered.

It is a summary that links to the authoritative detail in
[`SECURITY.md`](SECURITY.md) (controls, reporting) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (components, flow, boundaries) for
`presidio-v/presidio-evidence`. Design decisions are in [`docs/adr/`](docs/adr/).

## 1. Threat model

**Asset.** The integrity of a verification verdict. Consumers gate actions on it:
a compliance gate opens, a payment proceeds, a period closes. A false "verified"
is the failure that matters; a false "not verified" is an availability cost the
consumer can see and retry.

| Threat | Control |
|---|---|
| Forged evidence: a ref signed by no trusted signer | Signature verification against the consumer's trust store; an unknown signer, a wrong key or a bad signature verifies as `False`. |
| Cross-signer replay: a genuine signature presented under another signer id | The signer id is inside every signed message (`@1`–`@3`); covered by a vector. |
| Subject relabelling: a genuine ref copied under another item, framework or tier | `@3` signs `framework`, `item_id` and the resolved tier (ADR-0004). Under `@1`/`@2`, which do not sign the item, a ref claimed for several items in one envelope fails for all of them (reuse floor, D5). |
| Downgrade: an `@3` signature read as `@1`, or a field's presence choosing the message | The envelope schema selects the message; field presence never does. A consumer that needs subject binding passes `expected_framework`, and `@1`/`@2` refs then fail. |
| Tier inflation: a ref claiming an assurance tier this verifier cannot check | `optimistic` and `zk` refs fail closed here (ADR-0003 D6). |
| Key confusion: a published Ed25519 public key used as an HMAC secret | `public_key` implies Ed25519 and is rejected under `hmac-sha256` at trust-store load. |
| Malformed or hostile input crashing or confusing the verifier | Bounded, typed parsing that raises only `EvidenceError`; non-hex signatures, lone surrogates and control characters are rejected before any decode; CLI output is JSON-escaped. |
| Hash divergence between producers: two encodings of one value | Strict canonical JSON (floats rejected) and ADR-0005 decimal strings; golden vectors pin the bytes in both languages. |
| Contract drift: a change to schemas, messages or vectors that silently breaks consumers | Append-only vectors with a CI byte-stability check, two conformance suites, consumer vectors in this repository, and a required code-owner review on `main`. |
| Key leakage through the library | Keys load only from a `0600` file or an environment variable; no key material in errors or output; the CLI prints only the public half. |

**Out of scope** (documented, not assumed away):

- **Key custody and trust-store content.** The operator holds private keys and
  decides which signers the trust store lists. Whoever controls the trust store
  controls what verifies.
- **Content checks.** The library verifies the signature over `content_hash`; it
  does not fetch the evidence or re-hash it, and it does not check `item_id`
  against the consumer's vocabulary. The consumer holds the content and does both.
- **HMAC-SHA256 is a shared secret.** Anyone holding the key can sign. It exists
  for back-compatibility; Ed25519 is the default.
- **Known limitations.** The `@2` tier is not signed and can be stripped by
  whoever assembles an envelope; the `@1`/`@2` reuse floor works per envelope
  only. Both are why gates that need the guarantee demand `@3`.
- **Approval semantics** (Layer 2, e.g. dual control) and timestamp trust
  (`claimed_at` is a claim, not a trusted time).

## 2. Trust boundaries

The boundary names match [ARCHITECTURE.md](ARCHITECTURE.md#trust-boundaries).

- **Producer → envelope → consumer** (input validation, the primary boundary).
  Everything in an envelope is untrusted until `parse_document` has validated it
  and `verify_envelope` has checked each ref.
- **Operator → trust store** (trusted configuration, validated). Entries are
  normalised and key-type confusion is rejected; the content itself is trusted.
- **Operator → private key** (secret input). Mode, file type and size are checked
  on the opened descriptor; material never appears in errors.
- **Library → CLI output** (egress). One JSON-escaped line per ref; the exit code
  is the verdict.
- **Contract → consumers** (wire-format integrity). Vectors are the contract;
  CI and the review gate protect them.

The library makes no network calls, so there is no network egress boundary.

## 3. Secure design principles applied

- **Fail-safe defaults / secure by default.** Every verification path returns
  `False` or raises; none returns `True` by default. Verification never raises on
  bad evidence, so a caller cannot turn an exception into a pass by catching it
  broadly; a malformed envelope raises `EvidenceError`, which callers treat as a
  failure. Ed25519 is the default algorithm. New, stronger behaviour arrives as a
  new schema major (`@3`) that gates opt into, while existing behaviour is never
  weakened silently.
- **Complete mediation.** `verify_envelope` parses the whole envelope before
  verifying any ref and applies every check (tier, subject binding, reuse floor,
  signature) to every ref. The CLI calls `verify_envelope`, so it applies the same
  policy and exits 0 only when every ref passes.
- **Least privilege.** The library holds no keys, keeps no state, opens no
  sockets and logs nothing. It reads only the files a caller names. Key custody is
  the operator's by contract.
- **Defense in depth.** Independent controls cover distinct threats: structural
  parsing, signer binding, subject binding, the reuse floor, the tier check and
  key-type separation. Wire-format integrity is guarded by vectors, two language
  implementations and the review gate.
- **Economy of mechanism.** Ed25519 comes from `cryptography`; HMAC-SHA256 and
  SHA-256 from the Python standard library; the Rust crate uses `sha2` and does
  not sign or verify. There is no bespoke cryptography. The runtime has no dependencies beyond
  the optional `crypto` extra; the signed message is canonical JSON of five fields
  or fewer.

## 4. Common implementation weaknesses countered

| Weakness class | How it is countered |
|---|---|
| Improper input validation (CWE-20) | `parse_document` checks types, lengths (≤ 512), lowercase hex, UTF-8 validity, control characters and the `framework` pattern; trust-store entries are normalised and validated; `load_schema` accepts only well-formed schema ids. |
| Injection, output neutralisation (CWE-74, CWE-117, CWE-150) | No shell, SQL or template evaluation anywhere. CLI identifiers are JSON-escaped and control characters are rejected at parse time, so verdict lines and terminal escapes cannot be forged. |
| Memory safety (CWE-119 family) | Python is memory-safe; the Rust crate is safe Rust with `#![forbid(unsafe_code)]`. |
| Cryptographic misuse (CWE-327, CWE-347) | Vetted primitives only; HMAC comparison is constant-time (`hmac.compare_digest`); the message to sign is canonical and schema-selected; signer, subject and tier binding are covered by golden vectors. |
| Key-type confusion (CWE-347) | `public_key` is Ed25519 material only and is rejected under `hmac-sha256`. |
| Hard-coded or exposed secrets (CWE-798, CWE-532) | No secrets in code; the well-known test keys in `vectors/` are published fixtures and documented as such. Key material never appears in errors or output. Secret scanning and push protection are enabled on the repository. |
| Insecure file handling (CWE-367, CWE-732) | Key files are opened first and checked with `fstat` (no TOCTOU window); group/other permission bits are refused; new key files are created `0600` with `O_EXCL`. |
| Unsafe deserialization (CWE-502) | Only `json.loads`; no pickle, YAML or object hooks. Floats and NaN are rejected from canonical payloads. |
| Uncaught exceptions as a pass (CWE-755) | Verification returns `False` instead of raising on bad evidence; lone surrogates and non-hex input are rejected before any decode. Covered by the 2026-10-25 audit regression tests. |
| Vulnerable dependencies (CWE-1104) | Zero runtime dependencies; `cryptography` is optional. `pip-audit` runs in CI; Dependabot covers pip, cargo and GitHub Actions; release toolchains are hash-pinned. |

These classes are checked continuously: **CodeQL** (Python) on every push and pull
request and weekly; **ruff** with the `S` (flake8-bandit) security rule set as a
required CI step; **clippy** with warnings denied on the Rust crate; **OpenSSF
Scorecard** weekly and on every push to `main`; and an **Atheris** fuzz harness
over envelope parsing and verification. The test suite holds a 100% statement
coverage gate.

**Reviews.** Before publication the code had a security audit on 2026-10-25 (two
passes; four low-severity findings, all fixed in 0.5.0, see
[CHANGELOG.md](CHANGELOG.md)). That audit was tool-assisted and run by the
maintainer; it is not an independent third-party review. Every change to `main`
needs an approving code-owner review from someone other than the last pusher.

## Conclusion

The threats above are each matched to a control; the controls sit at explicit
trust boundaries; the design follows fail-safe, least-privilege, complete-
mediation, defense-in-depth, and economy-of-mechanism principles; and the common
implementation weakness classes are countered by design and checked by automated
analysis. The project's stated security requirements are therefore met, subject
to the documented out-of-scope assumptions and known limitations.
