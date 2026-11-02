# Stability & semver guarantees — presidio-evidence

For downstream integrators depending on this project.

## What is the public API

The public API is:

- every name in `presidio_evidence.__all__`, with its documented signature and
  return type;
- the `presidio-evidence` CLI: the `verify` and `keygen` subcommands, their
  options, and the exit codes (0 every ref verified, 1 failure or malformed input,
  2 usage error);
- the contract trees shipped as package data: `schemas/` and `vectors/`, reached
  through `schemas_dir()`, `vectors_dir()`, `schema_ids()` and `load_schema()`.

Underscore-prefixed modules (`presidio_evidence._refs`, `._signing` and the rest)
are internal; import from `presidio_evidence` instead. The Rust crate is
`publish = false` and consumed as a git dependency; its public items follow the
same rules, but it is versioned separately (currently 0.3.0).

## Versioning rules (semver, pre-1.0 profile)

- **Patch (0.x.Y):** bug fixes, security fixes, dependency floor bumps. No API
  change, no behaviour change except the fixed defect. Safe to auto-upgrade; this
  is the channel security releases ship on.
- **Minor (0.X.0):** additive API (new exports, new optional parameters with
  defaults, new optional extras). Existing code keeps working, including the
  documented public behaviour. Deprecations are announced here (docstring +
  CHANGELOG) at least one minor before any change.
- **Major (1.0.0+):** the only place deprecated surface may be removed.

**Pin guidance for integrators:** pin `presidio_evidence` to the current minor
in production and run the verification step (below) in your CI on every upgrade.

## Behavioural guarantees (stronger than API stability)

These are security invariants, not just interfaces; weakening any of them is
treated as a breaking change regardless of which version component moves.

- **Fail closed.** `verify_ref` and the `verify_*` functions return `False` for
  bad evidence (unknown signer, wrong key, tampered hash, non-hex or malformed
  signature) and never raise on it. A malformed envelope or trust store raises
  `EvidenceError`. The CLI exits 0 only if every ref verifies.
- **The schema selects the signed message.** Field presence never does, so a
  signature made for one major never verifies as another.
- **`@3` binds subject and tier.** An `@3` ref verifies only for the `framework`,
  `item_id` and resolved `assurance_tier` it was signed for; with
  `expected_framework`, `@1`/`@2` refs never verify.
- **Reuse floor.** `verify_envelope` and the CLI fail every copy of an `@1`/`@2`
  ref that one envelope claims for several items.
- **Tiers.** A ref declaring `optimistic` or `zk` is not verified by this
  library.
- **Key separation.** `public_key` is Ed25519 only and is never used as an HMAC
  secret.
- **Canonical bytes are stable.** `canonical_bytes`, `content_hash`, the signing
  messages, `encode_decimal` and `gate_certificate_identity` return the same bytes
  for the same input across every release. Floats stay rejected.
- **No key material in output.** Errors and CLI output never contain private key
  material; `write_private_key` never overwrites.

## Verifying an installation

Run the golden vectors against the installed package. They ship inside it, so no
checkout is needed:

```bash
pip install "presidio-evidence[crypto]==<version>"
python - <<'PY'
import json
from presidio_evidence import load_trust_store, verify_envelope, vectors_dir

v3 = vectors_dir() / "evidence-ref-v3"
expect = json.loads((v3 / "expectations.json").read_text())
trust = load_trust_store(expect["trust_store"])
for name, refs in expect["files"].items():
    results = verify_envelope(json.loads((v3 / name).read_text()), trust)
    assert [r.verified for r in results] == [e["envelope_verifies"] for e in refs], name
print("ok")
PY
```

A passing run prints `ok`. For a release artefact, also verify its provenance:
`gh attestation verify <wheel> --repo presidio-v/presidio-evidence`.

## Schema/wire stability

The wire contract is versioned per schema id (`presidio-hardened/<name>@<major>`),
independently of the package version (ADR-0001 D5):

- A published schema major is frozen. Its golden vectors are append-only: new
  cases may be added, existing ones are never edited.
- A change to a signed message or a required field is a **new major** of that
  schema (`evidence-ref@3` is the example), never an edit of the old one.
- Verifiers keep accepting every published major (`@1`, `@2` and `@3` today);
  removal is not planned. Producers choose the major they emit; a gate chooses the
  major it demands.
- A package minor may add schemas, vectors and optional fields with defaults; it
  never changes the bytes an existing major signs.

## Security response

See [SECURITY.md](SECURITY.md). Security fixes ship as patch releases on the
latest minor; any minimum-safe dependency floors are bumped in the same release.
