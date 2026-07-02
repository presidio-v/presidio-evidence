# Golden test vectors

**Append-only (ADR-0001 D5).** A published vector is never edited; superseded vectors move to `retired/` with a reason. Every file here is produced by `scripts/generate_vectors.py`; CI fails if the committed files drift from regeneration (`--check`) or if orphan files appear.

| Directory | Pins |
|---|---|
| `signing/` | Cross-repo wire format: detached Ed25519/HMAC-SHA256 over `canonical({content_hash, signer})`, plus tamper cases that must fail closed. The Ed25519 vector (priv `01`×32) is byte-identical to the ones committed in presidio-hardened-ai, x402, and ikigov-assess. |
| `canonical-json/` | Layer-0 strict canonical JSON profile (sorted keys, compact separators, UTF-8, no ASCII escaping, floats rejected) + SHA-256 content hashes. |
| `evidence-ref/` | `presidio-hardened/evidence-ref@1` envelopes: valid (incl. one end-to-end verifiable with companion `.notes.json`), and invalid documents schema validation must reject. |
| `trust-store/` | `presidio-hardened/trust-store@1`: valid store (Ed25519, rotation lists, HMAC back-compat forms) and invalid stores. |
| `training-run/` | ADR-0002 provenance-parents: a parents-bearing `presidio-hardened/training-run@1` Layer-0 payload (shape per arch-translucency `build_training_run_reading`) wrapped in a signed `evidence-ref@1` envelope. `lineage` (`parents`) lives inside the signed content; companion `.notes.json` carries the Layer-0 reading, signed content, and trust store. |
| `workshop-attestation/` | Schema freeze for `presidio-hardened/workshop-attestation@1` (ikigov-assess T-B4): a presidio-as-assessor countersignature whose `attests`/`parents[0]` reference the `training-run/` payload's content hash — the ADR-0002 DAG edge (L-EV-6). ASCII-only, float-free. |

The only private key in this repo is the well-known test key `01`×32 — a cross-repo fixture, not a secret.
