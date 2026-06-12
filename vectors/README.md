# Golden test vectors

**Append-only (ADR-0001 D5).** A published vector is never edited; superseded vectors move to `retired/` with a reason. Every file here is produced by `scripts/generate_vectors.py`; CI fails if the committed files drift from regeneration (`--check`) or if orphan files appear.

| Directory | Pins |
|---|---|
| `signing/` | Cross-repo wire format: detached Ed25519/HMAC-SHA256 over `canonical({content_hash, signer})`, plus tamper cases that must fail closed. The Ed25519 vector (priv `01`×32) is byte-identical to the ones committed in presidio-hardened-ai, x402, and ikigov-assess. |
| `canonical-json/` | Layer-0 strict canonical JSON profile (sorted keys, compact separators, UTF-8, no ASCII escaping, floats rejected) + SHA-256 content hashes. |
| `evidence-ref/` | `presidio-hardened/evidence-ref@1` envelopes: valid (incl. one end-to-end verifiable with companion `.notes.json`), and invalid documents schema validation must reject. |
| `trust-store/` | `presidio-hardened/trust-store@1`: valid store (Ed25519, rotation lists, HMAC back-compat forms) and invalid stores. |

The only private key in this repo is the well-known test key `01`×32 — a cross-repo fixture, not a secret.
