# ADR-0005: Numeric payload encoding — decimal strings in plain notation

**Status:** Accepted
**Date:** 2026-10-18
**Deciders:** V.S. (founder, governing account)
**Founder sign-off:** Accepted by V.S. on 2026-10-18.
**Source mandate:** suite numeric-encoding review 2026-10; canonical-json@1 float rejection (ADR-0001 D1); the energy fields of `training-run@1` and `energy-reading@1` (arch-translucency v0.23/v0.24). ADR-0004 is reserved for `evidence-ref@3` (issue #38).

## Context

canonical-json@1, the Layer-0 profile of ADR-0001 D1, rejects floats. That settles what may *not* appear in a signed payload, and it says nothing about how a non-integer quantity *does* travel. Producers have answered that on their own:

| Producer | Field(s) | Wire form today |
|---|---|---|
| arch-translucency `slo-reading@1` | `value`, `threshold` | JSON integers; p99 latency rounded to whole ms |
| arch-translucency `training-run@1` | `degree`, `samples_per_second`, `duration_s`, `device_count` | JSON integers; rounding upstream is the caller's decision |
| arch-translucency `training-run@1` (v0.23) | `energy_wh`, `mean_power_w` | string, `repr(float(s))`: `"840.0"`, `"420.0"`, and `"1e-05"` for small values |
| arch-translucency `energy-reading@1` (v0.24) | `energy_wh`, `mean_power_w` | same `repr(float)` profile: `"12.5"`, `"150.0"`, `"4800.0"` |
| treasury `checkpoint/v1` | timestamps | i64 nanoseconds, JSON integers |
| ikigov-assess `gate_predicate_content_hash` | risk weights `1.0`, `1.5`, `2.0` | **floats**, hashed with a non-strict canonicaliser |

Forces:

1. **One value, one spelling.** A content hash is only portable if two producers that agree on a number agree on its bytes. `repr(float)` is deterministic inside CPython and gives two spellings for numbers people consider the same (`"12"` from one producer, `"12.0"` from another); it also switches to exponent form below `1e-4`. A Rust or TypeScript producer would need to reproduce CPython's shortest-round-trip algorithm to match.
2. **Precision is a schema decision.** The meaningful resolution of watt-hours, of a latency, or of a probability differs per field. Leaving rounding to each producer means two honest producers hash the same measurement differently.
3. **Verifiers must not round.** If a verifier parses a decimal string to binary float to compare or hash it, verification depends on the platform's binary rounding. The verifier's job is byte comparison.
4. **canonical-json@1 is frozen.** This decision lives at the payload-schema layer. The canonicaliser, its vectors and every hash already published stay unchanged.
5. **Vectors are append-only** (ADR-0001 D5). Fields already shipped in another form cannot be rewritten; they can only be grandfathered or superseded by a new major.

## Decision

Adopt a payload-schema rule. canonical-json@1 is unchanged.

> Non-integer numeric values in signed payloads are encoded as decimal strings in plain notation: no exponent, no trailing zeros (and no trailing decimal point), optional leading '-', at least one digit before the point. Each payload schema declares, per such field, its precision (maximum fractional digits); producers round half-even to that precision before encoding. JSON numbers in signed payloads are integers only (canonical-json@1 already rejects floats). NaN and ±Infinity are rejected at the producer; 'unbounded' is expressed by a schema-declared sentinel string or by omitting the field, never by a float. Verifiers compare these strings byte-wise and never parse them to float for hashing or comparison. Existing scaled-integer fields already shipped (arch-translucency training-run@1) are grandfathered; new fields follow this rule.

Made precise:

- **N1 — Grammar.** A decimal string matches `-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?` in full, over ASCII digits only, and is not `-0`. That is: no exponent, no `+`, no leading zeros, no trailing zeros in the fraction, no trailing point, no leading point, no whitespace. Length is bounded by the family string bound (512 characters).
- **N2 — Negative zero (defined here).** Zero has one spelling, `"0"`. `"-0"` is rejected by verifiers. A producer whose value rounds to zero emits `"0"` whatever the sign (`-0.001` at precision 2 encodes as `"0"`).
- **N3 — Integral values.** An integral value in a decimal field is spelled without a point (`"12"`, not `"12.0"`). Integer-typed fields stay JSON integers; a field is either integer-typed or decimal-typed, declared by its schema.
- **N4 — Precision declaration.** A schema declares each decimal field as `{"type": "string", "pattern": <decimal_pattern(p)>, "x-decimal-precision": p}`. The pattern encodes the precision bound (at most `p` fractional digits), so plain JSON Schema validation enforces it; the annotation records the number for producers. Precision 0 admits integral values only.
- **N5 — Rounding.** Producers round half-even (banker's rounding) to the declared precision in decimal arithmetic, then strip trailing zeros and a trailing point. A binary float reaching a producer is converted explicitly by the caller (e.g. `Decimal(repr(x))`) before rounding; the reference encoder refuses a bare float so that step is visible.
- **N6 — Sentinels.** A field that needs "unbounded" declares a sentinel in its schema, as `oneOf` of the decimal pattern and a `const`. A sentinel is a lowercase ASCII word (`[a-z][a-z0-9-]*`), so it cannot be read as a number. The family spelling is `"unbounded"`. Omitting the field is the alternative where the schema says absence means unbounded. `"Infinity"`, `"inf"` and `"NaN"` are never valid.
- **N7 — Verification.** Verifiers check the grammar and precision on the string and compare byte-wise. They never convert to float for hashing or comparison.
- **N8 — Grandfathering.** The following shipped fields keep their current wire form, frozen under ADR-0001 D5, and are named in their schemas as exceptions:
  - integer fields already on the wire — `training-run@1` `degree` / `samples_per_second` / `duration_s` / `device_count`, `slo-reading@1` `value` / `threshold`, treasury nanosecond timestamps. These already conform (JSON integers);
  - `training-run@1` `energy_wh` / `mean_power_w` (arch-translucency v0.23) and `energy-reading@1` `energy_wh` / `mean_power_w` (v0.24): the shortest-round-trip IEEE-754 string (`repr(float)`), which includes `"840.0"` and exponent forms such as `"1e-05"`. These do **not** conform to N1. A new major of either schema adopts N1–N7.

  Every field added after this ADR is accepted follows N1–N7.

### Reference implementation and vectors

- `presidio_evidence.encode_decimal(value, *, precision)` (producer side), `is_decimal_string(value, *, precision, sentinels=())` (verifier side; a character-level check, with a test that fails if it calls `float`), `decimal_pattern(precision)` (the N4 schema pattern), `UNBOUNDED_SENTINEL`. Stdlib only.
- `vectors/numeric-encoding/vectors.json` (append-only): 34 validate cases (`"0.00001"` accepted, `"1e-05"`, `"12.0"`, `"-0"`, `"NaN"`, `"Infinity"`, `"840.0"` and others rejected), 17 encode cases with hand-written expected outputs (half-even: `"0.125"`→`"0.12"`, `"0.135"`→`"0.14"`, `"2.5"`@0→`"2"`), and 5 inputs the producer must refuse. The Python suite runs all three groups and checks that the schema pattern agrees with the validator. The Rust suite runs the validate cases with its own byte-walking validator.

## Options considered

**A — Decimal strings in plain notation, per-field precision (chosen).** One spelling per value, reproducible in any language without a float library, and the precision lives in the schema where a reviewer can see it. Costs a string where a number would read more naturally.

**B — Scaled integers everywhere** (milliwatt-hours, basis points). Integers are already legal and need no new grammar. Rejected as the general rule: the scale becomes part of the field name or a side convention, a change of resolution is a breaking change, and some quantities (ratios, probabilities) have no natural unit. Remains a valid choice for a schema that wants it; already-shipped integer fields are untouched (N8).

**C — Shortest-round-trip IEEE strings** (the arch-translucency v0.23 profile). Already shipped, lossless for binary floats. Rejected for new fields: it encodes the binary float rather than the decimal quantity, has two spellings for integral values across languages, uses exponent form below `1e-4`, and requires every implementation to reproduce one specific shortest-round-trip algorithm. Grandfathered where shipped (N8).

**D — Allow floats in canonical-json@2 with an RFC 8785 (JCS) number serialisation.** Standardised, but reopens the frozen canonicaliser, forces a second canonical profile across six consumers, and still leaves rounding to producers. Rejected.

## Consequences

- Easier: a new numeric field is a schema line (pattern + precision) and hashes identically in Python, Rust and any future implementation.
- Easier: verifiers stay float-free, which keeps Layer 0 free of platform rounding.
- Harder: the family now has two decimal profiles on the wire until `training-run@2` / `energy-reading@2` exist. The grandfathered fields are named in the schemas so the difference stays visible.
- Harder: precision is a decision each schema author has to make and defend; there is no family default.
- Not changed: canonical-json@1, its vectors, every published content hash.

## Open points (for founder review)

1. **The grandfather clause covers more than the mandate named.** The mandate grandfathered "scaled-integer fields (training-run@1)". The shipped `training-run@1` and `energy-reading@1` energy fields are not scaled integers; they are `repr(float)` strings that violate N1 (`"840.0"`, `"1e-05"`). N8 grandfathers them explicitly. Alternative: retire and reissue as `@2` now. Not proposed here, because both producers are shipped and vectors are append-only.
2. **ikigov `gate_predicate_content_hash` hashes floats.** The preimage carries risk weights `1.0`/`1.5`/`2.0` through a canonicaliser that does not reject floats, so no canonical-json@1 implementation (this repo's Python or Rust) can recompute `framework_content_hash`. It is not a signed-payload field, so N8 does not list it. Recommendation: the next predicate-hash revision encodes weights as N1 decimal strings at precision 1 (`"1"`, `"1.5"`, `"2"`). Tracked as an ikigov follow-up, not done here.
3. **Precision values per field are not chosen here.** No current schema has an N1 field yet; the first new decimal field sets the precedent.
4. **The leading-zero and whitespace rules are an interpretation** of "plain notation". The mandate text does not forbid `"01.5"` explicitly; N1 does, so that each value has exactly one spelling.

## Action items

1. [x] Founder sign-off on N1–N8 (Accepted 2026-10-18).
2. [x] Reference encoder/validator, `vectors/numeric-encoding/`, Python and Rust conformance (this PR).
3. [ ] arch-translucency: adopt N1–N7 when `training-run@2` / `energy-reading@2` are cut; until then, nothing changes on its wire.
4. [ ] ikigov-assess: predicate-hash preimage without floats (open point 2).
