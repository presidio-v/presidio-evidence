"""Conformance for the ADR-0005 numeric payload encoding.

``vectors/numeric-encoding/vectors.json`` is the contract: hand-written accept /
reject cases for the verifier, input -> output pairs for the producer, and inputs
the producer must refuse. The reference functions in :mod:`presidio_evidence`
must agree with every case, and the JSON Schema pattern a schema embeds for a
decimal field must agree with the validator.
"""

from __future__ import annotations

import re
from decimal import Decimal

import pytest
from conftest import VECTORS, load_json

from presidio_evidence import (
    DECIMAL_STRING_MAX_LEN,
    UNBOUNDED_SENTINEL,
    EvidenceError,
    canonical_bytes,
    decimal_pattern,
    encode_decimal,
    is_decimal_string,
)

DOC = load_json(VECTORS / "numeric-encoding" / "vectors.json")
VALIDATE = DOC["validate"]
ENCODE = DOC["encode"]
ENCODE_REJECTED = DOC["encode_rejected"]


@pytest.mark.parametrize("case", VALIDATE, ids=lambda c: c["name"])
def test_validate_vectors(case: dict) -> None:
    got = is_decimal_string(
        case["value"], precision=case["precision"], sentinels=case.get("sentinels", ())
    )
    assert got is case["valid"], case["reason"]


@pytest.mark.parametrize("case", VALIDATE, ids=lambda c: c["name"])
def test_schema_pattern_agrees_with_validator(case: dict) -> None:
    """A schema that embeds decimal_pattern(p) accepts exactly what the validator
    accepts (sentinels aside: a schema adds those as a separate const)."""
    if case.get("sentinels") or not isinstance(case["value"], str):
        pytest.skip("sentinel or non-string case: not a pattern question")
    value = case["value"]
    if len(value) > DECIMAL_STRING_MAX_LEN:
        pytest.skip("length is a maxLength question, not a pattern question")
    # JSON Schema patterns are ECMA-262; '$' does not match before a trailing
    # newline there, so test with fullmatch to keep the same semantics.
    pattern = decimal_pattern(case["precision"]).removeprefix("^").removesuffix("$")
    assert (re.fullmatch(pattern, value) is not None) is case["valid"], case["reason"]


@pytest.mark.parametrize("case", ENCODE, ids=lambda c: f"{c['input']}@{c['precision']}")
def test_encode_vectors(case: dict) -> None:
    encoded = encode_decimal(case["input"], precision=case["precision"])
    assert encoded == case["expected"]
    # What the producer emits, the verifier accepts.
    assert is_decimal_string(encoded, precision=case["precision"])


@pytest.mark.parametrize("case", ENCODE_REJECTED, ids=lambda c: c["input"])
def test_encode_rejected_vectors(case: dict) -> None:
    with pytest.raises(EvidenceError):
        encode_decimal(case["input"], precision=6)


def test_encoded_strings_are_canonical_json_strings() -> None:
    """The encoded value hashes like any string: canonical-json@1 is unchanged."""
    payload = {"energy": encode_decimal(Decimal("0.00001"), precision=6)}
    assert canonical_bytes(payload) == b'{"energy":"0.00001"}'


def test_encode_accepts_decimal_and_int() -> None:
    assert encode_decimal(Decimal("2.675"), precision=2) == "2.68"
    assert encode_decimal(Decimal("2.665"), precision=2) == "2.66"
    assert encode_decimal(-7, precision=0) == "-7"
    assert encode_decimal(" 1.5 ", precision=1) == "1.5"


@pytest.mark.parametrize("bad", [1.5, float("nan"), True, None, [1], b"1"])
def test_encode_rejects_floats_bools_and_other_types(bad: object) -> None:
    with pytest.raises(EvidenceError):
        encode_decimal(bad, precision=2)  # type: ignore[arg-type]


def test_encode_fails_closed_past_the_family_string_bound() -> None:
    with pytest.raises(EvidenceError, match="string bound"):
        encode_decimal(Decimal("1e600"), precision=0)


@pytest.mark.parametrize("bad", [-1, True, 1.0, "2", None])
def test_precision_must_be_a_non_negative_int(bad: object) -> None:
    with pytest.raises(EvidenceError):
        is_decimal_string("1", precision=bad)  # type: ignore[arg-type]
    with pytest.raises(EvidenceError):
        encode_decimal("1", precision=bad)  # type: ignore[arg-type]
    with pytest.raises(EvidenceError):
        decimal_pattern(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["1e3", "-inf", "Unbounded", "", 5])
def test_sentinel_declarations_cannot_collide_with_numbers(bad: object) -> None:
    with pytest.raises(EvidenceError):
        is_decimal_string("1", precision=2, sentinels=(bad,))  # type: ignore[arg-type]


def test_recommended_sentinel_is_a_valid_declaration() -> None:
    assert DOC["max_length"] == DECIMAL_STRING_MAX_LEN
    assert UNBOUNDED_SENTINEL == DOC["recommended_unbounded_sentinel"]
    assert is_decimal_string(UNBOUNDED_SENTINEL, precision=0, sentinels=(UNBOUNDED_SENTINEL,))


def test_validator_never_parses_to_float(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifiers compare these strings byte-wise (ADR-0005). Make float() explode
    and the validator must still answer every vector."""
    import builtins

    def no_float(*_: object) -> float:
        raise AssertionError("verifier parsed a decimal string to float")

    monkeypatch.setattr(builtins, "float", no_float)
    for case in VALIDATE:
        is_decimal_string(
            case["value"], precision=case["precision"], sentinels=case.get("sentinels", ())
        )


def test_precision_zero_pattern() -> None:
    assert decimal_pattern(0) == "^(0|-?[1-9][0-9]*)$"


def test_grandfathered_training_run_energy_strings_fail_the_new_rule() -> None:
    """ADR-0005 grandfathers training-run@1 energy_wh / mean_power_w. Their
    shipped IEEE round-trip form ("840.0") is NOT an ADR-0005 decimal string;
    this pins that the grandfather clause is load-bearing, not cosmetic."""
    notes = load_json(VECTORS / "training-run" / "valid-envelope-energy.notes.json")
    for field in ("energy_wh", "mean_power_w"):
        assert not is_decimal_string(notes["signed_content"][field], precision=6)
