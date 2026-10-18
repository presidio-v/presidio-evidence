"""Numeric payload encoding — decimal strings in plain notation (ADR-0005).

canonical-json@1 rejects floats (ADR-0001 D1), so a non-integer quantity in a
signed payload travels as a string. ADR-0005 fixes *which* string: plain
notation, no exponent, no trailing zeros, no trailing point, optional leading
``-``, at least one digit before the point, no leading zeros, and no negative
zero. With one spelling per value, two producers that agree on the number agree
on the content hash.

Two sides, kept apart on purpose:

* :func:`encode_decimal` is the **producer** side. It rounds half-even to the
  field's declared precision and emits the one canonical spelling. NaN and
  ±Infinity are rejected; a Python ``float`` is rejected too, because the
  caller, not this function, decides how a binary float becomes a decimal.
* :func:`is_decimal_string` is the **verifier** side. It checks the spelling
  character by character and never converts to float, so verification cannot
  depend on a platform's binary rounding. Comparison and hashing stay
  byte-wise.

Stdlib only, like the rest of Layer 0.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from decimal import ROUND_HALF_EVEN, Context, Decimal, InvalidOperation

from ._errors import EvidenceError

#: Family bound on any string field (ADR-0001 D1, ``evidence-ref@1``).
DECIMAL_STRING_MAX_LEN = 512

#: The recommended sentinel spelling for an unbounded value (ADR-0005). A schema
#: that needs one declares it explicitly; nothing here accepts it by default.
UNBOUNDED_SENTINEL = "unbounded"

# ASCII digits only: ``\d`` would also match non-ASCII digits such as U+FF11.
_DECIMAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.([0-9]*[1-9]))?")

# A sentinel starts with a lowercase letter, so it can never be read as a
# decimal string (which starts with a digit or '-').
_SENTINEL_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")


def _check_precision(precision: object) -> int:
    if isinstance(precision, bool) or not isinstance(precision, int) or precision < 0:
        raise EvidenceError("precision must be a non-negative integer")
    return precision


def _check_sentinels(sentinels: Iterable[str]) -> frozenset[str]:
    declared = frozenset(sentinels)
    for sentinel in declared:
        if not isinstance(sentinel, str) or not _SENTINEL_RE.fullmatch(sentinel):
            raise EvidenceError("a sentinel must be a lowercase word that cannot parse as a number")
    return declared


def decimal_pattern(precision: int) -> str:
    """The JSON Schema ``pattern`` for a decimal-string field of ``precision``.

    Schemas embed this for each decimal field together with the annotation
    ``"x-decimal-precision": precision``. ``-0`` is excluded by the pattern
    itself (the negative-zero rule, ADR-0005).
    """
    p = _check_precision(precision)
    nonzero_int = "[1-9][0-9]*"
    if p == 0:
        return f"^(0|-?{nonzero_int})$"
    frac = f"\\.[0-9]{{0,{p - 1}}}[1-9]"
    return f"^(0|-?{nonzero_int}|-?(0|{nonzero_int}){frac})$"


def is_decimal_string(value: object, *, precision: int, sentinels: Iterable[str] = ()) -> bool:
    """True iff ``value`` is a canonical ADR-0005 decimal string within ``precision``.

    ``sentinels`` lists the schema-declared non-numeric spellings the field
    admits (e.g. ``("unbounded",)``); none are admitted by default. Fails
    closed: a non-string, a bool, an over-long string, an exponent, a trailing
    zero, a leading zero, a ``+`` sign, surrounding whitespace, ``-0`` and the
    IEEE specials all return False. Never parses to float.
    """
    p = _check_precision(precision)
    declared = _check_sentinels(sentinels)
    if not isinstance(value, str) or len(value) > DECIMAL_STRING_MAX_LEN:
        return False
    if value in declared:
        return True
    match = _DECIMAL_RE.fullmatch(value)
    if match is None or value == "-0":
        return False
    fraction = match.group(1)
    return fraction is None or len(fraction) <= p


def encode_decimal(value: Decimal | int | str, *, precision: int) -> str:
    """Encode ``value`` as the canonical ADR-0005 decimal string.

    Rounds half-even to ``precision`` fractional digits, then drops trailing
    zeros and a trailing point. A value that rounds to zero encodes as ``"0"``,
    whatever its sign. Accepts :class:`~decimal.Decimal`, ``int``, or a numeric
    string (any spelling ``Decimal`` parses, e.g. ``"1e-05"``). Raises
    :class:`EvidenceError` on NaN, ±Infinity, a ``float``, a ``bool``, or a
    result longer than the family string bound.
    """
    p = _check_precision(precision)
    if isinstance(value, bool) or isinstance(value, float):
        raise EvidenceError(
            "encode_decimal takes Decimal, int, or str; convert a float explicitly "
            "(e.g. Decimal(repr(x))) so the binary-to-decimal step is the caller's decision"
        )
    if not isinstance(value, (Decimal, int, str)):
        raise EvidenceError(f"cannot encode {type(value).__name__} as a decimal string")
    try:
        number = Decimal(value) if not isinstance(value, str) else Decimal(value.strip())
    except InvalidOperation as exc:
        raise EvidenceError("value is not a decimal number") from exc
    if not number.is_finite():
        raise EvidenceError("NaN and Infinity have no decimal encoding (ADR-0005)")
    # Enough working precision for every integer digit plus the fractional
    # digits kept, so quantize never runs out of coefficient room.
    digits = max(number.adjusted() + 1, 1) + p + 1
    ctx = Context(prec=digits, rounding=ROUND_HALF_EVEN)
    rounded = number.quantize(Decimal(1).scaleb(-p), context=ctx)
    if rounded.is_zero():
        return "0"
    text = format(rounded, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if len(text) > DECIMAL_STRING_MAX_LEN:
        raise EvidenceError("encoded decimal exceeds the family string bound")
    return text
