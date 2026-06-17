"""Layer 0 — strict canonical JSON and SHA-256 content addressing (ADR-0001 D1).

The canonical encoding is the wire format every producer and consumer must
reproduce byte-for-byte (proved by ``vectors/canonical-json/``): keys sorted,
``(",", ":")`` separators, UTF-8 (not ASCII-escaped), and **floats rejected**
(the strict profile originating in treasury). This module is dependency-free.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _reject_floats(payload: Any) -> None:
    """Recursively reject floats anywhere in ``payload`` (strict profile)."""
    if isinstance(payload, float):
        raise ValueError("floats are not permitted in canonical payloads (strict profile)")
    if isinstance(payload, dict):
        for key, value in payload.items():
            _reject_floats(key)
            _reject_floats(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _reject_floats(value)


def canonical_bytes(payload: Any) -> bytes:
    """Return the Layer-0 strict canonical JSON encoding of ``payload``.

    Sorted keys, compact separators, UTF-8 preserved, floats/NaN rejected. The
    result is the exact byte sequence content hashes and signatures are computed
    over.
    """
    _reject_floats(payload)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def content_hash(payload: Any) -> str:
    """SHA-256 (lowercase hex) over the canonical encoding of ``payload``."""
    return sha256_hex(canonical_bytes(payload))
