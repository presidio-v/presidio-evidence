"""Shared fixtures: repo paths, schema loaders, and the reference canonicalizer.

The reference canonicalizer lives in test code on purpose — conformance tests
exist before library code (ADR-0001). When the Q4 extraction lands, the library
implementation must make these same tests pass unchanged.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "vectors"


def canonical_bytes(payload: Any) -> bytes:
    """Layer-0 strict canonical JSON (ADR-0001 D1): floats rejected."""
    _reject_floats(payload)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_floats(payload: Any) -> None:
    if isinstance(payload, float):
        raise ValueError("floats are not permitted in canonical payloads (strict profile)")
    if isinstance(payload, dict):
        for key, value in payload.items():
            _reject_floats(key)
            _reject_floats(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _reject_floats(value)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def evidence_ref_schema() -> dict:
    return load_json(SCHEMAS / "evidence-ref.v1.schema.json")


@pytest.fixture(scope="session")
def trust_store_schema() -> dict:
    return load_json(SCHEMAS / "trust-store.v1.schema.json")
