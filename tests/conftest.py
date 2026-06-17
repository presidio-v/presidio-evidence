"""Shared fixtures: repo paths, schema loaders, and the canonicalizer.

The Q4 extraction (ADR-0001 action item 5) has landed: the reference
canonicalizer now *is* the library — ``canonical_bytes`` is re-exported from
:mod:`presidio_evidence` so the Layer-0 conformance tests exercise the shipped
implementation, and must keep passing unchanged.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from presidio_evidence import canonical_bytes  # noqa: F401  (re-exported for tests)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "vectors"


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def evidence_ref_schema() -> dict:
    return load_json(SCHEMAS / "evidence-ref.v1.schema.json")


@pytest.fixture(scope="session")
def trust_store_schema() -> dict:
    return load_json(SCHEMAS / "trust-store.v1.schema.json")
