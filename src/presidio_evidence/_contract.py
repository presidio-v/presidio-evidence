"""The contract artefacts — ``schemas/`` and ``vectors/`` — shipped with the package.

The README's thesis is that the contract is ``schemas/`` + ``vectors/``, not the
code, so an installed package carries them: a consumer can validate against the
normative schema and run the golden vectors without cloning this repository.

In a wheel they live under ``presidio_evidence/_contract/``. In a source checkout
or an editable install they are read from the repository root, so tests and
tools see one tree either way.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from ._errors import EvidenceError

#: ``presidio-hardened/<name>@<major>`` → ``schemas/<name>.v<major>.schema.json``.
_SCHEMA_ID_RE = re.compile(r"presidio-hardened/([a-z][a-z0-9-]{0,63})@([1-9][0-9]{0,2})")


def _tree(name: str) -> Traversable:
    packaged = resources.files("presidio_evidence") / "_contract" / name
    if packaged.is_dir():
        return packaged
    source = Path(__file__).resolve().parents[2] / name
    if source.is_dir():
        return source
    raise EvidenceError(f"contract tree '{name}' not found in the installed package")


def schemas_dir() -> Traversable:
    """The ``schemas/`` tree (JSON Schemas, normative)."""
    return _tree("schemas")


def vectors_dir() -> Traversable:
    """The ``vectors/`` tree (golden test vectors, append-only)."""
    return _tree("vectors")


def schema_ids() -> tuple[str, ...]:
    """Every shipped schema id, sorted (``presidio-hardened/<name>@<major>``)."""
    ids = []
    for entry in schemas_dir().iterdir():
        match = re.fullmatch(r"([a-z][a-z0-9-]*)\.v([1-9][0-9]*)\.schema\.json", entry.name)
        if match:
            ids.append(f"presidio-hardened/{match.group(1)}@{match.group(2)}")
    return tuple(sorted(ids))


def load_schema(schema_id: str) -> dict:
    """The JSON Schema for ``schema_id``; fails closed on an unknown id."""
    match = _SCHEMA_ID_RE.fullmatch(schema_id) if isinstance(schema_id, str) else None
    if match is None:
        raise EvidenceError(f"not a presidio-hardened schema id: {schema_id!r}")
    entry = schemas_dir() / f"{match.group(1)}.v{match.group(2)}.schema.json"
    if not entry.is_file():
        raise EvidenceError(f"no shipped schema for {schema_id!r}")
    return json.loads(entry.read_text(encoding="utf-8"))
