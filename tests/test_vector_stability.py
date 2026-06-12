"""Committed vectors must byte-match regeneration (append-only discipline, ADR-0001 D5)."""

from __future__ import annotations

import importlib.util
import json

from conftest import ROOT


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_vectors", ROOT / "scripts" / "generate_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_vectors_match_regeneration():
    gen = _load_generator()
    for path, obj in gen.build().items():
        assert path.exists(), f"missing vector file: {path}"
        on_disk = path.read_text(encoding="utf-8")
        assert on_disk == gen.render(obj), f"vector drifted: {path.relative_to(ROOT)}"


def test_all_vector_files_are_generated():
    """No orphan vectors: everything under vectors/ comes from the generator."""
    gen = _load_generator()
    generated = {p.resolve() for p in gen.build()}
    on_disk = {p.resolve() for p in (ROOT / "vectors").rglob("*.json")}
    assert on_disk == generated


def test_vectors_are_valid_json():
    for path in (ROOT / "vectors").rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
