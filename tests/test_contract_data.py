"""The contract trees ship with the package and resolve in every install mode."""

from __future__ import annotations

import json
import pathlib

import pytest

import presidio_evidence
from presidio_evidence import (
    EvidenceError,
    _contract,
    load_schema,
    schema_ids,
    schemas_dir,
    vectors_dir,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_source_checkout_resolves_to_repo_root():
    assert pathlib.Path(str(schemas_dir())) == ROOT / "schemas"
    assert pathlib.Path(str(vectors_dir())) == ROOT / "vectors"


def test_schema_ids_match_the_tree():
    expected = sorted(
        "presidio-hardened/{}@{}".format(*p.name.removesuffix(".schema.json").rsplit(".v", 1))
        for p in (ROOT / "schemas").glob("*.schema.json")
    )
    assert list(schema_ids()) == expected
    assert "presidio-hardened/evidence-ref@2" in schema_ids()


@pytest.mark.parametrize("schema_id", schema_ids())
def test_load_schema_returns_the_file(schema_id):
    name, major = schema_id.split("/")[1].split("@")
    path = ROOT / "schemas" / f"{name}.v{major}.schema.json"
    assert load_schema(schema_id) == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "bad",
    [
        "presidio-hardened/evidence-ref@99",
        "presidio-hardened/../evidence-ref@1",
        "other/evidence-ref@1",
        "presidio-hardened/evidence-ref@0",
        "",
        None,
    ],
)
def test_load_schema_fails_closed(bad):
    with pytest.raises(EvidenceError):
        load_schema(bad)


def test_packaged_tree_is_preferred(tmp_path, monkeypatch):
    pkg = tmp_path / "presidio_evidence"
    (pkg / "_contract" / "schemas").mkdir(parents=True)
    monkeypatch.setattr(_contract.resources, "files", lambda _name: pkg)
    assert schemas_dir() == pkg / "_contract" / "schemas"


def test_missing_tree_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(_contract.resources, "files", lambda _name: tmp_path)
    monkeypatch.setattr(_contract, "__file__", str(tmp_path / "a" / "b" / "_contract.py"))
    with pytest.raises(EvidenceError, match="not found"):
        vectors_dir()


def test_exported():
    for name in ("schemas_dir", "vectors_dir", "schema_ids", "load_schema"):
        assert name in presidio_evidence.__all__
