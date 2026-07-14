"""The Layer-0 reading-type registry (PR #14 maintainer decision 5, 2026-07-13).

Before this, reserving a reading type meant touching five places with nothing
tying them together — the generator, PRESIDIO-REQ, vectors/README, and both test
lanes — so a type could be added in one and forgotten in another with a green
build. ``LAYER0_READING_SCHEMA_IDS`` is the single list; these tests are what
make it load-bearing rather than decorative.

Three independent derivations of "which reading types exist" must agree exactly:

1. the declared constant,
2. what ``scripts/generate_vectors.py`` actually builds, and
3. what is committed on disk under ``vectors/``.

Any two agreeing while the third drifts is the bug this catches.
"""

from __future__ import annotations

import importlib.util
import json

from conftest import ROOT, VECTORS

from presidio_evidence import LAYER0_READING_SCHEMA_IDS


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_vectors", ROOT / "scripts" / "generate_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema_ids_from_generator() -> set[str]:
    """Every layer0_reading.schema the generator emits."""
    gen = _load_generator()
    return {
        obj["layer0_reading"]["schema"]
        for obj in gen.build().values()
        if isinstance(obj, dict) and "layer0_reading" in obj
    }


def _schema_ids_from_vectors_tree() -> set[str]:
    """Every layer0_reading.schema committed under vectors/."""
    ids: set[str] = set()
    for path in VECTORS.rglob("*.notes.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        reading = doc.get("layer0_reading")
        if isinstance(reading, dict) and "schema" in reading:
            ids.add(reading["schema"])
    return ids


def test_constant_matches_the_generator() -> None:
    assert set(LAYER0_READING_SCHEMA_IDS) == _schema_ids_from_generator()


def test_constant_matches_the_committed_vectors_tree() -> None:
    assert set(LAYER0_READING_SCHEMA_IDS) == _schema_ids_from_vectors_tree()


def test_registry_is_sorted_and_free_of_duplicates() -> None:
    """Deterministic order, so the Rust mirror and this tuple can be compared by
    eye and a duplicate cannot hide behind set semantics."""
    assert list(LAYER0_READING_SCHEMA_IDS) == sorted(LAYER0_READING_SCHEMA_IDS)
    assert len(set(LAYER0_READING_SCHEMA_IDS)) == len(LAYER0_READING_SCHEMA_IDS)


def test_every_id_is_a_presidio_hardened_versioned_schema_id() -> None:
    for schema_id in LAYER0_READING_SCHEMA_IDS:
        assert schema_id.startswith("presidio-hardened/")
        assert "@" in schema_id


def test_energy_reading_is_registered() -> None:
    """The reservation this PR exists for."""
    assert "presidio-hardened/energy-reading@1" in LAYER0_READING_SCHEMA_IDS


def test_manifests_are_not_readings() -> None:
    """workshop-leavebehind@1 is an owner-signed manifest, not a Layer-0 reading
    under an evidence-ref envelope — it has no layer0_reading block, so it must
    not appear in the reading registry. Guards the boundary the registry draws."""
    assert "presidio-hardened/workshop-leavebehind@1" not in LAYER0_READING_SCHEMA_IDS
    assert "treasury-close/checkpoint/v1" not in LAYER0_READING_SCHEMA_IDS
