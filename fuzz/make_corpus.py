# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Write a seed corpus for the fuzz harness from the published vectors.

Each vector file is seeded as-is, and its ``document`` member (the envelope
in the invalid-case vectors) is seeded on its own, so the fuzzer starts from
real envelopes instead of random bytes.

Usage: ``python fuzz/make_corpus.py <corpus-dir>``
"""

import hashlib
import json
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


def seeds() -> list[bytes]:
    out: list[bytes] = []
    for path in sorted(VECTORS.rglob("*.json")):
        raw = path.read_bytes()
        out.append(raw)
        doc = json.loads(raw)
        if isinstance(doc, dict) and isinstance(doc.get("document"), dict):
            out.append(json.dumps(doc["document"]).encode())
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: make_corpus.py <corpus-dir>", file=sys.stderr)
        return 2
    target = Path(argv[1])
    target.mkdir(parents=True, exist_ok=True)
    written = 0
    for seed in seeds():
        name = hashlib.sha256(seed).hexdigest()[:16]
        (target / name).write_bytes(seed)
        written += 1
    print(f"wrote {written} seeds to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
