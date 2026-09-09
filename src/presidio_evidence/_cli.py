"""``presidio-evidence`` command line (ADR-0001 D4): ``verify`` exits 0/1.

``verify`` checks every ref in an evidence envelope against a trust store and
exits **0 only if every ref verifies**, else **1** — including on any malformed
input, unknown signer, or unreadable file (fail-closed, never fail-open).
A ref that declares an ``optimistic`` / ``zk`` assurance tier (ADR-0003) is
*unverified-by-this-verifier*: this CLI only knows how to check signature
attestations, so per ADR-0003 D6 it fails closed on those tiers even when the
signature itself is valid.

``keygen`` (D3 generation helper) writes a fresh Ed25519 private key to a new
``0600`` file and prints only the public half — never the private key.
Argument errors exit 2 (argparse convention).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ._constants import DEFAULT_ASSURANCE_TIER
from ._errors import EvidenceError
from ._keys import generate_ed25519_keypair, write_private_key
from ._refs import load_evidence, load_trust_store, verify_ref

EXIT_OK = 0
EXIT_FAIL = 1


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc.strerror or exc}") from exc


def cmd_verify(args: argparse.Namespace) -> int:
    refs = load_evidence(_read_text(args.envelope))
    trust = load_trust_store(_read_text(args.trust))
    if not refs:
        print("FAIL: envelope carries no evidence refs", file=sys.stderr)
        return EXIT_FAIL
    ok = True
    for ref in refs:
        if ref.tier != DEFAULT_ASSURANCE_TIER:
            ok = False
            print(
                f"FAIL {ref.item_id} {ref.signer}: assurance tier {ref.tier!r} "
                "is not verifiable by this verifier (signature attestation only)",
                file=sys.stderr,
            )
        elif verify_ref(ref, trust):
            print(f"ok   {ref.item_id} {ref.signer}")
        else:
            ok = False
            print(f"FAIL {ref.item_id} {ref.signer}: signature not verified", file=sys.stderr)
    return EXIT_OK if ok else EXIT_FAIL


def cmd_keygen(args: argparse.Namespace) -> int:
    private_hex, public_hex = generate_ed25519_keypair()
    write_private_key(args.out, private_hex)
    if args.signer:
        print(json.dumps({args.signer: {"alg": "ed25519", "public_key": public_hex}}, indent=2))
    else:
        print(public_hex)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="presidio-evidence",
        description="presidio-hardened evidence substrate: fail-closed verify + key helpers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify every ref in an envelope; exit 0 iff all verify")
    verify.add_argument("envelope", help="evidence-ref@1/@2 envelope JSON file")
    verify.add_argument("--trust", required=True, help="trust-store@1 JSON file")
    verify.set_defaults(func=cmd_verify)

    keygen = sub.add_parser(
        "keygen", help="generate an Ed25519 keypair; private key to a new 0600 file"
    )
    keygen.add_argument("--out", required=True, help="path for the private key (must not exist)")
    keygen.add_argument(
        "--signer", help="if given, print a trust-store@1 entry for this signer id instead"
    )
    keygen.set_defaults(func=cmd_keygen)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
