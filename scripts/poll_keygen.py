#!/usr/bin/env python3
"""Generate a poll key pair — run this offline.

The private key must never reach the server before the poll closes: it is the only
thing that keeps ballots secret from whoever runs the platform (docs/05 D-4).

Usage::

    python scripts/poll_keygen.py --out ./keys --poll <poll-uuid>

Writes ``<poll>.pub.json`` and ``<poll>.priv.json`` (mode 0600) and prints the
fingerprint that must match the one published in the audit log. Use
``--shamir N`` to be told, loudly, that threshold splitting is not implemented in
this build rather than to get a silent single key.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fairvote.security import crypto  # noqa: E402  (path bootstrap above)


def write_private(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="directory for the keys")
    parser.add_argument("--poll", required=True, help="poll id this key belongs to")
    parser.add_argument(
        "--shamir",
        type=int,
        default=0,
        help="threshold sharing of the private key (not implemented in this build)",
    )
    args = parser.parse_args(argv)

    if args.shamir:
        print(
            "error: threshold sharing (Shamir) is not implemented in this build.\n"
            "       Refusing to produce a silently non-shared key — see docs/04 Q5.",
            file=sys.stderr,
        )
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    private_key, public_key = crypto.x25519_keypair()
    fingerprint = crypto.blake2b_hex(public_key)

    public_document = {
        "poll": args.poll,
        "alg": "x25519-xsalsa20-poly1305",
        "public_key": public_key.hex(),
        "fingerprint": fingerprint,
    }
    private_document = {
        "warning": (
            "OFFLINE ONLY. Never upload before the poll closes: it decrypts every "
            "ballot. Publish it only after the close, as the protocol requires."
        ),
        "poll": args.poll,
        "public_key": public_key.hex(),
        "private_key": private_key.hex(),
        "fingerprint": fingerprint,
    }

    public_path = args.out / f"{args.poll}.pub.json"
    private_path = args.out / f"{args.poll}.priv.json"
    public_path.write_text(json.dumps(public_document, indent=2) + "\n", encoding="utf-8")
    write_private(private_path, private_document)

    print(f"public key:  {public_path}")
    print(f"private key: {private_path} (mode 0600, keep offline)")
    print(f"fingerprint: {fingerprint}")
    print(
        "Publish the fingerprint in an independent channel before the poll starts; "
        "the admin page will commit it to the audit log."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
