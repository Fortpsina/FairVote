#!/usr/bin/env python3
"""Vendor libsodium.js from the npm registry, with pins and integrity checks.

Why vendored at all: ``crypto_box_seal`` needs X25519 + XSalsa20-Poly1305, and
WebCrypto has no XSalsa20. The library is served from our own origin (no CDN), its
version and SHA-256 are pinned, and this script makes the step reproducible and
auditable (docs/05 D-1).

Usage::

    python tools/vendor_libsodium.py --verify   # check the files against vendor.lock
    python tools/vendor_libsodium.py --update   # re-download, verify, rewrite the lock

Only the standard library is used, so the script runs anywhere the project runs.
The two files are classic global scripts (not ES modules): the core exposes
``libsodium``, the wrapper replaces it with the friendlier ``sodium`` API, which is
why the page loads them in that exact order.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = ROOT / "fairvote" / "web" / "static" / "vendor"
LOCK_FILE = VENDOR_DIR / "vendor.lock"

PACKAGES = (
    {
        # The "sumo" build is used because passphrase-derived ballot secrets need
        # crypto_pwhash (Argon2id), which the standard build does not ship. It costs
        # ~300 KB more and is still served from our own origin.
        "path": "libsodium.js",
        "package": "libsodium-sumo",
        "version": "0.7.15",
        "member": "package/dist/modules-sumo/libsodium-sumo.js",
    },
    {
        "path": "libsodium-wrappers.js",
        "package": "libsodium-wrappers-sumo",
        "version": "0.7.15",
        "member": "package/dist/modules-sumo/libsodium-wrappers.js",
    },
)

REGISTRY = "https://registry.npmjs.org/{package}/-/{package}-{version}.tgz"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def extract_member(tarball: bytes, member: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        handle = archive.extractfile(member)
        if handle is None:
            raise SystemExit(f"member {member!r} not found in the tarball")
        return handle.read()


def read_lock() -> dict:
    if not LOCK_FILE.exists():
        return {"files": []}
    return json.loads(LOCK_FILE.read_text(encoding="utf-8"))


def verify() -> int:
    lock = read_lock()
    if not lock.get("files"):
        print("no vendor.lock: run --update first", file=sys.stderr)
        return 2
    failures = 0
    for entry in lock["files"]:
        path = VENDOR_DIR / entry["path"]
        if not path.exists():
            print(f"MISSING {entry['path']}", file=sys.stderr)
            failures += 1
            continue
        actual = sha256_hex(path.read_bytes())
        if actual != entry["sha256"]:
            print(
                f"CHANGED {entry['path']}: {actual} != {entry['sha256']}",
                file=sys.stderr,
            )
            failures += 1
        else:
            print(f"ok {entry['path']} {entry['package']}@{entry['version']}")
    return 1 if failures else 0


def update() -> int:
    previous = {entry["path"]: entry for entry in read_lock().get("files", [])}
    entries = []
    for spec in PACKAGES:
        url = REGISTRY.format(package=spec["package"], version=spec["version"])
        tarball = fetch(url)
        data = extract_member(tarball, spec["member"])
        target = VENDOR_DIR / spec["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        digest = sha256_hex(data)
        old = previous.get(spec["path"])
        if old and old.get("sha256") != digest:
            print(
                f"WARNING: {spec['path']} changed since the last lock "
                f"({old.get('sha256')} -> {digest})",
                file=sys.stderr,
            )
        entries.append(
            {
                **spec,
                "tarball": url,
                "tarball_sha256": sha256_hex(tarball),
                "sha256": digest,
                "bytes": len(data),
            }
        )
        print(f"vendored {spec['path']} ({len(data)} bytes, sha256 {digest})")

    lock = {
        "note": (
            "Pinned browser assets. Load libsodium.js before libsodium-wrappers.js. "
            "Regenerate with: python tools/vendor_libsodium.py --update"
        ),
        "libsodium_version": "1.0.20",
        "files": entries,
    }
    LOCK_FILE.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {LOCK_FILE.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", action="store_true", help="check files against the lock")
    group.add_argument("--update", action="store_true", help="download and rewrite the lock")
    args = parser.parse_args(argv)
    return verify() if args.verify else update()


if __name__ == "__main__":
    sys.exit(main())
