#!/usr/bin/env python3
"""Regenerate ``fairvote/web/static/manifest.json``.

Run this after any change to static assets (including vendoring a new libsodium):
the manifest hash is committed into the audit chain at poll start, so a stale
manifest means the published hash describes files that are no longer served.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fairvote import assets  # noqa: E402  (path bootstrap above)


def main() -> int:
    document = assets.write()
    print(f"files: {len(document['files'])}")
    for name, digest in document["files"].items():
        print(f"  {digest}  {name}")
    print(f"manifest_hash: {document['manifest_hash']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
