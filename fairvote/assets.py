"""Static asset manifest: what the browser will actually receive.

The transparency promise is that the JavaScript served to voters can be pinned: the
manifest lists a SHA-256 per file, its own hash is committed into the audit chain at
poll start (``js_manifest_hash``), and ``/manifest.json`` serves the same document.
A server that swaps a script after the start contradicts the published hash —
detectable, though not preventable (docs/01 N1).

The manifest is a build artefact: ``python tools/build_assets.py`` regenerates it.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from .security.canonical import dump_bytes

STATIC_DIR = Path(__file__).parent / "web" / "static"
MANIFEST_PATH = STATIC_DIR / "manifest.json"
INCLUDED_SUFFIXES = {".js", ".css", ".svg", ".png", ".ico", ".woff2"}
INCLUDED_NAMES = {"vendor.lock"}


def build(directory: Path = STATIC_DIR) -> dict:
    files: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "manifest.json":
            continue
        if path.suffix not in INCLUDED_SUFFIXES and path.name not in INCLUDED_NAMES:
            continue
        relative = path.relative_to(directory).as_posix()
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    document = {"v": 1, "files": files}
    document["manifest_hash"] = hashlib.sha256(dump_bytes(document)).hexdigest()
    return document


def write(directory: Path = STATIC_DIR) -> dict:
    document = build(directory)
    (directory / "manifest.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    return document


@lru_cache(maxsize=1)
def manifest() -> dict:
    """The committed manifest, or an empty one when the build step has not run."""
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"v": 1, "files": {}, "manifest_hash": ""}


def manifest_hash() -> str:
    return manifest().get("manifest_hash", "")
