"""Public catalogue of electoral districts.

The catalogue is public data (names and codes), not the voter registry. Keeping it in
a packaged file means the admin interface can offer a district picker **without** any
access to the registry store — the separation from docs/01 T3 is structural, not a
matter of discipline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class CatalogueEntry:
    code: str
    name: str
    level: str
    parent: str | None


@lru_cache(maxsize=1)
def entries() -> tuple[CatalogueEntry, ...]:
    resource = resources.files("fairvote").joinpath("data/districts.json")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    return tuple(
        CatalogueEntry(
            code=item["code"],
            name=item["name"],
            level=item["level"],
            parent=item.get("parent"),
        )
        for item in payload["districts"]
    )


def districts() -> list[CatalogueEntry]:
    """Only single-mandate districts: the level a vote is cast in."""
    return [entry for entry in entries() if entry.level == "district"]


def name_of(code: str) -> str:
    for entry in entries():
        if entry.code == code:
            return entry.name
    return code
