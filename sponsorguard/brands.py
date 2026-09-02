"""Loads the known-sponsor brand list used by identity rules.

Kept as versioned JSON (data/brands.json), never hardcoded, because this list
is the main thing that goes stale and needs regular updates.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "brands.json"


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]   # legitimate registrable domains
    aliases: tuple[str, ...]   # display-name / body spellings, all lowercase


@lru_cache(maxsize=1)
def load_brands() -> list[Brand]:
    raw = json.loads(_DATA.read_text(encoding="utf-8"))
    brands = []
    for entry in raw:
        name = entry["name"]
        domains = tuple(d.lower() for d in entry.get("domains", []))
        aliases = tuple(a.lower() for a in entry.get("aliases", [])) or (name.lower(),)
        brands.append(Brand(name=name, domains=domains, aliases=aliases))
    return brands
