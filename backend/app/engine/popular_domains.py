"""The Tranco top-1M list of popular registrable domains (refresh with scripts/update_tranco.py).

Loaded once per process (~1.5 s, ~120 MB) and shared by every rule that asks for it.
"""

import gzip
from functools import lru_cache
from pathlib import Path

from app.config import BACKEND_ROOT

POPULAR_DOMAINS_FILE = BACKEND_ROOT / "data" / "tranco_top_1m.txt.gz"


@lru_cache(maxsize=4)
def load_ranked_domains(path: Path = POPULAR_DOMAINS_FILE) -> tuple[str, ...]:
    """Domains in rank order (index 0 = most popular)."""
    with gzip.open(path, "rt", encoding="ascii") as f:
        return tuple(line for line in f.read().split("\n") if line)


@lru_cache(maxsize=8)
def top_domains(path: Path = POPULAR_DOMAINS_FILE, limit: int | None = None) -> frozenset[str]:
    """The `limit` most popular domains (all of them if None)."""
    return frozenset(load_ranked_domains(path)[:limit])
