"""Downloads the latest Tranco top-1M list into backend/data/.

Tranco (https://tranco-list.eu) is a research-grade ranking of popular domains, aggregated from
several sources and hardened against manipulation. The lookalike_domain rule uses it to decide
whether a de-obfuscated domain (paypa1.com -> paypal.com) is a well-known site.

Usage (from the repo root):  backend/.venv/Scripts/python scripts/update_tranco.py
Writes:
  backend/data/tranco_top_1m.txt.gz   one registrable domain per line, rank order
  backend/data/tranco_top_1m.json     list id and date (Tranco asks users to cite the list id)
"""

import csv
import gzip
import io
import json
import urllib.request
from pathlib import Path

LATEST_API = "https://tranco-list.eu/api/lists/date/latest"
DATA_DIR = Path(__file__).resolve().parent.parent / "backend" / "data"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def main() -> None:
    meta = json.loads(fetch(LATEST_API))
    rows = csv.reader(io.StringIO(fetch(meta["download"]).decode("ascii")))
    domains = [domain.strip().lower() for _, domain in rows]

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with gzip.open(DATA_DIR / "tranco_top_1m.txt.gz", "wt", encoding="ascii", compresslevel=9) as f:
        f.write("\n".join(domains))
    (DATA_DIR / "tranco_top_1m.json").write_text(
        json.dumps(
            {
                "source": "Tranco, https://tranco-list.eu",
                "list_id": meta["list_id"],
                "created_on": meta["created_on"],
                "permalink": f"https://tranco-list.eu/list/{meta['list_id']}",
                "domains": len(domains),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Saved {len(domains):,} domains from Tranco list {meta['list_id']} ({meta['created_on'][:10]})")


if __name__ == "__main__":
    main()
