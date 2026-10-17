"""Refresh backend/data/rdap_dns.json: IANA's map of TLD -> RDAP server (used by the new_domain rule).

Run from the repo root: python scripts/update_rdap_bootstrap.py
"""
import json
import urllib.request
from pathlib import Path

URL = "https://data.iana.org/rdap/dns.json"
OUT = Path(__file__).resolve().parent.parent / "backend" / "data" / "rdap_dns.json"

data = json.load(urllib.request.urlopen(URL, timeout=30))
if not data.get("services"):
    raise SystemExit("Unexpected bootstrap file: no services")
OUT.write_text(json.dumps(data, indent=1), encoding="utf-8")
tlds = sum(len(service[0]) for service in data["services"])
print(f"Wrote {OUT} (publication {data.get('publication')}, {tlds} TLDs)")
