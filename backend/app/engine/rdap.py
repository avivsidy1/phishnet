"""Minimal RDAP client: when was a domain registered? Used by the new_domain rule.

RDAP is the official, structured successor to WHOIS. IANA publishes which registry serves each TLD
(data/rdap_dns.json, refreshed with scripts/update_rdap_bootstrap.py); we ask that registry directly,
over HTTPS only. Only the domain name is sent, to the registry that already holds that data.
Registration dates never change, so they are cached for days.
"""

import datetime
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.config import BACKEND_ROOT

logger = logging.getLogger(__name__)

BOOTSTRAP_FILE = BACKEND_ROOT / "data" / "rdap_dns.json"
# Some registries refuse Python's default user agent (seen: 403 from the .info registry).
USER_AGENT = "PhishNet/1.0 (email phishing checker; RDAP registration-date lookups)"
MAX_RESPONSE_BYTES = 1_000_000
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


class RdapUnavailable(Exception):
    """The registry couldn't answer right now (timeout, rate limit, server error)."""


@dataclass(frozen=True)
class RdapResult:
    """has_service False: the TLD has no RDAP server (e.g. .de). registered None: no date given or not found."""

    has_service: bool
    registered: datetime.date | None


@lru_cache(maxsize=4)
def load_bootstrap(path: Path = BOOTSTRAP_FILE) -> dict[str, str]:
    """TLD -> RDAP base URL (HTTPS only), from IANA's bootstrap file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    servers: dict[str, str] = {}
    for tlds, urls in data.get("services", []):
        https = [u for u in urls if u.startswith("https://")]
        if https:
            for tld in tlds:
                servers[tld.lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
    return servers


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, "refusing non-HTTPS redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_HttpsOnlyRedirects())


def _http_get(url: str, timeout: float) -> tuple[int, dict]:
    """GET returning (status, parsed JSON). Separate function so tests can replace it."""
    request = urllib.request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT})
    try:
        with _opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(MAX_RESPONSE_BYTES))
    except urllib.error.HTTPError as exc:
        return exc.code, {}


class RdapClient:
    def __init__(self, timeout: float = 3.0, cache_seconds: int = 7 * 86400, no_date_cache_seconds: int = 86400,
                 bootstrap: dict[str, str] | None = None, max_cache_entries: int = 20_000) -> None:
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self.no_date_cache_seconds = no_date_cache_seconds
        self.servers = bootstrap if bootstrap is not None else load_bootstrap()
        self.max_cache_entries = max_cache_entries
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, RdapResult]] = {}
        self._blocked_until: dict[str, float] = {}  # registry host -> time, after a 429

    def lookup(self, domain: str) -> RdapResult:
        """Registration date for a registrable domain. Raises RdapUnavailable if the registry can't answer."""
        domain = domain.lower()
        server = self.servers.get(domain.rsplit(".", 1)[-1])
        if not server or not _DOMAIN_RE.fullmatch(domain):
            return RdapResult(has_service=False, registered=None)

        now = time.monotonic()
        host = server.split("/")[2]
        with self._lock:
            entry = self._cache.get(domain)
            if entry and entry[0] > now:
                return entry[1]
            if self._blocked_until.get(host, 0) > now:
                raise RdapUnavailable("registry rate limit (backing off)")

        try:
            status, body = _http_get(f"{server}domain/{domain}", self.timeout)
        except (OSError, ValueError) as exc:  # timeouts, connection errors, invalid JSON
            raise RdapUnavailable(type(exc).__name__) from exc

        if status == 429:
            with self._lock:
                self._blocked_until[host] = time.monotonic() + 60
            raise RdapUnavailable("registry rate limit")
        if status == 404:
            result = RdapResult(has_service=True, registered=None)  # not registered (or not public)
        elif status == 200:
            result = RdapResult(has_service=True, registered=_registration_date(body))
        else:
            raise RdapUnavailable(f"HTTP {status}")

        ttl = self.cache_seconds if result.registered else self.no_date_cache_seconds
        with self._lock:
            if len(self._cache) >= self.max_cache_entries:
                self._cache.pop(next(iter(self._cache)))
            self._cache[domain] = (time.monotonic() + ttl, result)
        return result


def _registration_date(body: dict) -> datetime.date | None:
    for event in body.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.datetime.fromisoformat(str(event.get("eventDate")).replace("Z", "+00:00")).date()
            except ValueError:
                return None
    return None
