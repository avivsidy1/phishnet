"""Minimal VirusTotal API v3 client, shared by the virustotal_domain and virustotal_file rules.

Only identifiers are sent: registrable domains (never full URLs, which can carry tokens or addresses)
and attachment SHA-256 hashes (never the files). Never email content. Results are cached in memory,
and one rate limiter per API key keeps the service under the public API's 4 requests per minute
across both rules, so a busy minute degrades to "not checked" instead of errors.
"""

import datetime
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import quote

from app.engine.vt_key import VtKeySource

logger = logging.getLogger(__name__)

API_URL = "https://www.virustotal.com/api/v3/"
# What may be looked up, per API collection. Anything else is refused before any request.
_VALID_IDS = {
    "domains": re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"),
    "files": re.compile(r"^[0-9a-f]{64}$"),
}


class VirusTotalUnavailable(Exception):
    """The item could not be checked (no key, rate limit, quota, timeout, or a VirusTotal error)."""


@dataclass(frozen=True)
class VtReport:
    malicious: int
    suspicious: int
    # Engines that gave a verdict (files also report "type-unsupported", "failure", ... which don't count).
    total: int
    # (vendor/engine, its raw result such as "phishing" or "Trojan.X"), for malicious verdicts.
    flagged_by: list[tuple[str, str]]
    created: datetime.date | None  # domains: WHOIS creation date


def _http_get(url: str, api_key: str, timeout: float) -> tuple[int, dict]:
    """GET returning (status, parsed JSON body). Separate function so tests can replace it."""
    request = urllib.request.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            body = json.load(exc)
        except ValueError:
            body = {}
        return exc.code, body


class VirusTotalClient:
    def __init__(self, key_source: VtKeySource, timeout: float = 5.0, requests_per_minute: int = 4,
                 max_cache_entries: int = 10_000) -> None:
        self.key_source = key_source
        self.timeout = timeout
        self.requests_per_minute = requests_per_minute
        self.max_cache_entries = max_cache_entries
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[float, VtReport | None]] = {}
        self._recent_requests: deque[float] = deque()
        self._blocked_until = 0.0

    def cached(self, collection: str, item: str) -> tuple[bool, VtReport | None]:
        """(found in cache, report). A cached None means VirusTotal has never seen the item."""
        with self._lock:
            entry = self._cache.get((collection, item))
            if entry and entry[0] > time.monotonic():
                return True, entry[1]
            self._cache.pop((collection, item), None)
            return False, None

    def lookup(self, collection: str, item: str, cache_seconds: int, not_found_cache_seconds: int) -> VtReport | None:
        """Report for the item, or None if VirusTotal has never seen it. Raises VirusTotalUnavailable."""
        hit, report = self.cached(collection, item)
        if hit:
            return report
        api_key = self.key_source.get()
        if not api_key:
            raise VirusTotalUnavailable("no API key available")
        if not _VALID_IDS[collection].fullmatch(item):
            raise VirusTotalUnavailable("not a valid identifier")
        self._reserve_request()

        try:
            status, body = _http_get(f"{API_URL}{collection}/{quote(item)}", api_key, self.timeout)
        except (OSError, ValueError) as exc:  # timeouts, DNS/connection errors, invalid JSON
            raise VirusTotalUnavailable(type(exc).__name__) from exc

        if status == 404:
            self._store(collection, item, None, not_found_cache_seconds)
            return None
        if status == 429:
            # Minute or daily quota used up (daily resets at midnight UTC). Back off for a minute.
            with self._lock:
                self._blocked_until = time.monotonic() + 60
            raise VirusTotalUnavailable("quota exceeded")
        if status != 200:
            code = body.get("error", {}).get("code", "") if isinstance(body, dict) else ""
            if status == 401:
                logger.error("VirusTotal rejected the API key (%s); re-reading it", code)
                self.key_source.refresh_after_rejection()  # it may have been rotated in Secrets Manager
            raise VirusTotalUnavailable(f"HTTP {status} {code}".strip())

        report = _parse(body)
        self._store(collection, item, report, cache_seconds)
        return report

    def lookup_many(self, collection: str, items: list[str], max_new_lookups: int,
                    cache_seconds: int, not_found_cache_seconds: int) -> tuple[dict[str, VtReport | None], list[str]]:
        """Cached answers plus up to `max_new_lookups` new ones (in parallel). Returns (reports, unchecked)."""
        reports: dict[str, VtReport | None] = {}
        to_fetch = []
        for item in items:
            hit, report = self.cached(collection, item)
            if hit:
                reports[item] = report
            else:
                to_fetch.append(item)

        unchecked = to_fetch[max_new_lookups:]
        to_fetch = to_fetch[:max_new_lookups]

        def attempt(item: str) -> VtReport | None | VirusTotalUnavailable:
            try:
                return self.lookup(collection, item, cache_seconds, not_found_cache_seconds)
            except VirusTotalUnavailable as exc:
                return exc

        if to_fetch:
            with ThreadPoolExecutor(max_workers=len(to_fetch)) as pool:
                for item, result in zip(to_fetch, pool.map(attempt, to_fetch)):
                    if isinstance(result, VirusTotalUnavailable):
                        unchecked.append(item)
                    else:
                        reports[item] = result
        return reports, unchecked

    def _reserve_request(self) -> None:
        """Count a request against the per-minute budget, or refuse if it is used up."""
        now = time.monotonic()
        with self._lock:
            if now < self._blocked_until:
                raise VirusTotalUnavailable("backing off after quota error")
            while self._recent_requests and now - self._recent_requests[0] >= 60:
                self._recent_requests.popleft()
            if len(self._recent_requests) >= self.requests_per_minute:
                raise VirusTotalUnavailable("local rate limit reached")
            self._recent_requests.append(now)

    def _store(self, collection: str, item: str, report: VtReport | None, ttl: int) -> None:
        with self._lock:
            if len(self._cache) >= self.max_cache_entries:
                self._cache.pop(next(iter(self._cache)))  # oldest insertion first
            self._cache[(collection, item)] = (time.monotonic() + ttl, report)


_shared: dict[int, VirusTotalClient] = {}
_shared_lock = threading.Lock()


def shared_client(key_source: VtKeySource, timeout: float, requests_per_minute: int) -> VirusTotalClient:
    """The one client (cache + rate limiter) for this key source, i.e. for the service's API key.

    VirusTotal's quota is per key, so both rules must count against the same limiter. The first
    rule to ask sets the timeout and rate; keep them equal in rules.yaml.
    """
    with _shared_lock:
        if id(key_source) not in _shared:
            _shared[id(key_source)] = VirusTotalClient(key_source, timeout, requests_per_minute)
        return _shared[id(key_source)]


def _parse(body: dict) -> VtReport:
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    flagged = sorted(
        (str(name), str(result.get("result") or "malicious"))
        for name, result in results.items()
        if isinstance(result, dict) and result.get("category") == "malicious"
    )
    created = attributes.get("creation_date")
    verdicts = ("malicious", "suspicious", "harmless", "undetected")
    return VtReport(
        malicious=int(stats.get("malicious") or 0),
        suspicious=int(stats.get("suspicious") or 0),
        total=sum(int(stats.get(k) or 0) for k in verdicts),
        flagged_by=flagged,
        created=datetime.datetime.fromtimestamp(created, datetime.UTC).date() if created else None,
    )
