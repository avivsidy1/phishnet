"""Derived view of a report that rules work with.

Parsing (domains, URLs, authentication results) happens once here, so each rule
stays small and focused on its own decision.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

from app.models import Attachment, EmailReport

# Use the bundled public-suffix snapshot: no network calls at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=())

_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
# "[^<>]" (not "[^>]") keeps this linear: with "[^>]+", 120 KB of "<" and no ">" made every "<"
# scan to the end of the text, ~9.6 s of CPU per analysis (ReDoS).
_TAG_RE = re.compile(r"<[^<>]*>")
# A domain anywhere in text: in a URL ("https://www.paypal.com/x"), a bare domain
# ("paypal.com"), or an email address ("support@paypal.com"). Candidates are confirmed by
# checking for a real public suffix, so "report.pdf" or "v2.5" don't count.
_DOMAIN_IN_TEXT_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().strip(".").lower()
    return host or None


def registrable_domain(host: str | None) -> str | None:
    """'login.mail.example.co.uk' -> 'example.co.uk'. IPs are returned as-is."""
    host = normalize_host(host)
    if host is None:
        return None
    if is_ip(host):
        return host
    return _extract(host).registered_domain or host


def domain_label(host: str | None) -> str | None:
    """'login.example.co.uk' -> 'example' (the registrable name without the public suffix)."""
    host = normalize_host(host)
    if host is None or is_ip(host):
        return None
    return _extract(host).domain or None


def public_suffix(host: str | None) -> str | None:
    host = normalize_host(host)
    if host is None or is_ip(host):
        return None
    return _extract(host).suffix or None


def domains_in_text(text: str) -> set[str]:
    """Registrable domains named anywhere in the text."""
    domains = set()
    for match in _DOMAIN_IN_TEXT_RE.finditer(text):
        host = match.group(1).lower()
        suffix = public_suffix(host)
        if not suffix or suffix == host:
            continue  # not a real domain: "report.pdf", "Node.js", or a bare suffix like "co.uk"
        domains.add(registrable_domain(host))
    return domains


def host_from_url(url: str) -> str | None:
    try:
        return normalize_host(urlsplit(url.strip()).hostname)
    except ValueError:
        return None


@dataclass(frozen=True)
class ParsedLink:
    url: str
    text: str
    source: str
    host: str | None
    registrable_domain: str | None
    is_ip: bool


@dataclass(frozen=True)
class AuthResults:
    """Results from the receiving server's Authentication-Results header."""

    present: bool = False
    spf: list[str] = field(default_factory=list)
    dkim: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EmailContext:
    report: EmailReport
    subject: str
    from_name: str
    from_address: str
    from_domain: str | None
    from_registrable_domain: str | None
    reply_to_domains: list[str]
    auth: AuthResults
    links: list[ParsedLink]
    attachments: list[Attachment]
    text: str
    html: str

    @property
    def content(self) -> str:
        """Subject + visible text, lowercased: what content rules search."""
        return f"{self.subject}\n{self.text}".lower()

    @classmethod
    def from_report(cls, report: EmailReport, trusted_auth_servers: list[str]) -> "EmailContext":
        sender = report.sender.from_
        from_domain = normalize_host(sender.domain) if sender else None
        text = report.body.text or _TAG_RE.sub(" ", report.body.html)

        return cls(
            report=report,
            subject=report.message.subject,
            from_name=sender.name if sender else "",
            from_address=sender.address if sender else "",
            from_domain=from_domain,
            from_registrable_domain=registrable_domain(from_domain),
            reply_to_domains=[
                d for d in (registrable_domain(a.domain) for a in report.sender.reply_to) if d
            ],
            auth=_parse_auth_results(report, trusted_auth_servers),
            links=[_parse_link(link.url, link.text, link.source) for link in report.links],
            attachments=report.attachments,
            text=text,
            html=report.body.html,
        )


def _parse_link(url: str, text: str, source: str) -> ParsedLink:
    host = host_from_url(url)
    return ParsedLink(
        url=url,
        text=text,
        source=source,
        host=host,
        registrable_domain=registrable_domain(host),
        is_ip=bool(host and is_ip(host)),
    )


def _parse_auth_results(report: EmailReport, trusted_auth_servers: list[str]) -> AuthResults:
    """Reads SPF/DKIM/DMARC results, trusting only headers stamped by our own mail server.

    Anyone can put an 'Authentication-Results: ...dmarc=pass' header in an email they send.
    Only the one whose authserv-id is the receiving server (e.g. mx.google.com) is meaningful.
    """
    trusted = {s.lower() for s in trusted_auth_servers}
    for header in report.headers:
        if header.name.lower() != "authentication-results":
            continue
        first_part = header.value.split(";", 1)[0].split()
        authserv_id = first_part[0].lower() if first_part else ""
        if authserv_id not in trusted:
            continue

        results: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
        for method, result in _AUTH_RESULT_RE.findall(header.value):
            results[method.lower()].append(result.lower())
        return AuthResults(present=True, **results)
    return AuthResults()


def domains_with_source(email: "EmailContext") -> dict[str, str]:
    """Registrable domains in the email (sender, links, text), each with where it first appeared."""
    found: dict[str, str] = {}
    if email.from_registrable_domain:
        found[email.from_registrable_domain] = "sender"
    for link in email.links:
        if link.registrable_domain and not link.is_ip:
            found.setdefault(link.registrable_domain, "link")
    for domain in sorted(domains_in_text(f"{email.subject}\n{email.text}")):
        if not is_ip(domain):
            found.setdefault(domain, "text")
    return found
