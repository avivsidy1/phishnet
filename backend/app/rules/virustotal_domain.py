import datetime
from pathlib import Path

from app.engine.context import EmailContext, domains_with_source
from app.engine.popular_domains import POPULAR_DOMAINS_FILE, top_domains
from app.engine.rule import Hit, Rule
from app.engine.virustotal import VirusTotalUnavailable, VtReport, shared_client
from app.engine.vt_key import vt_key_source

MAX_VENDORS_SHOWN = 4


class VirusTotalDomain(Rule):
    """A domain in the email that several security vendors on VirusTotal flag as malicious.

    Checks the sender's domain, every link's domain and domains written in the text. The most
    popular domains (Tranco top `skip_top_n`) are never sent: they are not what a phishing
    email hides behind, and skipping them saves the small public-API quota. Answers are cached.
    One vendor alone is not enough (even google.com has one).

    One of the two rules that call an outside service (with virustotal_file, sharing one client and
    rate limit). If a domain that needed checking could not be checked (rate limit, quota, timeout)
    and nothing was found, the rule raises, so the response lists it in rulesFailed instead of
    implying the domains are clean.
    """

    id = "virustotal_domain"
    title = "Domain flagged as malicious by security vendors (VirusTotal)"
    description = "A domain in the email (sender, link or text) is flagged as malicious by at least 2 security vendors on VirusTotal. Only the domain name is sent; very popular sites are skipped."
    category = "domain"
    default_score = 65
    default_params = {
        "domains_file": str(POPULAR_DOMAINS_FILE),
        "skip_top_n": 5_000,
        # Vendors that must call the domain malicious before the rule fires.
        "min_malicious": 2,
        # New (uncached) lookups per email; the public API allows only 4 per minute in total.
        "max_lookups_per_email": 3,
        "requests_per_minute": 4,
        "timeout_seconds": 5,
        "cache_hours": 24,
        # Shorter for "never seen": a new phishing domain can show up in VirusTotal within hours.
        "not_found_cache_hours": 6,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        self.skip = top_domains(Path(self.params["domains_file"]), self.params["skip_top_n"])
        self.client = shared_client(
            vt_key_source(),
            self.params["timeout_seconds"],
            self.params["requests_per_minute"],
        )

    def warm_up(self) -> None:
        self.client.key_source.get()  # read the key at startup, so a bad ARN/role shows in the startup log

    def evaluate(self, email: EmailContext) -> Hit | None:
        domains = [(d, where) for d, where in domains_with_source(email).items() if d not in self.skip]
        reports, unchecked = self.client.lookup_many(
            "domains",
            [d for d, _ in domains],
            self.params["max_lookups_per_email"],
            int(self.params["cache_hours"] * 3600),
            int(self.params["not_found_cache_hours"] * 3600),
        )

        evidence = [
            _describe(where, domain, reports[domain])
            for domain, where in domains
            if reports.get(domain) and reports[domain].malicious >= self.params["min_malicious"]
        ]
        if not evidence:
            if unchecked:
                raise VirusTotalUnavailable(f"{len(unchecked)} domain(s) could not be checked")
            return None
        if unchecked:
            evidence.append(f"{len(unchecked)} other domain(s) could not be checked right now")
        return Hit(
            explanation=(
                "Several independent security vendors list a domain in this email as malicious "
                "(phishing or malware sites), according to VirusTotal."
            ),
            evidence=evidence,
        )


def _describe(where: str, domain: str, report: VtReport) -> str:
    vendors = ", ".join(f"{name} ({result})" for name, result in report.flagged_by[:MAX_VENDORS_SHOWN])
    if len(report.flagged_by) > MAX_VENDORS_SHOWN:
        vendors += ", …"
    # Age before vendors: the scorer clips long evidence, and the vendor list is the part to lose.
    text = f"{where} domain {domain}: {report.malicious}/{report.total} vendors flag it as malicious"
    if report.created:
        days = (datetime.datetime.now(datetime.UTC).date() - report.created).days
        text += f"; registered {report.created.isoformat()} ({days} days ago)"
    if vendors:
        text += f"; flagged by {vendors}"
    return text
