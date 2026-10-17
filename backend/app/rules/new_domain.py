import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.engine.context import EmailContext, domains_with_source
from app.engine.popular_domains import POPULAR_DOMAINS_FILE, top_domains
from app.engine.rdap import RdapClient, RdapResult, RdapUnavailable
from app.engine.rule import Hit, Rule


class NewDomain(Rule):
    """A domain in the email (sender, link or text) registered less than `max_age_days` before the email.

    Phishing domains are typically used within days of registration; legitimate mail almost never
    comes from a week-old domain. The date comes from RDAP, asked of the TLD's own registry (no key,
    only the domain name is sent). Domains in the Tranco top 1M are skipped: Tranco ranks over 30 days,
    so they can't be a week old. TLDs without RDAP (e.g. .de, .io) are silently not applicable.
    If a registry couldn't answer and nothing was found, the rule raises (listed in rulesFailed).
   
    """

    id = "new_domain"
    title = "Recently registered domain"
    description = "A domain in the email was registered less than 7 days ago; phishing sites are usually brand new. Uses the registry's public data (RDAP), which some country domains such as .co.il don't offer."
    category = "domain"
    default_score = 30
    default_params = {
        "max_age_days": 7,
        "domains_file": str(POPULAR_DOMAINS_FILE),
        "skip_top_n": 1_000_000,
        "max_lookups_per_email": 5,
        "timeout_seconds": 3,
        "cache_days": 7,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        self.skip = top_domains(Path(self.params["domains_file"]), self.params["skip_top_n"])
        self.client = RdapClient(
            timeout=self.params["timeout_seconds"], cache_seconds=int(self.params["cache_days"] * 86400)
        )

    def evaluate(self, email: EmailContext) -> Hit | None:
        domains = [(d, where) for d, where in domains_with_source(email).items() if d not in self.skip]
        to_check = domains[: self.params["max_lookups_per_email"]]
        unchecked = len(domains) - len(to_check)

        results: list[RdapResult | None] = []
        if to_check:
            with ThreadPoolExecutor(max_workers=len(to_check)) as pool:
                results = list(pool.map(self._try_lookup, [d for d, _ in to_check]))
        unchecked += sum(r is None for r in results)

        reference = _email_date(email)
        evidence = []
        for (domain, where), result in zip(to_check, results):
            if result and result.registered:
                age = (reference - result.registered).days
                if 0 <= age < self.params["max_age_days"]:
                    when = "today" if age == 0 else "1 day" if age == 1 else f"{age} days"
                    ago = "" if age == 0 else " before this email"
                    evidence.append(f"{where} domain {domain} was registered {when}{ago} ({result.registered.isoformat()})")

        if not evidence:
            if unchecked:
                raise RdapUnavailable(f"{unchecked} domain(s) could not be checked")
            return None
        if unchecked:
            evidence.append(f"{unchecked} other domain(s) could not be checked right now")
        return Hit(
            explanation=(
                f"A domain in this email was registered less than {self.params['max_age_days']} days ago. "
                "Phishing sites are usually set up days before an attack; established senders use older domains."
            ),
            evidence=evidence,
        )

    def _try_lookup(self, domain: str) -> RdapResult | None:
        try:
            return self.client.lookup(domain)
        except RdapUnavailable:
            return None


def _email_date(email: EmailContext) -> datetime.date:
    """The email's own date (so old emails are judged as of when they arrived), else today."""
    raw = email.report.message.date
    if raw:
        try:
            return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(datetime.UTC).date()
        except ValueError:
            pass
    return datetime.datetime.now(datetime.UTC).date()
