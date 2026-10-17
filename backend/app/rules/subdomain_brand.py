from pathlib import Path

from app.engine.context import EmailContext, domain_label, registrable_domain
from app.engine.popular_domains import POPULAR_DOMAINS_FILE, load_ranked_domains
from app.engine.rule import Hit, Rule

# Top-10k sites named after common words. As subdomains they mean nothing ("login.mycompany.com"),
# so they don't count as a brand in the subdomain. 18 of these were top-10k labels on 2026-10-17.
GENERIC_LABELS = frozenset({
    "about", "account", "accounts", "admin", "cloud", "connect", "health", "login", "media", "mobile",
    "money", "office", "privacy", "service", "services", "share", "sport", "sports", "static", "weather",
    "email", "store", "secure", "support", "portal", "online", "update", "download", "signin", "webmail",
    "security", "gateway", "content", "assets", "images", "events", "travel", "careers", "partners",
})


class SubdomainBrand(Rule):
    """A well-known site's name in the subdomain of an unrelated domain: X.Y.com, X in the Tranco top 10k, Y not.

    paypal.somethingmalicious.com (the label "paypal" is the name of paypal.com) or
    paypal.com.somethingmalicious.com (the whole domain). Readers see "paypal" first and miss the real
    domain at the end. Checks the sender's hostname and every link's hostname.
    """

    id = "subdomain_brand"
    title = "Well-known site name used in a subdomain"
    description = (
        "A link or the sender uses a well-known site's name in front of a different domain, like "
        "paypal.somethingmalicious.com: the real domain is the part at the end."
    )
    category = "domain"
    default_score = 30
    default_params = {
        "domains_file": str(POPULAR_DOMAINS_FILE),
        "top_n": 10_000,
        # Short names collide with ordinary words (same guard as lookalike_domain).
        "min_label_length": 5,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        top = load_ranked_domains(Path(self.params["domains_file"]))[: self.params["top_n"]]
        self.popular = frozenset(top)
        self.brand_of: dict[str, str] = {}  # label -> its top-10k domain, e.g. "paypal" -> "paypal.com"
        for domain in top:
            label = domain_label(domain)
            if label and len(label) >= self.params["min_label_length"] and label not in GENERIC_LABELS:
                self.brand_of.setdefault(label, domain)

    def evaluate(self, email: EmailContext) -> Hit | None:
        hosts: dict[str, str] = {}
        if email.from_domain:
            hosts[email.from_domain] = "sender"
        for link in email.links:
            if link.host and not link.is_ip:
                hosts.setdefault(link.host, "link")

        evidence = []
        for host, where in hosts.items():
            match = self.imitated(host)
            if match:
                brand, real = match
                evidence.append(f"{where} {host} puts {brand} in front of the real domain {real}")
        if not evidence:
            return None
        return Hit(
            explanation=(
                "A well-known site's name appears at the start of an address that actually belongs to a "
                "different domain. People read the start and trust it; the real owner is the part at the end."
            ),
            evidence=evidence,
        )

    def imitated(self, host: str) -> tuple[str, str] | None:
        """(the well-known site, the real registrable domain), or None."""
        real = registrable_domain(host)
        if not real or real in self.popular or host == real or not host.endswith("." + real):
            return None
        labels = host[: -len(real) - 1].split(".")
        # A whole top-10k domain inside the subdomain: paypal.com.evil.com, login.paypal.com.evil.com.
        for i in range(len(labels)):
            for j in range(len(labels), i + 1, -1):
                candidate = ".".join(labels[i:j])
                if candidate in self.popular and candidate != real:
                    return candidate, real
        # A top-10k site's name as a subdomain label: paypal.evil.com.
        for label in labels:
            brand = self.brand_of.get(label)
            if brand and brand != real:
                return brand, real
        return None
