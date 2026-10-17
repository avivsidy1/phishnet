from collections.abc import Iterator
from itertools import combinations, product
from pathlib import Path

from app.engine.context import EmailContext, domain_label, public_suffix
from app.engine.popular_domains import POPULAR_DOMAINS_FILE, top_domains
from app.engine.rule import Hit, Rule

# Characters attackers swap in because they look alike at a glance, mapped to what they imitate.
# Domains are lowercase, so an uppercase "I" arrives as "i" and imitates "l" (and vice versa).
CONFUSABLES: dict[str, tuple[str, ...]] = {
    "0": ("o",),
    "1": ("l", "i"),
    "3": ("e",),
    "4": ("a",),
    "5": ("s",),
    "6": ("b", "g"),
    "7": ("t",),
    "8": ("b",),
    "9": ("g", "q"),
    "i": ("l",),
    "l": ("i",),
    "rn": ("m",),
    "vv": ("w",),
}


class LookalikeDomain(Rule):
    """A domain that turns into a well-known site's domain once look-alike characters are swapped back.

    paypa1.com -> paypal.com, rnicrosoft.com -> microsoft.com, g00gle.com -> google.com.
    "Well-known" comes from the Tranco popularity ranking, not a hand-made brand list:
    - the imitated domain must be in the top `target_top_n` (default 100k);
    - a domain anywhere in the top 1M is trusted and never fires.
    The guards were tuned on 50k real lower-ranked domains: 0.024% false positives, with all
    16 test attacks still caught.
    """

    id = "lookalike_domain"
    title = "Domain disguised as a well-known site"
    description = "A domain imitates a well-known site by swapping look-alike characters, like paypa1.com for paypal.com."
    category = "domain"
    default_score = 35
    default_params = {
        "domains_file": str(POPULAR_DOMAINS_FILE),
        # Only sites this popular count as worth imitating (rank <= target_top_n).
        "target_top_n": 100_000,
        # Short names collide with everything (lnc -> inc); attackers imitate longer names.
        "min_label_length": 5,
        # Upper bound on swapped characters per domain; keeps the search small and precise.
        "max_substitutions": 3,
        # Also try these extensions: paypa1.top -> paypal.com.
        "fallback_suffixes": ["com"],
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        path = Path(self.params["domains_file"])
        self.trusted = top_domains(path)
        self.targets = top_domains(path, self.params["target_top_n"])

    def evaluate(self, email: EmailContext) -> Hit | None:
        sources = {link.registrable_domain: "link" for link in email.links if link.registrable_domain}
        if email.from_registrable_domain:
            sources[email.from_registrable_domain] = "sender"

        evidence = []
        for domain in sorted(sources):
            match = self.imitated_domain(domain)
            if match:
                target, swaps = match
                evidence.append(f"{sources[domain]} domain {domain} looks like {target} ({', '.join(swaps)})")

        if not evidence:
            return None
        return Hit(
            explanation=(
                "A domain in this email becomes a well-known site's domain when look-alike "
                "characters are swapped back (for example 1 → l). This is a classic way to make "
                "a fake site or sender look real."
            ),
            evidence=evidence,
        )

    def imitated_domain(self, domain: str) -> tuple[str, list[str]] | None:
        """Returns (popular domain it imitates, swaps made), or None."""
        label, suffix = domain_label(domain), public_suffix(domain)
        if (
            not label
            or not suffix
            or domain in self.trusted  # popular domains are never look-alikes
            or label.startswith("xn--")  # handled by punycode_domain
            or len(label) < self.params["min_label_length"]
            or sum(c.isdigit() for c in label) * 2 > len(label)  # mostly digits (888, 53), not a disguised word
        ):
            return None

        suffixes = [suffix] + [s for s in self.params["fallback_suffixes"] if s != suffix]
        for candidate, swaps in _deobfuscations(label, self.params["max_substitutions"]):
            for s in suffixes:
                target = f"{candidate}.{s}"
                if target in self.targets:
                    return target, swaps
        return None


def _deobfuscations(label: str, max_substitutions: int) -> Iterator[tuple[str, list[str]]]:
    """All variants of `label` with 1..max_substitutions look-alike swaps, fewest swaps first."""
    sites = [
        (i, fake)
        for i in range(len(label))
        for fake in CONFUSABLES
        if label.startswith(fake, i)
    ]
    for count in range(1, max_substitutions + 1):
        for chosen in combinations(sites, count):
            if _overlap(chosen):
                continue
            for replacements in product(*(CONFUSABLES[fake] for _, fake in chosen)):
                chars = list(label)
                swaps = []
                # Replace right to left so earlier indexes stay valid when lengths change (rn -> m).
                for (i, fake), real in sorted(zip(chosen, replacements), reverse=True):
                    chars[i : i + len(fake)] = real
                    swaps.append(f"{fake}→{real}")
                yield "".join(chars), list(reversed(swaps))


def _overlap(sites: tuple[tuple[int, str], ...]) -> bool:
    end = -1
    for i, fake in sites:  # combinations preserve the sorted order of `sites`
        if i < end:
            return True
        end = i + len(fake)
    return False
