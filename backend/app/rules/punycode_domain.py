from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class PunycodeDomain(Rule):
    """Internationalized domains (xn--...) can render as exact visual copies of real ones,
    e.g. 'аpple.com' with a Cyrillic 'а'."""

    id = "punycode_domain"
    title = "Domain uses look-alike international characters"
    description = "A domain uses international characters (shown as xn--) that can look identical to a real brand's name."
    category = "domain"
    default_score = 20

    def evaluate(self, email: EmailContext) -> Hit | None:
        hosts = {link.host for link in email.links if link.host}
        if email.from_domain:
            hosts.add(email.from_domain)

        evidence = [
            f"{host} (displays as {_decode(host)})"
            for host in sorted(hosts)
            if any(label.startswith("xn--") for label in host.split("."))
        ]
        if not evidence:
            return None
        return Hit(
            explanation=(
                "A domain uses international characters that can look identical to normal "
                "letters, a known way to imitate real websites."
            ),
            evidence=evidence,
        )


def _decode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host
