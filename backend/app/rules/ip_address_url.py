from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class IpAddressUrl(Rule):
    id = "ip_address_url"
    title = "Link points to a raw IP address"
    description = "A link points to a raw IP address instead of a domain name."
    category = "links"
    default_score = 20

    def evaluate(self, email: EmailContext) -> Hit | None:
        hosts = sorted({link.host for link in email.links if link.is_ip and link.host})
        if not hosts:
            return None
        return Hit(
            explanation=(
                "A link goes to a numeric IP address instead of a named website. Legitimate "
                "companies use domain names; attackers use IPs to avoid domain reputation checks."
            ),
            evidence=[f"link host: {h}" for h in hosts],
        )
