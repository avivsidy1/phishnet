from app.engine.context import EmailContext, public_suffix
from app.engine.rule import Hit, Rule


class SuspiciousTld(Rule):
    id = "suspicious_tld"
    title = "Domain uses a high-abuse extension"
    description = "A domain ends in an extension that is often abused for phishing, such as .zip, .xyz or .top."
    category = "domain"
    default_score = 10
    default_params = {
        # Extensions with disproportionate abuse rates (cheap/free registration, lax enforcement).
        "tlds": [
            "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
            "work", "rest", "cam", "icu", "buzz", "monster", "sbs", "cfd", "lol",
        ],
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        tlds = set(self.params["tlds"])
        hosts = {link.host for link in email.links if link.host and not link.is_ip}
        if email.from_domain:
            hosts.add(email.from_domain)

        flagged = sorted(h for h in hosts if public_suffix(h) in tlds)
        if not flagged:
            return None
        return Hit(
            explanation=(
                "A domain in this email uses an extension that is heavily abused for "
                "phishing and spam."
            ),
            evidence=[f"domain: {h}" for h in flagged],
        )
