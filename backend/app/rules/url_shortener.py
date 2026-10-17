from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class UrlShortener(Rule):
    id = "url_shortener"
    title = "Link hides its destination (URL shortener)"
    description = "A link uses a URL shortener (bit.ly, tinyurl and similar), which hides where it really goes."
    category = "links"
    default_score = 10
    default_params = {
        "domains": [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
            "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "qrco.de",
        ],
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        shorteners = set(self.params["domains"])
        found = sorted({link.registrable_domain for link in email.links if link.registrable_domain in shorteners})
        if not found:
            return None
        return Hit(
            explanation="A link uses a URL shortener, which hides where it really leads.",
            evidence=[f"shortener: {d}" for d in found],
        )
