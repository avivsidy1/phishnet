from urllib.parse import unquote

from app.engine.context import EmailContext, ParsedLink, domains_in_text, registrable_domain
from app.engine.rule import Hit, Rule

class LinkTextMismatch(Rule):
    """A link whose visible text names one domain but whose destination is another.

    '<a href="https://paypa1.top">Sign in at www.paypal.com</a>' or
    '<a href="mailto:x@evil.com">support@paypal.com</a>'.
    """

    id = "link_text_mismatch"
    title = "Link shows one address but opens another"
    description = "A link shows one address but actually opens another one."
    category = "links"
    default_score = 30
    default_params = {
        # Services that legitimately rewrite links: email click tracking (newsletters show
        # "www.shop.com" but link through the provider) and corporate link scanning.
        # A destination host equal to or under one of these is not treated as a mismatch.
        "link_rewriting_services": [
            # Email marketing / transactional click tracking
            "list-manage.com",        # Mailchimp
            "mailchimp.com",
            "mandrillapp.com",        # Mailchimp Transactional
            "sendgrid.net",           # Twilio SendGrid
            "awstrack.me",            # Amazon SES
            "mailgun.org",
            "hubspotlinks.com",       # HubSpot
            "hubspotemail.net",
            "hs-sites.com",
            "exacttarget.com",        # Salesforce Marketing Cloud
            "pardot.com",             # Salesforce Pardot
            "rs6.net",                # Constant Contact
            "createsend.com",         # Campaign Monitor
            "cmail19.com",
            "cmail20.com",
            "klclick.com",            # Klaviyo
            "klclick1.com",
            "klclick2.com",
            "klclick3.com",
            "sendibt2.com",           # Brevo (Sendinblue)
            "sendibt3.com",
            "mjt.lu",                 # Mailjet
            "sparkpostmail.com",      # SparkPost
            "spgo.io",
            "pstmrk.it",              # Postmark
            "acemlna.com",            # ActiveCampaign
            "acemlnb.com",
            "acemlnc.com",
            "acemlnd.com",
            "convertkit-mail.com",    # ConvertKit (Kit)
            "ck.page",
            "mlsend.com",             # MailerLite
            "substack.com",
            # Corporate link protection (rewrites every link in incoming mail)
            "safelinks.protection.outlook.com",  # Microsoft Defender Safe Links
            "urldefense.com",                    # Proofpoint
            "urldefense.proofpoint.com",
            "mimecast.com",
            "cudasvc.com",                       # Barracuda
        ],
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        evidence = []
        for link in email.links:
            if link.source != "html":
                continue  # plain-text links have no hidden destination
            destination = _destination_domain(link)
            if not destination or self._is_link_rewriting_service(link.host):
                continue
            shown = domains_in_text(link.text)
            if shown and destination not in shown:
                evidence.append(f'shows "{link.text.strip()}" but opens {destination}')

        if not evidence:
            return None
        return Hit(
            explanation=(
                "A link's visible text names one address but the link actually goes somewhere else. "
                "Legitimate emails almost never do this."
            ),
            evidence=evidence,
        )

    def _is_link_rewriting_service(self, host: str | None) -> bool:
        return bool(host) and any(
            host == service or host.endswith("." + service) for service in self.params["link_rewriting_services"]
        )


def _destination_domain(link: ParsedLink) -> str | None:
    """The registrable domain the link really goes to, including mailto: links."""
    if link.registrable_domain:
        return link.registrable_domain
    if link.url.lower().startswith("mailto:"):
        address = unquote(link.url[len("mailto:"):]).split("?", 1)[0].split(",", 1)[0].strip()
        if "@" in address:
            return registrable_domain(address.rpartition("@")[2])
    return None
