from pathlib import Path

from app.engine.context import EmailContext
from app.engine.popular_domains import POPULAR_DOMAINS_FILE, top_domains
from app.engine.rule import Hit, Rule
from app.engine.sender_lists import FREE_MAIL_DOMAINS


class NewSender(Rule):
    """A sender you have no mail history with: you never wrote to them, and nothing from them is 30+ days old.

    The add-on searches the user's mailbox (it never sends the mailbox to us) for mail the user ever
    *sent to* the sender (no date limit), or mail *from* the sender before this email's date minus
    30 days. Either makes the sender "established", so one-way senders like a bank stop being
    "new" after a month. An attacker could avoid these 10 points by sending a harmless email 30+ days
    ahead, or by getting a reply.

    Well-known services (Tranco top `popular_top_n`) whose mail Gmail authenticated (DMARC pass) are
    never "new": nobody writes back to gitlab.com or a bank's notifications, and a phisher can't pass
    DMARC as those domains. Free-mail domains are excluded from that, since anyone can pass DMARC as
    gmail.com.

    Low points on purpose: shops, newsletters and new contacts are "new" too. It only tips emails
    that already have other warning signs. "unknown" (search failed) and missing data never fire.
    """

    id = "new_sender"
    title = "New sender: no history of mail with you"
    description = "You've never written to this sender, and nothing you received from them is older than 30 days. The add-on searches your mailbox inside Google; only \"new or not\" is sent. Authenticated mail from well-known services is exempt."
    category = "sender"
    default_score = 10
    default_params = {
        "domains_file": str(POPULAR_DOMAINS_FILE),
        "popular_top_n": 10_000,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        self.popular = top_domains(Path(self.params["domains_file"]), self.params["popular_top_n"])

    def evaluate(self, email: EmailContext) -> Hit | None:
        mailbox = email.report.mailbox
        if mailbox.sender_history != "new" or self._authenticated_popular_service(email):
            return None
        return Hit(
            explanation=(
                "You haven't corresponded with this sender for long. Phishing usually comes from strangers; "
                "on its own this is common and harmless (new shops, newsletters, new contacts)."
            ),
            evidence=[
                f"you have never written to {email.from_address or 'this sender'}, and nothing from them "
                f"is older than {mailbox.history_days} days in your mailbox"
            ],
        )

    def _authenticated_popular_service(self, email: EmailContext) -> bool:
        domain = email.from_registrable_domain
        return bool(
            domain
            and domain in self.popular
            and domain not in FREE_MAIL_DOMAINS
            and email.auth.present
            and "pass" in email.auth.dmarc
        )
