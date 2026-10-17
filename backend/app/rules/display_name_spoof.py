import re

from app.engine.context import EmailContext, registrable_domain
from app.engine.rule import Hit, Rule

_EMAIL_IN_NAME_RE = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[\w-]+)")


class DisplayNameSpoof(Rule):
    """The display name shows an email address on a different domain than the real sender.

    Most mail clients show only the display name, so '"ceo@mycompany.com" <x@evil.com>'
    looks like it comes from mycompany.com unless you inspect the address.
    """

    id = "display_name_spoof"
    title = "Sender name shows a different address"
    description = "The sender's display name contains a different email address, like \"ceo@company.com\" <x@outlook.com>, to fool screens that show only the name."
    category = "sender"
    default_score = 25

    def evaluate(self, email: EmailContext) -> Hit | None:
        sender_domain = email.from_registrable_domain
        match = _EMAIL_IN_NAME_RE.search(email.from_name.lower())
        if not match or not sender_domain or registrable_domain(match.group(1)) == sender_domain:
            return None
        return Hit(
            explanation=(
                f"The sender name shows the address '{match.group(0)}', but the email "
                f"actually comes from {email.from_address}."
            ),
            evidence=[f"display name: {email.from_name}", f"real address: {email.from_address}"],
        )
