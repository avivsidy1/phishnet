from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule
from app.engine.sender_lists import find_match, normalize_entries


class UserBlocklist(Rule):
    """The sender is on the user's own blocklist (set in the add-on's settings).

    Worth 100 points, so the email is always Malicious. No authentication check: if someone
    forges a blocked address, flagging the email is still the right outcome. It always wins
    over the trusted list.
    """

    id = "user_blocklist"
    title = "Sender is on your blocklist"
    description = "The sender's address or domain is on your blocklist. Always on, and it wins over your trusted list."
    category = "sender"
    default_score = 100

    def evaluate(self, email: EmailContext) -> Hit | None:
        entries = normalize_entries(email.report.preferences.blocked_senders, allow_free_mail_domains=True)
        match = find_match(email.from_address, email.from_domain, entries)
        if not match:
            return None
        return Hit(
            explanation="You blocked this sender in PhishNet's settings.",
            evidence=[f"sender {email.from_address} matches your blocklist entry {match}"],
        )
