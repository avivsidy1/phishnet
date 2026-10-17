from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class ReplyToMismatch(Rule):
    id = "reply_to_mismatch"
    title = "Replies go to a different domain"
    description = "Replies would go to a different domain than the sender's, a common trick to collect your answers elsewhere."
    category = "sender"
    default_score = 15

    def evaluate(self, email: EmailContext) -> Hit | None:
        if not email.from_registrable_domain:
            return None
        other = sorted({d for d in email.reply_to_domains if d != email.from_registrable_domain})
        if not other:
            return None
        return Hit(
            explanation=(
                f"The email is from {email.from_registrable_domain}, but replies would go to "
                f"{', '.join(other)}. Scammers use this to receive your answers."
            ),
            evidence=[f"from: {email.from_address}"] + [f"reply-to domain: {d}" for d in other],
        )
