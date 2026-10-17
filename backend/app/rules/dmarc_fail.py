from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class DmarcFail(Rule):
    id = "dmarc_fail"
    title = "Sender identity not verified (DMARC)"
    description = "Gmail checked the sender domain's own policy (DMARC) and it failed: the email may not really come from the domain it claims."
    category = "authentication"
    default_score = 30

    def evaluate(self, email: EmailContext) -> Hit | None:
        if "fail" not in email.auth.dmarc:
            return None
        return Hit(
            explanation=(
                f"This email claims to be from {email.from_domain}, but that domain's own "
                "policy says it did not send it. This is a strong sign of spoofing."
            ),
            evidence=["dmarc=fail", f"claimed sender: {email.from_address}"],
        )
