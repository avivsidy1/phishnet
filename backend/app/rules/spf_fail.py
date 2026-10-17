from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class SpfFail(Rule):
    id = "spf_fail"
    title = "Sender server not authorized (SPF)"
    description = "The server that sent this email isn't authorized to send for the sender's domain (SPF fail or softfail)."
    category = "authentication"
    default_score = 15
    default_params = {"failing_results": ["fail", "softfail"]}

    def evaluate(self, email: EmailContext) -> Hit | None:
        failed = [r for r in email.auth.spf if r in self.params["failing_results"]]
        if not failed:
            return None
        return Hit(
            explanation=(
                "The server that sent this email is not on the sender domain's list of "
                "authorized mail servers."
            ),
            evidence=[f"spf={failed[0]}", f"sender domain: {email.from_domain}"],
        )
