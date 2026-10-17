from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class DkimFail(Rule):
    id = "dkim_fail"
    title = "Invalid digital signature (DKIM)"
    description = "The email's digital signature (DKIM) is broken and no valid signature was found, so it may have been forged or altered."
    category = "authentication"
    default_score = 15
    default_params = {"failing_results": ["fail", "permerror"]}

    def evaluate(self, email: EmailContext) -> Hit | None:
        results = email.auth.dkim
        # An email can carry several signatures; one valid signature is enough.
        if "pass" in results:
            return None
        failed = [r for r in results if r in self.params["failing_results"]]
        if not failed:
            return None
        return Hit(
            explanation=(
                "The email's digital signature is invalid, so it may have been forged "
                "or altered in transit."
            ),
            evidence=[f"dkim={failed[0]}"],
        )
