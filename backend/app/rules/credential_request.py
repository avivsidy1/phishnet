from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class CredentialRequest(Rule):
    id = "credential_request"
    title = "Asks you to log in or share sensitive details"
    description = "The email asks you to verify your account, confirm a password or update payment details, and contains a link. Only the highest of this, urgency language and the ML wording rule counts."
    category = "content"
    default_score = 15
    default_params = {
        "phrases": [
            "verify your account", "verify your identity", "confirm your account",
            "confirm your password", "update your password", "reset your password",
            "update your payment", "update your billing", "confirm your payment details",
            "enter your credentials", "login to your account", "log in to your account",
            "sign in to your account", "social security number", "credit card number",
            "validate your account", "unlock your account",
        ],
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        content = email.content
        found = [p for p in self.params["phrases"] if p in content]
        # Asking for credentials only matters if there's somewhere to enter them.
        if not found or not email.links:
            return None
        return Hit(
            explanation=(
                "The email asks you to sign in or provide sensitive information through a link. "
                "Legitimate services rarely ask for this by email."
            ),
            evidence=[f'"{p}"' for p in found],
        )
