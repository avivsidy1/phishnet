from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class UrgencyLanguage(Rule):
    id = "urgency_language"
    title = "Pressure or urgency tactics"
    description = "The email uses two or more pressure phrases, such as \"urgent\" or \"within 24 hours\". Only the highest of this, credential request and the ML wording rule counts."
    category = "content"
    default_score = 10
    default_params = {
        "phrases": [
            "urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
            "account will be suspended", "account has been suspended", "account will be closed",
            "unusual activity", "suspicious activity", "final notice", "last warning",
            "failure to", "limited time", "expires today", "action required",
        ],
        # A single "urgent" is common in normal mail; require several phrases.
        "min_matches": 2,
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        content = email.content
        found = [p for p in self.params["phrases"] if p in content]
        if len(found) < self.params["min_matches"]:
            return None
        return Hit(
            explanation=(
                "The email uses pressure tactics to rush you into acting before you think, "
                "a hallmark of social engineering."
            ),
            evidence=[f'"{p}"' for p in found],
        )
