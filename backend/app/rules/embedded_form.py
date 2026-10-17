import re

from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule

_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]{0,500}?type\s*=\s*[\"']?password", re.IGNORECASE)


class EmbeddedForm(Rule):
    id = "embedded_form"
    title = "Email contains a data entry form"
    description = "The email contains a form or a password field, asking you to type information directly into the email."
    category = "content"
    default_score = 25

    def evaluate(self, email: EmailContext) -> Hit | None:
        evidence = []
        if _PASSWORD_INPUT_RE.search(email.html):
            evidence.append("password input field in the email body")
        elif _FORM_RE.search(email.html):
            evidence.append("HTML form in the email body")
        if not evidence:
            return None
        return Hit(
            explanation=(
                "The email contains a form that sends what you type to a third party. "
                "Legitimate services don't collect information this way."
            ),
            evidence=evidence,
        )
