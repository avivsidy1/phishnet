from pathlib import Path

from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule
from app.engine.text_classifier import PhishingTextClassifier

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "phishing-distilbert"


class MlPhishingText(Rule):
    """A machine-learning model reads the subject and body and rates how much they sound like phishing.

    It catches text-only scams the other rules can't see (gift-card requests, "our bank details
    changed"), but it also flags some legitimate transactional mail (password resets, shipping
    notices) and misses phishing whose tells are technical. So it is one bounded
    signal with a high threshold, never the verdict on its own.

    Model: cybersectony/phishing-email-detection-distilbert_v2.4.1, pinned in the Dockerfile.
    Classes: 0 legitimate email, 1 phishing, 2 legitimate URL, 3 phishing URL.
    """

    id = "ml_phishing_text"
    title = "Wording resembles phishing (ML model)"
    description = "A machine-learning model rates the subject and body as phishing with at least 99.85% confidence. Only the highest of this, credential request and urgency language counts."
    category = "content"
    default_score = 20
    default_params = {
        "model_dir": str(MODEL_DIR),
        # The model is often overconfident; only near-certain ratings count.
        "threshold": 0.9985,
        "phishing_labels": [1, 3],
        # DistilBERT's input limit. Longer emails are cut; phishing wording is usually up front.
        "max_tokens": 512,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        self.classifier = PhishingTextClassifier(
            Path(self.params["model_dir"]), self.params["phishing_labels"], self.params["max_tokens"]
        )

    def warm_up(self) -> None:
        self.classifier.load()

    def evaluate(self, email: EmailContext) -> Hit | None:
        text = f"{email.subject}\n\n{email.text}".strip()
        if not text:
            return None
        probability = self.classifier.phishing_probability(text)
        if probability < self.params["threshold"]:
            return None
        return Hit(
            explanation=(
                "A machine-learning model trained on phishing emails rates this wording as phishing. "
                "On its own this is a moderate signal: the model also flags some legitimate messages."
            ),
            evidence=[f"model phishing probability {probability:.2%} (threshold {self.params['threshold']:.2%})"],
        )
