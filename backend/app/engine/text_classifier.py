"""Local text classifier used by the ml_phishing_text rule.

A DistilBERT model fine-tuned on phishing emails, loaded from a directory baked into the Docker
image (see Dockerfile). It never downloads anything at runtime, and loads weights from
safetensors only (no pickle files, which can execute code when loaded).

torch and transformers are imported lazily, so the rest of the service and the test suite work
without them installed.
"""

import threading
from collections.abc import Sequence
from pathlib import Path


class PhishingTextClassifier:
    def __init__(self, model_dir: Path, phishing_labels: Sequence[int], max_tokens: int = 512) -> None:
        self.model_dir = model_dir
        self.phishing_labels = list(phishing_labels)
        self.max_tokens = max_tokens
        self._lock = threading.Lock()
        self._torch = None
        self._tokenizer = None
        self._model = None

    def load(self) -> None:
        """Load the model once. Safe to call from several request threads."""
        with self._lock:
            if self._model is not None:
                return
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            if not (self.model_dir / "model.safetensors").is_file():
                raise FileNotFoundError(f"model weights not found in {self.model_dir}")
            tokenizer = AutoTokenizer.from_pretrained(self.model_dir, local_files_only=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                self.model_dir, local_files_only=True, use_safetensors=True
            )
            model.eval()
            self._torch, self._tokenizer, self._model = torch, tokenizer, model

    def phishing_probability(self, text: str) -> float:
        """Probability (0..1) that the text is phishing: the sum of the phishing classes."""
        self.load()
        inputs = self._tokenizer(text, truncation=True, max_length=self.max_tokens, return_tensors="pt")
        with self._torch.inference_mode():
            probs = self._torch.softmax(self._model(**inputs).logits, dim=-1)[0]
        return float(sum(probs[i] for i in self.phishing_labels))
