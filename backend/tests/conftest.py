import copy
import os
from typing import Any

# Settings are read at import time of app.main, so set them before any test imports it.
TEST_AUDIENCE = "test-client.apps.googleusercontent.com"
TEST_EMAIL = "me@example.com"
os.environ["ALLOWED_AUDIENCES"] = TEST_AUDIENCE
os.environ["ALLOWED_EMAILS"] = TEST_EMAIL
os.environ["VT_API_KEY"] = "test-vt-key"

import pytest  # noqa: E402

from app.engine.context import EmailContext  # noqa: E402
from app.engine import rdap, virustotal  # noqa: E402
from app.engine.vt_key import vt_key_source  # noqa: E402
from app.engine.text_classifier import PhishingTextClassifier  # noqa: E402
from app.models import EmailReport  # noqa: E402


@pytest.fixture(autouse=True)
def fake_ml_model(monkeypatch):
    """Tests never load the real model (torch isn't installed locally). By default it rates
    everything as legitimate; tests of ml_phishing_text set their own probability."""
    monkeypatch.setattr(PhishingTextClassifier, "load", lambda self: None)
    monkeypatch.setattr(PhishingTextClassifier, "phishing_probability", lambda self, text: 0.0)


@pytest.fixture(autouse=True)
def fake_virustotal(monkeypatch):
    """Tests never call VirusTotal. By default everything is unknown to it (HTTP 404);
    tests of virustotal_domain replace this with their own responses."""
    monkeypatch.setattr(virustotal, "_http_get", lambda url, api_key, timeout: (404, {}))
    virustotal._shared.clear()  # fresh shared client (cache + rate limiter) for every test
    vt_key_source.cache_clear()


@pytest.fixture(autouse=True)
def fake_rdap(monkeypatch):
    """Tests never call real registries. By default every domain is unknown (HTTP 404);
    tests of new_domain replace this with their own responses."""
    monkeypatch.setattr(rdap, "_http_get", lambda url, timeout: (404, {}))

BENIGN_REPORT: dict[str, Any] = {
    "schemaVersion": "1.0",
    "message": {"id": "msg-1", "subject": "Team lunch on Friday"},
    "sender": {
        "from": {"raw": "Dana <dana@example.com>", "name": "Dana", "address": "dana@example.com", "domain": "example.com"},
        "replyTo": [],
    },
    "recipients": {"to": [{"address": "me@example.org", "domain": "example.org"}]},
    "headers": [
        {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com"},
    ],
    "body": {"text": "Hi all, lunch is at noon. Menu: https://example.com/menu", "html": ""},
    "links": [{"url": "https://example.com/menu", "text": "", "source": "text"}],
    "attachments": [],
}


def make_report(**overrides: Any) -> EmailReport:
    """A benign report with selected top-level sections replaced."""
    data = copy.deepcopy(BENIGN_REPORT)
    data.update(overrides)
    return EmailReport.model_validate(data)


def make_context(**overrides: Any) -> EmailContext:
    return EmailContext.from_report(make_report(**overrides), ["mx.google.com"])


def sender(address: str, name: str = "") -> dict[str, Any]:
    domain = address.rsplit("@", 1)[-1]
    return {"from": {"raw": f"{name} <{address}>", "name": name, "address": address, "domain": domain}, "replyTo": []}
