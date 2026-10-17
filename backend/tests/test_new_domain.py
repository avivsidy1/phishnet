import datetime

import pytest

from app.config import BACKEND_ROOT
from app.engine import rdap
from app.engine.loader import load_engine_config
from app.engine.rdap import RdapClient, RdapUnavailable, load_bootstrap
from app.engine.scorer import analyze
from app.rules.new_domain import NewDomain
from tests.conftest import make_context, make_report, sender

EMAIL_DATE = "2026-10-17T10:00:00Z"


def rdap_body(registered: str) -> dict:
    return {"events": [{"eventAction": "last changed", "eventDate": "2026-10-16T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": registered}]}


@pytest.fixture
def registry(monkeypatch):
    """Fake registries: domain -> (status, body); 404 otherwise. Records requested URLs."""
    responses, urls = {}, []

    def fake_get(url, timeout):
        urls.append(url)
        return responses.get(url.rsplit("/", 1)[-1], (404, {}))

    monkeypatch.setattr(rdap, "_http_get", fake_get)
    return responses, urls


def email(*urls, sender_address="dana@small-shop.info", text="Hello"):
    return make_context(
        message={"id": "1", "subject": "Hi", "date": EMAIL_DATE},
        sender=sender(sender_address),
        body={"text": text, "html": ""},
        links=[{"url": u, "text": "", "source": "html"} for u in urls],
    )


def test_bootstrap_maps_tlds_to_https_registries():
    servers = load_bootstrap()
    assert servers["com"] == "https://rdap.verisign.com/com/v1/"
    assert "de" not in servers  # no RDAP for .de
    assert all(url.startswith("https://") and url.endswith("/") for url in servers.values())


def test_fires_for_a_domain_registered_days_before_the_email(registry):
    responses, urls = registry
    responses["cerrowqei.click"] = (200, rdap_body("2026-10-15T19:42:06.370Z"))
    hit = NewDomain().evaluate(email("https://login.cerrowqei.click/x?u=1"))
    assert hit.evidence == ["link domain cerrowqei.click was registered 2 days before this email (2026-10-15)"]
    assert "https://rdap.registry.click/rdap/domain/cerrowqei.click" in urls  # domain only, its registry


def test_older_domain_does_not_fire(registry):
    responses, _ = registry
    responses["employee-centre.com"] = (200, rdap_body("2018-12-14T21:59:46Z"))
    assert NewDomain().evaluate(email("https://employee-centre.com/")) is None


def test_exactly_seven_days_is_not_new(registry):
    responses, _ = registry
    responses["edge-case.com"] = (200, rdap_body("2026-10-10T09:00:00Z"))
    assert NewDomain().evaluate(email("https://edge-case.com/")) is None


def test_age_is_measured_from_the_email_date_not_today(registry):
    responses, _ = registry
    responses["old-email.com"] = (200, rdap_body("2020-01-01T00:00:00Z"))
    ctx = make_context(message={"id": "1", "subject": "", "date": "2020-01-03T00:00:00Z"},
                       sender=sender("x@old-email.com"), links=[], body={"text": "", "html": ""})
    assert NewDomain().evaluate(ctx).evidence[0].startswith("sender domain old-email.com was registered 2 days")


def test_popular_domains_and_tlds_without_rdap_are_skipped(registry):
    _, urls = registry
    ctx = email("https://www.google.com/", "https://shop.example.de/", sender_address="x@gmail.com")
    assert NewDomain().evaluate(ctx) is None
    assert urls == []


def test_registry_failure_means_failed_not_clean(registry):
    responses, _ = registry
    responses["small-shop.info"] = (503, {})
    with pytest.raises(RdapUnavailable, match="could not be checked"):
        NewDomain().evaluate(email())


def test_rate_limited_registry_backs_off(registry):
    responses, urls = registry
    responses["one.info"] = (429, {})
    client = RdapClient()
    with pytest.raises(RdapUnavailable):
        client.lookup("one.info")
    with pytest.raises(RdapUnavailable, match="backing off"):
        client.lookup("two.info")  # same registry: not asked again
    assert len(urls) == 1


def test_dates_are_cached(registry):
    responses, urls = registry
    responses["fresh-phish.com"] = (200, rdap_body("2026-10-16T00:00:00Z"))
    rule = NewDomain()
    rule.evaluate(email("https://fresh-phish.com/"))
    rule.evaluate(email("https://fresh-phish.com/"))
    assert sum("fresh-phish.com" in u for u in urls) == 1


def test_scores_thirty_and_is_suspicious_alone(registry):
    responses, _ = registry
    responses["fresh-phish.com"] = (200, rdap_body("2026-10-16T00:00:00Z"))
    report = make_report(message={"id": "1", "subject": "Hi", "date": EMAIL_DATE}, sender=sender("x@fresh-phish.com"))
    result = analyze(report, load_engine_config(BACKEND_ROOT / "config" / "rules.yaml"))
    assert ("new_domain", 30) in [(f.rule_id, f.score) for f in result.findings]
    assert result.verdict == "suspicious"
