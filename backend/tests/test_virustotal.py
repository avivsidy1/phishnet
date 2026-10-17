import datetime

import pytest

from app.config import BACKEND_ROOT
from app.engine import virustotal
from app.engine.loader import load_engine_config
from app.engine.scorer import analyze
from app.engine.virustotal import VirusTotalUnavailable
from app.engine.vt_key import VtKeySource
from app.rules.virustotal_domain import VirusTotalDomain
from tests.conftest import make_context, make_report, sender

DEFAULT_CONFIG = BACKEND_ROOT / "config" / "rules.yaml"
CREATED = int(datetime.datetime(2026, 10, 10, tzinfo=datetime.UTC).timestamp())


def vt_body(malicious: int, created: int | None = None) -> dict:
    results = {f"Vendor{i}": {"category": "malicious", "result": "phishing"} for i in range(malicious)}
    results["CleanVendor"] = {"category": "harmless", "result": "clean"}
    attributes = {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 30, "timeout": 0},
        "last_analysis_results": results,
    }
    if created:
        attributes["creation_date"] = created
    return {"data": {"attributes": attributes}}


@pytest.fixture
def vt(monkeypatch):
    """Fake VirusTotal: answers from `responses` (domain -> (status, body)), 404 otherwise; records calls."""
    responses: dict[str, tuple[int, dict]] = {}
    calls: list[str] = []

    def fake_get(url, api_key, timeout):
        domain = url.rsplit("/", 1)[-1]
        calls.append(domain)
        assert api_key == "test-vt-key"
        return responses.get(domain, (404, {}))

    monkeypatch.setattr(virustotal, "_http_get", fake_get)
    return responses, calls


SENDER = sender("dana@small-shop.info")  # not popular, so it is looked up (example.com is Tranco #167)


def email_with_links(*urls: str, text: str = ""):
    links = [{"url": u, "text": "", "source": "html"} for u in urls]
    return make_context(sender=SENDER, links=links, body={"text": text, "html": ""})


def test_fires_when_two_or_more_vendors_flag_a_domain(vt):
    responses, calls = vt
    responses["consultawebgov.info"] = (200, vt_body(11, CREATED))
    hit = VirusTotalDomain().evaluate(email_with_links("https://login.consultawebgov.info/x?token=secret"))
    assert hit is not None
    assert hit.evidence[0].startswith("link domain consultawebgov.info: 11/101 vendors flag it as malicious; registered 2026-10-10")
    assert "flagged by Vendor0 (phishing), Vendor1 (phishing)" in hit.evidence[0]
    assert "consultawebgov.info" in calls and not any("token" in c or "/" in c for c in calls)  # domain only


def test_single_vendor_is_not_enough(vt):
    responses, _ = vt
    responses["somewhere.info"] = (200, vt_body(1))
    assert VirusTotalDomain().evaluate(email_with_links("https://somewhere.info/")) is None


def test_popular_domains_are_never_sent(vt):
    _, calls = vt
    assert VirusTotalDomain().evaluate(email_with_links("https://www.google.com/", "https://github.com/x")) is None
    assert calls == ["small-shop.info"]  # only the unpopular sender domain


def test_sender_text_and_link_domains_are_checked_ips_are_not(vt):
    responses, calls = vt
    responses["bad-sender.info"] = (200, vt_body(5))
    responses["bad-text.info"] = (200, vt_body(3))
    report_context = make_context(
        sender=sender("x@mail.bad-sender.info"),
        body={"text": "Pay at bad-text.info today", "html": ""},
        links=[{"url": "http://203.0.113.9/login", "text": "", "source": "html"}],
    )
    hit = VirusTotalDomain().evaluate(report_context)
    assert [e.split(":")[0] for e in hit.evidence] == ["sender domain bad-sender.info", "text domain bad-text.info"]
    assert "203.0.113.9" not in calls


def test_answers_are_cached_including_not_found(vt):
    responses, calls = vt
    responses["evil-login.top"] = (200, vt_body(4))
    rule = VirusTotalDomain()
    email = email_with_links("https://evil-login.top/a")
    assert rule.evaluate(email) is not None
    assert rule.evaluate(email) is not None
    assert calls.count("evil-login.top") == 1
    assert calls.count("small-shop.info") == 1  # 404 cached too


def test_lookups_per_email_are_capped_and_unchecked_means_failed_not_clean(vt):
    _, calls = vt
    rule = VirusTotalDomain(params={"max_lookups_per_email": 2, "requests_per_minute": 100})
    email = email_with_links(*(f"https://site{i}.info/" for i in range(4)))
    with pytest.raises(VirusTotalUnavailable, match="could not be checked"):
        rule.evaluate(email)
    assert len(calls) == 2


def test_rate_limit_is_enforced_locally(vt):
    _, calls = vt
    rule = VirusTotalDomain(params={"max_lookups_per_email": 10, "requests_per_minute": 3})
    with pytest.raises(VirusTotalUnavailable):
        rule.evaluate(email_with_links(*(f"https://site{i}.info/" for i in range(5))))
    assert len(calls) == 3


def test_quota_error_backs_off(vt):
    responses, calls = vt
    responses["small-shop.info"] = (429, {"error": {"code": "QuotaExceededError"}})
    rule = VirusTotalDomain()
    with pytest.raises(VirusTotalUnavailable):
        rule.evaluate(email_with_links())
    with pytest.raises(VirusTotalUnavailable):
        rule.evaluate(email_with_links())
    assert len(calls) == 1  # second email doesn't call during the back-off


def test_hit_still_reported_when_some_domains_unchecked(vt):
    responses, _ = vt
    responses["evil-login.top"] = (200, vt_body(4))
    rule = VirusTotalDomain(params={"max_lookups_per_email": 2})
    hit = rule.evaluate(email_with_links("https://evil-login.top/", "https://other1.info/", "https://other2.info/"))
    assert hit is not None
    assert hit.evidence[-1] == "2 other domain(s) could not be checked right now"


def test_missing_key_is_reported_as_failed_rule(vt):
    rule = VirusTotalDomain()
    rule.client.key_source = VtKeySource("", "VT_API_KEY", "")  # nothing configured
    config = load_engine_config(DEFAULT_CONFIG)
    config.rules[:] = [r if r.id != rule.id else rule for r in config.rules]
    result = analyze(make_report(sender=SENDER), config)
    assert "virustotal_domain" in result.rules_failed


# --- attachments (virustotal_file) ------------------------------------------------------------

from app.rules.virustotal_file import VirusTotalFile  # noqa: E402

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
CLEAN = "a" * 64


def email_with_attachments(*files):
    attachments = [{"filename": name, "contentType": "application/octet-stream", "sizeBytes": 68, "sha256": sha}
                   for name, sha in files]
    return make_context(sender=SENDER, attachments=attachments)


def test_file_fires_when_three_engines_detect_it(vt):
    responses, calls = vt
    responses[EICAR] = (200, vt_body(66))
    hit = VirusTotalFile().evaluate(email_with_attachments(("invoice.pdf", EICAR)))
    assert hit.evidence == ["attachment invoice.pdf: 66/156 antivirus engines detect it; e.g. Vendor0 (phishing), Vendor1 (phishing), Vendor10 (phishing), …"]
    assert calls == [EICAR]  # only the hash is sent


def test_file_with_two_detections_does_not_fire(vt):
    responses, _ = vt
    responses[CLEAN] = (200, vt_body(2))
    assert VirusTotalFile().evaluate(email_with_attachments(("report.docx", CLEAN))) is None


def test_unknown_file_and_unhashed_file_do_not_fire(vt):
    _, calls = vt
    email = email_with_attachments(("new.pdf", CLEAN), ("huge.iso", None))
    assert VirusTotalFile().evaluate(email) is None
    assert calls == [CLEAN]


def test_same_file_twice_is_looked_up_once(vt):
    responses, calls = vt
    responses[EICAR] = (200, vt_body(10))
    hit = VirusTotalFile().evaluate(email_with_attachments(("a.exe", EICAR), ("b.exe", EICAR)))
    assert len(hit.evidence) == 1 and calls == [EICAR]


def test_domain_and_file_rules_share_one_rate_limit(vt):
    _, calls = vt
    domain_rule = VirusTotalDomain(params={"max_lookups_per_email": 10})
    file_rule = VirusTotalFile()
    assert domain_rule.client is file_rule.client
    with pytest.raises(VirusTotalUnavailable):  # sender + 3 links = 4 lookups: the whole minute's budget
        domain_rule.evaluate(email_with_links(*(f"https://site{i}.info/" for i in range(4))))
    with pytest.raises(VirusTotalUnavailable, match="could not be checked"):
        file_rule.evaluate(email_with_attachments(("x.pdf", CLEAN)))
    assert len(calls) == 4


def test_file_scores_seventy_and_is_malicious_alone(vt):
    responses, _ = vt
    responses[EICAR] = (200, vt_body(66))
    report = make_report(attachments=[{"filename": "eicar.txt", "contentType": "text/plain", "sizeBytes": 68, "sha256": EICAR}])
    result = analyze(report, load_engine_config(DEFAULT_CONFIG))
    assert ("virustotal_file", 70) in [(f.rule_id, f.score) for f in result.findings]
    assert result.verdict == "malicious"
