"""The user's own settings: trusted/blocked senders and rules turned off."""

import pytest

from app.config import BACKEND_ROOT
from app.engine import virustotal
from app.engine.loader import load_engine_config
from app.engine.scorer import analyze
from app.engine.sender_lists import find_match, normalize_entries
from tests.conftest import make_report, sender

CONFIG = load_engine_config(BACKEND_ROOT / "config" / "rules.yaml")
DMARC_PASS = [{"name": "Authentication-Results", "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass header.from=shop.com"}]
DMARC_FAIL = [{"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=fail; dmarc=fail header.from=shop.com"}]
# Risky content from the sender: an IP-address link (20) shown as a different site (30).
RISKY_LINKS = [{"url": "http://203.0.113.9/login", "text": "https://www.shop.com/account", "source": "html"}]


def report(preferences=None, address="news@mail.shop.com", headers=DMARC_PASS, links=RISKY_LINKS):
    return make_report(
        sender=sender(address),
        headers=headers,
        links=links,
        body={"text": "Hello", "html": ""},
        preferences=preferences or {},
    )


# --- entries --------------------------------------------------------------------------------

def test_entries_are_normalized_and_invalid_ones_dropped():
    raw = [" Bob@Shop.com ", "shop.com", "SHOP.COM", "not an entry", "@shop.com", "localhost", "gmail.com"]
    assert normalize_entries(raw, allow_free_mail_domains=True) == ["bob@shop.com", "shop.com", "gmail.com"]
    assert normalize_entries(raw, allow_free_mail_domains=False) == ["bob@shop.com", "shop.com"]


@pytest.mark.parametrize(
    "address, domain, entries, expected",
    [
        ("bob@shop.com", "shop.com", ["bob@shop.com"], "bob@shop.com"),
        ("eve@shop.com", "shop.com", ["bob@shop.com"], None),
        ("x@mail.shop.com", "mail.shop.com", ["shop.com"], "shop.com"),  # subdomains covered
        ("x@evilshop.com", "evilshop.com", ["shop.com"], None),  # not a suffix match on labels
        ("x@shop.com.evil.ru", "shop.com.evil.ru", ["shop.com"], None),
    ],
)
def test_matching(address, domain, entries, expected):
    assert find_match(address, domain, entries) == expected


# --- blocklist ------------------------------------------------------------------------------

def test_blocked_sender_is_always_malicious():
    result = analyze(report({"blockedSenders": ["shop.com"]}, links=[]), CONFIG)
    assert result.score == 100 and result.verdict == "malicious"
    assert result.findings[0].rule_id == "user_blocklist"
    assert result.findings[0].evidence == ["sender news@mail.shop.com matches your blocklist entry shop.com"]


def test_blocklist_needs_no_authentication():
    result = analyze(report({"blockedSenders": ["news@mail.shop.com"]}, headers=DMARC_FAIL, links=[]), CONFIG)
    assert result.verdict == "malicious"


# --- trusted list ---------------------------------------------------------------------------

def test_trusted_authenticated_sender_scores_zero_but_findings_stay_visible():
    baseline = analyze(report(), CONFIG)
    assert baseline.score >= 50

    result = analyze(report({"trustedSenders": ["shop.com"]}), CONFIG)
    assert result.score == 0 and result.verdict == "safe"
    assert {f.rule_id for f in result.findings} == {f.rule_id for f in baseline.findings}
    assert all(f.score == 0 for f in result.findings)
    assert result.findings[0].evidence[0] == "Not counted in the score: the sender is on your trusted list."
    assert result.summary.startswith("Trusted sender.")
    assert result.notes == ["Trusted sender: news@mail.shop.com matches your trusted list (shop.com) and passed authentication."]


def test_trusted_list_ignored_when_dmarc_does_not_pass():
    result = analyze(report({"trustedSenders": ["shop.com"]}, headers=DMARC_FAIL), CONFIG)
    assert result.score > 0
    assert "DMARC did not pass" in result.notes[0]


def test_trusted_list_ignored_without_a_trusted_auth_header():
    forged = [{"name": "Authentication-Results", "value": "evil.example; dmarc=pass header.from=shop.com"}]
    result = analyze(report({"trustedSenders": ["shop.com"]}, headers=forged), CONFIG)
    assert result.score > 0


def test_free_mail_domain_cannot_be_trusted_but_an_address_can():
    gmail_pass = [{"name": "Authentication-Results", "value": "mx.google.com; dmarc=pass header.from=gmail.com"}]
    whole_domain = analyze(report({"trustedSenders": ["gmail.com"]}, address="anyone@gmail.com", headers=gmail_pass), CONFIG)
    assert whole_domain.score > 0 and whole_domain.notes == []
    one_address = analyze(report({"trustedSenders": ["friend@gmail.com"]}, address="friend@gmail.com", headers=gmail_pass), CONFIG)
    assert one_address.score == 0


def test_blocklist_wins_over_trusted_list():
    result = analyze(report({"trustedSenders": ["shop.com"], "blockedSenders": ["news@mail.shop.com"]}), CONFIG)
    assert result.verdict == "malicious"
    assert "blocklist wins" in result.notes[0]


# --- rules turned off -----------------------------------------------------------------------

def test_disabled_rules_do_not_run_and_are_noted():
    baseline = analyze(report(), CONFIG)
    result = analyze(report({"disabledRules": ["ip_address_url", "no_such_rule"]}), CONFIG)
    assert "ip_address_url" not in {f.rule_id for f in result.findings}
    assert result.rules_evaluated == baseline.rules_evaluated - 1
    assert result.notes == ["Turned off by you (1): Link points to a raw IP address"]  # unknown ids ignored


def test_blocklist_rule_cannot_be_turned_off():
    result = analyze(report({"disabledRules": ["user_blocklist"], "blockedSenders": ["shop.com"]}, links=[]), CONFIG)
    assert result.verdict == "malicious" and result.notes == []


def test_turning_off_virustotal_means_no_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(virustotal, "_http_get", lambda url, key, timeout: calls.append(url) or (404, {}))
    analyze(report({"disabledRules": ["virustotal_domain"]}, address="x@rare-domain-for-test.info"), CONFIG)
    assert calls == []


def test_report_without_preferences_still_works():
    data = make_report().model_dump(by_alias=True)
    data.pop("preferences")
    assert analyze(type(make_report()).model_validate(data), CONFIG).verdict == "safe"


# --- strict validation of client data --------------------------------------------------

U = chr  # build invisible characters from code points, no literal escapes


@pytest.mark.parametrize("raw", [
    '"john smith"@company.com', "<script>@x.com", "o'brien@x.com", "x@y", "@x.com", "x@-bad.com", "x@x..com",
    "../etc/passwd", "javascript:alert(1)", "a" * 65 + "@x.com", "x@" + "a" * 64 + ".com", "x@x.c0m",
    "ab" + U(0x202E) + "cd@x.com", "a" + U(0x200B) + "@x.com", "a@x.com" + U(0), "a" + U(10) + "b@x.com",
    U(0xFEFF) + "x.com", "x" + U(0x2066) + ".com",
])
def test_hostile_entries_are_dropped(raw):
    assert normalize_entries([raw], allow_free_mail_domains=True) == []


def test_non_string_entries_are_dropped():
    assert normalize_entries([None, 42, {"a": 1}], allow_free_mail_domains=True) == []  # type: ignore[list-item]


def test_hostile_trusted_entry_is_never_echoed_back():
    hostile = "<b>x</b>@shop.com"
    result = analyze(report({"trustedSenders": [hostile, "shop.com"]}), CONFIG)
    assert all("<b>" not in note for note in result.notes)
    assert result.score == 0  # the valid entry still applies


# --- trusted file types ----------------------------------------------------------------

def attachment_report(names, trusted=None):
    files = [{"filename": n, "contentType": "application/octet-stream", "sizeBytes": 10} for n in names]
    return make_report(attachments=files, preferences={"trustedExtensions": trusted or []})


def test_trusted_extension_is_not_flagged_by_type():
    findings = analyze(attachment_report(["report.html"], ["html"]), CONFIG).findings
    assert "dangerous_attachment" not in {f.rule_id for f in findings}


def test_untrusted_extensions_still_flagged():
    result = analyze(attachment_report(["report.html", "setup.exe"], ["html"]), CONFIG)
    hit = next(f for f in result.findings if f.rule_id == "dangerous_attachment")
    assert hit.evidence == ["setup.exe: .exe files can run code or open fake login pages"]


def test_disguised_name_is_flagged_even_if_its_type_is_trusted():
    result = analyze(attachment_report(["invoice.pdf.html"], ["html"]), CONFIG)
    hit = next(f for f in result.findings if f.rule_id == "dangerous_attachment")
    assert hit.evidence == ["invoice.pdf.html: disguised .html file"]


@pytest.mark.parametrize("bad", [".html", "HTML", "ht ml", "a" * 11, "<b>", "", "ht" + chr(0x202E) + "ml"])
def test_malformed_trusted_extensions_are_rejected(bad):
    with pytest.raises(ValueError):
        attachment_report(["x.html"], [bad])
