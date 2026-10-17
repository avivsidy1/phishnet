import gzip

import pytest

from app.engine.text_classifier import PhishingTextClassifier
from app.rules.dangerous_attachment import DangerousAttachment
from app.rules.display_name_spoof import DisplayNameSpoof
from app.rules.dmarc_fail import DmarcFail
from app.rules.embedded_form import EmbeddedForm
from app.rules.ip_address_url import IpAddressUrl
from app.rules.link_text_mismatch import LinkTextMismatch
from app.rules.lookalike_domain import LookalikeDomain
from app.rules.ml_phishing_text import MlPhishingText
from app.rules.punycode_domain import PunycodeDomain
from app.rules.reply_to_mismatch import ReplyToMismatch
from app.rules.urgency_language import UrgencyLanguage
from tests.conftest import make_context, sender


def link(url: str, text: str = "", source: str = "html") -> dict:
    return {"url": url, "text": text, "source": source}


def test_benign_email_triggers_nothing():
    email = make_context()
    for rule in [DmarcFail(), DisplayNameSpoof(), LookalikeDomain(), LinkTextMismatch(), ReplyToMismatch()]:
        assert rule.evaluate(email) is None, rule.id


def test_dmarc_fail_uses_trusted_header_only():
    forged = {"name": "Authentication-Results", "value": "evil.example; dmarc=pass"}
    real = {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dmarc=fail header.from=paypal.com"}
    assert DmarcFail().evaluate(make_context(headers=[forged, real])) is not None
    # A forged "fail" from an untrusted server must be ignored too.
    assert DmarcFail().evaluate(make_context(headers=[{"name": "Authentication-Results", "value": "evil.example; dmarc=fail"}])) is None


def test_display_name_with_foreign_address():
    rule = DisplayNameSpoof()
    assert rule.evaluate(make_context(sender=sender("x@evil.com", "ceo@mycompany.com"))) is not None
    assert rule.evaluate(make_context(sender=sender("dana@mail.example.com", "dana@example.com"))) is None
    # Brand names alone are not checked.
    assert rule.evaluate(make_context(sender=sender("x@gmail.com", "PayPal Support"))) is None


def test_reply_to_mismatch():
    s = sender("billing@example.com")
    s["replyTo"] = [{"address": "collect@other.net", "domain": "other.net"}]
    assert ReplyToMismatch().evaluate(make_context(sender=s)) is not None


@pytest.fixture
def small_popular_list(tmp_path):
    path = tmp_path / "popular.txt.gz"
    with gzip.open(path, "wt", encoding="ascii") as f:
        f.write("\n".join(["paypal.com", "google.com", "microsoft.com", "instagram.com", "linkedin.com", "example.com"]))
    return str(path)


@pytest.mark.parametrize(
    ("domain", "imitates"),
    [
        ("paypa1.com", "paypal.com"),         # 1 -> l
        ("rnicrosoft.com", "microsoft.com"),  # rn -> m
        ("g00gle.com", "google.com"),         # two swaps
        ("lnstagram.com", "instagram.com"),   # l -> i (looks like a capital I)
        ("linkedln.com", "linkedin.com"),     # l -> i
        ("paypa1.top", "paypal.com"),         # fallback to .com
    ],
)
def test_lookalike_detects_deobfuscated_popular_domain(small_popular_list, domain, imitates):
    rule = LookalikeDomain(params={"domains_file": small_popular_list, "target_top_n": None})
    hit = rule.evaluate(make_context(sender=sender(f"a@{domain}")))
    assert hit is not None and imitates in hit.evidence[0]


@pytest.mark.parametrize(
    "domain",
    [
        "paypal.com",               # the real, popular domain
        "example.com",              # popular, nothing to undo
        "paypal-secure-login.com",  # brand inside a name: out of scope by design
        "goggle.com",               # a typo, not a look-alike character
        "small-bakery.com",         # unknown domain that de-obfuscates to nothing popular
        "lnc.ru",                   # too short: collides with inc.ru
        "88800.com",                # mostly digits
    ],
)
def test_lookalike_ignores(small_popular_list, domain):
    rule = LookalikeDomain(params={"domains_file": small_popular_list, "target_top_n": None})
    assert rule.evaluate(make_context(sender=sender(f"a@{domain}"))) is None


def test_lookalike_checks_link_domains(small_popular_list):
    rule = LookalikeDomain(params={"domains_file": small_popular_list, "target_top_n": None})
    hit = rule.evaluate(make_context(links=[link("https://login.paypa1.com/verify")]))
    assert hit is not None and hit.evidence[0].startswith("link domain paypa1.com")


def test_lookalike_with_real_tranco_list():
    rule = LookalikeDomain()
    assert rule.imitated_domain("paypa1.com") == ("paypal.com", ["1→l"])
    assert rule.imitated_domain("paypal.com") is None
    assert rule.imitated_domain("gmail.com") is None


@pytest.mark.parametrize(
    ("url", "text"),
    [
        ("https://evil.ru/login", "https://www.paypal.com"),
        ("https://evil.ru/login", "WWW.PAYPAL.COM"),
        ("https://evil.ru/login", "Sign in at www.paypal.com to continue"),   # address inside a sentence
        ("https://paypal.com.account-verify.ru/", "paypal.com"),             # subdomain trick
        ("mailto:help@evil.com", "support@paypal.com"),                     # email address vs mailto target
        ("https://evil.ru/form", "Questions? Write to support@paypal.com"),  # email address in a sentence
        ("https://ct.sendgrid.net.evil.ru/x", "www.shop-example.com"),       # fake tracking host
    ],
)
def test_link_text_mismatch_fires(url, text):
    assert LinkTextMismatch().evaluate(make_context(links=[link(url, text)])) is not None


@pytest.mark.parametrize(
    ("url", "text"),
    [
        ("https://www.paypal.com/x", "paypal.com"),
        ("https://mail.paypal.com/x", "Go to www.paypal.com"),                     # same registrable domain
        ("mailto:support@paypal.com", "support@paypal.com"),
        ("https://evil.ru", "Click here"),                                       # no address claimed
        ("https://evil.ru", "Download report.pdf"),                              # .pdf is not a domain
        ("https://evil.ru", "Built with Node.js"),
        ("https://us1.list-manage.com/track/click?u=1", "www.shop-example.com"),  # Mailchimp tracking
        ("https://ct.sendgrid.net/ls/click?upn=abc", "https://www.shop-example.com/sale"),
        ("https://eur01.safelinks.protection.outlook.com/?url=x", "https://www.paypal.com"),  # Safe Links
    ],
)
def test_link_text_mismatch_ignores(url, text):
    assert LinkTextMismatch().evaluate(make_context(links=[link(url, text)])) is None


def test_link_text_mismatch_ignores_plain_text_links():
    assert LinkTextMismatch().evaluate(make_context(links=[link("https://evil.ru", "paypal.com", "text")])) is None


def test_ip_address_url():
    assert IpAddressUrl().evaluate(make_context(links=[link("http://192.168.10.5/login")])) is not None


def test_punycode_domain():
    assert PunycodeDomain().evaluate(make_context(links=[link("https://xn--pple-43d.com/")])) is not None


def test_dangerous_attachment():
    rule = DangerousAttachment()
    hit = rule.evaluate(make_context(attachments=[{"filename": "invoice.pdf.exe"}]))
    assert hit is not None and "disguised" in hit.evidence[0]
    assert rule.evaluate(make_context(attachments=[{"filename": "report.pdf"}])) is None


def test_urgency_requires_multiple_phrases():
    rule = UrgencyLanguage()
    assert rule.evaluate(make_context(message={"id": "1", "subject": "Urgent"})) is None
    body = {"text": "Unusual activity detected. Act now or your account will be suspended.", "html": ""}
    assert rule.evaluate(make_context(body=body)) is not None


def test_embedded_password_form():
    body = {"text": "", "html": '<form action="https://x"><input name="p" type="password"></form>'}
    assert EmbeddedForm().evaluate(make_context(body=body)) is not None


def test_ml_phishing_text_fires_only_above_threshold(monkeypatch):
    seen = []

    def fake_probability(probability):
        def rate(self, text):
            seen.append(text)
            return probability
        return rate

    rule = MlPhishingText()
    email = make_context(message={"id": "1", "subject": "Quick favor"}, body={"text": "Buy gift cards today.", "html": ""})

    monkeypatch.setattr(PhishingTextClassifier, "phishing_probability", fake_probability(0.9995))
    hit = rule.evaluate(email)
    assert hit is not None and "99.95%" in hit.evidence[0]
    assert seen[-1] == "Quick favor\n\nBuy gift cards today."  # subject + body, original case

    monkeypatch.setattr(PhishingTextClassifier, "phishing_probability", fake_probability(0.998))  # just under 99.85%
    assert rule.evaluate(email) is None


def test_ml_phishing_text_skips_empty_email(monkeypatch):
    monkeypatch.setattr(PhishingTextClassifier, "phishing_probability", lambda self, text: 1.0)
    email = make_context(message={"id": "1", "subject": ""}, body={"text": "", "html": ""}, links=[])
    assert MlPhishingText().evaluate(email) is None
