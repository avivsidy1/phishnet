import pytest

from app.config import BACKEND_ROOT
from app.engine.loader import load_engine_config
from app.engine.scorer import analyze
from app.rules.subdomain_brand import SubdomainBrand
from tests.conftest import make_context, make_report, sender


@pytest.fixture(scope="module")
def rule():
    return SubdomainBrand()


@pytest.mark.parametrize("host, brand, real", [
    ("paypal.somethingmalicious.com", "paypal.com", "somethingmalicious.com"),     # brand name as a label
    ("paypal.com.somethingmalicious.com", "paypal.com", "somethingmalicious.com"), # whole brand domain
    ("login.paypal.com.evil.ru", "paypal.com", "evil.ru"),
    ("amazon.de.evil.top", "amazon.de", "evil.top"),
    ("microsoft.evil.co.uk", "microsoft.com", "evil.co.uk"),
    ("netflix.account-verify.ru", "netflix.com", "account-verify.ru"),
])
def test_brand_in_subdomain_of_unrelated_domain(rule, host, brand, real):
    assert rule.imitated(host) == (brand, real)


@pytest.mark.parametrize("host", [
    "www.paypal.com", "paypal.com", "docs.google.com",   # the real sites
    "apple.stackexchange.com",                            # Y is itself a top-10k site
    "login.mycompany.com", "mail.mycompany.com", "account.small-shop.info", "cloud.example-firm.de",  # common words
    "www.mycompany.com", "shop.small-store.info",
    "paypal-login.evil.com",                              # no subdomain: combosquatting, not this rule
])
def test_not_flagged(rule, host):
    assert rule.imitated(host) is None


def test_checks_sender_and_link_hosts_with_evidence(rule):
    email = make_context(
        sender=sender("alerts@paypal.secure-mail.top"),
        links=[{"url": "https://apple.com.id-verify.ru/login", "text": "", "source": "html"},
               {"url": "https://www.google.com/", "text": "", "source": "html"}],
    )
    hit = rule.evaluate(email)
    assert hit.evidence == [
        "sender paypal.secure-mail.top puts paypal.com in front of the real domain secure-mail.top",
        "link apple.com.id-verify.ru puts apple.com in front of the real domain id-verify.ru",
    ]


def test_scores_thirty(rule):
    report = make_report(links=[{"url": "https://paypal.somethingmalicious.com/", "text": "", "source": "html"}])
    result = analyze(report, load_engine_config(BACKEND_ROOT / "config" / "rules.yaml"))
    assert ("subdomain_brand", 30) in [(f.rule_id, f.score) for f in result.findings]
