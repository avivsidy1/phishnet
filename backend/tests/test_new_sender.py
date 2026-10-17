import pytest

from app.config import BACKEND_ROOT
from app.engine.loader import load_engine_config
from app.engine.scorer import analyze
from app.rules.new_sender import NewSender
from tests.conftest import make_context, make_report, sender

CONFIG = load_engine_config(BACKEND_ROOT / "config" / "rules.yaml")


def test_fires_for_a_new_sender():
    email = make_context(sender=sender("x@shop.example"), mailbox={"senderHistory": "new", "historyDays": 30})
    hit = NewSender().evaluate(email)
    assert hit is not None
    assert hit.evidence == ["you have never written to x@shop.example, and nothing from them is older than 30 days in your mailbox"]


@pytest.mark.parametrize("mailbox", [{"senderHistory": "established"}, {"senderHistory": "unknown"}, {}])
def test_does_not_fire_when_established_unknown_or_missing(mailbox):
    assert NewSender().evaluate(make_context(mailbox=mailbox)) is None


def test_scores_ten_and_can_be_switched_off():
    new = {"senderHistory": "new"}
    unpopular = sender("dana@small-shop.info")  # example.com would be exempt (Tranco #167 + DMARC pass)
    result = analyze(make_report(sender=unpopular, mailbox=new), CONFIG)
    assert [(f.rule_id, f.score) for f in result.findings] == [("new_sender", 10)]
    assert result.verdict == "safe"  # never decides alone
    off = analyze(make_report(sender=unpopular, mailbox=new, preferences={"disabledRules": ["new_sender"]}), CONFIG)
    assert off.findings == []


def test_invalid_mailbox_values_are_rejected():
    with pytest.raises(ValueError):
        make_report(mailbox={"senderHistory": "trusted"})


def auth_header(result: str, domain: str) -> list[dict]:
    return [{"name": "Authentication-Results", "value": f"mx.google.com; dmarc={result} header.from={domain}"}]


def test_authenticated_popular_service_is_never_new():
    # First email after signing up: no history at all, but it really is gitlab.com.
    email = make_context(sender=sender("gitlab@mg.gitlab.com"), headers=auth_header("pass", "mg.gitlab.com"),
                         mailbox={"senderHistory": "new"})
    assert NewSender().evaluate(email) is None


def test_popular_domain_without_dmarc_pass_is_still_new():
    email = make_context(sender=sender("security@gitlab.com"), headers=auth_header("fail", "gitlab.com"),
                         mailbox={"senderHistory": "new"})
    assert NewSender().evaluate(email) is not None


def test_free_mail_domains_get_no_exemption():
    email = make_context(sender=sender("stranger@gmail.com"), headers=auth_header("pass", "gmail.com"),
                         mailbox={"senderHistory": "new"})
    assert NewSender().evaluate(email) is not None


def test_unpopular_authenticated_domain_is_still_new():
    email = make_context(sender=sender("x@shop.example"), headers=auth_header("pass", "shop.example"),
                         mailbox={"senderHistory": "new"})
    assert NewSender().evaluate(email) is not None
