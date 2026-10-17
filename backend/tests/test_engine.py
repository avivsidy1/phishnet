from pathlib import Path

import pytest

from app.config import BACKEND_ROOT
from app.engine.loader import EngineConfig, discover_rule_classes, load_engine_config
from app.engine.rule import Hit, Rule
from app.engine.scorer import analyze
from tests.conftest import make_report, sender

DEFAULT_CONFIG = BACKEND_ROOT / "config" / "rules.yaml"


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_all_rules_discovered_and_enabled_by_default():
    config = load_engine_config(DEFAULT_CONFIG)
    assert {r.id for r in config.rules} == {cls.id for cls in discover_rule_classes()}


def test_disable_and_override_rule(tmp_path):
    config = load_engine_config(write_config(tmp_path, """
rules:
  spf_fail: { enabled: false }
  dmarc_fail: { score: 50 }
"""))
    ids = {r.id: r for r in config.rules}
    assert "spf_fail" not in ids
    assert ids["dmarc_fail"].score == 50


def test_unknown_rule_in_config_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown rules"):
        load_engine_config(write_config(tmp_path, "rules:\n  dmark_fail: { enabled: false }\n"))


def test_benign_email_is_safe():
    result = analyze(make_report(), load_engine_config(DEFAULT_CONFIG))
    assert result.verdict == "safe"
    assert result.score == 0


def test_phishing_email_is_malicious():
    report = make_report(
        message={"id": "2", "subject": "Action required: unusual activity"},
        sender=sender("security@paypa1.com", "PayPal Security"),
        headers=[{"name": "Authentication-Results", "value": "mx.google.com; spf=softfail; dmarc=fail"}],
        body={"text": "Verify your account within 24 hours or it will be closed.", "html": ""},
        links=[{"url": "http://203.0.113.9/login", "text": "https://www.paypal.com/signin", "source": "html"}],
    )
    result = analyze(report, load_engine_config(DEFAULT_CONFIG))
    assert result.verdict == "malicious"
    assert result.score == 100
    assert result.findings[0].score >= result.findings[-1].score  # sorted by impact


def test_failing_rule_is_reported_not_fatal():
    class Broken(Rule):
        id = "broken"
        title = "Broken"
        category = "test"
        default_score = 10

        def evaluate(self, email):
            raise RuntimeError("boom")

    config = EngineConfig(rules=[Broken()], suspicious_threshold=30, malicious_threshold=70, trusted_auth_servers=[])
    result = analyze(make_report(), config)
    assert result.rules_failed == ["broken"]
    assert result.verdict == "safe"


def fixed_rule(rule_id: str, points: int, fires: bool = True) -> Rule:
    class Fixed(Rule):
        id = rule_id
        title = f"Rule {rule_id}"
        category = "test"
        default_score = points

        def evaluate(self, email):
            return Hit(explanation="matched", evidence=["e1"]) if fires else None

    return Fixed()


def group_config(*rules: Rule, groups: dict[str, list[str]]) -> EngineConfig:
    return EngineConfig(
        rules=list(rules), suspicious_threshold=30, malicious_threshold=70, trusted_auth_servers=[], score_groups=groups
    )


def test_score_group_counts_only_the_highest_rule():
    config = group_config(
        fixed_rule("ml", 20), fixed_rule("words", 15), fixed_rule("urgent", 10), fixed_rule("other", 25),
        groups={"wording": ["ml", "words", "urgent"]},
    )
    result = analyze(make_report(), config)
    scores = {f.rule_id: f.score for f in result.findings}
    assert scores == {"other": 25, "ml": 20, "words": 0, "urgent": 0}
    assert result.score == 45
    words = next(f for f in result.findings if f.rule_id == "words")
    assert words.severity == "low"
    assert words.evidence == ['Not counted in the score: overlaps with "Rule ml", which counts instead.', "e1"]
    assert len(result.findings) == 4  # overlapped rules are still shown as reasons


def test_score_group_with_one_hit_is_unchanged():
    config = group_config(fixed_rule("ml", 20, fires=False), fixed_rule("words", 15), groups={"g": ["ml", "words"]})
    result = analyze(make_report(), config)
    assert [(f.rule_id, f.score) for f in result.findings] == [("words", 15)]
    assert result.score == 15


def test_score_group_tie_goes_to_first_listed_rule():
    config = group_config(fixed_rule("a", 10), fixed_rule("b", 10), groups={"g": ["b", "a"]})
    scores = {f.rule_id: f.score for f in analyze(make_report(), config).findings}
    assert scores == {"b": 10, "a": 0}


def test_wording_group_with_real_rules():
    report = make_report(
        message={"id": "3", "subject": "Urgent"},
        body={"text": "Urgent: verify your account immediately or it will be suspended.", "html": ""},
        links=[{"url": "https://example.com/x", "text": "here", "source": "html"}],
    )
    scores = {f.rule_id: f.score for f in analyze(report, load_engine_config(DEFAULT_CONFIG)).findings}
    assert scores["credential_request"] == 15
    assert scores["urgency_language"] == 0


@pytest.mark.parametrize(
    "groups, message",
    [
        ("  g: [dmarc_fail, dmark_fail]", "unknown rules"),
        ("  g: [dmarc_fail]", "at least two"),
        ("  g: [dmarc_fail, spf_fail]\n  h: [spf_fail, dkim_fail]", "only one group"),
    ],
)
def test_invalid_score_groups_are_rejected(tmp_path, groups, message):
    with pytest.raises(ValueError, match=message):
        load_engine_config(write_config(tmp_path, f"score_groups:\n{groups}\n"))


def test_html_to_text_strips_tags():
    report = make_report(body={"text": "", "html": '<p>Hello <b>you</b></p><a href="x">link</a>'})
    from app.engine.context import EmailContext
    text = EmailContext.from_report(report, ["mx.google.com"]).text
    assert "Hello" in text and "you" in text and "<" not in text


HOSTILE_HTML = {  # built inside the test: long parameters break pytest's test ids on Windows
    "only-lt": lambda: "<" * 120_000,
    "lt-a": lambda: "<a" * 60_000,
    "one-open-tag": lambda: "<" + "a" * 119_999,
    "empty-tags": lambda: "<>" * 60_000,
}


@pytest.mark.parametrize("case", sorted(HOSTILE_HTML))
def test_hostile_html_is_analyzed_quickly(case):
    """ReDoS regression: the old tag pattern took ~9.6 s on 120 KB of '<'."""
    import time
    html = HOSTILE_HTML[case]()
    config = load_engine_config(DEFAULT_CONFIG)  # outside the timing: first load reads the Tranco list
    report = make_report(body={"text": "", "html": html})
    start = time.perf_counter()
    analyze(report, config)
    assert time.perf_counter() - start < 0.5
