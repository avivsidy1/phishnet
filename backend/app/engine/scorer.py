"""Runs the rules against a report and turns the hits into a score and verdict."""

import logging

from app.engine.context import EmailContext
from app.engine.loader import EngineConfig
from app.engine.sender_lists import find_match, normalize_entries
from app.models import AnalysisResult, EmailReport, Finding, Preferences, Severity, Verdict

logger = logging.getLogger(__name__)

RESPONSE_SCHEMA_VERSION = "1.0"
MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_CHARS = 200
# Driven by the user's blocklist itself, so it can't be switched off separately.
ALWAYS_ON_RULES = frozenset({"user_blocklist"})


def analyze(report: EmailReport, config: EngineConfig) -> AnalysisResult:
    email = EmailContext.from_report(report, config.trusted_auth_servers)
    preferences = report.preferences
    notes: list[str] = []

    disabled = set(preferences.disabled_rules) - ALWAYS_ON_RULES
    rules = [r for r in config.rules if r.id not in disabled]
    turned_off = [r.title for r in config.rules if r.id in disabled]
    if turned_off:
        notes.append(f"Turned off by you ({len(turned_off)}): {', '.join(turned_off)}")

    findings: list[Finding] = []
    failed: list[str] = []
    for rule in rules:
        try:
            hit = rule.evaluate(email)
        except Exception as exc:  # one broken rule must not break the whole analysis
            # Log only the exception type: messages can contain email content.
            logger.error("Rule %s raised %s", rule.id, type(exc).__name__)
            failed.append(rule.id)
            continue
        if hit is None or rule.score == 0:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                category=rule.category,
                severity=_severity(rule.score),
                score=rule.score,
                explanation=hit.explanation,
                evidence=[_clip(e) for e in hit.evidence[:MAX_EVIDENCE_ITEMS]],
            )
        )

    findings = _apply_score_groups(findings, config.score_groups)
    trusted = _trusted_sender(email, preferences, findings, notes)
    if trusted:
        findings = [_not_counted(f, "Not counted in the score: the sender is on your trusted list.") for f in findings]
    findings.sort(key=lambda f: f.score, reverse=True)
    score = min(100, sum(f.score for f in findings))
    verdict = _verdict(score, config)

    return AnalysisResult(
        schema_version=RESPONSE_SCHEMA_VERSION,
        score=score,
        verdict=verdict,
        summary=_trusted_summary(len(findings)) if trusted else _summary(verdict, len(findings)),
        findings=findings,
        notes=notes,
        rules_evaluated=len(rules) - len(failed),
        rules_failed=failed,
        suspicious_threshold=config.suspicious_threshold,
        malicious_threshold=config.malicious_threshold,
    )


def _trusted_sender(email: EmailContext, preferences: Preferences, findings: list[Finding], notes: list[str]) -> bool:
    """True if the user's trusted list applies: sender listed, Gmail confirmed it (DMARC pass), not blocked.

    A From address is trivial to forge, so an unauthenticated match must not zero the score:
    otherwise trusting "mybank.com" would let anyone sending as @mybank.com through.
    """
    entries = normalize_entries(preferences.trusted_senders, allow_free_mail_domains=False)
    match = find_match(email.from_address, email.from_domain, entries)
    if not match:
        return False
    if any(f.rule_id == "user_blocklist" for f in findings):
        notes.append(f"The sender is on both your lists ({match} is trusted); the blocklist wins.")
        return False
    if not (email.auth.present and "pass" in email.auth.dmarc):
        notes.append(
            f"The sender matches your trusted list ({match}) but Gmail could not confirm it really "
            "came from there (DMARC did not pass), so the trusted list was not applied."
        )
        return False
    notes.append(f"Trusted sender: {email.from_address} matches your trusted list ({match}) and passed authentication.")
    return True


def _not_counted(finding: Finding, note: str) -> Finding:
    return finding.model_copy(
        update={"score": 0, "severity": _severity(0), "evidence": [note, *finding.evidence][:MAX_EVIDENCE_ITEMS]}
    )


def _trusted_summary(finding_count: int) -> str:
    if finding_count:
        return f"Trusted sender. {finding_count} signal(s) noted but not counted: still be careful with unexpected requests."
    return "Trusted sender. No warning signs found."


def _apply_score_groups(findings: list[Finding], groups: dict[str, list[str]]) -> list[Finding]:
    """If several rules of a group fired, keep only the highest score; the others stay as reasons at 0 points.

    The rules in a group react to the same evidence (e.g. phishing wording), so adding them up would
    count it more than once. Ties go to the rule listed first in the group.
    """
    by_id = {f.rule_id: f for f in findings}
    for members in groups.values():
        fired = [by_id[rule_id] for rule_id in members if rule_id in by_id]
        if len(fired) < 2:
            continue
        counted = max(fired, key=lambda f: f.score)
        for finding in fired:
            if finding is counted:
                continue
            by_id[finding.rule_id] = _not_counted(
                finding, f'Not counted in the score: overlaps with "{counted.title}", which counts instead.'
            )
    return list(by_id.values())


def _severity(score: int) -> Severity:
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def _verdict(score: int, config: EngineConfig) -> Verdict:
    if score >= config.malicious_threshold:
        return "malicious"
    if score >= config.suspicious_threshold:
        return "suspicious"
    return "safe"


def _summary(verdict: Verdict, finding_count: int) -> str:
    if verdict == "malicious":
        return (
            f"High risk: {finding_count} warning signs found. "
            "Do not click links, open attachments, or reply."
        )
    if verdict == "suspicious":
        return (
            f"Be careful: {finding_count} warning signs found. "
            "Verify the sender through another channel before acting."
        )
    if finding_count:
        return f"Probably safe. {finding_count} minor signal(s) noted."
    return "No warning signs found."


def _clip(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS] + "…"
