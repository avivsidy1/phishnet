"""Discovers rule classes in app/rules/ and applies config/rules.yaml to them."""

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

import app.rules as rules_package
from app.engine.rule import Rule


@dataclass(frozen=True)
class EngineConfig:
    rules: list[Rule]
    suspicious_threshold: int
    malicious_threshold: int
    trusted_auth_servers: list[str]
    # Rules that react to the same evidence: if several in a group fire, only the highest score counts.
    score_groups: dict[str, list[str]] = field(default_factory=dict)


def discover_rule_classes() -> list[type[Rule]]:
    """Every Rule subclass defined in a module of app/rules/ (modules starting with '_' are helpers)."""
    classes: list[type[Rule]] = []
    for module_info in pkgutil.iter_modules(rules_package.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{rules_package.__name__}.{module_info.name}")
        for obj in vars(module).values():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Rule)
                and obj.__module__ == module.__name__
                and not inspect.isabstract(obj)
            ):
                classes.append(obj)

    ids = [cls.id for cls in classes]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate rule ids: {sorted(duplicates)}")
    return sorted(classes, key=lambda cls: cls.id)


def load_engine_config(path: Path) -> EngineConfig:
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rule_settings: dict[str, Any] = raw.get("rules") or {}
    classes = discover_rule_classes()

    # Fail fast on typos: a misspelled rule id in the config would otherwise be silently ignored.
    unknown = set(rule_settings) - {cls.id for cls in classes}
    if unknown:
        raise ValueError(f"{path} references unknown rules: {sorted(unknown)}")

    rules: list[Rule] = []
    for cls in classes:
        settings = rule_settings.get(cls.id) or {}
        if not settings.get("enabled", True):
            continue
        score = settings.get("score")
        if score is not None and not (isinstance(score, int) and 0 <= score <= 100):
            raise ValueError(f"Rule {cls.id}: score must be an integer between 0 and 100")
        rules.append(cls(score=score, params=settings.get("params")))

    verdict = raw.get("verdict") or {}
    suspicious = verdict.get("suspicious_threshold", 30)
    malicious = verdict.get("malicious_threshold", 70)
    if not (0 < suspicious < malicious <= 100):
        raise ValueError("Verdict thresholds must satisfy 0 < suspicious < malicious <= 100")

    return EngineConfig(
        rules=rules,
        suspicious_threshold=suspicious,
        malicious_threshold=malicious,
        trusted_auth_servers=raw.get("trusted_auth_servers") or ["mx.google.com"],
        score_groups=_score_groups(raw.get("score_groups") or {}, {cls.id for cls in classes}),
    )


def _score_groups(groups: dict[str, Any], known_ids: set[str]) -> dict[str, list[str]]:
    """Validate score groups: lists of known rule ids, each rule in at most one group."""
    seen: set[str] = set()
    for name, members in groups.items():
        if not isinstance(members, list) or len(members) < 2:
            raise ValueError(f"Score group {name}: must list at least two rule ids")
        unknown = set(members) - known_ids
        if unknown:
            raise ValueError(f"Score group {name} references unknown rules: {sorted(unknown)}")
        repeated = seen & set(members)
        if repeated or len(set(members)) != len(members):
            raise ValueError(f"Score group {name}: a rule can belong to only one group")
        seen |= set(members)
    return {name: list(members) for name, members in groups.items()}
