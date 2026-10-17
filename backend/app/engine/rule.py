"""Base class for detection rules.

To add a rule: create a new file in app/rules/ with one Rule subclass. It is discovered
automatically. Its score and params can be overridden (or the rule disabled) in config/rules.yaml.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.engine.context import EmailContext


@dataclass(frozen=True)
class Hit:
    """Returned by a rule that matched: a plain-language reason plus the concrete evidence."""

    explanation: str
    evidence: list[str] = field(default_factory=list)


class Rule(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    # One or two plain sentences for users (the add-on's rule info screen).
    description: ClassVar[str] = ""
    category: ClassVar[str]
    default_score: ClassVar[int]
    default_params: ClassVar[dict[str, Any]] = {}

    def __init__(self, score: int | None = None, params: dict[str, Any] | None = None) -> None:
        self.score = self.default_score if score is None else score
        self.params = {**self.default_params, **(params or {})}

    def warm_up(self) -> None:
        """Optional: load heavy resources (e.g. an ML model) at startup instead of on the first request."""

    @abstractmethod
    def evaluate(self, email: EmailContext) -> Hit | None:
        """Return a Hit if the rule matches, otherwise None.

        Rules should not perform network I/O. The one exception, virustotal_domain, uses a bounded
        timeout, a cache and a rate limit, and raises when it cannot check (listed in rulesFailed).
        """
