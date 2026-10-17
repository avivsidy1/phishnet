"""API contract: the report the add-on sends, and the analysis we return.

Every field is bounded. The report is built from attacker-controlled email content,
so the schema is the first line of defense, not just documentation.
JSON uses camelCase (to match the add-on); Python uses snake_case.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from pydantic.alias_generators import to_camel

MAX_STRING = 200_000


class ApiModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="ignore",
        str_max_length=MAX_STRING,
    )


# --- Request: the report produced by the add-on -----------------------------------


class Address(ApiModel):
    raw: str = Field(default="", max_length=2_000)
    name: str = Field(default="", max_length=1_000)
    address: str = Field(default="", max_length=500)
    domain: str | None = Field(default=None, max_length=255)


class MessageInfo(ApiModel):
    id: str = Field(max_length=200)
    thread_id: str | None = Field(default=None, max_length=200)
    date: str | None = Field(default=None, max_length=100)
    subject: str = Field(default="", max_length=2_000)
    raw_size_bytes: int | None = Field(default=None, ge=0)


class Sender(ApiModel):
    from_: Address | None = Field(default=None, alias="from")
    reply_to: list[Address] = Field(default_factory=list, max_length=50)
    return_path: str | None = Field(default=None, max_length=2_000)


class Recipients(ApiModel):
    to: list[Address] = Field(default_factory=list, max_length=500)
    cc: list[Address] = Field(default_factory=list, max_length=500)


class Header(ApiModel):
    name: str = Field(max_length=200)
    value: str = Field(max_length=10_000)


class Body(ApiModel):
    text: str = Field(default="", max_length=60_000)
    text_length: int = Field(default=0, ge=0)
    text_truncated: bool = False
    html: str = Field(default="", max_length=120_000)
    html_length: int = Field(default=0, ge=0)
    html_truncated: bool = False


class Link(ApiModel):
    url: str = Field(max_length=8_192)
    text: str = Field(default="", max_length=2_000)
    source: Literal["html", "text"]


class Attachment(ApiModel):
    filename: str = Field(default="", max_length=1_000)
    content_type: str = Field(default="", max_length=255)
    size_bytes: int = Field(default=0, ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


# One trusted/blocked entry: an address or a domain (validated further in engine/sender_lists.py).
ListEntry = Annotated[str, StringConstraints(max_length=254)]
MAX_LIST_ENTRIES = 200


class Preferences(ApiModel):
    """The user's own settings, stored in the add-on (Apps Script user properties).

    Client-supplied, so bounded here; they only ever change this user's own result.
    """

    # Rule ids: strict pattern; anything else rejects the request (422), it can't come from our add-on.
    disabled_rules: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]] = Field(
        default_factory=list, max_length=100
    )
    trusted_senders: list[ListEntry] = Field(default_factory=list, max_length=MAX_LIST_ENTRIES)
    blocked_senders: list[ListEntry] = Field(default_factory=list, max_length=MAX_LIST_ENTRIES)
    # File types the user trusts (no dot, lowercase). Malformed -> 422, like rule ids.
    trusted_extensions: list[Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,10}$")]] = Field(
        default_factory=list, max_length=50
    )


class MailboxContext(ApiModel):
    """Facts the add-on derived from the user's mailbox (schema 1.2). Never mailbox content.

    sender_history: "established" = the user ever sent mail to the sender, or received mail from
    them more than `history_days` before this email; "new" = neither;
    "unknown" = the search couldn't run. None = not provided (older add-on, or rule switched off).
    """

    sender_history: Literal["new", "established", "unknown"] | None = None
    history_days: int = Field(default=30, ge=1, le=3650)


class EmailReport(ApiModel):
    schema_version: str = Field(max_length=20)
    generated_at: str | None = Field(default=None, max_length=100)
    message: MessageInfo
    sender: Sender = Field(default_factory=Sender)
    recipients: Recipients = Field(default_factory=Recipients)
    headers: list[Header] = Field(default_factory=list, max_length=300)
    body: Body = Field(default_factory=Body)
    links: list[Link] = Field(default_factory=list, max_length=500)
    attachments: list[Attachment] = Field(default_factory=list, max_length=100)
    preferences: Preferences = Field(default_factory=Preferences)  # schema 1.1; absent in 1.0
    mailbox: MailboxContext = Field(default_factory=MailboxContext)  # schema 1.2


# --- Response: what the add-on renders --------------------------------------------

Verdict = Literal["safe", "suspicious", "malicious"]
Severity = Literal["low", "medium", "high"]


class Finding(ApiModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    score: int
    explanation: str
    evidence: list[str]


class RuleInfo(ApiModel):
    id: str
    title: str
    description: str
    category: str
    score: int
    can_disable: bool


class AnalysisResult(ApiModel):
    schema_version: str
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    findings: list[Finding]
    # How the user's own settings affected this result (trusted sender, rules turned off, ...).
    notes: list[str] = Field(default_factory=list)
    rules_evaluated: int
    rules_failed: list[str]
    # Verdict thresholds from rules.yaml, so the card can show each verdict's score range.
    suspicious_threshold: int = 30
    malicious_threshold: int = 70
