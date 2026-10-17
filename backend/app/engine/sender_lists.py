"""The user's own trusted and blocked senders (sent by the add-on with each report).

Entries are a full address ("bob@shop.com") or a domain ("shop.com", which also covers its
subdomains). They come from the client, so they are untrusted: validated strictly here (the same
rules as the add-on's Validation.gs), and invalid entries are ignored rather than failing the
whole analysis. Only entries that passed are ever echoed back (in notes).
"""

import re

# Local part: letters, digits and ._%+- only (no quotes, brackets, spaces, control or invisible characters).
_ADDRESS_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Control characters, zero-width characters, bidi overrides/isolates and the BOM (as code point ranges).
_INVISIBLE_RANGES = [(0x00, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x200B, 0x200F), (0x2028, 0x202E),
                     (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF)]
_INVISIBLE_RE = re.compile("[" + "".join(re.escape(chr(a)) + "-" + re.escape(chr(b)) for a, b in _INVISIBLE_RANGES) + "]")
MAX_ENTRY_LENGTH = 254


def validate_entry(raw: object, allow_free_mail_domains: bool) -> str | None:
    """The normalized entry if it is a valid address or domain, else None."""
    if not isinstance(raw, str) or _INVISIBLE_RE.search(raw):
        return None
    entry = raw.strip().lower()
    if not entry or len(entry) > MAX_ENTRY_LENGTH:
        return None
    if _ADDRESS_RE.fullmatch(entry):
        return entry
    if _DOMAIN_RE.fullmatch(entry) and len(entry) <= 253:
        if not allow_free_mail_domains and entry in FREE_MAIL_DOMAINS:
            return None
        return entry
    return None


# Trusting a whole free-mail domain would trust every account on it, attackers included.
# For these, only full addresses can be trusted.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "mail.ru",
    "zoho.com", "web.de", "qq.com", "163.com",
})


def normalize_entries(entries: list[str], allow_free_mail_domains: bool) -> list[str]:
    """Valid, normalized, de-duplicated entries; the rest are dropped."""
    result: list[str] = []
    for raw in entries:
        entry = validate_entry(raw, allow_free_mail_domains)
        if entry and entry not in result:
            result.append(entry)
    return result


def find_match(address: str, domain: str | None, entries: list[str]) -> str | None:
    """The first entry that matches the sender (exact address, or domain incl. subdomains)."""
    address = address.strip().lower()
    domain = (domain or "").strip().lower()
    for entry in entries:
        if "@" in entry:
            if address == entry:
                return entry
        elif domain and (domain == entry or domain.endswith("." + entry)):
            return entry
    return None
