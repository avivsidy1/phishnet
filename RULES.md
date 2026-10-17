# PhishNet Detection Rules

This is the reference for all 22 detection rules: what each one looks for, exactly when it fires, examples,
and where it deliberately stays silent. For the product overview, architecture and setup, see the
[README](README.md).

Each rule lives in its own file in [`backend/app/rules/`](backend/app/rules/). The points shown are the
defaults from [`backend/config/rules.yaml`](backend/config/rules.yaml), where every rule can be switched
off, re-weighted or re-parameterized without touching code.

---

## Contents

- [At a glance](#at-a-glance)
- [How the score is computed](#how-the-score-is-computed)
- [Authentication](#authentication-did-it-really-come-from-the-domain-it-claims)
- [Sender](#sender-is-the-sender-who-they-appear-to-be)
- [Domains](#domains-is-a-domain-pretending-to-be-another)
- [Links](#links-does-a-link-lead-where-it-claims)
- [Attachments](#attachments)
- [Content](#content-what-is-the-email-asking-you-to-do)
- [User settings and the rules](#user-settings-and-the-rules)
- [Rules that use outside services](#rules-that-use-outside-services)
- [Why the points differ](#why-the-points-differ)
- [Tuning and adding rules](#tuning-and-adding-rules)

---

## At a glance

| Rule | Category | Points | One-line summary |
|---|---|---|---|
| [`dmarc_fail`](#dmarc_fail-30) | Authentication | 30 | The domain's own DMARC policy says it didn't send this |
| [`spf_fail`](#spf_fail-15) | Authentication | 15 | Sent from a server the domain doesn't authorize |
| [`dkim_fail`](#dkim_fail-15) | Authentication | 15 | Signature broken and no valid one found |
| [`user_blocklist`](#user_blocklist-100) | Sender | 100 | The sender is on the user's blocklist |
| [`display_name_spoof`](#display_name_spoof-25) | Sender | 25 | A different email address hidden in the display name |
| [`reply_to_mismatch`](#reply_to_mismatch-15) | Sender | 15 | Replies would go to another domain |
| [`new_sender`](#new_sender-10) | Sender | 10 | No mail history with this sender |
| [`virustotal_domain`](#virustotal_domain-65) | Domains | 65 | At least 2 security vendors flag a domain as malicious |
| [`lookalike_domain`](#lookalike_domain-35) | Domains | 35 | `paypa1.com`: a well-known site with look-alike characters |
| [`new_domain`](#new_domain-30) | Domains | 30 | A domain registered less than 7 days ago |
| [`subdomain_brand`](#subdomain_brand-30) | Domains | 30 | `paypal.somethingmalicious.com`: a brand in front of another domain |
| [`punycode_domain`](#punycode_domain-20) | Domains | 20 | International characters that can mimic a brand |
| [`suspicious_tld`](#suspicious_tld-10) | Domains | 10 | A high-abuse extension such as `.xyz` or `.top` |
| [`link_text_mismatch`](#link_text_mismatch-30) | Links | 30 | A link shows one address but opens another |
| [`ip_address_url`](#ip_address_url-20) | Links | 20 | A link to a raw IP address |
| [`url_shortener`](#url_shortener-10) | Links | 10 | A link through a URL shortener |
| [`virustotal_file`](#virustotal_file-70) | Attachments | 70 | An attachment is known malware (matched by fingerprint) |
| [`dangerous_attachment`](#dangerous_attachment-35) | Attachments | 35 | A risky file type, or a disguised name like `invoice.pdf.exe` |
| [`embedded_form`](#embedded_form-25) | Content | 25 | A form or password field inside the email |
| [`ml_phishing_text`](#ml_phishing_text-20) | Content | 20 | A language model rates the wording as phishing |
| [`credential_request`](#credential_request-15) | Content | 15 | Asks you to verify an account or enter details, with a link |
| [`urgency_language`](#urgency_language-10) | Content | 10 | Two or more pressure phrases |

---

## How the score is computed

1. **Rules the user switched off don't run.** For rules that contact an outside service, that also means no
   lookup is made.
2. **Each rule that fires adds its points.**
3. **Score group for wording.** `ml_phishing_text`, `credential_request` and `urgency_language` all react to
   the same thing, the email's wording. If two or more fire, **only the highest counts**; the others are still
   listed as reasons, at +0, with a note saying which one counted instead. One pushy sentence isn't counted
   three times.
4. **Trusted sender override.** A sender on the user's trusted list scores **0**, but only if Gmail's own
   header says DMARC passed and the sender isn't also blocked. See [User settings](#user-settings-and-the-rules).
5. **The total is capped at 100.**

| Score | Verdict |
|---|---|
| 0–29 | **Safe** |
| 30–69 | **Suspicious** |
| 70–100 | **Malicious** |

A rule that **can't check** (for example, an outside service is down or a rate limit is reached) is listed under
"rules that failed to run". It is never treated as "clean".

---

## Authentication: did it really come from the domain it claims?

These rules read **only** the `Authentication-Results` header stamped by Gmail's own server (`mx.google.com`),
the topmost one, added when the email arrived. Anyone can put a fake `dmarc=pass` header in an email they send,
so every other `Authentication-Results` header is ignored.

Mail sent through Gmail itself always passes these checks, so they show up on genuinely spoofed mail.

### `dmarc_fail` (30)
- **Goal:** the strongest "this is not really from them" signal, for domains whose owners publish a DMARC policy.
- **Fires when:** Gmail's header says `dmarc=fail`.
- **Example:** `From: security@paypal.com`, but the email came from an attacker's server. Neither SPF nor DKIM
  aligns with paypal.com, so Gmail records `dmarc=fail`.

### `spf_fail` (15)
- **Goal:** catch email sent from a server the domain doesn't authorize.
- **Fires when:** Gmail's header says `spf=fail` or `spf=softfail`.
- **Example:** an email claiming to be from `@acme.com` sent from a server that isn't in acme.com's SPF record.

### `dkim_fail` (15)
- **Goal:** catch forged or altered messages.
- **Fires when:** a DKIM result is `fail` or `permerror` **and no signature passed** (one valid signature is enough).
- **Example:** a message changed after it was signed, or one carrying a fake signature.

---

## Sender: is the sender who they appear to be?

### `user_blocklist` (100)
- **Goal:** let users block senders they know are bad.
- **Fires when:** the sender's address, or its domain including subdomains, is on the user's blocklist (Settings,
  or the "Block sender" button on the card).
- **Example:** blocklist `scam-shop.com`; an email from `offers@mail.scam-shop.com` scores 100, Malicious.
- **Notes:** no authentication check is needed (flagging a forged blocked address is still right). It is always
  on, and it wins over the trusted list.

### `display_name_spoof` (25)
- **Goal:** most mail apps show only the sender's *name*, so attackers put a fake address there. On a phone the
  user sees `ceo@mycompany.com` and assumes that's the sender.
- **Fires when:** the display name contains an email address on a different domain than the real sender's
  (compared by registrable domain, so `mail.example.com` and `example.com` match).
- **Examples:** `"ceo@mycompany.com" <boss.urgent@outlook.com>`, `"support@paypal.com" <x@evil.ru>`.
- **Doesn't fire on** brand names alone (`"PayPal Support" <x@gmail.com>`): ordinary names and words collide with
  brand names too often. Brand impersonation through domains is covered by the domain rules.

### `reply_to_mismatch` (15)
- **Goal:** the sender looks right, but your reply goes to the attacker. Common in invoice and CEO fraud.
- **Fires when:** a Reply-To address is on a different registrable domain than the From address.
- **Example:** `From: billing@acme.com`, `Reply-To: acme.billing.dept@outlook.com`.

### `new_sender` (10)
- **Goal:** phishing comes from strangers; mail from people you really correspond with rarely is.
- **How:** the add-on searches the user's mailbox, inside Google, for mail **the user ever sent to** this address
  (no date limit), or mail **received from** it more than **30 days** before this email. Either one means
  "established". Only the conclusion ("new", "established" or "unknown") is sent to the server, never mailbox
  content. Mail in Spam and Trash doesn't count.
- **Fires when:** the sender is "new". If the search failed ("unknown") or the rule is switched off, it doesn't fire.
- **Never fires for well-known services:** a sender on a Tranco top-10k domain whose mail passed DMARC (for example,
  your first email from a service you just signed up to). Free-mail domains get no exemption, because anyone can
  pass DMARC as `gmail.com`.
- **Example:** a first email from `billing@new-vendor.example` adds 10 points: Safe on its own, but it can tip an
  email that already has 20+ points into Suspicious.
- **Known noise:** every sender's first month (new shops, newsletters, new contacts), hence only 10 points.
- **Known bypass:** an attacker who sent a harmless email more than 30 days earlier (still in the inbox), or whom
  the user replied to, isn't "new".

---

## Domains: is a domain pretending to be another?

These check the sender's domain and every link's domain; `virustotal_domain` and `new_domain` also check domain
names written in the text. "Well-known" always means the [Tranco](https://tranco-list.eu) popularity ranking, not
a hand-made brand list, so any popular site is covered.

### `virustotal_domain` (65)
- **Goal:** catch domains that security vendors already know are malicious (phishing, malware).
- **How:** each registrable domain (`login.evil.com` → `evil.com`) that isn't in the Tranco top 5k is looked up on
  VirusTotal. Answers are cached for 24 hours ("never seen" for 6). At most 3 new lookups per email.
- **Fires when:** **at least 2** of VirusTotal's roughly 90 vendors call the domain malicious. One isn't enough:
  even google.com has one.
- **Example evidence:** "link domain evil-login.example: 11/92 vendors flag it as malicious; registered 2026-10-10
  (7 days ago); flagged by BitDefender (phishing), ESET (phishing), …".
- **Known gaps:** brand-new phishing domains may have 0 detections yet; phishing hosted on popular platforms
  (`*.pages.dev`, `*.github.io`) is skipped because the platform itself is popular; a malicious subdomain of a clean
  parent domain is missed, because only the registrable domain is looked up.

### `lookalike_domain` (35)
- **Goal:** catch domains that turn into a well-known site's domain once look-alike characters are swapped back.
- **How:** tries 1–3 swaps from a confusable map (`0→o, 1→l/i, 3→e, 4→a, 5→s, 6→b/g, 7→t, 8→b, 9→g/q, i↔l, rn→m,
  vv→w`), fewest first, and looks up the result (same extension, then `.com`) in the Tranco **top 100k**.
- **Fires when:** a variant is a top-100k domain and the original domain is **not** in the top 1M.
- **Examples:** `paypa1.com` → paypal.com (1→l), `rnicrosoft.com` → microsoft.com (rn→m), `g00gle.com` →
  google.com, `lnstagram.com` → instagram.com, `paypa1.top` → paypal.com.
- **Doesn't fire on:** popular domains themselves; names under 5 characters; mostly-digit names; ordinary typos
  (`goggle.com`); a brand inside a longer name (`paypal-secure-login.com`).
- **Measured:** 0.024% false positives on 50,000 real lower-ranked domains, with all 16 test attacks caught.

### `new_domain` (30)
- **Goal:** phishing domains are usually registered days before the attack; established senders use older domains.
- **How:** asks the domain's own registry over **RDAP** (the structured successor to WHOIS; free, no key) for the
  registration date. Domains in the Tranco top 1M are skipped: the ranking covers 30 days, so they can't be a week
  old. Dates are cached for 7 days; at most 5 lookups per email.
- **Fires when:** a domain was registered **less than 7 days** before the email's date.
- **Example evidence:** "link domain fresh-login.example was registered 2 days before this email (2026-10-15)".
  This catches new phishing domains that reputation services haven't flagged yet.
- **Not applicable** to extensions whose registry offers no RDAP (`.il` including `.co.il`, `.de`, `.io`, `.es`,
  `.us` and others): the rule stays silent for them.

### `subdomain_brand` (30)
- **Goal:** catch addresses that *start* with a well-known name but belong to someone else. People read the start.
- **Fires when:** the sender's or a link's hostname is X.Y.com, where Y (the real domain) is **not** in the Tranco
  top 10k, and X contains a whole top-10k domain (`paypal.com.evil.ru`) or is a top-10k site's name
  (`paypal.evil.com` → paypal.com). Names need 5+ letters, and common words (login, account, admin, cloud, office,
  …) don't count.
- **Example evidence:** "link apple.com.id-verify.ru puts apple.com in front of the real domain id-verify.ru".
- **Doesn't fire on:** the real sites (`docs.google.com`); subdomains of other top-10k sites
  (`apple.stackexchange.com`); hyphenated names without a subdomain (`paypal-login.evil.com`).

### `punycode_domain` (20)
- **Goal:** catch internationalized domains whose letters look identical to Latin ones.
- **Fires when:** any label of the domain starts with `xn--`.
- **Example:** `https://xn--pple-43d.com` displays as "аpple.com" with a Cyrillic "а".

### `suspicious_tld` (10)
- **Goal:** flag extensions with very high abuse rates (cheap or free registration, weak enforcement).
- **Fires when:** the extension is one of `zip, mov, xyz, top, click, country, gq, tk, ml, cf, ga, work, rest, cam,
  icu, buzz, monster, sbs, cfd, lol`.
- **Example:** a link to `https://secure-update.xyz/login`.

---

## Links: does a link lead where it claims?

### `link_text_mismatch` (30)
- **Goal:** the classic trick where a link *names* a trusted address but *opens* a different one.
- **How:** finds every domain mentioned in the link's visible text (a URL, a bare domain, or an email address,
  even inside a sentence) and compares it with the real destination (web links and `mailto:`), by registrable domain.
- **Fires when:** the text names at least one domain and none of them matches the destination.
- **Examples:** text `https://www.paypal.com/signin` → `https://paypa1.top/verify`; text "Sign in at
  www.paypal.com" → `https://evil.ru/login`; text `support@paypal.com` → `mailto:help@evil.com`.
- **Doesn't fire on:** text with no address ("Click here"); the same registrable domain (`www.paypal.com` →
  `mail.paypal.com`); file names (`report.pdf`); plain-text links; links through about 38 known **link-rewriting
  services** (email click tracking such as Mailchimp, SendGrid, HubSpot and Amazon SES; corporate scanners such as
  Microsoft Safe Links and Proofpoint).

### `ip_address_url` (20)
- **Goal:** real companies link to named domains; raw IP addresses avoid domain reputation checks.
- **Fires when:** a link's host is an IP address.
- **Example:** `http://185.23.4.10/login`.

### `url_shortener` (10)
- **Goal:** shorteners hide the real destination. Not malicious by itself, which is why it scores low.
- **Fires when:** a link uses bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, cutt.ly, rb.gy or a similar service.
- **Example:** `https://bit.ly/3Kx9TqZ`.

---

## Attachments

### `virustotal_file` (70)
- **Goal:** catch attachments that are known malware, whatever their name.
- **How:** the add-on computes each attachment's SHA-256 fingerprint (files up to 25 MB); the server looks it up on
  VirusTotal. **The file is never uploaded.** Cached for 24 hours; at most 3 new lookups per email.
- **Fires when:** **at least 3** antivirus engines detect the file. Stricter than for domains, because 70 points make
  an email Malicious on its own and harmless files sometimes collect one or two low-quality detections.
- **Example evidence:** "attachment Invoice_Oct.pdf.exe: 66/68 antivirus engines detect it; e.g. ALYac
  (Misc.Eicar-Test-File), …" (the EICAR antivirus test file).
- **Doesn't fire on** files VirusTotal has never seen (new or targeted malware, private documents): unknown isn't
  clean, it just isn't evidence.

### `dangerous_attachment` (35)
- **Goal:** catch file types used to deliver malware or fake login pages.
- **Fires when:** the file is
  - a type that runs code or opens content: `exe, scr, com, pif, bat, cmd, msi, js, jse, vbs, vbe, wsf, hta, ps1,
    jar, lnk, iso, img, vhd, html, htm, svg`;
  - an Office file that can contain macros: `docm, xlsm, pptm, dotm, xlam, xlsb`; or
  - **disguised** with a fake document extension in front of the real one: `invoice.pdf.exe`.
- **Examples:** `Invoice_2026.pdf.html`, `payment_details.html`, `report.docm`, `shipment.iso`.
- **Why HTML and SVG:** they open locally in the browser, a common way to show a fake login page that link scanners
  never see.
- **User setting:** file types the user trusts (for example `html`) aren't flagged for their type. A disguised name
  is always flagged, and known malware is still caught by `virustotal_file`.

---

## Content: what is the email asking you to do?

Searched in the subject and body, case-insensitively.

### `embedded_form` (25)
- **Goal:** legitimate services don't collect data through a form inside an email.
- **Fires when:** the email's HTML contains a password field, or any `<form>`.
- **Example:** `<form action="https://…"><input type="password"></form>`.

### `ml_phishing_text` (20)
- **Goal:** catch scams that are *only words*: no link, attachment or spoofing for the other rules to see.
- **How:** a DistilBERT model fine-tuned on phishing emails
  ([`cybersectony/phishing-email-detection-distilbert_v2.4.1`](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1),
  pinned) reads the subject and body (first 512 tokens) and returns a phishing probability. It runs on the server;
  nothing is sent elsewhere.
- **Fires when:** the probability is **at least 99.85%**.
- **Examples:** "Are you at your desk? Buy 5 Apple gift cards for a client today, keep it confidential, send me the
  codes" (99.98%); "Our banking details have changed, use the new IBAN for this week's invoice" (99.96%).
- **Why only 20 points:** it also rates some legitimate transactional mail as phishing (a real password reset and a
  shipping notice scored 99.98%), and it misses phishing whose tells are technical (a polite fake invoice with an
  IP-address link scored 0.5%). It's one signal, never the verdict.
- Part of the **wording score group** (see [How the score is computed](#how-the-score-is-computed)).

### `credential_request` (15)
- **Goal:** catch requests to log in or hand over sensitive details.
- **Fires when:** a phrase such as "verify your account", "confirm your password", "update your payment", "log in
  to your account" or "social security number" appears **and** the email contains at least one link (somewhere to
  enter the details).
- **Example:** "Please verify your account by clicking the link below." plus a link.
- Part of the **wording score group**.

### `urgency_language` (10)
- **Goal:** pressure is the core of social engineering: rush the victim before they think.
- **Fires when:** **two or more** phrases appear, such as "urgent", "immediately", "within 24 hours", "account will be
  suspended", "unusual activity", "final notice", "action required", "expires today" or "failure to". A single
  "urgent" is normal in business email.
- **Example:** "Action required: your account will be suspended within 24 hours."
- Part of the **wording score group**.

---

## User settings and the rules

Each user controls these in the add-on's Settings. They only affect that user's results, and all of them are
validated strictly on the add-on and again on the server.

| Setting | Effect on scoring |
|---|---|
| **Rule switches** | A switched-off rule doesn't run at all (no lookups for rules that use outside services). `user_blocklist` can't be switched off: it's controlled by the blocklist itself. |
| **Trusted senders** (addresses, or domains including subdomains) | The email scores **0**, but **only if** Gmail's header says DMARC passed and the sender isn't blocked. Other findings stay visible at +0, so a hacked trusted account sending a malicious link is still seen. Whole free-mail domains (`gmail.com`) can't be trusted, only individual addresses. |
| **Blocked senders** | `user_blocklist` fires: 100 points, Malicious. Wins over the trusted list. |
| **Trusted file types** | `dangerous_attachment` doesn't flag those types. Disguised names and known malware are still flagged. |

---

## Rules that use outside services

| Rule | Service | What is sent | Never sent |
|---|---|---|---|
| `virustotal_domain` | VirusTotal | registrable domain names (not the Tranco top 5k) | full URLs, email content |
| `virustotal_file` | VirusTotal | attachment SHA-256 fingerprints | the files, email content |
| `new_domain` | the domain's own RDAP registry | domain names (not the Tranco top 1M) | anything else |
| `new_sender` | (Gmail, inside Google) | nothing leaves Google except "new / established / unknown" | mailbox content |

All four have short timeouts, cache their answers, and cap the number of lookups per email. VirusTotal's free API
allows 4 lookups per minute in total, so the two VirusTotal rules share one budget. When a rule can't check, it is
listed as "failed to run", never treated as clean.

---

## Why the points differ

- **65–100: near-certain on their own.** A blocked sender (100), a known-malware attachment (70), a domain flagged by
  several security vendors (65).
- **30–35: close to proof of deception.** Failed DMARC, look-alike domain, brand in a subdomain, brand-new domain,
  deceptive link, dangerous attachment. One of these alone makes an email Suspicious.
- **20–25: strong, but with innocent explanations.** IP links in internal tools, forms in newsletters, punycode for
  real international brands, the model's false alarms on routine mail.
- **10–15: weak alone and common in legitimate mail.** Shorteners, urgency, Reply-To on mailing lists, new senders.
  They matter alongside stronger signals.

So apart from the near-certain signals, **Malicious (70+) normally requires several independent signals**, which
keeps false alarms down.

---

## Tuning and adding rules

**Tuning** is done in [`backend/config/rules.yaml`](backend/config/rules.yaml):

```yaml
verdict:
  suspicious_threshold: 30
  malicious_threshold: 70

score_groups:
  wording: [ml_phishing_text, credential_request, urgency_language]

rules:
  url_shortener: { enabled: true, score: 10 }      # change points or disable
  virustotal_domain:
    score: 65
    params:
      min_malicious: 2                            # rule-specific parameters
```

Unknown rule ids are rejected at startup, so a typo can't silently disable a check.

**Adding a rule** takes one file in [`backend/app/rules/`](backend/app/rules/) with a `Rule` subclass. It is
discovered automatically:

```python
from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class ManyLinks(Rule):
    id = "many_links"
    title = "Unusually many links"
    description = "The email contains an unusually large number of links."   # shown in the add-on's Settings
    category = "links"
    default_score = 10
    default_params = {"threshold": 30}

    def evaluate(self, email: EmailContext) -> Hit | None:
        if len(email.links) < self.params["threshold"]:
            return None
        return Hit(
            explanation="Phishing and spam often pack an email with links.",
            evidence=[f"{len(email.links)} links"],
        )
```

The rule then appears in the add-on's Settings (with its description and points) without any add-on change. More
detail on the engine: [`backend/README.md`](backend/README.md).
