# PhishNet

**A Gmail add-on that tells you whether the email you just opened is safe to act on, and why.**

When you open an email, PhishNet analyzes it and shows a **verdict** (Safe / Suspicious / Malicious),
a **0–100 risk score**, and **the reasons behind it**, each with concrete evidence taken from that email:
"this link says paypal.com but opens 203.0.113.9", "this domain was registered 2 days ago",
"11 of 92 security vendors flag this domain".

It consists of two parts that you'll find in this repository:

| Part | What it is | Where |
|---|---|---|
| **Gmail add-on** | Apps Script (Google Workspace add-on). Collects facts about the open email, masks sensitive data, sends a report, renders the verdict card and the user's settings | [`addon/`](addon/) |
| **Analysis backend** | Python / FastAPI service on AWS EC2 behind Caddy (HTTPS). Verifies the caller's Google identity, validates the report, runs 22 detection rules, returns a score, verdict and evidence | [`backend/`](backend/) |

```
┌─────────────────────────────────────────────┐
│        ◯ 45 / 100     ⚠ SUSPICIOUS          │   animated ring + verdict (one image)
│                       Score between 30–69    │
│ Be careful: 3 warning signs found. Verify   │
│ the sender through another channel.          │
│                                              │
│ Show why (3)                                 │   collapsed until tapped
│   Link shows one address but opens another   │
│   +30  shows "www.paypal.com/signin" but     │
│        opens secure-login.top                │
│   Recently registered domain  +30 …          │
│                                              │
│ [Trust sender] [Block sender] [Settings]     │
│ Details ▸  rules checked, what was masked    │
└─────────────────────────────────────────────┘
```

> **Reviewer shortcut.** If you have ten minutes: read [What it does and why](#1-what-it-does-and-why),
> skim [Architecture](#2-architecture) and [Security design](#5-security-design), and look at
> [Key decisions](#8-key-decisions-and-trade-offs). Every rule is explained in [`RULES.md`](RULES.md).

---

## Contents

1. [What it does and why](#1-what-it-does-and-why)
2. [Architecture](#2-architecture)
3. [Detection rules and scoring](#3-detection-rules-and-scoring)
4. [The user experience](#4-the-user-experience)
5. [Security design](#5-security-design)
6. [Privacy: what leaves the mailbox](#6-privacy-what-leaves-the-mailbox)
7. [Setup and running](#7-setup-and-running)
8. [Key decisions and trade-offs](#8-key-decisions-and-trade-offs)
9. [What's next](#9-whats-next)
10. [Repository layout](#10-repository-layout)

---

## 1. What it does and why

**The user's real question is "is it safe to click, reply or open this?"** A bare number doesn't answer
that, so the product is built around *explanation*:

- **Explainable by design.** The score is the sum of the rules that fired. Every point on the screen traces
  back to a reason the user can read and verify with their own eyes. No black box decides the verdict: the
  one machine-learning signal is a single, capped rule among 22.
- **Signals attackers actually use**, in six categories:
  - **Authentication:** the email's domain didn't authorize the sender (DMARC / SPF / DKIM failures, read
    only from Gmail's own trusted header).
  - **Sender:** a fake address in the display name, replies redirected elsewhere, a sender you've never
    corresponded with, and the user's own blocklist.
  - **Domains:** look-alike domains (`paypa1.com`), brand names in front of an unrelated domain
    (`paypal.somethingmalicious.com`), internationalized look-alikes, high-abuse TLDs, domains registered
    in the last 7 days, and domains flagged by security vendors on VirusTotal.
  - **Links:** link text that names one address but opens another, raw IP addresses, URL shorteners.
  - **Attachments:** risky file types and disguised names (`invoice.pdf.exe`), and known malware matched by
    SHA-256 on VirusTotal (the file is never uploaded).
  - **Content:** credential requests, pressure language, embedded login forms, and a local language model
    for text-only scams such as gift-card or changed-bank-details fraud.
- **The user stays in control.** A Settings screen in the add-on lets each user switch rules off (including
  every rule that calls an outside service, for privacy), keep **trusted senders** (always score 0, but only
  when Gmail authenticates the sender), **blocked senders** (always Malicious) and **trusted file types**.
- **Privacy by default.** Before the report leaves Google, the add-on reduces links that carry tokens or
  passwords to their domain and masks credit cards, ID numbers, IBANs, bank accounts and secrets. The
  backend never stores or logs email content.
- **Built to be tuned.** Each rule is one file. Rules can be disabled, re-weighted or re-parameterized in
  one YAML file without touching code, which is how a security team iterates on false positives.

---

## 2. Architecture

```
┌──────────────────────────────── Google (Gmail + Apps Script) ─────────────────────────────────┐
│  Apps Script add-on (addon/), runs on Google's servers, not in the browser                     │
│   1. onGmailMessageOpen: read the open message (per-message access token)                     │
│   2. Report.gs: collect facts (headers, sender, bodies, links + visible text, attachments +   │
│      SHA-256), the user's settings, and one derived mailbox fact (Mailbox.gs)                 │
│   3. Privacy.gs: reduce sensitive links to their domain, mask sensitive values                 │
│   4. render the result card (Cards.gs) and Settings (Settings.gs); validate all client data    │
│      with Validation.gs                                                                         │
└───────────────┬───────────────────────────────────────────────────────────────────────────────┘
                │ HTTPS POST /analyze      Authorization: Bearer <Google-signed identity token>
                ▼
┌──────────────────────────── AWS EC2 (static IP) · Docker Compose · port 443 only ──────────────┐
│  Caddy: TLS (Let's Encrypt, TLS-ALPN-01), 1 MB body limit, HSTS                                │
│  FastAPI backend (backend/), non-root, read-only filesystem, not exposed to the host           │
│   1. verify the identity token: RS256 signature (Google keys), issuer, expiry, audience =     │
│      this add-on, verified email allowed                                                        │
│   2. validate the bounded report schema (Pydantic)                                              │
│   3. parse once → EmailContext (domains, hosts, trusted auth results)                           │
│   4. run the enabled rules (one file each, configured in rules.yaml)                            │
│   5. score groups → trusted-sender override → sum, cap 100 → verdict → findings + notes         │
└───────┬───────────────────────────────┬─────────────────────────────────┬──────────────────────┘
        │ domain names / file hashes     │ domain names                    │ instance IAM role
        ▼                                ▼                                 ▼
   VirusTotal API v3              RDAP registries (per TLD,         AWS Secrets Manager
   (cached, 4/min limit)          from IANA's bootstrap list)       (VirusTotal API key)
```

### Why this split

- **The add-on is thin: it collects facts and renders; it never judges.** All interpretation lives in the
  backend, where it can change without redeploying the add-on. Two exceptions are on
  purpose and stay inside Google: masking (it must happen *before* data leaves) and the mailbox search
  (the backend has no mailbox access, and gets only the one-word conclusion).
- **A rules engine, not one big function.** `engine/loader.py` discovers every `Rule` subclass in
  `app/rules/` and applies `config/rules.yaml` (enable, points, parameters). Unknown rule ids in the config
  fail startup, so a typo can't silently disable a check. A rule that crashes is reported in `rulesFailed`
  instead of breaking the analysis, and a rule that *can't* check (an outside service is down) also
  reports itself there instead of implying "clean".

### The contract between add-on and backend

The add-on sends a JSON report (`schemaVersion` `1.3`), validated by
[`backend/app/models.py`](backend/app/models.py) with a size limit on every field:

```json
{
  "schemaVersion": "1.3",
  "message":     { "id", "threadId", "date", "subject", "rawSizeBytes" },
  "sender":      { "from": { "raw", "name", "address", "domain" }, "replyTo": [], "returnPath" },
  "recipients":  { "to": [], "cc": [] },
  "headers":     [ { "name", "value" } ],
  "body":        { "text", "textLength", "textTruncated", "html", "htmlLength", "htmlTruncated" },
  "links":       [ { "url", "text", "source": "html | text" } ],
  "attachments": [ { "filename", "contentType", "sizeBytes", "sha256" } ],
  "preferences": { "disabledRules", "trustedSenders", "blockedSenders", "trustedExtensions" },
  "mailbox":     { "senderHistory": "new | established | unknown", "historyDays": 30 },
  "privacy":     { "urlsReduced", "masked": { "credit card": 1 } }
}
```

The response:

```json
{
  "score": 45, "verdict": "suspicious", "summary": "Be careful: 3 warning signs found. …",
  "findings": [ { "ruleId", "title", "category", "severity", "score", "explanation", "evidence": [] } ],
  "notes": [], "rulesEvaluated": 22, "rulesFailed": [],
  "suspiciousThreshold": 30, "maliciousThreshold": 70
}
```

Other endpoints: `GET /rules` (authenticated; rule ids, titles, descriptions and points for the Settings
screen, so the add-on never keeps its own copy), `GET /gauge/<0-100>.gif` (the public, cacheable score
image), `GET /health`.

---

## 3. Detection rules and scoring

22 rules, one file each in [`backend/app/rules/`](backend/app/rules/). Points are the defaults from
[`backend/config/rules.yaml`](backend/config/rules.yaml).

> **Full rule reference: [`RULES.md`](RULES.md)**: what each rule looks for, exactly when it fires, examples, where it
> deliberately stays silent, which rules use outside services, and how to tune or add a rule.

### Authentication: did it really come from the domain it claims?

| Rule | Points | Fires when |
|---|---|---|
| `dmarc_fail` | 30 | Gmail's own `Authentication-Results` says DMARC failed |
| `spf_fail` | 15 | SPF fail or softfail |
| `dkim_fail` | 15 | a DKIM signature failed and none passed |

Only the topmost `Authentication-Results` stamped by `mx.google.com` is trusted. Anyone can put a fake
`dmarc=pass` header in the email they send.

### Sender: is the sender who they appear to be?

| Rule | Points | Fires when |
|---|---|---|
| `user_blocklist` | **100** | the sender's address or domain is on the user's blocklist (always on; wins over the trusted list) |
| `display_name_spoof` | 25 | the display name contains another address: `"ceo@company.com" <x@outlook.com>` |
| `reply_to_mismatch` | 15 | replies would go to a different domain |
| `new_sender` | 10 | you never wrote to the sender, and nothing you received from them is older than 30 days. The add-on searches the mailbox inside Google; only "new / established / unknown" is sent. Authenticated mail from well-known services is exempt |

### Domains: the sender's domain and every domain in links and text

| Rule | Points | Fires when |
|---|---|---|
| `virustotal_domain` | 65 | at least 2 security vendors on VirusTotal flag the domain as malicious (top 5k never sent; cached 24 h) |
| `lookalike_domain` | 35 | swapping look-alike characters back (1→l, 0→o, rn→m…) gives a top-100k site: `paypa1.com` → paypal.com |
| `new_domain` | 30 | the domain was registered less than 7 days before the email (RDAP, from the TLD's own registry) |
| `subdomain_brand` | 30 | X.Y.com where X is a top-10k site and Y isn't: `paypal.somethingmalicious.com`, `paypal.com.evil.ru` |
| `punycode_domain` | 20 | `xn--` domains that can display as look-alikes |
| `suspicious_tld` | 10 | high-abuse extensions such as `.zip`, `.xyz`, `.top` |

### Links: does a link go where it claims?

| Rule | Points | Fires when |
|---|---|---|
| `link_text_mismatch` | 30 | the link text names a domain or address other than where the link goes (about 38 click-tracking services exempt) |
| `ip_address_url` | 20 | the link goes to a raw IP address |
| `url_shortener` | 10 | bit.ly, tinyurl and similar |

### Attachments

| Rule | Points | Fires when |
|---|---|---|
| `virustotal_file` | 70 | at least 3 antivirus engines detect the attachment, matched by its SHA-256 (never uploaded) |
| `dangerous_attachment` | 35 | executables, scripts, HTML/SVG, disk images, macro Office files, or a disguised name like `invoice.pdf.exe` |

### Content: what does the email ask you to do?

| Rule | Points | Fires when |
|---|---|---|
| `embedded_form` | 25 | a `<form>` or password field inside the email |
| `ml_phishing_text` | 20 | a local DistilBERT model rates subject + body at least 99.85% phishing |
| `credential_request` | 15 | "verify your account"-style phrases plus a link |
| `urgency_language` | 10 | two or more pressure phrases |

### How the score is computed

1. **Rules the user switched off don't run** (switching off an outside-service rule stops its lookups too).
2. **Each rule that fires adds its points.**
3. **Score group:** `ml_phishing_text`, `credential_request` and `urgency_language` all react to wording, so
   if two or more fire, **only the highest counts**; the others stay listed at +0 with a note. One pushy
   sentence isn't counted three times.
4. **Trusted sender override:** a sender on the user's trusted list scores **0**, but only if Gmail's header
   says DMARC passed and the sender isn't also blocked. The other findings stay visible at +0, so a hacked
   trusted account sending a malicious link is still seen.
5. **Cap at 100. Verdict:** 0–29 **Safe** · 30–69 **Suspicious** · 70–100 **Malicious**.

Calibration intent: the strongest single signals (VirusTotal domain, look-alike, risky attachment, DMARC
failure, deceptive link) make an email Suspicious on their own; Malicious needs corroboration, or one
near-certain signal (a known-malware attachment at 70, a blocked sender at 100).

---

## 4. The user experience

### Result card

- **One image carries the verdict:** an animated ring that fills to the score, plus the verdict word with
  an outline icon (✓ / warning triangle / stop sign) and its score range. Card text can't be enlarged or
  animated, so the backend renders this as a GIF per score (`GET /gauge/<n>.gif`); the verdict is drawn
  from the first frame.
- **A one-line summary** telling the user what to do ("Do not click links, open attachments, or reply").
- **"Show why (N)"**, collapsed by default: each finding with its title, points, plain-language explanation
  and evidence from the email.
- **Trust sender / Block sender** (or "Remove from …"): adds the sender's **full address** (never the whole
  domain) and re-checks the email. Hidden when the address wouldn't pass validation.
- **Details**: rules checked, rules that couldn't run, what was masked before sending, and a
  development-only **"Show what was sent"** screen with the exact masked report.

### Settings

Opened from the add-on's menu or the card. Everything saves immediately:

- **Rule switches** grouped by category; tapping a rule expands its description and points inline.
- **Trusted senders**, **Blocked senders**, **Trusted file types**: type, Add, see the list, remove with ✕.
  Invalid entries are refused with the reason (for example, a whole free-mail domain such as `gmail.com`
  can't be trusted, only individual addresses).

Settings live in the user's own Apps Script storage, are sent with each report, and only ever affect that
user's results. Previous layouts are kept behind switches (`SCORE_DISPLAY`, `SETTINGS_STYLE` in the add-on)
so any UI change can be reverted with one line.

---

## 5. Security design

**Threat model.** The primary adversary is **whoever sent the email**: they control every header, the
display name, subject, bodies, links and attachment names. Secondary: **any client** with a valid token,
which can send arbitrary JSON (including fake settings), and **the public internet** hitting our endpoints.
Third-party responses (VirusTotal, RDAP, AWS) are handled defensively too. **Nothing from the client is
trusted, including the user's own settings.**

| Concern | Measure |
|---|---|
| **Who can call the API** | Google-signed OpenID Connect identity tokens, no shared secret. The backend verifies the RS256 signature against Google's published keys (cached), the issuer, the expiry, the **audience** (the token must have been issued to *this* add-on) and a verified email against a policy (`*`, `*@domain`, or a list). Fails closed: the service won't start without this configuration. |
| **Hostile email content** | Every field is size-bounded in the add-on *and* in the backend schema; requests over 1 MB are rejected before parsing (Caddy and middleware). Validation errors never echo input back. |
| **Slow-input attacks (ReDoS)** | Patterns that run on email content are linear. A quadratic HTML-tag pattern (9.6 s of CPU on a crafted 120 KB body) was found in review and fixed (2 ms). |
| **Client data (settings, clicks, storage)** | One strict definition of valid in the add-on (`Validation.gs`) and the server (`sender_lists.py`, schema): plain address/domain/rule-id/file-type patterns, no control or invisible characters. Applied to typed input, **every value a card sends back on a click**, and **settings read back from storage** (cleaned and saved back). Rule switches only accept rules the server actually listed. The server re-validates: malformed ids → 422, invalid list entries dropped, nothing unvalidated echoed back. |
| **Trusted senders can't be forged** | The trusted list only applies when Gmail's own header says DMARC passed. Whole free-mail domains can't be trusted. The blocklist always wins. |
| **Rendering** | All email- and server-derived text is HTML-escaped before it enters a card; the response shape is validated before rendering. |
| **Gmail search injection** | The sender address is strictly validated before it goes into the mailbox search, so a crafted From header can't rewrite the query to look "established". |
| **No active content** | Links in the email are never fetched (no SSRF, no tipping off the sender); attachments are hashed, never uploaded. |
| **Outbound requests** | Only identifiers, never content: registrable domains and attachment hashes to VirusTotal; domain names to each TLD's RDAP registry (HTTPS only, servers from IANA's list, redirects to non-HTTPS refused, responses capped). Per-email lookup caps and timeouts; "couldn't check" is never "clean". |
| **Secrets** | One application secret: the VirusTotal API key, in **AWS Secrets Manager**. The API reads it with the instance's **IAM role** (least privilege: `GetSecretValue` on that one secret), keeps it in memory only, never logs it, and re-reads it if VirusTotal rejects it (rotation). The server's disk holds only the secret's ARN; no AWS keys anywhere. |
| **Network surface** | Only port 443 is open (certificates via TLS-ALPN, no port 80). The API container runs as non-root on a read-only filesystem and isn't exposed to the host. Interactive API docs are disabled. |
| **Public endpoint** | `GET /gauge/<n>.gif` is unauthenticated because Gmail's image proxy fetches it without our token. It encodes nothing but a validated number 0–100 and is cached; at most 101 images exist. |
| **Logging** | No email content, settings or masked values. Each request logs the user, a hash of the message id, score, verdict, rule ids, schema version and the mailbox fact. |

**Why the audience check matters.** Anyone can get a valid Google-signed token for themselves (their own
Apps Script, `gcloud auth print-identity-token`). The `aud` claim names the app the token was issued to and
is the same for every user of this add-on. Checking it is what makes the API usable only through this
add-on, while still allowing any user who installs it.

**Security review.** A dedicated input-validation review went through every input path. Its fixes are in
place: linear patterns on email content (ReDoS) and strict validation of all client data.

---

## 6. Privacy: what leaves the mailbox

| Data | Where it goes |
|---|---|
| The open email (masked) | Our backend, over HTTPS, for one request. **Never stored or logged.** |
| Links with a sensitive parameter name (`token`, `password`, `session`, `secret`, `auth`, `otp`, `reset`, …) | Reduced to `https://domain/` **before** leaving Google |
| Credit cards (Luhn), Israeli IDs (check digit), US SSNs, IBANs (mod-97), bank account numbers, known secret formats (cloud/API keys, JWTs, private keys) | Replaced with `[credit card]`, `[israeli id]`, `[ssn]`, `[iban]`, `[bank account]`, `[secret]` **before** leaving Google |
| The user's mailbox | **Never leaves Google.** Two Gmail searches run inside the add-on; only "new / established / unknown" is sent |
| The user's settings | Stored in the user's own Apps Script storage; sent with each report; never stored on the server |
| Registrable domains, attachment SHA-256 | VirusTotal (the top 5k domains are never sent). VirusTotal adds queried indicators to its dataset |
| Domain names | The TLD's own RDAP registry (the Tranco top 1M is skipped) |

Masking runs on the subject, both bodies, link text and the path of each link, never on the host (the
rules need it). The card's Details say how many items were masked. Each rule that contacts an outside
service can be switched off in Settings.

---

## 7. Setup and running

**PhishNet is a hosted service.** There is **one backend**, run by the maintainer on a single AWS EC2 server.
Users don't run any server: they only install the Gmail add-on, which already points at that backend.

### For users: install the add-on

The add-on is built to be installed from Google Workspace Marketplace (planned; listing requires Google's
review, see [Privacy](#6-privacy-what-leaves-the-mailbox) for the mailbox permission). Once installed:

1. Open Gmail and open any email.
2. Open **PhishNet** in the side panel and approve the permissions it asks for the first time.
3. The verdict appears for every email you open. Your settings (rule switches, trusted and blocked senders,
   trusted file types) are under **Settings** in the add-on's menu.

Nothing to configure: the backend address is built in.

**Today (before the Marketplace listing)** the add-on runs as a test deployment of the maintainer's Apps Script
project. The backend only accepts requests from that project (it checks the identity token's *audience*), so a
copy of the code in someone else's Apps Script project is rejected unless the maintainer allows that project.

### Try it

Send these from a second Gmail account to the one with the add-on. Insert links with **Ctrl+K** ("Text" is
what's shown, "Web address" is where it goes), and don't click them.

| # | Subject and body | Link (shown → real) | Expected |
|---|---|---|---|
| A | *Urgent: unusual activity on your account.* "We detected unusual activity on your PayPal account… your account will be suspended within 24 hours unless you verify your account. Please log in here: [link]" | `https://www.paypal.com/signin` → `https://paypa1.top/verify` | **Malicious**: look-alike domain, deceptive link, phishing wording, high-abuse TLD |
| B | *FINAL NOTICE: invoice overdue.* "Please arrange payment immediately… View the invoice online: [link]", plus an attachment named `Invoice_2026-0412.pdf.html` (any text file saved under that name) | `https://billing.microsoft.com/invoices` → `http://203.0.113.45/portal/invoice` | **Malicious**: disguised attachment, deceptive link, raw IP address, urgency |
| C | *Action required: your mailbox is almost full.* "Upgrade immediately to keep receiving email. [Upgrade storage] Short link: https://bit.ly/3Kx9TqZ" | `Upgrade storage` → `https://xn--microsft-sbh.com/storage` | **Suspicious**: internationalized look-alike, urgency, URL shortener |
| D | *Photos from the weekend.* "Uploaded the photos from Saturday: [album link]" | `album link` → `https://bit.ly/4abcXYZ` | **Safe** (a short link alone isn't enough) |
| E | *Lunch tomorrow?* "Are you free for lunch around 12:30?" | none | **Safe** |

Exact scores vary by a few points with your mailbox history (`new_sender`) and live lookups (domain age,
VirusTotal). Mail sent from Gmail always passes SPF/DKIM/DMARC, so the authentication rules only show on
genuinely spoofed mail. To see the display-name and Reply-To rules, set the sending account's name to an
email address (e.g. `service@paypal.com`) or a Reply-To on another domain in Gmail's "Send mail as" settings.

### Adding a rule

One file in `backend/app/rules/` with a `Rule` subclass (`id`, `title`, `description`, `category`, `default_score`,
`evaluate()`); see [`backend/README.md`](backend/README.md).

---

## 8. Key decisions and trade-offs

The choices that shaped the product most, and why:

| Decision | Why |
|---|---|
| **Additive, explainable rules; ML as one capped signal** | Every point is a reason the user can check; a model alone false-alarms on routine mail and can't explain itself |
| **Google identity tokens, audience-checked** | No shared secret to leak or rotate; restricts the API to this add-on while allowing any of its users |
| **Facts in the add-on, judgment in the backend** | One place for all detection logic, changeable without redeploying the add-on |
| **Trust only Gmail's own authentication header** | Senders can include fake `dmarc=pass` headers |
| **Popularity from Tranco, not a brand list** | Covers any well-known site; measurable false-alarm rate |
| **Outside services: identifiers only, capped, cached; "can't check" ≠ "clean"** | Privacy and the free API's 4/min limit; an outage must not make phishing look safe |
| **Secrets Manager via instance role** | No key on disk, no AWS credentials anywhere |
| **Masking in the add-on** | Data must be cleaned *before* it leaves Google; server-side masking is too late |
| **Never trust client data, including settings** | Click values and stored settings cross the client boundary like any input |
| **Full mailbox read for `new_sender`** | Real correspondence history; only a one-word conclusion leaves Google |

---

## 9. What's next

1. **Intelligence across all users.** Every user's scans together give a view no single mailbox has: trends,
   domains and senders behind ongoing phishing campaigns, and the same link, attachment or email template
   reaching many different people at once (matched by domain, link host or file hash, never by content). A
   campaign seen across many mailboxes can be flagged for everyone while it's still new, before reputation
   services such as VirusTotal catch up.
2. **Custom rules for security teams.** Let an organization add its own rules (for example "external mail
   that mentions our CEO", "attachments from new senders to finance", their own blocked domains and
   keywords) with their own points, so the product adapts to each team's threats and policies.
3. **Protect everyone from what one user finds.** With many users, a phishing or spam email reported or
   blocked by one user (its sender, domain, link or attachment fingerprint) becomes a signal that protects
   all other users who receive it.
4. **Per-user rate limits** keyed by the verified email, with a per-user budget for outside lookups.
5. **Local blocklists** (OpenPhish, URLhaus) in front of VirusTotal: unlimited, private, and they cover
   phishing on shared hosting by full hostname.
6. **Actions from the card:** report to the security team, move to spam.

---

## 10. Repository layout

```
addon/                      Gmail add-on (Apps Script; paste into script.google.com)
  appsscript.json           manifest: scopes, URL allowlist, Settings menu item, Gmail advanced service
  Code.gs                   entry points, backend calls (identity token), response validation
  Report.gs                 builds the report: facts only
  Privacy.gs                link reduction and masking before sending
  Validation.gs             one definition of valid for all client data
  Mailbox.gs                new_sender fact: two Gmail searches, only the conclusion is sent
  Cards.gs                  result card: gauge image, findings, buttons, details
  Settings.gs               settings screen, lists, rule switches, click handlers
backend/                    FastAPI service
  app/main.py               endpoints: /analyze, /rules, /gauge, /health
  app/security.py           Google identity-token verification, body size limit
  app/models.py             bounded request/response schema
  app/gauge.py              animated verdict image
  app/engine/               context parsing, rule loader, scorer, Tranco list, VirusTotal / RDAP clients,
                            Secrets Manager key source, sender-list validation, ML classifier
  app/rules/                22 rules, one per file
  config/rules.yaml         points, thresholds, parameters, score groups
  data/                     Tranco top-1M list, IANA RDAP bootstrap
  Dockerfile, docker-compose.yml, Caddyfile, .env.example, README.md
scripts/                    deploy.sh, update_tranco.py, update_rdap_bootstrap.py
README.md                   this file
RULES.md                    all 22 detection rules in detail
```
