# PhishNet — Backend

FastAPI service that receives an email report from the Gmail add-on, runs a set of
configurable detection rules, and returns a 0–100 score, a verdict, and plain-language reasons.

```
POST /analyze   (Authorization: Bearer <Google ID token>)   report JSON  ->  { score, verdict, summary, findings[], notes[], suspiciousThreshold, maliciousThreshold }
GET  /rules     (Authorization: Bearer <Google ID token>)   ->  [{ id, title, description, category, score, canDisable }]  (settings card)
GET  /gauge/<0-100>.gif  (public)                           ->  animated score ring for the card
GET  /health
```

## Layout

```
app/
  main.py            HTTP layer: auth, size limit, safe error handling, logging
  models.py          Request/response schema (bounded fields; email content is untrusted)
  security.py        Google identity token verification, request size limit
  config.py          Settings from environment
  engine/
    context.py       Parses the report once (domains, links, auth results) for all rules
    popular_domains.py  Loads the Tranco top-1M list (data/), cached per process
    rule.py          Rule base class
    text_classifier.py  Loads the DistilBERT phishing model (ml_phishing_text), offline, lazy torch import
    loader.py        Discovers rules in app/rules/ and applies config/rules.yaml
    scorer.py        Runs rules, sums scores, picks verdict
  rules/             One file per rule (files starting with "_" are shared data)
config/rules.yaml    Enable/disable rules, scores, params, verdict thresholds
data/                Tranco top-1M popular domains (refresh: scripts/update_tranco.py)
```

## Run locally

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env              # set ALLOWED_AUDIENCES, ALLOWED_EMAILS (VT_API_KEY optional)
uvicorn app.main:app --reload
```

Running the server locally without PyTorch and the model files works: `ml_phishing_text` is then listed in `rulesFailed`. The Docker
image installs CPU-only PyTorch and bakes in the model at a pinned commit (see `Dockerfile`).

## User preferences

Reports (schema 1.1) may carry `preferences: { disabledRules, trustedSenders, blockedSenders }`, stored by the
add-on per user. The scorer skips disabled rules (`user_blocklist` excepted), `user_blocklist` scores a blocked
sender 100, and a trusted sender with DMARC pass scores 0 (findings kept at +0). Each effect is explained in
`notes`. Entries are validated in `app/engine/sender_lists.py`; invalid ones are ignored.

## Mailbox context

Reports (schema 1.2) may carry `mailbox: { senderHistory: "new" | "established" | "unknown", historyDays }`,
computed by the add-on from two Gmail searches. Only `new` makes `new_sender` fire; the server never
receives mailbox content.

## Configure rules

Edit `config/rules.yaml`: `enabled: false` turns a rule off, `score` changes its weight,
`params` overrides its settings. The final score is the sum of matched rule scores,
capped at 100. `score_groups` lists rules that react to the same evidence: if several in a group
fire, only the highest score counts and the others are shown with 0 points. Thresholds map it to `safe` / `suspicious` / `malicious`.

## Add a rule

Give every rule a `title` and a one- or two-sentence `description` for users (shown in the add-on's rule info screen).


Create `app/rules/my_rule.py`:

```python
from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule

class MyRule(Rule):
    id = "my_rule"
    title = "Short title shown to the user"
    category = "links"
    default_score = 10
    default_params = {"threshold": 3}

    def evaluate(self, email: EmailContext) -> Hit | None:
        if len(email.links) < self.params["threshold"]:
            return None
        return Hit(explanation="Why this is suspicious, in plain language.",
                   evidence=[f"{len(email.links)} links"])
```

It is picked up automatically on restart. To remove a rule, delete its file (and its entry in `rules.yaml`).

## Deploy to EC2

1. Launch an Ubuntu instance. Security group: 443 open, 22 from your IP only.
   Port 80 is not needed: Caddy validates the certificate over 443 (TLS-ALPN-01).
2. Install Docker: `sudo apt-get install -y docker.io docker-compose-v2 && sudo usermod -aG docker ubuntu`
3. From the repo root:
   `ALLOWED_EMAILS=you@gmail.com ALLOWED_AUDIENCES=<client-id> scripts/deploy.sh <ec2-public-dns> [domain]`

The script copies the code, writes the allowlists to the server's `.env` (kept on later runs if omitted),
sets `DOMAIN` (default: `<public-ip-with-dashes>.sslip.io`), starts the containers and waits for
`/health`. Caddy obtains the HTTPS certificate automatically. HTTPS is required: Apps Script
add-ons may only call `https://` URLs.

### When the IP or domain changes

Without an Elastic IP, stopping and starting the instance changes its public IP, and with it the
sslip.io hostname. Re-run `scripts/deploy.sh <new-ec2-dns> [domain]`, then update the add-on's
`urlFetchWhitelist` (in `appsscript.json`) and `BACKEND_URL` (in `Code.gs`). Authentication is unaffected.

## Authentication

The add-on calls `ScriptApp.getIdentityToken()` and sends the result as a bearer token: an
OpenID Connect ID token signed by Google for the signed-in user, valid for about an hour.
The backend accepts a request only if:

1. the RS256 signature verifies against Google's published keys (cached for an hour);
2. `iss` is Google and the token is not expired;
3. `aud` is in `ALLOWED_AUDIENCES`, the OAuth client of *this* Apps Script project, so a token
   Google issued to any other app (including another Apps Script) is rejected;
4. `email` is verified and matches `ALLOWED_EMAILS`: `*` (any user of the add-on),
   `*@example.com` (one organization) or an explicit list.

Check 3 is what makes the API usable only through this add-on; check 4 is a policy choice
about *who* may use the add-on, so a public add-on uses `*`.

No shared secret is involved in calling the API. To find the audience and email values, run
`debugIdentityToken()` in the Apps Script editor. A correctly signed token with an unknown
audience is also logged by the backend, which helps when the Apps Script project changes.

## Security notes

- **Untrusted input:** every field has a length/count limit; requests over 1 MB are rejected
  before parsing (in Caddy and in the app). Validation errors never echo input back.
- **No content in logs:** only a hash of the message id, the score and the matched rule ids are logged.
- **Forged headers:** only `Authentication-Results` stamped by `mx.google.com` are trusted;
  senders can include their own fake `dmarc=pass`.
- **Outbound requests:** rules never fetch URLs from the email (avoids SSRF and tipping off attackers). The only outbound
  calls are the two VirusTotal rules (one shared client): registrable domains (top-5k skipped) and attachment
  SHA-256 hashes only, cached, rate-limited to 4/min per key, 5 s timeout; and `new_domain` to RDAP registries
  (domain names only, HTTPS only, servers from IANA's bootstrap in `data/rdap_dns.json`, 3 s timeout, cached).
- **Fault isolation:** a crashing rule is reported in `rulesFailed` and doesn't fail the request.
- **One secret:** the VirusTotal key, in AWS Secrets Manager (`VT_API_KEY_SECRET_ARN`), read with the instance's IAM
  role, kept in memory, never logged (`app/engine/vt_key.py`). Without an ARN, the `VT_API_KEY` setting is used (local
  development, tests, rollback). Callers are authenticated with Google-signed identity tokens, not shared secrets.
