from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule
from app.engine.virustotal import VirusTotalUnavailable, shared_client
from app.engine.vt_key import vt_key_source

MAX_ENGINES_SHOWN = 3


class VirusTotalFile(Rule):
    """An attachment that antivirus engines on VirusTotal detect as malicious, matched by its SHA-256.

    The add-on hashes each attachment (up to 25 MB); only the hash is looked up, so the file is never
    uploaded and a private document reveals nothing. 70 points: a known-malicious file makes the
    email Malicious on its own. Hence a stricter bar than for domains (3 engines by default): harmless
    files sometimes collect one or two low-quality detections.

    Shares the VirusTotal client, cache and rate limit with virustotal_domain. If a file that needed
    checking could not be checked and nothing was found, the rule raises (listed in rulesFailed).
    A file VirusTotal has never seen (404) is unknown, not clean, and doesn't fire.
    """

    id = "virustotal_file"
    title = "Attachment detected as malware (VirusTotal)"
    description = "An attachment matches known malware: at least 3 antivirus engines on VirusTotal detect it. Only the file's fingerprint (SHA-256) is sent, never the file."
    category = "attachments"
    default_score = 70
    default_params = {
        "min_malicious": 3,
        "max_lookups_per_email": 3,
        # Keep equal to virustotal_domain: both rules share one client per API key.
        "requests_per_minute": 4,
        "timeout_seconds": 5,
        "cache_hours": 24,
        "not_found_cache_hours": 6,
    }

    def __init__(self, score=None, params=None) -> None:
        super().__init__(score, params)
        self.client = shared_client(
            vt_key_source(),
            self.params["timeout_seconds"],
            self.params["requests_per_minute"],
        )

    def warm_up(self) -> None:
        self.client.key_source.get()  # read the key at startup, so a bad ARN/role shows in the startup log

    def evaluate(self, email: EmailContext) -> Hit | None:
        names: dict[str, str] = {}  # sha256 -> first filename with that content
        for attachment in email.attachments:
            if attachment.sha256:  # validated as 64 hex chars by the schema; None if too large to hash
                names.setdefault(attachment.sha256, attachment.filename or "(unnamed)")
        if not names:
            return None

        reports, unchecked = self.client.lookup_many(
            "files",
            list(names),
            self.params["max_lookups_per_email"],
            int(self.params["cache_hours"] * 3600),
            int(self.params["not_found_cache_hours"] * 3600),
        )

        evidence = []
        for sha256, filename in names.items():
            report = reports.get(sha256)
            if report and report.malicious >= self.params["min_malicious"]:
                engines = ", ".join(f"{n} ({r})" for n, r in report.flagged_by[:MAX_ENGINES_SHOWN])
                if len(report.flagged_by) > MAX_ENGINES_SHOWN:
                    engines += ", …"
                evidence.append(
                    f"attachment {filename}: {report.malicious}/{report.total} antivirus engines detect it"
                    + (f"; e.g. {engines}" if engines else "")
                )
        if not evidence:
            if unchecked:
                raise VirusTotalUnavailable(f"{len(unchecked)} attachment(s) could not be checked")
            return None
        if unchecked:
            evidence.append(f"{len(unchecked)} other attachment(s) could not be checked right now")
        return Hit(
            explanation=(
                "An attached file matches a file that antivirus engines on VirusTotal detect as malware. "
                "It was identified by its fingerprint (SHA-256); the file itself was not uploaded. Don't open it."
            ),
            evidence=evidence,
        )
