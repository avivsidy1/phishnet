from app.engine.context import EmailContext
from app.engine.rule import Hit, Rule


class DangerousAttachment(Rule):
    """Attachment types used to deliver malware or fake login pages, and disguised names like invoice.pdf.exe.

    The user can trust file types in Settings: a trusted type is no longer flagged *by type*, but a
    disguised name is always flagged, and known malware is still caught by virustotal_file.
    """

    id = "dangerous_attachment"
    title = "Risky attachment type"
    description = "An attachment's type can run code or show a fake login page (.exe, .html, .iso, macro Office files), or it's disguised, like invoice.pdf.exe. File types you trust in Settings aren't flagged by type; disguised names always are."
    category = "attachments"
    default_score = 35
    default_params = {
        # Run code when opened, or are common malware/phishing containers.
        "dangerous_extensions": [
            "exe", "scr", "com", "pif", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "wsf",
            "hta", "ps1", "jar", "lnk", "iso", "img", "vhd", "html", "htm", "svg",
        ],
        # Office files that can contain macros.
        "macro_extensions": ["docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"],
        # Extensions attackers use as the decoy in "invoice.pdf.exe".
        "decoy_extensions": ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"],
    }

    def evaluate(self, email: EmailContext) -> Hit | None:
        dangerous = set(self.params["dangerous_extensions"])
        macro = set(self.params["macro_extensions"])
        decoy = set(self.params["decoy_extensions"])
        trusted = set(email.report.preferences.trusted_extensions)  # validated by the schema

        evidence = []
        for attachment in email.attachments:
            name = attachment.filename.strip().lower()
            parts = name.rsplit(".", 2)
            ext = parts[-1] if len(parts) > 1 else ""
            if len(parts) == 3 and parts[1] in decoy and ext in dangerous | macro:
                evidence.append(f"{attachment.filename}: disguised .{ext} file")  # even if .{ext} is trusted
            elif ext in trusted:
                continue
            elif ext in dangerous:
                evidence.append(f"{attachment.filename}: .{ext} files can run code or open fake login pages")
            elif ext in macro:
                evidence.append(f"{attachment.filename}: Office file that can contain macros")

        if not evidence:
            return None
        return Hit(
            explanation="This email has an attachment of a type commonly used to deliver malware or phishing pages.",
            evidence=evidence,
        )
