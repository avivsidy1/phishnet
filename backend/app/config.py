"""Service settings, read from environment variables (or a local .env file)."""

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Comma-separated. The OAuth client ID(s) of the Apps Script project: the "aud" claim
    # of the identity tokens it issues. Rejects tokens Google issued to any other app.
    allowed_audiences: str = ""
    # Comma-separated. Which signed-in users may use the add-on:
    #   "*"                any verified Google account (public add-on)
    #   "*@example.com"    any account in that domain
    #   "a@x.com,b@y.com"  specific accounts
    # Required (no default) so opening the service to everyone is an explicit decision.
    allowed_emails: str = ""

    rules_config_path: Path = BACKEND_ROOT / "config" / "rules.yaml"
    # Hard cap on request size. The add-on already truncates bodies, so real reports are far smaller.
    max_request_bytes: int = 1_000_000
    log_level: str = "INFO"
    # VirusTotal API key. Production reads it from AWS Secrets Manager: set the secret's ARN
    # (not secret) and, for a key/value secret, the field holding the key. The instance's IAM role
    # grants access; the value is kept in memory only and never logged.
    vt_api_key_secret_arn: str = ""
    vt_api_key_secret_field: str = "VT_API_KEY"
    # Fallback when no ARN is set: local development, tests, or a rollback to the previous setup.
    vt_api_key: SecretStr = SecretStr("")

    @property
    def audience_list(self) -> list[str]:
        return _split(self.allowed_audiences)

    @property
    def email_list(self) -> list[str]:
        return [e.lower() for e in _split(self.allowed_emails)]

    @model_validator(mode="after")
    def allowlists_required(self) -> "Settings":
        # Fail closed: refuse to start rather than run with authentication effectively disabled.
        if not self.audience_list or not self.email_list:
            raise ValueError("ALLOWED_AUDIENCES and ALLOWED_EMAILS must both be set")
        return self


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
