"""Where the VirusTotal API key comes from.

Production: AWS Secrets Manager, read with the EC2 instance's IAM role (no AWS credentials stored),
held in memory only, never logged. Configured by VT_API_KEY_SECRET_ARN (not secret).
Local development and tests, or a rollback: the VT_API_KEY setting, as before.
"""

import json
import logging
import threading
import time
from collections.abc import Callable
from functools import lru_cache

from app.config import get_settings

logger = logging.getLogger(__name__)

# After VirusTotal rejects the key (e.g. it was rotated), re-read the secret at most this often.
REFRESH_AFTER_REJECTION_SECONDS = 300
# After a failed read (no permission, AWS unreachable), wait this long before trying again.
RETRY_AFTER_FAILURE_SECONDS = 60


class VtKeyUnavailable(Exception):
    """The secret couldn't be read. Messages never contain the secret's value."""


def fetch_from_secrets_manager(secret_arn: str, field: str) -> str:
    """The key from the secret: the `field` of a key/value (JSON) secret, or a plaintext secret as is."""
    import boto3  # lazy: only needed when a secret ARN is configured
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    region = secret_arn.split(":")[3]  # arn:aws:secretsmanager:<region>:<account>:secret:<name>
    client = boto3.client(
        "secretsmanager",
        region_name=region,
        config=Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2}),
    )
    try:
        secret = client.get_secret_value(SecretId=secret_arn).get("SecretString") or ""
    except ClientError as exc:
        raise VtKeyUnavailable(f"Secrets Manager refused: {exc.response.get('Error', {}).get('Code', 'error')}") from None
    except BotoCoreError as exc:
        raise VtKeyUnavailable(f"Secrets Manager unreachable: {type(exc).__name__}") from None

    try:
        parsed = json.loads(secret)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        value = parsed.get(field)
        if not isinstance(value, str) or not value.strip():
            raise VtKeyUnavailable(f"secret has no non-empty field {field!r}")
        return value.strip()
    if not secret.strip():
        raise VtKeyUnavailable("secret is empty")
    return secret.strip()


class VtKeySource:
    def __init__(self, secret_arn: str, secret_field: str, fallback_key: str,
                 fetch: Callable[[str, str], str] = fetch_from_secrets_manager) -> None:
        self.secret_arn = secret_arn
        self.secret_field = secret_field
        self._fallback_key = fallback_key
        self._fetch = fetch
        self._lock = threading.Lock()
        self._key = ""
        self._last_attempt = float("-inf")

    @property
    def description(self) -> str:
        """Where the key comes from, for logs (the ARN's secret name is not secret)."""
        if self.secret_arn:
            return f"AWS Secrets Manager ({self.secret_arn.rsplit(':', 1)[-1]})"
        return "VT_API_KEY setting" if self._fallback_key else "nowhere (not configured)"

    def get(self) -> str:
        """The key, or "" if it isn't available right now (the VirusTotal rules then report failure)."""
        if not self.secret_arn:
            return self._fallback_key
        with self._lock:
            if not self._key and time.monotonic() - self._last_attempt >= RETRY_AFTER_FAILURE_SECONDS:
                self._load_locked()
            return self._key

    def refresh_after_rejection(self) -> None:
        """VirusTotal said 401: the secret may have been rotated. Re-read it (throttled)."""
        if not self.secret_arn:
            return
        with self._lock:
            if time.monotonic() - self._last_attempt >= REFRESH_AFTER_REJECTION_SECONDS:
                self._key = ""
                self._load_locked()

    def _load_locked(self) -> None:
        self._last_attempt = time.monotonic()
        try:
            self._key = self._fetch(self.secret_arn, self.secret_field)
            logger.info("VirusTotal API key loaded from %s", self.description)
        except VtKeyUnavailable as exc:
            logger.error("VirusTotal API key not available from %s: %s", self.description, exc)
        except Exception as exc:  # never let a surprise here take down the service
            logger.error("VirusTotal API key not available from %s: %s", self.description, type(exc).__name__)


@lru_cache
def vt_key_source() -> VtKeySource:
    settings = get_settings()
    return VtKeySource(
        settings.vt_api_key_secret_arn,
        settings.vt_api_key_secret_field,
        settings.vt_api_key.get_secret_value(),
    )
