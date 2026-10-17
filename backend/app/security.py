"""Caller authentication (Google identity tokens) and request size limiting.

The add-on sends `Authorization: Bearer <token>`, where the token comes from
ScriptApp.getIdentityToken(): an OpenID Connect ID token signed by Google, valid for ~1 hour.
There is no shared secret: a caller is accepted only if Google vouches for who they are
and which app the token was issued to.
"""

import logging
from collections.abc import Callable
from typing import Any

import jwt
from fastapi import Header, HTTPException, Request, status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
CLOCK_SKEW_SECONDS = 30
MAX_TOKEN_CHARS = 4096

# Given a raw token, returns the public key it claims to be signed with.
KeyResolver = Callable[[str], Any]


class AuthError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def google_key_resolver() -> KeyResolver:
    """Looks up Google's signing key by the token's key id. Keys are cached for an hour."""
    client = jwt.PyJWKClient(GOOGLE_CERTS_URL, cache_jwk_set=True, lifespan=3600, timeout=5)
    return lambda token: client.get_signing_key_from_jwt(token).key


class GoogleIdentityVerifier:
    def __init__(self, audiences: list[str], emails: list[str], key_resolver: KeyResolver) -> None:
        self.audiences = audiences
        self.emails = {e.lower() for e in emails}
        self._resolve_key = key_resolver

    def verify(self, token: str) -> str:
        """Returns the caller's email if the token is valid and the account is allowed."""
        try:
            key = self._resolve_key(token)
        except jwt.PyJWKClientConnectionError:
            raise AuthError(status.HTTP_503_SERVICE_UNAVAILABLE, "Could not reach Google to verify the token")
        except jwt.PyJWTError:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token")

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],  # never accept "none" or a symmetric algorithm
                audience=self.audiences,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "email"]},
            )
        except jwt.InvalidAudienceError:
            self._log_rejected_audience(token, key)
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token")
        except jwt.PyJWTError:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token")

        if claims["iss"] not in GOOGLE_ISSUERS:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token")

        email = str(claims["email"]).lower()
        if claims.get("email_verified") is not True or not self._is_allowed(email):
            raise AuthError(status.HTTP_403_FORBIDDEN, "This account is not allowed to use this service")
        return email

    def _is_allowed(self, email: str) -> bool:
        domain = email.rpartition("@")[2]
        return "*" in self.emails or email in self.emails or f"*@{domain}" in self.emails

    @staticmethod
    def _log_rejected_audience(token: str, key: Any) -> None:
        # The signature is valid (Google issued it), just for a different client. Logging the
        # audience makes ALLOWED_AUDIENCES easy to set up or fix after the add-on's project changes.
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
        except jwt.PyJWTError:
            return
        logger.warning("Rejected Google token for unknown audience %r", str(claims.get("aud"))[:200])


def require_google_user(request: Request, authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency: the authenticated caller's email, or 401/403."""
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > MAX_TOKEN_CHARS:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing or malformed bearer token", headers={"WWW-Authenticate": "Bearer"}
        )
    verifier: GoogleIdentityVerifier = request.app.state.verifier
    try:
        return verifier.verify(token)
    except AuthError as exc:
        raise HTTPException(exc.status_code, exc.detail) from None


class BodySizeLimitMiddleware:
    """Rejects oversized requests before the body is read or parsed.

    Requests with a body must declare Content-Length (the add-on always does),
    which lets us refuse large payloads up front instead of buffering them.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        content_length = headers.get(b"content-length")
        if content_length is None:
            await _reject(411, "Content-Length required", scope, receive, send)
            return
        try:
            too_large = int(content_length) > self.max_bytes
        except ValueError:
            too_large = True
        if too_large:
            await _reject(413, "Request body too large", scope, receive, send)
            return

        await self.app(scope, receive, send)


async def _reject(status_code: int, detail: str, scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse({"detail": detail}, status_code=status_code)
    await response(scope, receive, send)
