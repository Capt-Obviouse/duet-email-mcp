"""Authentication: which credential a request carries, and the one place each kind is checked.

EML-002 accepts one credential, the **API key** (SSM SecureString ``<prefix>/api-key``), as
``X-API-Key: <key>`` or as a non-JWT ``Authorization: Bearer <key>``. It is the client
``api-key``. ``ENABLE_API_KEY=false`` turns it off (401, no SSM read). The key's token carries
both mail scopes, but the key client is **read only unless** ``client-limits`` grants
``draft`` (``accounts.effective_scopes``), so by default it can only read.

A JWT-shaped bearer goes to the JWT verifier (Cognito, EML-005) and is never compared with the
key. Until a verifier is configured such a bearer is 503, never a pass. The seam is
pool-agnostic: ``Authenticator`` takes any ``JwtVerifier``.

Routing never tries one credential as the other:

- ``X-API-Key`` present (even empty): it is the API key, and ``Authorization`` is ignored.
- ``Authorization`` must be exactly ``Bearer <token>`` (scheme case-insensitive, one token, no
  other whitespace); anything else counts as no credential (401).
- A JWT-shaped bearer (three dot-separated base64url segments, the last may be empty) goes to
  the JWT verifier only. Any other bearer is the API key.

``Authenticator.authenticate`` returns a ``VerifiedToken`` or raises ``TokenRejected`` (401) or
``AuthUnavailable`` (503). This module never imports the MCP SDK at import time;
``auth_context.py`` converts a ``VerifiedToken`` into the SDK's ``AccessToken``.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import anyio.to_thread

if TYPE_CHECKING:  # the SDK type, for the TokenVerifier shape only
    from mcp.server.auth.provider import AccessToken

API_KEY_HEADER = "X-API-Key"
AUTHORIZATION_HEADER = "Authorization"
BEARER_SCHEME = "bearer"
# The client identity of the API key, as used in ``client-limits`` and audit lines.
API_KEY_CLIENT_ID = "api-key"

SCOPE_READ = "mail.read"
SCOPE_DRAFT = "mail.draft"
ALL_SCOPES = (SCOPE_READ, SCOPE_DRAFT)

METHOD_API_KEY = "api_key"
METHOD_OAUTH = "oauth"

_JWT_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class VerifiedToken:
    """An authenticated caller. Holds no credential, so it is safe to keep on ``request.state``.

    ``scopes`` are what the credential carries; what the caller may actually do is these
    narrowed by its client limit (``accounts.effective_scopes``).
    """

    client_id: str
    scopes: tuple[str, ...]
    method: str  # METHOD_API_KEY or METHOD_OAUTH
    expires_at: int | None = None
    subject: str | None = None
    resource: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict)


class TokenRejected(Exception):
    """The credential is missing, malformed or invalid: 401. ``reason`` is a short code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class AuthUnavailable(Exception):
    """The credential cannot be checked right now (configuration or dependency outage): 503.

    Never a reason to let a request through. ``reason`` is a short code.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class JwtVerifier(Protocol):
    """The seam EML-005 fills with the Cognito verifier (pool id from configuration)."""

    async def verify(self, token: str) -> VerifiedToken: ...


class KeySource(Protocol):
    def api_key(self) -> str | None: ...


# ------------------------------------------------------------------ routing (pure)


@dataclass(frozen=True)
class Credential:
    kind: str  # METHOD_API_KEY or "jwt"
    value: str | None  # None: none presented, or malformed


def credential_from_headers(headers: Mapping[str, str]) -> Credential:
    """The presented credential and which verifier owns it.

    ``headers`` must be case-insensitive (Starlette ``Headers``).
    """
    api_key = headers.get(API_KEY_HEADER)
    if api_key is not None:
        return Credential(METHOD_API_KEY, api_key or None)
    token = bearer_token(headers.get(AUTHORIZATION_HEADER))
    if token is not None and looks_like_jwt(token):
        return Credential("jwt", token)
    return Credential(METHOD_API_KEY, token)


def bearer_token(value: str | None) -> str | None:
    """The token from ``Bearer <token>``; None for any other shape."""
    if not value:
        return None
    parts = value.split(" ")
    if len(parts) != 2 or parts[0].lower() != BEARER_SCHEME:
        return None
    token = parts[1]
    if not token or any(ch.isspace() for ch in token):
        return None
    return token


def looks_like_jwt(token: str) -> bool:
    return _JWT_SHAPE.fullmatch(token) is not None


def key_matches(supplied: str | None, expected: str | None) -> bool:
    """Constant-time comparison; empty values never match."""
    if not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


# ------------------------------------------------------------------ verifiers


API_KEY_TOKEN = VerifiedToken(client_id=API_KEY_CLIENT_ID, scopes=ALL_SCOPES, method=METHOD_API_KEY)


class ApiKeyVerifier:
    """Checks a presented key against the configured one.

    ``verify_key`` blocks (SSM read on a cold cache). ``verify_token`` is the SDK
    ``TokenVerifier`` shape: it returns ``AccessToken`` or ``None`` and never raises for a bad
    key (an unconfigured key is still ``None``: no pass).
    """

    def __init__(self, keys: KeySource):
        self._keys = keys

    def verify_key(self, key: str | None) -> VerifiedToken:
        expected = self._keys.api_key()  # read first: an unconfigured key is 503 for everyone
        if expected is None:
            raise AuthUnavailable("api_key_unconfigured")
        if not key:
            raise TokenRejected("no_credential")
        if not key_matches(key, expected):
            raise TokenRejected("bad_api_key")
        return API_KEY_TOKEN

    async def verify(self, token: str) -> VerifiedToken:
        return await anyio.to_thread.run_sync(self.verify_key, token)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            verified = await self.verify(token)
        except (TokenRejected, AuthUnavailable):
            return None
        from .auth_context import to_access_token  # imports the SDK

        return to_access_token(verified, None)


class Authenticator:
    """Routes the request's credential to exactly one verifier."""

    def __init__(self, api_keys: ApiKeyVerifier, jwt: JwtVerifier | None, *, api_key_enabled: bool):
        self._api_keys = api_keys
        self._jwt = jwt
        self._api_key_enabled = api_key_enabled

    async def authenticate(self, headers: Mapping[str, str]) -> tuple[VerifiedToken, str | None]:
        """The verified caller and the raw JWT (None for the API key)."""
        credential = credential_from_headers(headers)
        if credential.kind == "jwt":
            assert credential.value is not None
            if self._jwt is None:
                raise AuthUnavailable("oauth_unconfigured")
            return await self._jwt.verify(credential.value), credential.value
        if not self._api_key_enabled:
            raise TokenRejected("api_key_disabled")
        return await anyio.to_thread.run_sync(self._api_keys.verify_key, credential.value), None
