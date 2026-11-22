"""Hands the verified caller to MCP tool code through the SDK's own context (``/mcp`` only).

Importing this module imports the MCP SDK (about 2 s cold), so it is only imported on ``/mcp``
requests. Tool code reads the caller with the SDK's ``get_access_token()``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from mcp.server.auth.middleware.auth_context import auth_context_var, get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from .auth import VerifiedToken

__all__ = ["get_access_token", "published", "to_access_token"]


def to_access_token(verified: VerifiedToken, token: str | None) -> AccessToken:
    """The SDK shape. ``token`` is the JWT; the API key is never copied in (empty string)."""
    return AccessToken(
        token=token or "",
        client_id=verified.client_id,
        scopes=list(verified.scopes),
        expires_at=verified.expires_at,
        resource=verified.resource,
        subject=verified.subject,
        claims=dict(verified.claims) or None,
    )


@contextmanager
def published(verified: VerifiedToken, token: str | None) -> Iterator[None]:
    """Sets the SDK ``auth_context_var`` for the duration of the block."""
    reset = auth_context_var.set(AuthenticatedUser(to_access_token(verified, token)))
    try:
        yield
    finally:
        auth_context_var.reset(reset)
