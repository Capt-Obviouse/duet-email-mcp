"""Audit log: one JSON line per MCP tool call (design section 13, decision 11).

A line looks like::

    {"event": "audit", "ts": "2026-11-22T14:03:22.123Z", "client_id": "api-key",
     "auth": "api_key", "tool": "list_accounts", "account": "*", "status": "ok", "ms": 3.1}

- ``tool`` is the tool name, or ``unknown`` for a name that is not a tool (never echoed).
- ``account`` is the alias the call addressed, ``*`` for a call over all effective accounts,
  or absent when no valid alias was addressed. A submitted value that is not a configured
  alias is never logged.
- ``status`` is ``ok``, ``error``, ``denied`` (the caller may not do that) or ``partial`` (a
  fan-out with skipped accounts), with ``error_class``: a fixed category from ``errors.py``,
  a protocol code (``unknown_tool``, ``unknown_parameter``) or, for an unexpected failure, the
  exception's type name. Never a message.
- Fan-out calls add the counts ``accounts_ok`` and ``accounts_skipped`` (EML-003b).

Never subjects, bodies, addresses, search text, message ids, filenames, folder names, argument
values, tokens or keys. ``record`` builds the line from an allowlist of keys, so a new field
cannot leak in by accident. Failed authentication is not a call: it shows only in the access line.
This module never imports the MCP SDK.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime

from pydantic import ValidationError

from .auth import METHOD_API_KEY, METHOD_OAUTH, VerifiedToken
from .errors import FORBIDDEN, INVALID_ARGUMENT, MailError

logger = logging.getLogger("mail.audit")

AUTH_API_KEY = "api_key"
AUTH_OAUTH = "oauth"
AUTH_NONE = "none"

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_DENIED = "denied"
STATUS_PARTIAL = "partial"

UNKNOWN_TOOL = "unknown"
ALL_ACCOUNTS = "*"

LINE_KEYS = (
    "event", "ts", "client_id", "auth", "tool", "account", "status", "error_class", "ms",
    "accounts_ok", "accounts_skipped",
)

# Reason codes are short literals from our own code; anything else is logged as "other".
_REASON = re.compile(r"[a-z][a-z0-9_]{0,39}")

Outcome = tuple[str, str | None]  # (status, error_class)
OK: Outcome = (STATUS_OK, None)


def classify(exc: BaseException) -> Outcome:
    """The audit status and error class for a failure. Never reads the exception's message."""
    if isinstance(exc, MailError):
        return (STATUS_DENIED if exc.category == FORBIDDEN else STATUS_ERROR), exc.category
    if isinstance(exc, ValidationError):
        return STATUS_ERROR, INVALID_ARGUMENT
    return STATUS_ERROR, type(exc).__name__


def auth_label(method: str) -> str:
    """``api_key`` or ``oauth`` for a ``VerifiedToken.method``."""
    return {METHOD_API_KEY: AUTH_API_KEY, METHOD_OAUTH: AUTH_OAUTH}.get(method, AUTH_NONE)


def reason_code(reason: str | None) -> str | None:
    """A verifier reason code, or ``other`` if it is not one of our short literals."""
    if reason is None:
        return None
    return reason if _REASON.fullmatch(reason) else "other"


# ------------------------------------------------------------------ caller context (MCP)

_caller: ContextVar[VerifiedToken | None] = ContextVar("mail_audit_caller", default=None)


@contextmanager
def caller(verified: VerifiedToken) -> Iterator[None]:
    """Publishes the verified caller for ``MailMCPServer.call_tool`` (set by the middleware)."""
    reset = _caller.set(verified)
    try:
        yield
    finally:
        _caller.reset(reset)


def current_caller() -> VerifiedToken | None:
    return _caller.get()


# ------------------------------------------------------------------ the line


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def record(
    verified: VerifiedToken | None,
    tool: str,
    outcome: Outcome,
    started: float,
    *,
    account: str | None = None,
    accounts_ok: int | None = None,
    accounts_skipped: int | None = None,
) -> None:
    """Writes one audit line. ``started`` is a ``time.perf_counter()`` value.

    ``account`` must already be a configured alias or ``ALL_ACCOUNTS``: callers pass only
    values they validated, never raw arguments.
    """
    status, error_class = outcome
    fields: dict[str, object | None] = {
        "event": "audit",
        "ts": _timestamp(),
        "client_id": verified.client_id if verified else None,
        "auth": auth_label(verified.method) if verified else AUTH_NONE,
        "tool": tool,
        "account": account,
        "status": status,
        "error_class": error_class,
        "ms": round((time.perf_counter() - started) * 1000, 1),
        "accounts_ok": accounts_ok,
        "accounts_skipped": accounts_skipped,
    }
    line = {key: fields[key] for key in LINE_KEYS if fields[key] is not None or key == "client_id"}
    logger.info(json.dumps(line))
