"""Fixed error categories (design section 7.5).

Every failure a tool can report is one of these. The text a caller sees is built from the
category, an optional argument *name* and a fixed hint; it never contains a submitted value,
a server response or an exception message. The audit line records the category only.
"""

from __future__ import annotations

INVALID_ARGUMENT = "invalid_argument"
FORBIDDEN = "forbidden"
ACCOUNT_NOT_FOUND = "account_not_found"
FOLDER_MISSING = "folder_missing"
STALE_ID = "stale_id"
NOT_FOUND = "not_found"
AUTH_FAILED = "auth_failed"
UNAVAILABLE = "unavailable"
TIMEOUT = "timeout"
TOO_LARGE = "too_large"
CONFLICT = "conflict"

CATEGORIES = frozenset(
    {
        INVALID_ARGUMENT, FORBIDDEN, ACCOUNT_NOT_FOUND, FOLDER_MISSING, STALE_ID, NOT_FOUND,
        AUTH_FAILED, UNAVAILABLE, TIMEOUT, TOO_LARGE, CONFLICT,
    }
)

_HINTS = {
    INVALID_ARGUMENT: "check the argument against the tool's schema",
    FORBIDDEN: "this client may not do that; tell the user",
    ACCOUNT_NOT_FOUND: "call list_accounts for the accounts you can use",
    FOLDER_MISSING: "that folder does not exist in this account",
    STALE_ID: "the message id is out of date; search again",
    NOT_FOUND: "no such message; search again",
    AUTH_FAILED: "the mail provider refused the login; tell the user",
    UNAVAILABLE: "the mail service is not available right now; try again later or tell the user",
    TIMEOUT: "the mail provider did not answer in time; try again with narrower filters",
    TOO_LARGE: "the result is too large; narrow the request",
    CONFLICT: "the request conflicts with existing state",
}

# Argument names come from our own tool signatures; anything else is not repeated.
_ARGUMENT_NAME_MAX = 40


class MailError(Exception):
    """A failure with a fixed category. ``str()`` is safe to show and never carries a value."""

    category: str = UNAVAILABLE

    def __init__(self, category: str | None = None, *, argument: str | None = None):
        category = category or type(self).category
        if category not in CATEGORIES:
            raise ValueError("unknown error category")
        self.category = category
        self.argument = argument if _safe_name(argument) else None
        super().__init__(self.public_message())

    def public_message(self) -> str:
        hint = _HINTS[self.category]
        if self.argument:
            return f"{self.category}: {self.argument}: {hint}"
        return f"{self.category}: {hint}"


def _safe_name(name: str | None) -> bool:
    return bool(name) and len(name) <= _ARGUMENT_NAME_MAX and name.replace("_", "").isalnum() and name.isascii()


class InvalidArgument(MailError):
    category = INVALID_ARGUMENT


class Forbidden(MailError):
    category = FORBIDDEN


class AccountNotFound(MailError):
    category = ACCOUNT_NOT_FOUND


class Unavailable(MailError):
    category = UNAVAILABLE
