"""The mail backend seam: the only interface between ``MailService`` and a mail protocol.

``MailBackend`` is a protocol so that the IMAP implementation (``ImapBackend``, EML-003b, using
``imapclient`` as transport only) and the test ``FakeBackend`` are interchangeable, and so a
later OAuth adapter (Gmail API, Microsoft Graph) can slot in without touching the service.

Rules every implementation keeps:

- Every method takes the caller's effective aliases as the required keyword ``allowed`` and
  refuses any account outside it (``ensure_allowed``), as a second check behind the service.
- Results are plain dataclasses of primitives and raw bytes. MIME parsing and sanitising happen
  outside the backend (stdlib ``email``, ``sanitize.py`` in EML-003a), never in the transport.
- Failures are ``MailError`` subclasses with a fixed category; never a library exception or its
  text, which can carry server responses.
- Read operations never change mailbox state (``EXAMINE`` and ``BODY.PEEK`` in the IMAP backend).

EML-002 has no implementation in the deployed code: no tool calls the backend yet, and
``MailService`` reports ``unavailable`` if one is asked for before EML-003b lands.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Protocol

from .accounts import Account
from .credentials import Secret
from .errors import Forbidden


@dataclass(frozen=True)
class SearchCriteria:
    """Validated search filters (EML-003b maps them to IMAP ``SEARCH`` or ``X-GM-RAW``)."""

    query: str | None = None
    sender: str | None = None
    recipient: str | None = None
    subject: str | None = None
    since: date | None = None  # inclusive
    before: date | None = None  # exclusive
    unread_only: bool = False


@dataclass(frozen=True)
class MessageSummary:
    """One search hit: header bytes for the service to decode and sanitise."""

    account: str
    folder: str  # logical name
    uidvalidity: int
    uid: int
    headers: bytes  # raw header block (From, To, Subject, Date, Message-ID)
    internal_date: str | None = None
    unread: bool = False
    attachments: int = 0


@dataclass(frozen=True)
class AttachmentInfo:
    filename: str | None
    content_type: str
    size: int


@dataclass(frozen=True)
class MessageDetail:
    """One message: headers and at most one chosen text part, size-capped by the backend."""

    account: str
    folder: str
    uidvalidity: int
    uid: int
    headers: bytes
    body: bytes = b""
    body_content_type: str = "text/plain"
    body_charset: str | None = None
    body_truncated: bool = False
    unread_before: bool = False
    attachments: tuple[AttachmentInfo, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DraftRef:
    account: str
    uidvalidity: int | None
    uid: int | None
    replayed: bool = False


class MailBackend(Protocol):
    """Blocking mail operations; the service runs them in worker threads with a deadline."""

    def search(
        self,
        account: Account,
        password: Secret,
        folder: str,
        criteria: SearchCriteria,
        limit: int,
        *,
        allowed: Sequence[str],
        timeout: float,
    ) -> list[MessageSummary]: ...

    def fetch(
        self,
        account: Account,
        password: Secret,
        folder: str,
        uidvalidity: int,
        uid: int,
        *,
        allowed: Sequence[str],
        max_bytes: int,
        timeout: float,
    ) -> MessageDetail: ...

    def append_draft(
        self,
        account: Account,
        password: Secret,
        message: bytes,
        message_id: str,
        *,
        allowed: Sequence[str],
        timeout: float,
    ) -> DraftRef: ...

    def close(self) -> None:
        """Close every cached connection (container shutdown, or after a deadline)."""
        ...


def ensure_allowed(account: Account, allowed: Sequence[str]) -> None:
    """The backend's own check: refuse an account the service did not pass as effective."""
    if account.alias not in allowed:
        raise Forbidden()
