"""Mailbox app passwords from one Secrets Manager JSON secret (decision A591).

The secret holds ``{"<alias>": "<app password>", ...}``. The stack creates it as ``{}``; the
operator fills it with ``aws secretsmanager put-secret-value``. Rules (design section 6):

- Read lazily: nothing is fetched until a tool first needs a password (``list_accounts`` never
  does). One ``GetSecretValue`` per container per 15 minutes; after a failed, empty or
  unparsable read the next attempt waits 60 s, so an outage is not hammered.
- Values are wrapped in ``Secret``, whose ``repr`` and ``str`` are redacted. ``reveal()`` is
  the only way to the plain text and is meant for the IMAP login call only.
- Never logged: problems log a fixed sentence and the exception type, never the secret id
  (an ARN carries the account id), a value, a key or exception text.
- ``forget(alias)`` drops one cached password, e.g. after the provider rejects the login.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("mail.credentials")

SecretFetcher = Callable[[str], "str | None"]

_client = None


class Secret:
    """A string that does not print itself."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __reduce__(self):  # never pickled into anything that might be logged or stored
        raise TypeError("Secret cannot be pickled")


def secrets_client():
    """The container's boto3 Secrets Manager client, created on first use."""
    global _client
    if _client is None:
        import boto3  # provided by the Lambda runtime

        _client = boto3.client("secretsmanager")
    return _client


def _boto3_fetcher(secret_id: str) -> str | None:
    client = secrets_client()
    try:
        resp = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException:
        return None
    return resp.get("SecretString") or None


class InvalidSecret(ValueError):
    """The secret does not have the documented shape. Never carries a value or key."""


def parse_secret(raw: str | None) -> dict[str, Secret]:
    """``{"alias": "password"}`` to wrapped values. Missing or blank is ``{}``.

    Malformed raises ``InvalidSecret``: not JSON, not an object, duplicate keys, or a value
    that is not a non-empty string. The exception text is fixed.
    """
    if raw is None or not raw.strip():
        return {}

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        if len({k for k, _ in pairs}) != len(pairs):
            raise InvalidSecret("duplicate key")
        return dict(pairs)

    try:
        doc = json.loads(raw, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError:
        raise InvalidSecret("not valid JSON") from None
    if not isinstance(doc, dict):
        raise InvalidSecret("expected a JSON object keyed by account alias")
    out: dict[str, Secret] = {}
    for alias, value in doc.items():
        if not isinstance(value, str) or not value:
            raise InvalidSecret("every value must be a non-empty string")
        out[alias] = Secret(value)
    return out


class CredentialStore:
    """App passwords by account alias, read lazily from one secret and cached per container."""

    def __init__(
        self,
        secret_id: str,
        fetch: SecretFetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 900.0,
        retry_seconds: float = 60.0,
    ):
        self._secret_id = secret_id
        self._fetch = fetch or _boto3_fetcher
        self._clock = clock
        self._ttl = ttl_seconds
        self._retry = retry_seconds
        self._lock = threading.Lock()
        self._values: dict[str, Secret] = {}
        self._read_at: float | None = None
        self._good = False

    def password(self, alias: str) -> Secret | None:
        """The app password for ``alias``, or ``None`` if the secret has none (or cannot be read)."""
        with self._lock:
            self._refresh_if_due()
            return self._values.get(alias)

    def forget(self, alias: str) -> None:
        """Drop one cached password; the next ``password()`` for it re-reads the secret."""
        with self._lock:
            if self._values.pop(alias, None) is not None:
                self._read_at = None

    def _refresh_if_due(self) -> None:
        now = self._clock()
        if self._read_at is not None:
            wait = self._ttl if self._good else self._retry
            if now - self._read_at < wait:
                return
        self._read_at = now
        self._values = self._load()
        self._good = bool(self._values)

    def _load(self) -> dict[str, Secret]:
        if not self._secret_id:
            logger.error("credentials: no secret is configured; no mailbox can log in")
            return {}
        try:
            raw = self._fetch(self._secret_id)
        except Exception as exc:  # access denied, throttling, network
            logger.error("credentials: secret read failed (%s)", type(exc).__name__)
            return {}
        try:
            values = parse_secret(raw)
        except InvalidSecret as exc:
            logger.error("credentials: secret is unparsable (%s); no mailbox can log in", exc)
            return {}
        if not values:
            logger.error("credentials: secret is empty; no mailbox can log in")
        return values
