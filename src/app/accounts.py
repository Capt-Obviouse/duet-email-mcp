"""Which mailboxes exist, and which a client may use: account config and per-client limits, from SSM.

Two String parameters under the SSM prefix, both created by the stack (design section 5):

- ``<prefix>/accounts``: one JSON object keyed by account **alias**. Its keys are the global
  allowlist. No secrets: app passwords are in Secrets Manager (``credentials.py``).
- ``<prefix>/client-limits``: one JSON object keyed by client id, each entry
  ``{"accounts": [...], "access": "read" | "draft"}`` with both fields optional.

Effective accounts for a client = the global list, intersected with the client's ``accounts``
when it has an entry, in global order; an entry can only narrow, and ``"accounts": []`` locks
the client out. Effective scopes = the token's scopes, capped by the client's ``access``
(``read`` allows ``mail.read``; ``draft`` allows ``mail.read`` and ``mail.draft``). A limit never
grants a scope the token lacks. The API key client (``api-key``) is capped at ``read`` unless its
entry says ``"access": "draft"``.

Fail closed. Missing, blank or unparsable ``accounts`` (any unknown field, duplicate key, wrong
type, bad alias, bad port, ``tls`` other than ``implicit``/``starttls``, a generic account without
``imap``) means no mailbox at all, not "the valid ones". Missing or unparsable ``client-limits``
means no access for any client. Each problem is logged once per cache refresh, naming the
parameter and never its value, an alias or an address.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .auth import ALL_SCOPES, API_KEY_CLIENT_ID, SCOPE_DRAFT, SCOPE_READ
from .ssm_params import ParameterReader

ACCOUNTS_PARAM = "accounts"
CLIENT_LIMITS_PARAM = "client-limits"

ALIAS_PATTERN = r"^[a-z0-9][a-z0-9-]{0,31}$"
_ALIAS = re.compile(ALIAS_PATTERN)
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_LOCAL_PART = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
HOST_MAX = 253
ADDRESS_MAX = 254
USERNAME_MAX = 254
DESCRIPTION_MAX = 80
FOLDER_NAME_MAX = 200
CLIENT_ID_MAX = 128

TLS_IMPLICIT = "implicit"
TLS_STARTTLS = "starttls"
TLS_MODES = frozenset({TLS_IMPLICIT, TLS_STARTTLS})
DEFAULT_PORTS = {TLS_IMPLICIT: 993, TLS_STARTTLS: 143}

# Logical folder names: the only folder names a caller ever sends or sees.
LOGICAL_FOLDERS = ("inbox", "sent", "drafts", "all_mail")
# Folders every account has (resolved by preset, config or SPECIAL-USE discovery in EML-003b).
BASE_FOLDERS = ("inbox", "sent", "drafts")

PROVIDER_GOOGLE = "google"
PROVIDER_ICLOUD = "icloud"
PROVIDER_GENERIC = "generic"
# Accepted spellings and the preset each one selects.
PROVIDER_ALIASES = {
    "google": PROVIDER_GOOGLE,
    "gmail": PROVIDER_GOOGLE,
    "workspace": PROVIDER_GOOGLE,
    "icloud": PROVIDER_ICLOUD,
    "generic": PROVIDER_GENERIC,
}

SEARCH_GMAIL = "gmail"
SEARCH_IMAP = "imap"

ACCESS_READ = "read"
ACCESS_DRAFT = "draft"
# Each access level and the scopes it lets through, in ladder order (send would be a new rung).
ACCESS_SCOPES = {ACCESS_READ: (SCOPE_READ,), ACCESS_DRAFT: (SCOPE_READ, SCOPE_DRAFT)}

ACCOUNT_FIELDS = frozenset({"provider", "address", "username", "description", "imap", "folders", "smtp"})
ENDPOINT_FIELDS = frozenset({"host", "port", "tls"})
LIMIT_FIELDS = frozenset({"accounts", "access"})

logger = logging.getLogger("mail.config")


class InvalidParameter(ValueError):
    """A parameter value without the documented shape. The text is fixed: never a value."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    tls: str  # TLS_IMPLICIT or TLS_STARTTLS; there is no plaintext mode


@dataclass(frozen=True)
class Preset:
    imap: Endpoint | None
    smtp: Endpoint | None
    folders: Mapping[str, str]
    search: str


PRESETS: Mapping[str, Preset] = {
    PROVIDER_GOOGLE: Preset(
        imap=Endpoint("imap.gmail.com", 993, TLS_IMPLICIT),
        smtp=Endpoint("smtp.gmail.com", 587, TLS_STARTTLS),
        folders={
            "inbox": "INBOX",
            "sent": "[Gmail]/Sent Mail",
            "drafts": "[Gmail]/Drafts",
            "all_mail": "[Gmail]/All Mail",
        },
        search=SEARCH_GMAIL,
    ),
    PROVIDER_ICLOUD: Preset(
        imap=Endpoint("imap.mail.me.com", 993, TLS_IMPLICIT),
        smtp=Endpoint("smtp.mail.me.com", 587, TLS_STARTTLS),
        folders={"inbox": "INBOX", "sent": "Sent Messages", "drafts": "Drafts"},
        search=SEARCH_IMAP,
    ),
    PROVIDER_GENERIC: Preset(imap=None, smtp=None, folders={"inbox": "INBOX"}, search=SEARCH_IMAP),
}


@dataclass(frozen=True)
class Account:
    """One configured mailbox, with its preset already applied."""

    alias: str
    provider: str  # PROVIDER_GOOGLE, PROVIDER_ICLOUD or PROVIDER_GENERIC
    address: str
    username: str
    imap: Endpoint
    folders: Mapping[str, str] = field(default_factory=dict)  # logical -> actual name, when known
    description: str | None = None
    smtp: Endpoint | None = None  # reserved for a send feature that is not planned (A590)
    search: str = SEARCH_IMAP

    @property
    def logical_folders(self) -> tuple[str, ...]:
        """The logical folders this account offers: the base three, plus ``all_mail`` if mapped."""
        return tuple(f for f in LOGICAL_FOLDERS if f in BASE_FOLDERS or f in self.folders)


@dataclass(frozen=True)
class ClientLimit:
    accounts: tuple[str, ...] | None = None  # None: no account limit (the global list)
    access: str | None = None  # ACCESS_READ or ACCESS_DRAFT; None: the client's default


ClientLimits = Mapping[str, ClientLimit]


# ------------------------------------------------------------------ JSON helpers (pure)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({k for k, _ in pairs}) != len(pairs):  # json.loads would silently keep the last one
        raise InvalidParameter("duplicate key")
    return dict(pairs)


def _loads(raw: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError:
        raise InvalidParameter("not valid JSON") from None
    except RecursionError:
        raise InvalidParameter("nested too deeply") from None


def _object(value: Any, allowed: frozenset[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidParameter(f"{what} must be a JSON object")
    if not set(value) <= allowed:  # a typo must never silently mean "default"
        raise InvalidParameter(f"unknown field in {what}")
    return value


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in text)


def _text(value: Any, max_len: int, what: str) -> str:
    """A non-empty single-line string without control or format characters."""
    if not isinstance(value, str) or not value.strip() or len(value) > max_len or _has_control(value):
        raise InvalidParameter(f"{what} must be a non-empty single-line string of at most {max_len} characters")
    return value.strip()


def is_alias(value: Any) -> bool:
    return isinstance(value, str) and _ALIAS.fullmatch(value) is not None


def _host(value: Any, what: str) -> str:
    if not isinstance(value, str) or len(value) > HOST_MAX or not _HOST.fullmatch(value):
        raise InvalidParameter(f"{what} host must be a DNS name")
    return value.lower()


def _port(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise InvalidParameter(f"{what} port must be an integer from 1 to 65535")
    return value


def _tls(value: Any, what: str) -> str:
    if value not in TLS_MODES:
        raise InvalidParameter(f"{what} tls must be \"implicit\" or \"starttls\"")
    return value


def _address(value: Any) -> str:
    if not isinstance(value, str) or len(value) > ADDRESS_MAX or value.count("@") != 1:
        raise InvalidParameter("address must be one email address")
    local, domain = value.split("@")
    if not _LOCAL_PART.fullmatch(local) or not _HOST.fullmatch(domain) or "." not in domain:
        raise InvalidParameter("address must be one email address")
    return value


# ------------------------------------------------------------------ accounts (pure)


def _endpoint(value: Any, default: Endpoint | None, what: str) -> Endpoint:
    """An endpoint block, each field overriding the preset's; generic accounts need a host."""
    block = _object(value, ENDPOINT_FIELDS, what)
    if "host" in block:
        host = _host(block["host"], what)
    elif default is not None:
        host = default.host
    else:
        raise InvalidParameter(f"{what} host is required for a generic account")
    tls = _tls(block["tls"], what) if "tls" in block else (default.tls if default else TLS_IMPLICIT)
    if "port" in block:
        port = _port(block["port"], what)
    elif default is not None and "tls" not in block:
        port = default.port
    else:
        port = DEFAULT_PORTS[tls]
    return Endpoint(host=host, port=port, tls=tls)


def _folders(value: Any, preset: Mapping[str, str]) -> dict[str, str]:
    block = _object(value, frozenset(LOGICAL_FOLDERS), "folders")
    merged = dict(preset)
    for logical, actual in block.items():
        merged[logical] = _text(actual, FOLDER_NAME_MAX, "a folder name")
    return {name: merged[name] for name in LOGICAL_FOLDERS if name in merged}


def _parse_account(alias: str, entry: Any) -> Account:
    if not is_alias(alias):
        raise InvalidParameter("an account alias must match " + ALIAS_PATTERN)
    entry = _object(entry, ACCOUNT_FIELDS, "an account entry")
    if "provider" not in entry or entry["provider"] not in PROVIDER_ALIASES:
        raise InvalidParameter("provider must be one of: " + ", ".join(PROVIDER_ALIASES))
    provider = PROVIDER_ALIASES[entry["provider"]]
    preset = PRESETS[provider]
    if "address" not in entry:
        raise InvalidParameter("address is required")
    address = _address(entry["address"])
    if provider == PROVIDER_GENERIC and "imap" not in entry:
        raise InvalidParameter("imap is required for a generic account")
    username = _text(entry["username"], USERNAME_MAX, "username") if "username" in entry else address
    description = _text(entry["description"], DESCRIPTION_MAX, "description") if "description" in entry else None
    imap = _endpoint(entry.get("imap", {}), preset.imap, "imap")
    smtp = _endpoint(entry["smtp"], preset.smtp, "smtp") if "smtp" in entry else preset.smtp
    folders = _folders(entry["folders"], preset.folders) if "folders" in entry else dict(preset.folders)
    return Account(
        alias=alias, provider=provider, address=address, username=username, imap=imap,
        folders=folders, description=description, smtp=smtp, search=preset.search,
    )


def parse_accounts(raw: str | None) -> dict[str, Account]:
    """The accounts document, in its own key order. Missing or blank is ``{}`` (no mailbox).

    Anything malformed raises ``InvalidParameter`` for the whole document.
    """
    if raw is None or not raw.strip():
        return {}
    doc = _loads(raw)
    if not isinstance(doc, dict):
        raise InvalidParameter("expected a JSON object keyed by account alias")
    return {alias: _parse_account(alias, entry) for alias, entry in doc.items()}


# ------------------------------------------------------------------ client limits (pure)


def _parse_limit(entry: Any) -> ClientLimit:
    entry = _object(entry, LIMIT_FIELDS, "a client entry")
    accounts = None
    if "accounts" in entry:
        items = entry["accounts"]
        if not isinstance(items, list) or not all(is_alias(item) for item in items):
            raise InvalidParameter("accounts must be a JSON array of account aliases")
        accounts = tuple(dict.fromkeys(items))
    access = entry.get("access")
    if "access" in entry and access not in ACCESS_SCOPES:
        raise InvalidParameter("access must be \"read\" or \"draft\" when present")
    return ClientLimit(accounts=accounts, access=access)


def parse_client_limits(raw: str | None) -> dict[str, ClientLimit]:
    """The per-client limits document. Missing, blank or malformed raises ``InvalidParameter``."""
    if raw is None or not raw.strip():
        raise InvalidParameter("missing")
    doc = _loads(raw)
    if not isinstance(doc, dict):
        raise InvalidParameter("expected a JSON object keyed by client id")
    limits: dict[str, ClientLimit] = {}
    for client_id, entry in doc.items():
        if not client_id.strip() or len(client_id) > CLIENT_ID_MAX or _has_control(client_id):
            raise InvalidParameter("bad client id")
        limits[client_id] = _parse_limit(entry)
    return limits


def default_access(client_id: str | None) -> str | None:
    """The cap for a client without an ``access`` entry: ``read`` for the API key, else none."""
    return ACCESS_READ if client_id == API_KEY_CLIENT_ID else None


def effective_accounts(
    accounts: Mapping[str, Account], limits: ClientLimits | None, client_id: str | None
) -> tuple[Account, ...]:
    """The accounts ``client_id`` may use, in config order. ``limits=None`` denies all."""
    if limits is None or not client_id:
        return ()
    entry = limits.get(client_id)
    if entry is None or entry.accounts is None:
        return tuple(accounts.values())
    wanted = set(entry.accounts)
    return tuple(account for alias, account in accounts.items() if alias in wanted)


def effective_scopes(
    token_scopes: tuple[str, ...], limits: ClientLimits | None, client_id: str | None
) -> tuple[str, ...]:
    """The token's scopes that the client's access level lets through. ``limits=None``: none."""
    if limits is None or not client_id:
        return ()
    entry = limits.get(client_id)
    access = entry.access if entry is not None and entry.access else default_access(client_id)
    allowed = ACCESS_SCOPES[access] if access is not None else ALL_SCOPES
    return tuple(scope for scope in ALL_SCOPES if scope in token_scopes and scope in allowed)


# ------------------------------------------------------------------ cached view over SSM


def _load_accounts(raw: str | None) -> dict[str, Account]:
    try:
        accounts = parse_accounts(raw)
    except InvalidParameter as exc:
        logger.error("account config: %s is unparsable (%s); no mailbox is usable", ACCOUNTS_PARAM, exc)
        return {}
    if not accounts:
        logger.error("account config: %s is missing or empty; no mailbox is usable", ACCOUNTS_PARAM)
    return accounts


def _load_limits(raw: str | None) -> dict[str, ClientLimit] | None:
    if raw is None or not raw.strip():
        logger.error("account config: %s is missing or empty; all mailbox access is denied", CLIENT_LIMITS_PARAM)
        return None
    try:
        return parse_client_limits(raw)
    except InvalidParameter as exc:
        logger.error("account config: %s is unparsable (%s); all mailbox access is denied", CLIENT_LIMITS_PARAM, exc)
        return None


@dataclass(frozen=True)
class Grant:
    """What one caller may do, resolved once per call."""

    client_id: str | None
    accounts: tuple[Account, ...]
    scopes: tuple[str, ...]

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(a.alias for a in self.accounts)

    @property
    def access(self) -> str:
        """``draft`` when the caller may draft, else ``read`` (as shown by ``list_accounts``)."""
        return ACCESS_DRAFT if SCOPE_DRAFT in self.scopes else ACCESS_READ


class AccountAccess:
    """Resolves grants from the two SSM parameters (cached by the reader)."""

    def __init__(self, prefix: str, params: ParameterReader):
        self._prefix = prefix
        self._params = params

    def _name(self, leaf: str) -> str:
        return f"{self._prefix}/{leaf}"

    def accounts(self) -> dict[str, Account]:
        return self._params.get(self._name(ACCOUNTS_PARAM), _load_accounts)

    def client_limits(self) -> ClientLimits | None:
        """The limits document, or ``None`` when it is missing or unparsable (deny all)."""
        return self._params.get(self._name(CLIENT_LIMITS_PARAM), _load_limits)

    def grant(self, client_id: str | None, token_scopes: tuple[str, ...]) -> Grant:
        limits = self.client_limits()
        scopes = effective_scopes(token_scopes, limits, client_id)
        accounts = effective_accounts(self.accounts(), limits, client_id) if scopes else ()
        return Grant(client_id=client_id, accounts=accounts, scopes=scopes)
