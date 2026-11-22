"""Mail operations behind the MCP tools. Every rule lives here once.

Each operation takes the verified caller, resolves its ``Grant`` (effective accounts and
scopes, ``accounts.py``) once, checks the tool's scope before anything else, and passes the
effective aliases as the required ``allowed=`` keyword to every backend method, which checks
again. Credentials are read only for aliases that passed both checks. The MCP adapter
(``mcp_server.py``) stays thin: no rule belongs there.

Operations raise ``MailError`` subclasses (fixed categories, ``errors.py``) and nothing else on
purpose. They block (SSM reads, later IMAP), so async callers run them in a worker thread.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .accounts import Account, AccountAccess, Grant
from .auth import SCOPE_DRAFT, SCOPE_READ, VerifiedToken
from .backend import MailBackend
from .credentials import CredentialStore
from .errors import Forbidden, Unavailable

# The scopes that let a caller use each tool (any one of them is enough).
TOOL_SCOPES: dict[str, tuple[str, ...]] = {
    "list_accounts": (SCOPE_READ, SCOPE_DRAFT),
}


@dataclass(frozen=True)
class AccountItem:
    account: str
    address: str
    folders: tuple[str, ...]
    search: str
    access: str
    description: str | None = None


class MailService:
    """The server's operations. ``backend`` is resolved lazily, so list-only calls never build it."""

    def __init__(
        self,
        access: AccountAccess,
        credentials: CredentialStore,
        backend: Callable[[], MailBackend | None],
    ):
        self._access = access
        self._credentials = credentials
        self._backend = backend

    # ---------------------------------------------------------------- grants

    def grant(self, caller: VerifiedToken | None) -> Grant:
        """The caller's effective accounts and scopes (empty for no caller)."""
        if caller is None:
            return Grant(client_id=None, accounts=(), scopes=())
        return self._access.grant(caller.client_id, caller.scopes)

    def _authorise(self, caller: VerifiedToken | None, tool: str) -> Grant:
        """The grant, or ``Forbidden`` if it carries none of the tool's scopes or no account."""
        grant = self.grant(caller)
        if not any(scope in grant.scopes for scope in TOOL_SCOPES[tool]):
            raise Forbidden()
        if not grant.accounts:
            raise Forbidden()
        return grant

    def backend(self) -> MailBackend:
        backend = self._backend()
        if backend is None:  # no mail transport until EML-003b
            raise Unavailable()
        return backend

    def password_for(self, account: Account, grant: Grant):
        """The app password for an account the grant allows; never for any other alias."""
        if account.alias not in grant.aliases:
            raise Forbidden()
        secret = self._credentials.password(account.alias)
        if secret is None:
            raise Unavailable()
        return secret

    # ---------------------------------------------------------------- tools

    def list_accounts(self, caller: VerifiedToken | None) -> list[AccountItem]:
        """The caller's effective accounts. Configuration only: no network, no credentials."""
        grant = self._authorise(caller, "list_accounts")
        return [
            AccountItem(
                account=a.alias,
                address=a.address,
                folders=a.logical_folders,
                search=a.search,
                access=grant.access,
                description=a.description,
            )
            for a in grant.accounts
        ]
