from __future__ import annotations

import json
import os
from collections.abc import Sequence

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")  # boto3 is never called; no network

from app.accounts import Account
from app.backend import DraftRef, MailBackend, MessageDetail, MessageSummary, SearchCriteria, ensure_allowed
from app.config import Settings
from app.credentials import CredentialStore, Secret
from app.main import create_app
from app.ssm_params import ApiKeyStore, ParameterReader

TEST_KEY = "unit-test-api-key-not-a-real-secret-000000"  # fake; avoids vendor key patterns
PREFIX = "/duet-email-mcp"
ACCOUNTS_PARAM = f"{PREFIX}/accounts"
LIMITS_PARAM = f"{PREFIX}/client-limits"
API_KEY_PARAM = f"{PREFIX}/api-key"
SECRET_ID = "test-credentials-secret"
ACCEPT = {"Accept": "application/json, text/event-stream"}

ACCOUNTS = {
    "personal": {"provider": "gmail", "address": "me@example.com", "description": "Personal mail"},
    "business": {"provider": "workspace", "address": "me@example.org"},
    "icloud": {"provider": "icloud", "address": "me@example.net", "username": "apple-id@example.net"},
    "other": {
        "provider": "generic",
        "address": "me@example.info",
        "imap": {"host": "imap.example.info", "port": 993, "tls": "implicit"},
        "folders": {"sent": "Sent Items"},
    },
}
SSM_VALUES = {
    API_KEY_PARAM: TEST_KEY,
    ACCOUNTS_PARAM: json.dumps(ACCOUNTS),
    LIMITS_PARAM: "{}",
}
PASSWORDS = {"personal": "pw-personal-canary", "business": "pw-business-canary"}


class FakeSSM:
    def __init__(self, values: dict[str, str] | None = None):
        self.values = dict(SSM_VALUES if values is None else values)
        self.calls: list[str] = []

    def __call__(self, name: str) -> str | None:
        self.calls.append(name)
        return self.values.get(name)


class FakeSecrets:
    """Secrets Manager stand-in: counts reads, can fail."""

    def __init__(self, value: str | None = None, error: Exception | None = None):
        self.value = json.dumps(PASSWORDS) if value is None else value
        self.error = error
        self.calls: list[str] = []

    def __call__(self, secret_id: str) -> str | None:
        self.calls.append(secret_id)
        if self.error is not None:
            raise self.error
        return self.value


class FakeBackend:
    """In-memory ``MailBackend``. Like the real one it refuses aliases outside ``allowed``."""

    def __init__(self):
        self.calls: list[tuple] = []

    def search(self, account: Account, password: Secret, folder: str, criteria: SearchCriteria, limit: int,
               *, allowed: Sequence[str], timeout: float) -> list[MessageSummary]:
        self.calls.append(("search", account.alias))
        ensure_allowed(account, allowed)
        return []

    def fetch(self, account: Account, password: Secret, folder: str, uidvalidity: int, uid: int,
              *, allowed: Sequence[str], max_bytes: int, timeout: float) -> MessageDetail:
        self.calls.append(("fetch", account.alias))
        ensure_allowed(account, allowed)
        return MessageDetail(account=account.alias, folder=folder, uidvalidity=uidvalidity, uid=uid, headers=b"")

    def append_draft(self, account: Account, password: Secret, message: bytes, message_id: str,
                     *, allowed: Sequence[str], timeout: float) -> DraftRef:
        self.calls.append(("append", account.alias))
        ensure_allowed(account, allowed)
        return DraftRef(account=account.alias, uidvalidity=1, uid=1)

    def close(self) -> None:
        self.calls.append(("close",))


_: type[MailBackend] = FakeBackend  # type-checks the fake against the protocol


def make_app(ssm: FakeSSM | None = None, secrets: FakeSecrets | None = None, backend=None,
             settings: Settings | None = None, token_verifier=None):
    settings = settings or Settings(credentials_secret_id=SECRET_ID)
    ssm = ssm if ssm is not None else FakeSSM()
    secrets = secrets if secrets is not None else FakeSecrets()
    return create_app(
        settings=settings,
        parameters=ParameterReader(fetch=ssm),
        api_keys=ApiKeyStore(settings.ssm_prefix, fetch=ssm),
        credentials=CredentialStore(settings.credentials_secret_id, fetch=secrets),
        backend=backend,
        token_verifier=token_verifier,
    )


@pytest.fixture
def ssm() -> FakeSSM:
    return FakeSSM()


@pytest.fixture
def secrets() -> FakeSecrets:
    return FakeSecrets()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def client(ssm, secrets, backend) -> TestClient:
    return TestClient(make_app(ssm, secrets, backend))


@pytest.fixture
def auth() -> dict[str, str]:
    return {"X-API-Key": TEST_KEY, **ACCEPT}


def rpc(client, method, params=None, *, id=1, headers=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if id is not None:
        msg["id"] = id
    return client.post("/mcp", json=msg, headers={"X-API-Key": TEST_KEY, **ACCEPT} if headers is None else headers)


def call(client, name, arguments=None, headers=None):
    r = rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["result"]
