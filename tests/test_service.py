"""MailService guards, error categories, and the backend seam."""

from __future__ import annotations

import json

import pytest

from app.accounts import AccountAccess, parse_accounts
from app.auth import API_KEY_TOKEN, VerifiedToken
from app.backend import ensure_allowed
from app.credentials import CredentialStore
from app.errors import CATEGORIES, Forbidden, InvalidArgument, MailError, Unavailable
from app.service import TOOL_SCOPES, MailService
from app.ssm_params import ParameterReader
from conftest import ACCOUNTS, PREFIX, SECRET_ID, FakeBackend, FakeSecrets, FakeSSM


def service(backend=None, secrets=None):
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM()))
    creds = CredentialStore(SECRET_ID, fetch=secrets or FakeSecrets())
    return MailService(access, creds, lambda: backend)


def test_no_caller_or_no_scope_is_forbidden():
    with pytest.raises(Forbidden):
        service().list_accounts(None)
    with pytest.raises(Forbidden):
        service().list_accounts(VerifiedToken(client_id="c", scopes=("calendar.read",), method="oauth"))


def test_every_tool_declares_its_scopes():
    assert set(TOOL_SCOPES) == {"list_accounts"}


def test_no_backend_yet_is_unavailable():
    with pytest.raises(Unavailable):
        service().backend()
    fake = FakeBackend()
    assert service(fake).backend() is fake


def test_password_only_for_granted_aliases():
    secrets = FakeSecrets()
    svc = service(secrets=secrets)
    grant = svc.grant(API_KEY_TOKEN)
    accounts = parse_accounts(json.dumps(ACCOUNTS))
    assert svc.password_for(accounts["personal"], grant).reveal() == "pw-personal-canary"
    with pytest.raises(Unavailable):  # granted, but no password in the secret
        svc.password_for(accounts["icloud"], grant)
    narrowed = type(grant)(client_id=grant.client_id, accounts=(accounts["icloud"],), scopes=grant.scopes)
    secrets.calls.clear()
    with pytest.raises(Forbidden):
        svc.password_for(accounts["personal"], narrowed)
    assert secrets.calls == []  # refused before any secret read


def test_fake_backend_refuses_aliases_outside_allowed():
    accounts = parse_accounts(json.dumps(ACCOUNTS))
    fake = FakeBackend()
    with pytest.raises(Forbidden):
        fake.fetch(accounts["personal"], None, "inbox", 1, 1, allowed=("icloud",), max_bytes=1, timeout=1)
    ensure_allowed(accounts["personal"], ("personal",))


def test_error_messages_are_fixed_and_never_carry_values():
    for category in CATEGORIES:
        text = MailError(category).public_message()
        assert text.startswith(f"{category}: ")
    assert InvalidArgument(argument="limit").public_message().startswith("invalid_argument: limit: ")
    for bad in ("value-canary with spaces", "x" * 41, "naïve", "a;b", "", None):
        assert "canary" not in str(InvalidArgument(argument=bad))
        assert InvalidArgument(argument=bad).argument is None
    with pytest.raises(ValueError):
        MailError("made_up_category")
