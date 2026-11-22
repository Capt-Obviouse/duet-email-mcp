"""Credentials: one Secrets Manager JSON secret, lazy, cached, redacted, never logged."""

from __future__ import annotations

import json
import logging
import pickle

import pytest

from app.credentials import CredentialStore, InvalidSecret, Secret, parse_secret
from conftest import PASSWORDS, SECRET_ID, FakeSecrets


def store(fake, now=None, **kw):
    clock = (lambda: now[0]) if now is not None else (lambda: 0.0)
    return CredentialStore(SECRET_ID, fetch=fake, clock=clock, **kw)


def test_nothing_is_read_until_a_password_is_needed():
    fake = FakeSecrets()
    creds = store(fake)
    assert fake.calls == []
    assert creds.password("personal").reveal() == PASSWORDS["personal"]
    assert fake.calls == [SECRET_ID]


def test_one_read_per_ttl():
    now = [0.0]
    fake = FakeSecrets()
    creds = store(fake, now, ttl_seconds=900)
    for alias in ("personal", "business", "personal", "missing"):
        creds.password(alias)
    assert len(fake.calls) == 1
    now[0] = 899
    creds.password("personal")
    assert len(fake.calls) == 1
    now[0] = 900
    creds.password("personal")
    assert len(fake.calls) == 2


def test_unknown_alias_is_none():
    assert store(FakeSecrets()).password("other") is None


def test_failures_are_retried_after_the_retry_interval_not_every_call():
    now = [0.0]
    fake = FakeSecrets(error=RuntimeError("AccessDenied for arn:aws:secretsmanager:canary"))
    creds = store(fake, now, retry_seconds=60)
    assert creds.password("personal") is None
    assert creds.password("personal") is None
    assert len(fake.calls) == 1
    fake.error = None
    now[0] = 60
    assert creds.password("personal").reveal() == PASSWORDS["personal"]


def test_empty_secret_is_retried_after_the_retry_interval():
    now = [0.0]
    fake = FakeSecrets(value="{}")
    creds = store(fake, now, retry_seconds=60, ttl_seconds=900)
    assert creds.password("personal") is None
    fake.value = json.dumps(PASSWORDS)  # the operator fills the secret
    now[0] = 61
    assert creds.password("personal") is not None


def test_no_secret_configured_is_none_without_a_read():
    fake = FakeSecrets()
    assert CredentialStore("", fetch=fake).password("personal") is None
    assert fake.calls == []


def test_forget_rereads_on_next_use():
    fake = FakeSecrets()
    creds = store(fake)
    creds.password("personal")
    creds.forget("personal")
    creds.forget("never-there")
    creds.password("personal")
    assert len(fake.calls) == 2


def test_secret_is_redacted():
    secret = Secret("hunter2-canary")
    for text in (repr(secret), str(secret), f"{secret}", repr([secret]), repr({"a": secret})):
        assert "hunter2" not in text
    assert secret.reveal() == "hunter2-canary"
    with pytest.raises(TypeError):
        pickle.dumps(secret)


@pytest.mark.parametrize("raw", [
    "not json {hunter2-canary",
    '["hunter2-canary"]',
    '{"personal": 1}',
    '{"personal": ""}',
    '{"personal": {"password": "hunter2-canary"}}',
    '{"personal": "hunter2-canary", "personal": "other"}',
])
def test_malformed_secret_raises_without_the_value(raw):
    with pytest.raises(InvalidSecret) as exc:
        parse_secret(raw)
    assert "hunter2" not in str(exc.value) and "personal" not in str(exc.value)


def test_parse_secret_empty():
    assert parse_secret(None) == {} and parse_secret("") == {} and parse_secret("{}") == {}


@pytest.mark.parametrize("fake", [
    FakeSecrets(value='{"personal": "hunter2-canary", "bad": 7}'),
    FakeSecrets(value="hunter2-canary"),
    FakeSecrets(error=RuntimeError("hunter2-canary in an error message")),
    FakeSecrets(value="{}"),
    FakeSecrets(value='{"personal": "hunter2-canary"}'),
])
def test_nothing_secret_is_ever_logged(fake, caplog):
    with caplog.at_level(logging.DEBUG):
        creds = store(fake)
        creds.password("personal")
        creds.password("personal")
    text = caplog.text
    assert "hunter2" not in text
    assert SECRET_ID not in text  # the id is an ARN in production (account id)
    assert "personal" not in text
