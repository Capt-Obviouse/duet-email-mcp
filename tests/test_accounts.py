"""Account config and client limits: strict parsing, fail closed, limits only narrow."""

from __future__ import annotations

import json
import logging

import pytest

from app.accounts import (
    ACCESS_DRAFT,
    ACCESS_READ,
    AccountAccess,
    ClientLimit,
    InvalidParameter,
    effective_accounts,
    effective_scopes,
    parse_accounts,
    parse_client_limits,
)
from app.auth import ALL_SCOPES, API_KEY_CLIENT_ID, SCOPE_DRAFT, SCOPE_READ
from app.ssm_params import ParameterReader
from conftest import ACCOUNTS, ACCOUNTS_PARAM, LIMITS_PARAM, PREFIX, FakeSSM

GOOD = {"personal": {"provider": "google", "address": "me@example.com"}}


def accounts_with(**entry):
    return json.dumps({"personal": {"provider": "google", "address": "me@example.com", **entry}})


# ---------------------------------------------------------------- accounts: shapes that parse


def test_presets_apply():
    parsed = parse_accounts(json.dumps(ACCOUNTS))
    assert list(parsed) == ["personal", "business", "icloud", "other"]
    gmail = parsed["personal"]
    assert gmail.provider == "google" and gmail.search == "gmail"
    assert (gmail.imap.host, gmail.imap.port, gmail.imap.tls) == ("imap.gmail.com", 993, "implicit")
    assert gmail.folders["drafts"] == "[Gmail]/Drafts"
    assert gmail.logical_folders == ("inbox", "sent", "drafts", "all_mail")
    assert gmail.username == "me@example.com"  # defaults to the address
    assert gmail.description == "Personal mail"
    assert parsed["business"].provider == "google"  # "workspace" selects the same preset
    icloud = parsed["icloud"]
    assert icloud.imap.host == "imap.mail.me.com" and icloud.search == "imap"
    assert icloud.username == "apple-id@example.net"
    assert icloud.logical_folders == ("inbox", "sent", "drafts")
    other = parsed["other"]
    assert other.imap.host == "imap.example.info" and other.folders == {"inbox": "INBOX", "sent": "Sent Items"}
    assert other.smtp is None


def test_preset_fields_are_overridden_one_by_one():
    acct = parse_accounts(accounts_with(imap={"tls": "starttls"}, folders={"drafts": "Entwürfe"}))["personal"]
    assert (acct.imap.host, acct.imap.port, acct.imap.tls) == ("imap.gmail.com", 143, "starttls")
    assert acct.folders["drafts"] == "Entwürfe" and acct.folders["sent"] == "[Gmail]/Sent Mail"


def test_generic_defaults_port_from_tls():
    raw = json.dumps({"x": {"provider": "generic", "address": "a@example.com", "imap": {"host": "mail.example.com", "tls": "starttls"}}})
    assert parse_accounts(raw)["x"].imap.port == 143
    raw = json.dumps({"x": {"provider": "generic", "address": "a@example.com", "imap": {"host": "mail.example.com"}}})
    assert (parse_accounts(raw)["x"].imap.port, parse_accounts(raw)["x"].imap.tls) == (993, "implicit")


def test_smtp_block_is_parsed_and_validated():
    acct = parse_accounts(accounts_with(smtp={"port": 465, "tls": "implicit"}))["personal"]
    assert (acct.smtp.host, acct.smtp.port, acct.smtp.tls) == ("smtp.gmail.com", 465, "implicit")
    with pytest.raises(InvalidParameter):
        parse_accounts(accounts_with(smtp={"tls": "none"}))


@pytest.mark.parametrize("raw", [None, "", "   ", "{}"])
def test_missing_or_empty_accounts_is_no_mailbox(raw):
    assert parse_accounts(raw) == {}


# ---------------------------------------------------------------- accounts: everything else fails


@pytest.mark.parametrize("raw", [
    "not json",
    "[]",
    '"personal"',
    '{"personal": {"provider": "google", "address": "me@example.com"}, "personal": {"provider": "icloud", "address": "me@example.com"}}',
    json.dumps({"Personal": GOOD["personal"]}),  # upper case alias
    json.dumps({"has.dot": GOOD["personal"]}),
    json.dumps({"-lead": GOOD["personal"]}),
    json.dumps({"a" * 33: GOOD["personal"]}),
    json.dumps({"personal": "google"}),
    json.dumps({"personal": None}),
    json.dumps({"personal": {"address": "me@example.com"}}),  # no provider
    json.dumps({"personal": {"provider": "outlook", "address": "me@example.com"}}),
    json.dumps({"personal": {"provider": "google"}}),  # no address
    json.dumps({"x": {"provider": "generic", "address": "me@example.com"}}),  # generic without imap
    json.dumps({"x": {"provider": "generic", "address": "me@example.com", "imap": {"port": 993}}}),  # no host
    accounts_with(password="hunter2"),  # unknown field (and a secret where none belongs)
    accounts_with(Address="x"),
    accounts_with(address="not-an-address"),
    accounts_with(address="two@@example.com"),
    accounts_with(address="me@localhost"),
    accounts_with(address="me@example.com\r\nBcc: x@example.com"),
    accounts_with(address=["me@example.com"]),
    accounts_with(username=""),
    accounts_with(username="me\nyou"),
    accounts_with(description="d" * 81),
    accounts_with(description="line‮override"),
    accounts_with(imap={"host": "imap.gmail.com", "port": 0}),
    accounts_with(imap={"port": 65536}),
    accounts_with(imap={"port": "993"}),
    accounts_with(imap={"port": True}),
    accounts_with(imap={"tls": "none"}),
    accounts_with(imap={"tls": "ssl"}),
    accounts_with(imap={"host": "bad host"}),
    accounts_with(imap={"host": "imap.example.com", "verify": False}),
    accounts_with(imap=None),
    accounts_with(folders={"trash": "Trash"}),
    accounts_with(folders={"drafts": ""}),
    accounts_with(folders={"drafts": "a\r\nb"}),
    accounts_with(folders={"drafts": 7}),
    "[" * 5000 + "]" * 5000,
])
def test_malformed_accounts_raise(raw):
    with pytest.raises(InvalidParameter) as exc:
        parse_accounts(raw)
    assert "hunter2" not in str(exc.value) and "example" not in str(exc.value)


def test_one_bad_entry_disables_every_mailbox_and_logs_no_value(caplog):
    doc = json.dumps({**ACCOUNTS, "broken": {"provider": "google", "address": "secret-canary@example.com", "x": 1}})
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({ACCOUNTS_PARAM: doc, LIMITS_PARAM: "{}"})))
    with caplog.at_level(logging.ERROR):
        assert access.accounts() == {}
        assert access.grant(API_KEY_CLIENT_ID, ALL_SCOPES).accounts == ()
    text = caplog.text
    assert "accounts is unparsable" in text
    assert "secret-canary" not in text and "personal" not in text and "example" not in text


def test_missing_accounts_parameter_is_no_mailbox(caplog):
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({LIMITS_PARAM: "{}"})))
    with caplog.at_level(logging.ERROR):
        assert access.grant(API_KEY_CLIENT_ID, ALL_SCOPES).accounts == ()
    assert "missing or empty" in caplog.text


# ---------------------------------------------------------------- client limits


def test_client_limits_parse():
    limits = parse_client_limits(json.dumps({
        "api-key": {"access": "draft"},
        "agent": {"accounts": ["personal", "personal", "icloud"], "access": "read"},
        "locked": {"accounts": []},
    }))
    assert limits["api-key"] == ClientLimit(accounts=None, access="draft")
    assert limits["agent"] == ClientLimit(accounts=("personal", "icloud"), access="read")
    assert limits["locked"].accounts == ()
    assert parse_client_limits("{}") == {}


@pytest.mark.parametrize("raw", [
    None, "", "  ", "nope", "[]",
    '{"a": {"access": "read"}, "a": {"access": "draft"}}',
    json.dumps({"a": {"access": "send"}}),
    json.dumps({"a": {"access": "write"}}),
    json.dumps({"a": {"access": None}}),
    json.dumps({"a": {"calendars": ["x"]}}),  # unknown field
    json.dumps({"a": {"accounts": "personal"}}),
    json.dumps({"a": {"accounts": [1]}}),
    json.dumps({"a": {"accounts": ["Not An Alias"]}}),
    json.dumps({"a": []}),
    json.dumps({"": {}}),
    json.dumps({"x" * 129: {}}),
    json.dumps({"a\nb": {}}),
])
def test_malformed_limits_raise(raw):
    with pytest.raises(InvalidParameter):
        parse_client_limits(raw)


def test_unparsable_limits_deny_every_client(caplog):
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({
        ACCOUNTS_PARAM: json.dumps(ACCOUNTS), LIMITS_PARAM: '{"api-key": {"access": "admin"}}',
    })))
    with caplog.at_level(logging.ERROR):
        for client_id in (API_KEY_CLIENT_ID, "other-client"):
            grant = access.grant(client_id, ALL_SCOPES)
            assert grant.accounts == () and grant.scopes == ()
    assert "client-limits is unparsable" in caplog.text and "admin" not in caplog.text


def test_missing_limits_deny_every_client():
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({ACCOUNTS_PARAM: json.dumps(ACCOUNTS)})))
    assert access.grant(API_KEY_CLIENT_ID, ALL_SCOPES).accounts == ()


def test_limits_only_narrow_and_keep_config_order():
    accounts = parse_accounts(json.dumps(ACCOUNTS))
    limits = {"agent": ClientLimit(accounts=("icloud", "personal", "not-configured"))}
    assert [a.alias for a in effective_accounts(accounts, limits, "agent")] == ["personal", "icloud"]
    assert [a.alias for a in effective_accounts(accounts, limits, "other")] == list(accounts)
    assert effective_accounts(accounts, {"agent": ClientLimit(accounts=())}, "agent") == ()
    assert effective_accounts(accounts, None, "agent") == ()
    assert effective_accounts(accounts, {}, None) == ()
    assert effective_accounts(accounts, {}, "") == ()


def test_api_key_is_read_only_by_default():
    assert effective_scopes(ALL_SCOPES, {}, API_KEY_CLIENT_ID) == (SCOPE_READ,)
    assert effective_scopes(ALL_SCOPES, {API_KEY_CLIENT_ID: ClientLimit(accounts=("personal",))}, API_KEY_CLIENT_ID) == (SCOPE_READ,)
    assert effective_scopes(ALL_SCOPES, {API_KEY_CLIENT_ID: ClientLimit(access=ACCESS_DRAFT)}, API_KEY_CLIENT_ID) == ALL_SCOPES


def test_access_caps_scopes_and_never_grants_one_the_token_lacks():
    draft = {"c": ClientLimit(access=ACCESS_DRAFT)}
    read = {"c": ClientLimit(access=ACCESS_READ)}
    assert effective_scopes(ALL_SCOPES, {}, "c") == ALL_SCOPES  # OAuth client without entry: token scopes
    assert effective_scopes(ALL_SCOPES, read, "c") == (SCOPE_READ,)
    assert effective_scopes((SCOPE_READ,), draft, "c") == (SCOPE_READ,)
    assert effective_scopes((SCOPE_DRAFT,), read, "c") == ()
    assert effective_scopes((), draft, "c") == ()
    assert effective_scopes(("mail.send", "calendar.read"), draft, "c") == ()
    assert effective_scopes(ALL_SCOPES, None, "c") == ()


def test_grant_with_no_scope_has_no_accounts():
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({
        ACCOUNTS_PARAM: json.dumps(ACCOUNTS), LIMITS_PARAM: "{}",
    })))
    assert access.grant("c", ()).accounts == ()
    grant = access.grant(API_KEY_CLIENT_ID, ALL_SCOPES)
    assert grant.aliases == tuple(ACCOUNTS) and grant.access == ACCESS_READ


def test_config_is_cached_per_ttl():
    now = [0.0]
    ssm = FakeSSM({ACCOUNTS_PARAM: json.dumps(GOOD), LIMITS_PARAM: "{}"})
    access = AccountAccess(PREFIX, ParameterReader(fetch=ssm, clock=lambda: now[0], ttl_seconds=60))
    for _ in range(3):
        access.grant(API_KEY_CLIENT_ID, ALL_SCOPES)
    assert ssm.calls.count(ACCOUNTS_PARAM) == 1
    ssm.values[ACCOUNTS_PARAM] = "{}"  # the kill switch: removing the account
    now[0] = 61
    assert access.grant(API_KEY_CLIENT_ID, ALL_SCOPES).accounts == ()


# ---------------------------------------------------------------- shapes that once raised TypeError/ValueError

HUGE_INT = "9" * 5000  # json refuses integers of over 4300 digits with ValueError

ACCOUNT_PROBES = [
    json.dumps({"personal": {"provider": ["google"], "address": "me@example.com"}}),
    json.dumps({"personal": {"provider": {"g": 1}, "address": "me@example.com"}}),
    accounts_with(imap={"host": "imap.example.com", "tls": ["implicit"]}),
    '{"personal": ' + HUGE_INT + "}",
]
LIMIT_PROBES = [
    json.dumps({"api-key": {"access": ["read"]}}),
    json.dumps({"api-key": {"access": {"read": 1}}}),
    '{"api-key": ' + HUGE_INT + "}",
]


@pytest.mark.parametrize("raw", ACCOUNT_PROBES)
def test_probe_accounts_raise_invalid_parameter(raw):
    with pytest.raises(InvalidParameter):
        parse_accounts(raw)


@pytest.mark.parametrize("raw", LIMIT_PROBES)
def test_probe_limits_raise_invalid_parameter(raw):
    with pytest.raises(InvalidParameter):
        parse_client_limits(raw)


@pytest.mark.parametrize("accounts_raw, limits_raw", [
    *[(raw, "{}") for raw in ACCOUNT_PROBES],
    *[(json.dumps(ACCOUNTS), raw) for raw in LIMIT_PROBES],
])
def test_probe_shapes_deny_log_once_and_are_cached(accounts_raw, limits_raw, caplog):
    ssm = FakeSSM({ACCOUNTS_PARAM: accounts_raw, LIMITS_PARAM: limits_raw})
    access = AccountAccess(PREFIX, ParameterReader(fetch=ssm))
    with caplog.at_level(logging.ERROR):
        for _ in range(3):
            assert access.grant(API_KEY_CLIENT_ID, ALL_SCOPES).accounts == ()
    assert sum("unparsable" in r.getMessage() for r in caplog.records) == 1
    assert ssm.calls.count(LIMITS_PARAM) == 1  # the negative result is cached, not re-read per call
    assert ssm.calls.count(ACCOUNTS_PARAM) <= 1


@pytest.mark.parametrize("exc", [TypeError("canary-value"), ValueError("canary-value"), RecursionError()])
def test_loaders_deny_any_parse_error_without_its_text(monkeypatch, exc, caplog):
    def boom(raw):
        raise exc

    from app import accounts as accounts_module

    monkeypatch.setattr(accounts_module, "parse_accounts", boom)
    monkeypatch.setattr(accounts_module, "parse_client_limits", boom)
    access = AccountAccess(PREFIX, ParameterReader(fetch=FakeSSM({ACCOUNTS_PARAM: "{}", LIMITS_PARAM: "{}"})))
    with caplog.at_level(logging.ERROR):
        assert access.accounts() == {}
        assert access.client_limits() is None
    assert "malformed" in caplog.text and "canary-value" not in caplog.text
