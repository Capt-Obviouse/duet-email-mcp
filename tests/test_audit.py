"""Audit and access lines: allowed fields only, one audit line per tool call, no values anywhere."""

from __future__ import annotations

import json
import logging
import re
import time

import pytest
from fastapi.testclient import TestClient

from app import audit
from app.auth import API_KEY_TOKEN
from app.errors import Forbidden, Unavailable
from conftest import ACCEPT, LIMITS_PARAM, PASSWORDS, TEST_KEY, FakeSSM, call, make_app, rpc

ALLOWED_KEYS = {"event", "ts", "client_id", "auth", "tool", "account", "status", "error_class", "ms",
                "accounts_ok", "accounts_skipped"}
ACCESS_KEYS = {"method", "path", "status", "auth", "reason", "ms"}
TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")
CLIENT_LOGGERS = ("httpx", "httpcore")  # the test client's own logger prints URLs


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG)
    return caplog


def audit_lines(caplog) -> list[dict]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "mail.audit"]


def access_lines(caplog) -> list[dict]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "mail.access"]


def app_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith(CLIENT_LOGGERS))


def test_one_audit_line_per_tool_call_with_allowed_fields_only(client, logs):
    call(client, "list_accounts")
    lines = audit_lines(logs)
    assert len(lines) == 1
    line = lines[0]
    assert set(line) <= ALLOWED_KEYS
    assert line == {"event": "audit", "ts": line["ts"], "client_id": "api-key", "auth": "api_key",
                    "tool": "list_accounts", "account": "*", "status": "ok", "ms": line["ms"]}
    assert TS.fullmatch(line["ts"]) and isinstance(line["ms"], float)


def test_no_audit_line_for_non_tool_requests_or_failed_auth(client, logs):
    rpc(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "1"}})
    rpc(client, "tools/list", {})
    rpc(client, "ping", headers=ACCEPT)  # no key
    client.get("/health")
    assert audit_lines(logs) == []


def test_denied_and_error_outcomes(logs):
    ssm = FakeSSM()
    ssm.values[LIMITS_PARAM] = json.dumps({"api-key": {"accounts": []}})
    client = TestClient(make_app(ssm))
    call(client, "list_accounts")
    call(client, "list_accounts", {"x": 1})
    rpc(client, "tools/call", {"name": "nope", "arguments": {}})
    lines = audit_lines(logs)
    assert [(l["tool"], l["status"], l.get("error_class")) for l in lines] == [
        ("list_accounts", "denied", "forbidden"),
        ("list_accounts", "error", "unknown_parameter"),
        ("unknown", "error", "unknown_tool"),
    ]
    assert all(set(l) <= ALLOWED_KEYS for l in lines)


def test_access_line_per_request(client, logs):
    client.get("/health")
    rpc(client, "ping")
    rpc(client, "ping", headers={"X-API-Key": "wrong-canary", **ACCEPT})
    client.get("/raw/path/canary", headers={"X-API-Key": TEST_KEY})
    lines = access_lines(logs)
    assert [(l["method"], l["path"], l["status"], l["auth"]) for l in lines] == [
        ("GET", "/health", 200, "none"),
        ("POST", "/mcp", 200, "api_key"),
        ("POST", "/mcp", 401, "api_key"),
        ("GET", "<unmatched>", 404, "api_key"),
    ]
    assert lines[2]["reason"] == "bad_api_key"
    assert all(set(l) <= ACCESS_KEYS for l in lines)
    assert "canary" not in app_text(logs)


def test_canary_values_never_reach_any_log_line(logs):
    """Every tool and failure path with canary strings in arguments, headers and secrets."""
    ssm = FakeSSM()
    client = TestClient(make_app(ssm))
    canaries = ["arg-canary-1", "tool-canary-2", "hdr-canary-3"]
    call(client, "list_accounts")
    call(client, "list_accounts", {"query": canaries[0], "account": canaries[0]})
    rpc(client, "tools/call", {"name": canaries[1], "arguments": {"q": canaries[0]}})
    rpc(client, "ping", headers={"X-API-Key": canaries[2], **ACCEPT})
    rpc(client, "ping", headers={"Authorization": f"Bearer {canaries[2]}", **ACCEPT})
    client.post("/mcp", content=f"{{{canaries[0]}".encode(),
                headers={"X-API-Key": TEST_KEY, "Content-Type": "application/json", **ACCEPT})
    text = app_text(logs)
    for value in [*canaries, TEST_KEY, *PASSWORDS.values(), "me@example.com", "Personal mail"]:
        assert value not in text, value


def test_record_builds_from_the_allowlist():
    with pytest.raises(TypeError):
        audit.record(API_KEY_TOKEN, "t", audit.OK, time.perf_counter(), subject="x")  # type: ignore[call-arg]


def test_classify_uses_categories_never_messages():
    assert audit.classify(Forbidden()) == ("denied", "forbidden")
    assert audit.classify(Unavailable()) == ("error", "unavailable")
    assert audit.classify(RuntimeError("canary")) == ("error", "RuntimeError")


def test_record_without_caller(logs):
    audit.record(None, "list_accounts", audit.OK, time.perf_counter())
    line = audit_lines(logs)[0]
    assert line["client_id"] is None and line["auth"] == "none" and "account" not in line


def test_reason_code_only_passes_short_literals():
    assert audit.reason_code("bad_api_key") == "bad_api_key"
    assert audit.reason_code("Has Spaces") == "other"
    assert audit.reason_code(None) is None
