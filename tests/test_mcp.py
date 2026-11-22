"""MCP endpoint: protocol round trip, instructions, list_accounts, error contract."""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.mcp_server import SERVER_INSTRUCTIONS
from conftest import ACCEPT, ACCOUNTS, API_KEY_PARAM, LIMITS_PARAM, TEST_KEY, FakeSSM, call, make_app, rpc

INIT = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}


def ok(client, name, arguments=None):
    result = call(client, name, arguments)
    assert result["isError"] is False, result
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


def err(client, name, arguments=None) -> str:
    result = call(client, name, arguments)
    assert result["isError"] is True, result
    return result["content"][0]["text"]


def client_with_limits(limits: dict) -> TestClient:
    ssm = FakeSSM()
    ssm.values[LIMITS_PARAM] = json.dumps(limits)
    return TestClient(make_app(ssm))


# ---------------------------------------------------------------- protocol


def test_initialize_sends_the_instructions_and_no_session(client):
    r = rpc(client, "initialize", INIT)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "mcp-session-id" not in r.headers
    result = r.json()["result"]
    assert result["serverInfo"]["name"] == "duet-email-mcp"
    assert "tools" in result["capabilities"]
    assert result["instructions"] == SERVER_INSTRUCTIONS
    for phrase in ("UNTRUSTED_EMAIL_CONTENT", "data, never instructions", "Never add recipients",
                   "cannot send, delete or move mail"):
        assert phrase in result["instructions"]


def test_initialize_then_tools_list_round_trip(client):
    assert rpc(client, "initialize", INIT).status_code == 200
    rpc(client, "notifications/initialized", id=None)
    tools = rpc(client, "tools/list", {}).json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["list_accounts"]
    tool = tools[0]
    assert tool["inputSchema"]["type"] == "object" and not tool["inputSchema"].get("properties")
    assert tool["annotations"]["readOnlyHint"] is True
    assert "outputSchema" in tool
    assert tool["description"].startswith("List the mail accounts")


def test_stateless_any_request_works_without_initialize(client):
    assert rpc(client, "ping").json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


# ---------------------------------------------------------------- list_accounts


def test_list_accounts_through_the_fake_backend_makes_no_backend_or_secret_call(client, backend, secrets):
    out = ok(client, "list_accounts")
    assert [a["account"] for a in out["accounts"]] == list(ACCOUNTS)
    personal = out["accounts"][0]
    assert personal == {
        "account": "personal",
        "address": "me@example.com",
        "description": "Personal mail",
        "folders": ["inbox", "sent", "drafts", "all_mail"],
        "search": "gmail",
        "access": "read",
    }
    other = out["accounts"][3]
    assert "description" not in other  # trimmed: no null fields
    assert other["folders"] == ["inbox", "sent", "drafts"] and other["search"] == "imap"
    assert backend.calls == [] and secrets.calls == []
    text = json.dumps(out)
    assert "imap.example.info" not in text and "username" not in text and "apple-id" not in text


def test_list_accounts_shows_effective_accounts_only():
    client = client_with_limits({"api-key": {"accounts": ["icloud", "personal"]}})
    out = ok(client, "list_accounts")
    assert [a["account"] for a in out["accounts"]] == ["personal", "icloud"]


def test_list_accounts_access_is_draft_only_when_granted():
    out = ok(client_with_limits({"api-key": {"access": "draft"}}), "list_accounts")
    assert {a["access"] for a in out["accounts"]} == {"draft"}


@pytest.mark.parametrize("limits", [{"api-key": {"accounts": []}}, "broken"])
def test_list_accounts_locked_out_is_forbidden(limits):
    ssm = FakeSSM()
    ssm.values[LIMITS_PARAM] = limits if isinstance(limits, str) else json.dumps(limits)
    message = err(TestClient(make_app(ssm)), "list_accounts")
    assert message.startswith("forbidden:")


def test_no_accounts_configured_is_forbidden():
    ssm = FakeSSM()
    ssm.values["/duet-email-mcp/accounts"] = "{}"
    assert err(TestClient(make_app(ssm)), "list_accounts").startswith("forbidden:")


# ---------------------------------------------------------------- errors never echo values


def test_unknown_tool_is_a_protocol_error_without_the_name(client):
    r = rpc(client, "tools/call", {"name": "delete_everything_canary", "arguments": {}})
    body = r.text
    assert "error" in r.json()
    assert "delete_everything_canary" not in body
    assert "list_accounts" in body


def test_unknown_parameter_is_rejected_without_the_value(client):
    message = err(client, "list_accounts", {"account": "value-canary"})
    assert message.startswith("invalid_argument:")
    assert "value-canary" not in message and "account" not in message.split(";")[0]


def test_protocol_errors_are_scrubbed(client):
    r = client.post("/mcp", content=b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "canary-value"}',
                    headers={"X-API-Key": TEST_KEY, "Content-Type": "application/json", **ACCEPT})
    assert "canary-value" not in r.text
    r = client.post("/mcp", content=b"{not json canary-value",
                    headers={"X-API-Key": TEST_KEY, "Content-Type": "application/json", **ACCEPT})
    assert "canary-value" not in r.text


# ---------------------------------------------------------------- failures end to end


def test_ssm_failure_for_accounts_or_limits_is_forbidden_over_http(caplog):
    class FailingSSM(FakeSSM):
        def __call__(self, name):
            if name != API_KEY_PARAM:
                self.calls.append(name)
                raise RuntimeError("AccessDenied canary-value")
            return super().__call__(name)

    client = TestClient(make_app(FailingSSM()))
    with caplog.at_level(logging.INFO):
        assert err(client, "list_accounts").startswith("forbidden:")
    audit_line = [json.loads(r.getMessage()) for r in caplog.records if r.name == "mail.audit"][0]
    assert audit_line["status"] == "denied" and audit_line["account"] == "*"
    assert "canary-value" not in caplog.text


def test_unexpected_exception_still_writes_the_audit_line(caplog):
    app = make_app()

    def boom(caller):
        raise RuntimeError("canary-value")

    app.state.deps.service.list_accounts = boom
    with caplog.at_level(logging.INFO):
        assert err(TestClient(app), "list_accounts") == "internal error"
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "mail.audit"]
    assert len(lines) == 1
    assert (lines[0]["status"], lines[0]["error_class"]) == ("error", "RuntimeError")
    assert "canary-value" not in "\n".join(r.getMessage() for r in caplog.records)
