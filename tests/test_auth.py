"""Auth: the public health check, the API key, credential routing and the verifier seam."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    ALL_SCOPES,
    API_KEY_CLIENT_ID,
    ApiKeyVerifier,
    AuthUnavailable,
    TokenRejected,
    VerifiedToken,
    bearer_token,
    credential_from_headers,
    key_matches,
    looks_like_jwt,
)
from app.config import Settings
from conftest import ACCEPT, API_KEY_PARAM, SECRET_ID, TEST_KEY, FakeSSM, make_app, rpc

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"


def test_health_is_public_and_touches_nothing(client, ssm, secrets, backend):
    for method in ("get", "head"):
        r = getattr(client, method)("/health")
        assert r.status_code == 200
    assert client.get("/health").json() == {"status": "ok"}
    assert ssm.calls == [] and secrets.calls == [] and backend.calls == []


def test_mcp_without_key_is_401_and_reads_nothing_but_the_key(client, ssm, secrets):
    r = rpc(client, "ping", headers=ACCEPT)
    assert r.status_code == 401
    assert r.json() == {"detail": "missing or invalid credentials"}
    assert r.headers["www-authenticate"] == "Bearer"
    assert ssm.calls == [API_KEY_PARAM]  # the key only: no account config, no secret
    assert secrets.calls == []


@pytest.mark.parametrize("headers", [
    {"X-API-Key": TEST_KEY + "x"},
    {"X-API-Key": ""},
    {"X-API-Key": "", "Authorization": f"Bearer {TEST_KEY}"},  # X-API-Key wins, even empty
    {"Authorization": f"Basic {TEST_KEY}"},
    {"Authorization": f"Bearer  {TEST_KEY}"},
    {"Authorization": f"Bearer {TEST_KEY} extra"},
    {"Authorization": "Bearer"},
])
def test_wrong_or_malformed_credentials_are_401(client, secrets, headers):
    assert rpc(client, "ping", headers={**ACCEPT, **headers}).status_code == 401
    assert secrets.calls == []


def test_right_key_in_either_header_is_accepted(client):
    assert rpc(client, "ping").status_code == 200
    assert rpc(client, "ping", headers={"Authorization": f"bearer {TEST_KEY}", **ACCEPT}).status_code == 200


def test_jwt_bearer_is_never_compared_with_the_key(ssm):
    ssm.values[API_KEY_PARAM] = JWT  # even a key that looks like a JWT is not tried
    client = TestClient(make_app(ssm))
    r = rpc(client, "ping", headers={"Authorization": f"Bearer {JWT}", **ACCEPT})
    assert r.status_code == 503
    assert r.headers["retry-after"] == "30"
    assert ssm.calls == []


def test_jwt_bearer_goes_to_a_configured_verifier():
    class Verifier:
        def __init__(self):
            self.seen = []

        async def verify(self, token):
            self.seen.append(token)
            return VerifiedToken(client_id="oauth-client", scopes=("mail.read",), method="oauth")

    verifier = Verifier()
    client = TestClient(make_app(token_verifier=verifier))
    assert rpc(client, "ping", headers={"Authorization": f"Bearer {JWT}", **ACCEPT}).status_code == 200
    assert verifier.seen == [JWT]


def test_unconfigured_key_is_503_for_everyone():
    client = TestClient(make_app(FakeSSM({})))
    r = rpc(client, "ping")
    assert r.status_code == 503
    assert r.json() == {"detail": "API key is not configured on the server"}


def test_disabled_api_key_is_401_without_reading_ssm(ssm):
    settings = Settings(credentials_secret_id=SECRET_ID, enable_api_key=False)
    client = TestClient(make_app(ssm, settings=settings))
    assert rpc(client, "ping").status_code == 401
    assert ssm.calls == []


def test_docs_openapi_and_unknown_paths_need_the_key(client, auth):
    for path in ("/openapi.json", "/docs", "/nope"):
        assert client.get(path).status_code == 401, path
    assert client.post("/health").status_code == 401
    assert client.get("/openapi.json", headers=auth).status_code == 200
    assert client.get("/nope", headers=auth).status_code == 404


def test_get_and_delete_on_mcp_are_405(client, auth):
    for method in ("get", "delete"):
        r = getattr(client, method)("/mcp", headers=auth)
        assert r.status_code == 405
        assert r.headers["allow"] == "POST"


def test_oversized_body_is_413_after_auth(client, auth):
    big = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * 300_000}}
    assert client.post("/mcp", json=big, headers=ACCEPT).status_code == 401
    assert client.post("/mcp", json=big, headers=auth).status_code == 413


def test_api_key_client_is_api_key_with_both_token_scopes():
    verifier = ApiKeyVerifier(type("Keys", (), {"api_key": lambda self: TEST_KEY})())
    verified = verifier.verify_key(TEST_KEY)
    assert verified.client_id == API_KEY_CLIENT_ID
    assert verified.scopes == ALL_SCOPES  # narrowed to read by client limits (test_accounts)


def test_verify_key_failures():
    keys = type("Keys", (), {"api_key": lambda self: TEST_KEY})()
    none = type("Keys", (), {"api_key": lambda self: None})()
    with pytest.raises(TokenRejected) as exc:
        ApiKeyVerifier(keys).verify_key(None)
    assert exc.value.reason == "no_credential"
    with pytest.raises(TokenRejected) as exc:
        ApiKeyVerifier(keys).verify_key("nope")
    assert exc.value.reason == "bad_api_key"
    with pytest.raises(AuthUnavailable):
        ApiKeyVerifier(none).verify_key(TEST_KEY)


def test_verify_token_has_the_sdk_token_verifier_shape():
    from mcp.server.auth.provider import AccessToken

    verifier = ApiKeyVerifier(type("Keys", (), {"api_key": lambda self: TEST_KEY})())
    token = asyncio.run(verifier.verify_token(TEST_KEY))
    assert isinstance(token, AccessToken)
    assert token.client_id == API_KEY_CLIENT_ID and token.token == ""  # the key is never copied in
    assert asyncio.run(verifier.verify_token("wrong")) is None
    unconfigured = ApiKeyVerifier(type("Keys", (), {"api_key": lambda self: None})())
    assert asyncio.run(unconfigured.verify_token(TEST_KEY)) is None


def test_key_matches_is_strict():
    assert key_matches("abc", "abc")
    assert not key_matches("abc", "abd")
    assert not key_matches("", "")
    assert not key_matches(None, "abc")
    assert not key_matches("abc", None)
    assert not key_matches("abc", "abcd")


def test_bearer_and_jwt_shapes():
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("BEARER abc") == "abc"
    for bad in (None, "", "Bearer", "Bearer ", "Token abc", "Bearer a b", "Bearer\tabc"):
        assert bearer_token(bad) is None
    assert looks_like_jwt(JWT)
    assert looks_like_jwt("a.b.")
    assert not looks_like_jwt(TEST_KEY)
    assert credential_from_headers({"Authorization": f"Bearer {JWT}"}).kind == "jwt"
    assert credential_from_headers({"Authorization": f"Bearer {TEST_KEY}"}).value == TEST_KEY
