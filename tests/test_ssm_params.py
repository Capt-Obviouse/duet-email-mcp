"""SSM readers: parsed-value cache, failures treated as missing, API key cache."""

from __future__ import annotations

import logging

import pytest

from app import credentials, ssm_params
from app.ssm_params import MIN_API_KEY_LENGTH, ApiKeyStore, ParameterReader
from conftest import API_KEY_PARAM, PREFIX, TEST_KEY, FakeSSM


def test_parameter_reader_caches_parsed_value_per_ttl():
    now = [0.0]
    ssm = FakeSSM({"/p": "1"})
    parsed = []

    def parse(raw):
        parsed.append(raw)
        return raw

    reader = ParameterReader(fetch=ssm, clock=lambda: now[0], ttl_seconds=60)
    assert reader.get("/p", parse) == "1"
    assert reader.get("/p", parse) == "1"
    assert parsed == ["1"]
    now[0] = 60
    ssm.values["/p"] = "2"
    assert reader.get("/p", parse) == "2"


def test_parameter_read_failure_reaches_parse_as_none_and_logs_no_value(caplog):
    def boom(name):
        raise RuntimeError("value-canary")

    with caplog.at_level(logging.ERROR):
        assert ParameterReader(fetch=boom).get("/p", lambda raw: raw) is None
    assert "RuntimeError" in caplog.text and "value-canary" not in caplog.text


def test_empty_parameter_is_none():
    assert ParameterReader(fetch=FakeSSM({"/p": ""})).get("/p", lambda raw: raw) is None


def test_api_key_store_caches_and_negative_caches_a_missing_key():
    now = [0.0]
    ssm = FakeSSM({})
    keys = ApiKeyStore(PREFIX, fetch=ssm, clock=lambda: now[0], ttl_seconds=900, retry_seconds=30)
    assert keys.api_key() is None
    ssm.values[API_KEY_PARAM] = TEST_KEY  # created by the operator: works within retry_seconds
    assert keys.api_key() is None
    assert ssm.calls == [API_KEY_PARAM]  # an unconfigured key is not re-read on every request
    now[0] = 30
    assert keys.api_key() == TEST_KEY
    now[0] = 900
    assert keys.api_key() == TEST_KEY
    assert ssm.calls == [API_KEY_PARAM, API_KEY_PARAM]
    now[0] = 930
    ssm.values[API_KEY_PARAM] = "rotated-" + TEST_KEY
    assert keys.api_key() == "rotated-" + TEST_KEY


def test_failed_key_read_is_negative_cached():
    now = [0.0]
    calls = []

    def throttled(name):
        calls.append(name)
        raise RuntimeError("ThrottlingException")

    keys = ApiKeyStore(PREFIX, fetch=throttled, clock=lambda: now[0], retry_seconds=30)
    for _ in range(5):
        assert keys.api_key() is None
    assert len(calls) == 1
    now[0] = 30
    assert keys.api_key() is None
    assert len(calls) == 2


@pytest.mark.parametrize("stored", ["tiny-key", "k" * (MIN_API_KEY_LENGTH - 1)])
def test_short_key_is_unconfigured_and_logged_without_the_value(stored, caplog):
    keys = ApiKeyStore(PREFIX, fetch=FakeSSM({API_KEY_PARAM: stored}))
    with caplog.at_level(logging.ERROR):
        assert keys.api_key() is None
    assert "shorter than 32 characters" in caplog.text and stored not in caplog.text


def test_key_of_minimum_length_is_accepted():
    key = "a" * MIN_API_KEY_LENGTH
    assert ApiKeyStore(PREFIX, fetch=FakeSSM({API_KEY_PARAM: key})).api_key() == key


def test_aws_clients_have_short_timeouts_and_bounded_retries(monkeypatch):
    monkeypatch.setattr(ssm_params, "_client", None)
    monkeypatch.setattr(credentials, "_client", None)
    for client in (ssm_params.ssm_client(), credentials.secrets_client()):
        config = client.meta.config
        assert config.connect_timeout == 2 and config.read_timeout == 3
        assert config.retries == {"total_max_attempts": 2, "mode": "standard"}


def test_api_key_read_failure_is_none_and_logs_no_value(caplog):
    def boom(name):
        raise RuntimeError(TEST_KEY)

    with caplog.at_level(logging.ERROR):
        assert ApiKeyStore(PREFIX, fetch=boom).api_key() is None
    assert TEST_KEY not in caplog.text
