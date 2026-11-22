"""SSM readers: parsed-value cache, failures treated as missing, API key cache."""

from __future__ import annotations

import logging

from app.ssm_params import ApiKeyStore, ParameterReader
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


def test_api_key_store_caches_and_rereads_a_missing_key():
    now = [0.0]
    ssm = FakeSSM({})
    keys = ApiKeyStore(PREFIX, fetch=ssm, clock=lambda: now[0], ttl_seconds=900)
    assert keys.api_key() is None
    ssm.values[API_KEY_PARAM] = TEST_KEY  # created by the operator: works at once
    assert keys.api_key() == TEST_KEY
    assert keys.api_key() == TEST_KEY
    assert ssm.calls == [API_KEY_PARAM, API_KEY_PARAM]
    now[0] = 900
    ssm.values[API_KEY_PARAM] = "rotated"
    assert keys.api_key() == "rotated"


def test_api_key_read_failure_is_none_and_logs_no_value(caplog):
    def boom(name):
        raise RuntimeError(TEST_KEY)

    with caplog.at_level(logging.ERROR):
        assert ApiKeyStore(PREFIX, fetch=boom).api_key() is None
    assert TEST_KEY not in caplog.text
