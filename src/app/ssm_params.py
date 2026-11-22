"""SSM Parameter Store: plain String configuration and the API key SecureString, cached per container.

``ParameterReader.get(name, parse)`` fetches a String parameter at most once per TTL (default
60 s) and caches the *parsed* value, so ``parse`` runs once per refresh and can log a problem
once per refresh rather than once per request. A missing parameter, an empty value or a failed
read all reach ``parse`` as ``None``; the caller decides what that means (the account allowlist
treats it as "no mailbox").

``ApiKeyStore`` reads the operator-created SecureString ``<prefix>/api-key`` with decryption,
cached 15 minutes. CloudFormation cannot create SecureStrings, so the stack does not own it. A
missing, failed, throttled or too short (under ``MIN_API_KEY_LENGTH`` characters) read counts as
"no key" and is cached for ``retry_seconds`` (30 s), so anonymous traffic cannot turn every
request into an SSM call.

The boto3 clients (here and in ``credentials.py``) use ``AWS_CLIENT_CONFIG``: short connect and
read timeouts and two attempts, so a stalled AWS API fails in seconds, well inside the 30 s
Lambda limit, instead of after botocore's 60 s defaults.

Values are never logged; a failed read logs the parameter name and the exception type only.
Nothing here does I/O until first use.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T")

ParamFetcher = Callable[[str], "str | None"]

DEFAULT_TTL_SECONDS = 60.0
API_KEY_PARAM = "api-key"
# A stored key shorter than this is treated as unconfigured (generate one with `openssl rand -hex 32`).
MIN_API_KEY_LENGTH = 32
API_KEY_RETRY_SECONDS = 30.0

logger = logging.getLogger("mail.config")

_client = None


def aws_client_config():
    """botocore ``Config`` for every AWS client here: 2 s connect, 3 s read, at most 2 attempts in total (about 10 s worst case)."""
    from botocore.config import Config  # provided by the Lambda runtime

    return Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2, "mode": "standard"})


def ssm_client():
    """The container's boto3 SSM client, created on first use (no I/O at import)."""
    global _client
    if _client is None:
        import boto3  # provided by the Lambda runtime

        _client = boto3.client("ssm", config=aws_client_config())
    return _client


def _fetch(name: str, decrypt: bool) -> str | None:
    client = ssm_client()
    try:
        resp = client.get_parameter(Name=name, WithDecryption=decrypt)
    except client.exceptions.ParameterNotFound:
        return None
    return resp["Parameter"]["Value"] or None


def _string_fetcher(name: str) -> str | None:
    return _fetch(name, decrypt=False)


def _secure_fetcher(name: str) -> str | None:
    return _fetch(name, decrypt=True)


class ParameterReader:
    """Fetches String parameters through ``fetch`` and caches parsed values for ``ttl_seconds``."""

    def __init__(
        self,
        fetch: ParamFetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ):
        self._fetch = fetch or _string_fetcher
        self._clock = clock
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, Any]] = {}

    def get(self, name: str, parse: Callable[[str | None], T]) -> T:
        """``parse(value)`` for parameter ``name``, refreshed at most once per TTL.

        The cache is keyed by ``name`` only: use one ``parse`` per parameter name.
        """
        with self._lock:
            now = self._clock()
            hit = self._cache.get(name)
            if hit is not None and now - hit[0] < self._ttl:
                return hit[1]
            parsed = parse(self._read(name))
            self._cache[name] = (now, parsed)
            return parsed

    def _read(self, name: str) -> str | None:
        try:
            return self._fetch(name) or None
        except Exception as exc:  # throttling, access denied, network: treated as missing
            logger.error("ssm parameter read failed: %s %s", name, type(exc).__name__)
            return None


class ApiKeyStore:
    """The API key from SSM ``<prefix>/api-key`` (SecureString), cached for ``ttl_seconds``.

    No usable key (missing, empty, shorter than ``MIN_API_KEY_LENGTH``, or a failed read) is
    cached too, for ``retry_seconds``: creating or fixing the parameter takes effect within that
    time, and an outage or an unconfigured stack is not re-read on every request. No key is
    never a pass (503).
    """

    def __init__(
        self,
        prefix: str,
        fetch: ParamFetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 900.0,
        retry_seconds: float = API_KEY_RETRY_SECONDS,
    ):
        self._name = f"{prefix}/{API_KEY_PARAM}"
        self._fetch = fetch or _secure_fetcher
        self._clock = clock
        self._ttl = ttl_seconds
        self._retry = retry_seconds
        self._lock = threading.Lock()
        self._value: str | None = None
        self._read_at: float | None = None

    def api_key(self) -> str | None:
        with self._lock:
            now = self._clock()
            wait = self._ttl if self._value is not None else self._retry
            if self._read_at is None or now - self._read_at >= wait:
                self._value = self._read()
                self._read_at = now
            return self._value

    def _read(self) -> str | None:
        try:
            value = self._fetch(self._name) or None
        except Exception as exc:
            logger.error("ssm parameter read failed: %s %s", self._name, type(exc).__name__)
            return None
        if value is not None and len(value) < MIN_API_KEY_LENGTH:
            logger.error(
                "ssm parameter %s is shorter than %d characters; treated as unconfigured",
                self._name, MIN_API_KEY_LENGTH,
            )
            return None
        return value
