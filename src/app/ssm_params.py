"""SSM Parameter Store: plain String configuration and the API key SecureString, cached per container.

``ParameterReader.get(name, parse)`` fetches a String parameter at most once per TTL (default
60 s) and caches the *parsed* value, so ``parse`` runs once per refresh and can log a problem
once per refresh rather than once per request. A missing parameter, an empty value or a failed
read all reach ``parse`` as ``None``; the caller decides what that means (the account allowlist
treats it as "no mailbox").

``ApiKeyStore`` reads the operator-created SecureString ``<prefix>/api-key`` with decryption,
cached 15 minutes. CloudFormation cannot create SecureStrings, so the stack does not own it.

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

logger = logging.getLogger("mail.config")

_client = None


def ssm_client():
    """The container's boto3 SSM client, created on first use (no I/O at import)."""
    global _client
    if _client is None:
        import boto3  # provided by the Lambda runtime

        _client = boto3.client("ssm")
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

    A missing key is re-read on the next request (no negative cache), so creating the
    parameter takes effect at once; a failed read is treated as missing (503, never a pass).
    """

    def __init__(
        self,
        prefix: str,
        fetch: ParamFetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 900.0,
    ):
        self._name = f"{prefix}/{API_KEY_PARAM}"
        self._fetch = fetch or _secure_fetcher
        self._clock = clock
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._value: str | None = None
        self._read_at: float | None = None

    def api_key(self) -> str | None:
        with self._lock:
            now = self._clock()
            if self._value is None or self._read_at is None or now - self._read_at >= self._ttl:
                try:
                    self._value = self._fetch(self._name) or None
                except Exception as exc:
                    logger.error("ssm parameter read failed: %s %s", self._name, type(exc).__name__)
                    self._value = None
                self._read_at = now
            return self._value
