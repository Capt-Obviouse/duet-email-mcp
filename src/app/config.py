"""Runtime configuration, read from environment variables once per container.

The mailbox allowlist and per-client limits are not here: they are SSM parameters read at
request time with a short cache (``accounts.py``). App passwords are in Secrets Manager
(``credentials.py``). Nothing in this module does I/O.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache

DEFAULT_SSM_PREFIX = "/duet-email-mcp"
_PREFIX = re.compile(r"/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*")


@dataclass(frozen=True)
class Settings:
    ssm_prefix: str = DEFAULT_SSM_PREFIX
    # The one JSON secret holding {"<alias>": "<app password>"} (ARN or name). Empty: no
    # credentials can be read, and any tool that needs one fails with ``unavailable``.
    credentials_secret_id: str = ""
    # The API key path; false rejects X-API-Key and non-JWT bearers with 401 without reading SSM.
    enable_api_key: bool = True
    parameter_cache_seconds: float = 60.0  # accounts, client-limits
    api_key_cache_seconds: float = 900.0
    credentials_cache_seconds: float = 900.0
    # After a failed or empty credentials read, wait this long before reading again.
    credentials_retry_seconds: float = 60.0
    # Requests with a larger declared body are refused (413) before they reach the MCP SDK.
    max_request_bytes: int = 262_144


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    prefix = os.environ.get("SSM_PREFIX", DEFAULT_SSM_PREFIX).rstrip("/")
    if not _PREFIX.fullmatch(prefix):
        raise ValueError("SSM_PREFIX must look like /name or /name/sub")
    return Settings(
        ssm_prefix=prefix,
        credentials_secret_id=os.environ.get("CREDENTIALS_SECRET_ARN", "").strip(),
        enable_api_key=_flag("ENABLE_API_KEY", os.environ.get("ENABLE_API_KEY", "true")),
    )


def _flag(name: str, value: str) -> bool:
    """``true`` or ``false`` (any case); anything else fails the cold start rather than guess."""
    normalised = value.strip().lower()
    if normalised not in ("true", "false"):
        raise ValueError(f"{name} must be true or false")
    return normalised == "true"
