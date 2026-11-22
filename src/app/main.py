"""FastAPI app: ``GET /health`` and the stateless MCP endpoint at ``/mcp``, behind the API key.

Lambda entry point: ``handler`` (Mangum, lifespan off).

One HTTP middleware authenticates every request except ``GET``/``HEAD /health`` before any
SSM, Secrets Manager or mail call, refuses oversized bodies, publishes the verified caller to
the MCP tools, and writes one access line per request (method, matched route template,
status, auth kind, reason code, ms). Bodies, query strings and raw paths are never logged.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from mangum import Mangum
from pydantic import BaseModel
from starlette.routing import BaseRoute, Match

from . import audit
from .accounts import AccountAccess
from .auth import (
    ApiKeyVerifier,
    Authenticator,
    AuthUnavailable,
    JwtVerifier,
    TokenRejected,
    credential_from_headers,
)
from .backend import MailBackend
from .config import Settings, get_settings
from .credentials import CredentialStore
from .service import MailService
from .ssm_params import ApiKeyStore, ParameterReader

MCP_PATH = "/mcp"
PUBLIC_PATHS = {(method, "/health") for method in ("GET", "HEAD")}
RETRY_AFTER_SECONDS = "30"
# The access line's ``path`` for a request that matches no route (the raw path is never logged).
UNMATCHED_PATH = "<unmatched>"

logger = logging.getLogger("mail.access")


class HealthOut(BaseModel):
    status: str = "ok"


def _configure_logging() -> None:
    logging.getLogger().setLevel(logging.INFO)
    # Libraries below can log request or response data at DEBUG; keep them quiet.
    for name in ("urllib3", "botocore", "boto3", "mangum", "imapclient"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _error(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail}, headers=headers)


def _auth_unavailable(reason: str) -> JSONResponse:
    if reason == "api_key_unconfigured":
        return _error(503, "API key is not configured on the server")
    return _error(503, "authentication is temporarily unavailable; retry later", {"Retry-After": RETRY_AFTER_SECONDS})


def _unauthorized() -> JSONResponse:
    # A bare challenge; EML-005 adds resource_metadata (RFC 9728) and error codes.
    return _error(401, "missing or invalid credentials", {"WWW-Authenticate": "Bearer"})


class Deps:
    """Per-container singletons, created lazily so a cold start does no network I/O."""

    def __init__(
        self,
        settings: Settings,
        parameters: ParameterReader,
        api_keys: ApiKeyStore,
        credentials: CredentialStore,
        backend: MailBackend | None,
        token_verifier: JwtVerifier | None,
    ):
        self.settings = settings
        self.parameters = parameters
        self.credentials = credentials
        self.authenticator = Authenticator(
            ApiKeyVerifier(api_keys), token_verifier, api_key_enabled=settings.enable_api_key
        )
        self.access = AccountAccess(settings.ssm_prefix, parameters)
        self._backend = backend
        self.service = MailService(self.access, credentials, lambda: self._backend)


class LazyMCPEndpoint:
    """``/mcp``, importing the MCP SDK on first use (about 2 s), so ``/health`` cold starts skip it."""

    def __init__(self, service: MailService):
        self._service = service
        self._endpoint = None

    async def __call__(self, scope, receive, send) -> None:
        if self._endpoint is None:
            from .mcp_server import build_endpoint

            self._endpoint = build_endpoint(self._service)
        await self._endpoint(scope, receive, send)


def create_app(
    settings: Settings | None = None,
    parameters: ParameterReader | None = None,
    api_keys: ApiKeyStore | None = None,
    credentials: CredentialStore | None = None,
    backend: MailBackend | None = None,
    token_verifier: JwtVerifier | None = None,
) -> FastAPI:
    _configure_logging()
    settings = settings or get_settings()
    deps = Deps(
        settings,
        parameters or ParameterReader(ttl_seconds=settings.parameter_cache_seconds),
        api_keys or ApiKeyStore(settings.ssm_prefix, ttl_seconds=settings.api_key_cache_seconds),
        credentials
        or CredentialStore(
            settings.credentials_secret_id,
            ttl_seconds=settings.credentials_cache_seconds,
            retry_seconds=settings.credentials_retry_seconds,
        ),
        backend,
        token_verifier,
    )

    app = FastAPI(
        title="duet-email-mcp",
        version="0.1.0",
        description=(
            "MCP server for read and draft access to the operator's own mailboxes. POST JSON-RPC to "
            "`/mcp` with the API key in `X-API-Key` or `Authorization: Bearer <key>`. Only "
            "`GET /health` is public."
        ),
        redoc_url=None,
    )
    app.state.deps = deps

    @app.middleware("http")
    async def auth_and_access_log(request: Request, call_next):
        started = time.perf_counter()
        status = 500
        auth_kind = audit.AUTH_NONE
        reason: str | None = None
        route = _route_template(app.router.routes, request.scope)
        try:
            if (request.method, request.url.path) not in PUBLIC_PATHS:
                try:
                    verified, token = await deps.authenticator.authenticate(request.headers)
                except AuthUnavailable as exc:
                    auth_kind, reason = _presented_auth(request), exc.reason
                    response = _auth_unavailable(exc.reason)
                    status = response.status_code
                    return response
                except TokenRejected as exc:
                    auth_kind, reason = _presented_auth(request), exc.reason
                    response = _unauthorized()
                    status = response.status_code
                    return response
                auth_kind = audit.auth_label(verified.method)
                if _body_too_large(request, settings.max_request_bytes):
                    reason = "body_too_large"
                    response = _error(413, "request body too large")
                    status = response.status_code
                    return response
                request.state.access_token = verified
                request.state.client_id = verified.client_id
                if request.url.path == MCP_PATH:
                    from .auth_context import published  # imports the SDK, as /mcp does anyway

                    with published(verified, token), audit.caller(verified):
                        response = await _call(call_next)(request)
                    status = response.status_code
                    return response
            response = await _call(call_next)(request)
            status = response.status_code
            return response
        finally:
            line: dict[str, object] = {
                "method": request.method,
                "path": route or UNMATCHED_PATH,
                "status": status,
                "auth": auth_kind,
            }
            if reason is not None:
                line["reason"] = audit.reason_code(reason)
            line["ms"] = round((time.perf_counter() - started) * 1000, 1)
            logger.info(json.dumps(line))

    @app.get("/health", response_model=HealthOut, tags=["meta"])
    def health() -> HealthOut:
        """Liveness check. No auth, no SSM, Secrets Manager or mail call."""
        return HealthOut()

    # Every method reaches the endpoint, which answers 405 for anything but POST.
    app.add_route(MCP_PATH, LazyMCPEndpoint(deps.service), include_in_schema=False)
    return app


def _body_too_large(request: Request, limit: int) -> bool:
    """A declared body over ``limit``, or an unparsable Content-Length. Chunked bodies are bounded
    by the Function URL payload limit."""
    declared = request.headers.get("content-length")
    if declared is None:
        return False
    try:
        return int(declared) > limit
    except ValueError:
        return True


def _call(call_next):
    async def run(request: Request) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:  # never let a traceback carry request data into the logs
            logger.error("unhandled %s", type(exc).__name__)
            return _error(500, "internal error")

    return run


def _route_template(routes: Iterable[BaseRoute], scope) -> str | None:
    """The matched route's path template, never the concrete path. A full match wins, then a
    path-only match (a 405), else None."""
    partial = None
    for route in routes:
        path = getattr(route, "path", None)
        if path is None:
            continue
        match, _ = route.matches(scope)
        if match is Match.FULL:
            return path
        if match is Match.PARTIAL and partial is None:
            partial = path
    return partial


def _presented_auth(request: Request) -> str:
    """The kind of credential a rejected request presented: ``api_key``, ``oauth`` or ``none``."""
    credential = credential_from_headers(request.headers)
    if credential.value is None:
        return audit.AUTH_NONE
    return audit.AUTH_OAUTH if credential.kind == "jwt" else audit.AUTH_API_KEY


app = create_app()
handler = Mangum(app, lifespan="off")
