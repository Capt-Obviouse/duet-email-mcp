# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project skeleton: CLAUDE.md with the founding decisions, MIT license, planning folders.
- EML-001 architecture and threat-model spike: `docs/architecture/EML-001-architecture.md` (IMAP on Lambda, fan-out, account config, credentials, tool surface, untrusted-content handling, auth, send seams, STRIDE threat model, cost, story revisions).
- EML-002 skeleton:
  - FastAPI + Mangum (lifespan off) app on Lambda: public `GET /health`, stateless MCP
    (streamable HTTP, JSON responses, SDK imported lazily) at `POST /mcp`.
  - API-key auth (SSM SecureString `<prefix>/api-key`, `X-API-Key` or non-JWT Bearer,
    constant-time compare), `EnableApiKey` switch, and a pool-agnostic JWT verifier seam
    (a JWT bearer is 503 until EML-005). The verifier has the SDK `TokenVerifier` shape.
  - Account config (`<prefix>/accounts`) and client limits (`<prefix>/client-limits`) parsers
    that fail closed; provider presets for Google and iCloud; limits only narrow; the API key
    client is read only unless `client-limits` grants `draft`.
  - Secrets Manager credentials reader for one JSON secret: lazy, cached 15 minutes, values
    redacted, never logged.
  - `MailBackend` protocol and result types (no IMAP code yet).
  - `list_accounts` tool (configuration only, no network).
  - One audit JSON line per tool call, built from an allowlist of fields; access line per request.
  - Server instructions text telling the model that email content is untrusted data.
  - Fixed error categories that never echo submitted values.
  - SAM template (arm64, Python 3.12, 1024 MB, 30 s, reserved concurrency 5, no VPC, Function
    URL), `samconfig.example.toml`, hash-locked `src/requirements.txt`, test suite.
  - Per-call audit note so tools can record the alias addressed, fan-out counts and `partial`.
  - README: creating the API key and filling the credentials secret; forcing a key rotation.

### Security
- EML-002 review fixes: the credentials secret is created with no value, retained on deletion
  and replacement, and named after the stack, so stored app passwords cannot be overwritten or
  orphaned; SSM and Secrets Manager calls have 2 s/3 s timeouts and 2 attempts; a missing,
  failed or throttled API-key read is cached 30 s; a stored key under 32 characters counts as
  unconfigured; every 503 has the same generic body; malformed accounts or client-limits of any
  shape deny, log once and are cached; the function role writes only to its own log group; the
  log group is retained; responses carry `nosniff` and `no-store`.

### Changed
- Recorded the EML-001 operator decisions (2026-11-19): optional reuse of an existing Cognito pool via `ExistingUserPoolId`, draft-only (no send tool planned), one JSON secret for credentials.
- Backlog: EML-003 split into 003a, 003b and 003c; EML-002 grows to include account config, audit and `list_accounts`.
