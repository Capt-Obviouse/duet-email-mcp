# duet-email-mcp

MCP server that gives an AI assistant read and draft access to **several mailboxes the operator
owns**, over IMAP/SMTP with per-account app passwords, on AWS Lambda. **Public from day one**
(MIT): every committed file must be safe to publish.

Status: early development. EML-001 (design) is done; EML-002 (skeleton: auth, config, credentials
seam, audit, `list_accounts`) is in review. No mail is read yet (EML-003b).

## Branching
- **Main branch:** `master` (trunk-based; no dev branch). Feature branches `feature/EML-00N-desc`
  off `master`, PRs to `master`. No CI yet; the local pytest run is the gate.
- Operator-specific notes (AWS account and profile, real mailboxes, repo URL) live in
  `CLAUDE.local.md`, which is gitignored and loaded automatically by Claude Code. Never put them in
  committed files. The same goes for `samconfig.toml` (commit `samconfig.example.toml` only).

## Founding decisions (do not re-litigate without the operator)
1. **Separate project.** Email does not go into the sibling calendar MCP (icloud-cal-bridge):
   email is far more sensitive (password resets, client data, can send as the user), carries
   attacker-written input, and uses different credentials. Separate repo, stack, IAM, secrets and
   scopes; MCP clients connect to both servers at once.
2. **Public from the start.** No URLs, account ids, pool ids, email addresses, mailbox names or
   personal names in committed files. Generic docs written for any operator. MIT license.
3. **Provider-agnostic via IMAP/SMTP + app passwords.** Any mailbox whose provider offers IMAP
   with an app password (Gmail personal with 2-Step Verification, Google Workspace if the admin
   allows it, iCloud Mail, Fastmail, Yahoo, others). Per-account config: host, port, TLS mode,
   username, Drafts/Sent folder names (providers differ: Gmail uses `[Gmail]/Drafts`). Provider
   presets are a convenience, never a requirement.
4. **Only operator-owned mailboxes.** Mailboxes controlled by an employer or client are out of
   scope; no forwarding, scraping or password-reuse workarounds. The design should leave room for a
   later OAuth provider adapter (Microsoft Graph, Gmail API) that a tenant admin explicitly
   consents to, but none is planned.
5. **Least privilege, staged.** Read + draft first. `send_message` only later, behind its own
   scope (`mail.send`), and only if the operator decides to add it. No delete, no permanent
   moves in the first release.
6. **Email content is untrusted input.** Every message body, subject and sender is attacker
   controlled (prompt injection). Tools return plain text (HTML stripped), size-capped, clearly
   delimited as untrusted data; no link fetching, no attachment content in the first release
   (metadata only); server instructions tell the model not to follow instructions found in email.
7. **Architecture reused from icloud-cal-bridge** (read its CLAUDE.md for the proven details):
   Python 3.12, FastAPI + Mangum (lifespan off) on Lambda arm64 behind a Function URL, AWS SAM,
   official `mcp` Python SDK in stateless streamable-HTTP JSON mode, narrow flat typed tools,
   trimmed output, fixed-category errors that never echo submitted values, hash-locked
   dependencies (`uv pip compile --generate-hashes`, `pip-audit`), lazy SDK import for cold start.
8. **Auth for MCP clients:** start with an API-key seam shaped like the SDK `TokenVerifier`, then
   Cognito OAuth (resource-server mode, RFC 9728 metadata, client-credentials for headless agents,
   code + PKCE for Claude.ai), as in icloud-cal-bridge. Whether to create a pool in this stack or
   optionally point at an existing pool is an EML-001 question (the public template must work
   standalone).
9. **Allowlist and limits fail closed:** the mailboxes the server may touch are an SSM parameter
   created by the stack; per-client limits can narrow (never widen) it. Missing or unparsable
   config means no access.
10. **Credentials:** app passwords in AWS Secrets Manager (one secret per mailbox or one JSON
    secret; EML-001 decides), read lazily and cached per container; never logged, never in
    template outputs.
11. **Audit log:** one JSON line per tool call (client, tool, mailbox alias, status, ms); never
    subjects, bodies, addresses, search text or message ids.
12. **Lambda limits shape the design:** 30 s max; IMAP connect + login per mailbox per cold
    container; all-mailbox searches fan out with a per-mailbox timeout and an overall deadline,
    returning partial results with `truncated` and a note (same pattern as the calendar search).

## Decided (EML-001 questions, operator answers 2026-11-19)
13. **Mailbox mix:** consumer Gmail, Google Workspace where the operator is the admin (so IMAP and
    app passwords can be allowed), and iCloud Mail. The design must work for all three.
14. **Cognito:** the template creates its own pool by default. An optional `ExistingUserPoolId`
    parameter (plus the pool's domain) makes the stack add its own resource server (`mail.read`,
    `mail.draft`) and app clients to an existing pool, so an operator running a sibling MCP stack can
    sign in once. Only the pool is shared; Lambda, IAM, secrets, SSM and Function URL stay separate.
    Caveats: deploy order and dependence on the pool-owning stack, pool-wide settings shared (MFA
    must stay required), scopes per resource server keep services isolated. The verifier stays
    pool-agnostic.
15. **Draft-only.** No send tool is planned (`send_draft` not planned; revisit only if the operator
    raises it). Reserved seams stay as designed in the architecture doc.
16. **Credentials:** one JSON secret for now (supersedes the "EML-001 decides" note in decision 10).

## Workflow
- The operator's global CLAUDE.md applies: orchestrator delegates to agents, one at a time unless
  the operator approves parallel work; everything needing the operator goes through the asks
  queue (`ASKS_PROJECT=duet-email-mcp`); Conventional Commits; Keep a Changelog.
- Story IDs `EML-NNN`; backlog in `docs/project-management/BACKLOG.md` until GitHub Issues exist;
  specs in `docs/planning/stories/` from `TEMPLATE.md`; designs in `docs/architecture/`.
- Security review for anything touching auth, credentials, email content handling or deploy.
- Before any push to the public repo: scan the diff for personal values.

## Architecture
Design: `docs/architecture/EML-001-architecture.md`. What exists (EML-002):

- **Runtime:** Python 3.12, FastAPI app wrapped by Mangum with lifespan off
  (`src/app/main.py:handler`) on AWS Lambda arm64, 1024 MB, 30 s, reserved concurrency 5
  (`ReservedConcurrency`), no VPC, exposed by a Function URL with auth type NONE. Deployed by AWS
  SAM (`template.yaml`; operator settings in the gitignored `samconfig.toml`, copied from
  `samconfig.example.toml`). Not deployed yet.
- **Routes:** `GET`/`HEAD /health` (public, touches nothing) and `/mcp` (POST only; other methods
  405). Everything else, including `/docs` and `/openapi.json`, needs a credential.
- **Middleware (`main.py`):** authenticates every non-public request before any SSM (beyond the
  key), Secrets Manager or mail call; 401 `missing or invalid credentials` with a bare
  `WWW-Authenticate: Bearer`, 503 with one generic body for every cause (key not configured or too
  short, SSM failure, JWT with no verifier; `Retry-After: 30`; only the access line's `reason`
  tells them apart); then refuses a declared body over 256 KiB (413); publishes the caller on
  `request.state`, the SDK `auth_context_var` (`auth_context.py`) and `audit.caller()`; writes one
  access line per request (`mail.access`: method, matched route template or `<unmatched>`, status,
  `auth` `api_key`/`oauth`/`none`, `reason` code on rejections, ms). Unhandled exceptions are logged
  by type name only. Every response carries `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store`.
- **Auth (`auth.py`):** API key = SSM SecureString `<prefix>/api-key`, created by the operator
  (CloudFormation cannot create SecureStrings; generate it with `openssl rand -hex 32`), read by
  `ssm_params.ApiKeyStore` (15 min cache; a missing, failed or shorter-than-32-character key counts
  as unconfigured and is cached 30 s, so a new key works within 30 s), sent as `X-API-Key` or a non-JWT
  `Authorization: Bearer`, compared only by `key_matches` (`hmac.compare_digest`). `X-API-Key`
  wins whenever present (even empty); `Authorization` must be exactly `Bearer <token>`; a
  JWT-shaped bearer goes only to the `JwtVerifier` seam and never to the key. The key is client
  `api-key` (`API_KEY_CLIENT_ID`) carrying `mail.read` and `mail.draft`, capped to read by default
  (below). `EnableApiKey` -> `ENABLE_API_KEY`; `false` is 401 without reading SSM.
  `ApiKeyVerifier.verify_token` has the SDK `TokenVerifier` shape. EML-005 plugs the Cognito
  verifier into `create_app(token_verifier=...)`; nothing in the seam names a pool. `auth.py`
  never imports the SDK at import time.
- **Account config and limits (`accounts.py`):** two stack-created SSM Strings fed by the template
  parameters `Accounts` and `ClientLimits` (default `{}`), read through `ssm_params.ParameterReader`
  (parsed value cached 60 s; a denying result from a malformed document is cached too). `<prefix>/accounts`: JSON keyed by alias (`^[a-z0-9][a-z0-9-]{0,31}$`),
  fields `provider` (`google`/`gmail`/`workspace`, `icloud`, `generic`), `address`, optional
  `username`, `description` (80 chars), `imap` and `smtp` (`host`, `port`, `tls`
  `implicit`/`starttls`; required for `generic`, else overriding the preset field by field),
  `folders` (logical `inbox`/`sent`/`drafts`/`all_mail` to real names). Presets: Google
  (`imap.gmail.com`, `[Gmail]/...` folders, search `gmail`), iCloud (`imap.mail.me.com`,
  `Sent Messages`, `Drafts`). Any unknown field, duplicate key, wrong type, control character,
  bad alias, host, port or tls disables **every** mailbox (the loaders also catch any
  `TypeError`/`ValueError`/`RecursionError` and deny). `<prefix>/client-limits`:
  `{"<client_id>": {"accounts": [...], "access": "read"|"draft"}}`; missing or malformed denies
  every client. `AccountAccess.grant(client_id, token_scopes)` returns a `Grant`: accounts = global
  list intersected with the entry, in config order (never wider; `[]` locks out); scopes = token
  scopes capped by `access` (`read` -> `mail.read`; `draft` -> both; no entry: `read` for
  `api-key`, uncapped for other clients). No scope means no accounts. Errors log the parameter name
  only.
- **Credentials (`credentials.py`):** one Secrets Manager secret `<stack name>/mailbox-credentials`
  (`CREDENTIALS_SECRET_ARN`), JSON `{"<alias>": "<app password>"}`, created by the stack **with no
  value** (no `SecretString`, so no update can overwrite it; `DeletionPolicy`/`UpdateReplacePolicy`
  Retain) and filled by the operator with `put-secret-value` (never a template parameter). Until it
  is filled, `GetSecretValue` raises `ResourceNotFoundException`, read as no credentials. `CredentialStore` reads it on first need only, caches 15
  min, waits 60 s after a failed, empty or unparsable read, and wraps values in `Secret` (redacted
  `repr`/`str`, not picklable, `reveal()` for the login call only). `forget(alias)` drops one.
  Logs never include values, keys, the secret id or exception text. `MailService.password_for`
  refuses aliases outside the grant before reading.
- **Service (`service.py`):** `MailService` holds every rule. Each tool resolves the caller's grant
  once, checks `TOOL_SCOPES[tool]` (any one scope suffices) and that the grant has accounts
  (`forbidden` otherwise), and will pass `allowed=` aliases to the backend. `backend()` is
  `unavailable` until EML-003b provides `ImapBackend`.
- **Backend seam (`backend.py`):** `MailBackend` protocol (`search`, `fetch`, `append_draft`,
  `close`), each with a required `allowed=` keyword checked again by `ensure_allowed`; result
  dataclasses carry primitives and raw bytes (`MessageSummary`, `MessageDetail`, `DraftRef`,
  `SearchCriteria`, `AttachmentInfo`). No implementation ships; tests use `tests/conftest.py`
  `FakeBackend`. EML-003b may refine the signatures.
- **MCP (`mcp_server.py`):** official `mcp` SDK 2.3.0 `MCPServer`, stateless streamable HTTP with
  JSON responses (a fresh session manager per request, no `Mcp-Session-Id`), imported on the first
  `/mcp` request only (`LazyMCPEndpoint`). DNS-rebinding protection is off (public URL, header
  credential, no cookies). `SERVER_INSTRUCTIONS` is the design section 9 text. Tools:
  `list_accounts` (read-only annotation; returns `account`, `address`, optional `description`,
  `folders`, `search`, `access` for effective accounts; configuration only, no network, no
  credentials). `MailMCPServer.call_tool` opens a per-call `audit.AuditNote` (ContextVar), rejects unknown tools (JSON-RPC error that never echoes
  the name) and unknown parameters, turns failures into `isError` results with fixed categories
  (`errors.py`, design 7.5: `"<category>: <hint>"`, optionally the argument *name*), and writes
  the one audit line from the note. A send wrapper scrubs SDK JSON-RPC error bodies; `mcp.*` loggers are at WARNING
  with a filter that strips arguments and tracebacks (re-applied after the first request). `tools/list` scope filtering is EML-005.
- **Audit (`audit.py`):** one JSON line per `tools/call` (`mail.audit`), built from an allowlist of
  keys: `event`, `ts`, `client_id`, `auth`, `tool` (`unknown` for a bad name), `account` (a
  configured alias or `*`; `list_accounts` logs `*`), `status` `ok`/`error`/`denied`/`partial`,
  optional `error_class` (a category, `unknown_tool`, `unknown_parameter`, `protocol`, or an
  exception type name), `ms`, `accounts_ok`/`accounts_skipped`. Per-call values come from the
  service: `audit.note_call(account=<validated alias>, accounts_ok=, accounts_skipped=,
  partial=True)` writes into the open note (a no-op outside a call); `partial` turns `ok` into
  status `partial`, never a failure. Never subjects, bodies,
  addresses, search text, ids, argument values, tokens or keys. No audit line for failed auth.
  Log group `/aws/lambda/<FunctionName>`, retention `LogRetentionDays` (400), retained on stack
  deletion.
- **AWS clients:** SSM and Secrets Manager clients share `ssm_params.aws_client_config()`: 2 s
  connect, 3 s read, 2 attempts in total.
- **IAM:** an explicit role (`MailFunctionRole`, not SAM's basic execution role):
  `logs:CreateLogStream`/`PutLogEvents` on the function's own log group only; `ssm:GetParameter` on
  `<prefix>/*`; `kms:Decrypt` via SSM on `alias/aws/ssm` only; `secretsmanager:GetSecretValue` on
  the one secret ARN.
- **Not built yet:** sanitiser (EML-003a), `ImapBackend` and read tools (EML-003b), drafts
  (EML-004), Cognito and RFC 9728 metadata (EML-005).

## Dependencies
- `src/requirements.in` is the source (fastapi, mangum, pydantic, mcp; boto3 comes from the Lambda
  runtime); `src/requirements.txt` is the hashed lock for the Lambda target. Regenerate, then audit:
  `uv pip compile src/requirements.in --generate-hashes --python-version 3.12 --python-platform aarch64-manylinux2014 -o src/requirements.txt`
  `uvx pip-audit -r src/requirements.txt --require-hashes --no-deps --disable-pip`
- `requirements-dev.txt` includes `src/requirements.in` plus boto3, httpx and pytest. The local
  venv is x86_64; only the Lambda artifact is arm64.
- `imapclient` is added by EML-003b, not before.

## Testing
- Setup: `~/.pyenv/versions/3.12.9/bin/python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`
- Run: `.venv/bin/python -m pytest` (SSM, Secrets Manager and the mail backend are faked; no network).
- Template: `sam validate --lint` and `sam build` (with Python 3.12 on `PATH`); the build must be
  arm64 only.
- No CI yet: the local pytest run is the gate.
- `test_service.py::test_every_tool_declares_its_scopes` compares the registered MCP tools with
  `TOOL_SCOPES`: a new tool needs an entry there.
