# duet-email-mcp

MCP server that gives an AI assistant read and draft access to **several mailboxes the operator
owns**, over IMAP/SMTP with per-account app passwords, on AWS Lambda. **Public from day one**
(MIT): every committed file must be safe to publish.

Status: planning. No application code yet. The first step is the EML-001 architect spike.

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

## Open questions (for EML-001, ask the operator through the asks queue)
- Which mailboxes are personal Gmail vs Google Workspace (and is the operator the Workspace
  admin, so IMAP/app passwords can be allowed)? Any non-Google providers?
- Cognito: own pool per stack, or optional reuse of an existing pool?
- Draft-only forever, or plan for `send_message`?

## Workflow
- The operator's global CLAUDE.md applies: orchestrator delegates to agents, one at a time unless
  the operator approves parallel work; everything needing the operator goes through the asks
  queue (`ASKS_PROJECT=duet-email-mcp`); Conventional Commits; Keep a Changelog.
- Story IDs `EML-NNN`; backlog in `docs/project-management/BACKLOG.md` until GitHub Issues exist;
  specs in `docs/planning/stories/` from `TEMPLATE.md`; designs in `docs/architecture/`.
- Security review for anything touching auth, credentials, email content handling or deploy.
- Before any push to the public repo: scan the diff for personal values.

## Architecture
Not built yet. Replace this section with the real architecture as soon as EML-002 lands; keep it
accurate so every agent can check that its work integrates.
