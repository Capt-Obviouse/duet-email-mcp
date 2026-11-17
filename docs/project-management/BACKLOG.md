# Backlog

Live prioritized list until the GitHub repo and Issues exist. Specs live in
`docs/planning/stories/` (template `TEMPLATE.md`); completed stories move to `docs/planning/archive/`.

| Order | ID | Title | Layer | Est | Pri | Status | Owner |
|-------|----|-------|-------|-----|-----|--------|-------|
| 1 | EML-001 | Spike: architecture and threat model (IMAP on Lambda, multi-account fan-out, prompt-injection handling, credentials, Cognito reuse, cost) | architect | M | P1 | In review (design in `docs/architecture/EML-001-architecture.md`; operator decisions A589, A590, A591) | Architect |
| 2 | EML-002 | Skeleton: FastAPI + Mangum + SAM, `/health`, stateless MCP at `/mcp`, API-key seam (read-only by default), account/limit parsers (fail closed), `MailBackend` + fake, Secrets Manager seam, `list_accounts`, audit line from day one | backend, infra | L | P1 | After EML-001 | Developer |
| 3 | EML-003a | Sanitiser: Unicode stripping, HTML-to-text, untrusted-content fence, header sanitising, id parser, argument validators (pure code, fixtures, fuzz) | backend | M | P1 | After EML-002 | Developer |
| 4 | EML-003b | `ImapBackend` (imapclient), connection cache, circuit breaker, `search_messages`, `get_message`, fan-out and deadline | backend | L | P1 | After EML-003a | Developer, Security |
| 5 | EML-003c | Live gate on the deployed function: Gmail, Workspace, iCloud (latency, cloud-IP login, folder names, search charset) | cross-cutting | S | P1 | After EML-003b | Developer, Operator |
| 6 | EML-004 | `create_draft` (IMAP APPEND to Drafts, idempotent Message-ID, plain text only) | backend | M | P2 | After EML-003c | Developer |
| 7 | EML-005 | Cognito OAuth (own pool per stack, pending A589), per-tool scope enforcement, scopes `mail.read` / `mail.draft` (/ later `mail.send`), RFC 9728 metadata | backend, infra | L | P2 | After EML-003 | Developer, Security |
| 8 | EML-006 | Operator helper scripts, injection test set, whole-stack security review, Launch Stack one-click deploy, public README quickstart | cross-cutting | L | P2 | Later | Developer, Security, Docs |
| - | EML-0xx | `send_draft` behind `mail.send` (only after A590 says yes; never free-form send) | backend | M | P3 | Idea, needs a decision | - |
