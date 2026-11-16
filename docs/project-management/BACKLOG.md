# Backlog

Live prioritized list until the GitHub repo and Issues exist. Specs live in
`docs/planning/stories/` (template `TEMPLATE.md`); completed stories move to `docs/planning/archive/`.

| Order | ID | Title | Layer | Est | Pri | Status | Owner |
|-------|----|-------|-------|-----|-----|--------|-------|
| 1 | EML-001 | Spike: architecture and threat model (IMAP on Lambda, multi-account fan-out, prompt-injection handling, credentials, Cognito reuse, cost) | architect | M | P1 | Ready once the open questions in CLAUDE.md are answered | Architect |
| 2 | EML-002 | Skeleton: FastAPI + Mangum + SAM, `/health`, stateless MCP at `/mcp`, API-key auth seam, tests | backend, infra | M | P1 | After EML-001 | Developer |
| 3 | EML-003 | Read tools: `list_accounts`, `search_messages`, `get_message` (text only, trimmed, untrusted-content marking) | backend | L | P1 | After EML-002 | Developer |
| 4 | EML-004 | `create_draft` (IMAP APPEND to Drafts) | backend | M | P2 | After EML-003 | Developer |
| 5 | EML-005 | Cognito OAuth, scopes `mail.read` / `mail.draft` (/ later `mail.send`), RFC 9728 metadata | backend, infra | L | P2 | After EML-003 | Developer, Security |
| 6 | EML-006 | Audit log, security review, Launch Stack one-click deploy, public README quickstart | cross-cutting | L | P2 | Later | Developer, Security, Docs |
| - | EML-0xx | `send_message` behind `mail.send` | backend | M | P3 | Idea, needs a decision | - |
