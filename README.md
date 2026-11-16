# duet-email-mcp

An MCP server that lets an AI assistant (Claude.ai, Claude Code, or any MCP client) read and
draft email across **several of your own mailboxes at once**, over plain IMAP/SMTP with
per-account app passwords. Runs serverless on AWS Lambda, deployed with AWS SAM.

Status: **planning**. Nothing is deployable yet; see `CLAUDE.md` for the design decisions and
`docs/project-management/BACKLOG.md` for the plan.

Planned:
- Any provider that supports IMAP with an app password (Gmail with 2-Step Verification, iCloud
  Mail, Fastmail, Yahoo, and others).
- Narrow, typed tools: `list_accounts`, `search_messages`, `get_message`, `create_draft`
  (sending comes later, behind its own permission).
- OAuth for MCP clients (Amazon Cognito), an account allowlist, an audit log that never records
  message content, and app passwords kept in AWS Secrets Manager.

Only connect mailboxes you own and control. Mailboxes managed by an employer or client are out of
scope: use the tools their IT approves.

License: MIT.
