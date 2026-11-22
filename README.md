# duet-email-mcp

An MCP server that lets an AI assistant (Claude.ai, Claude Code, or any MCP client) read and
draft email across **several of your own mailboxes at once**, over plain IMAP/SMTP with
per-account app passwords. Runs serverless on AWS Lambda, deployed with AWS SAM.

Status: **early development**. The skeleton (auth, account configuration, credentials seam,
audit log and the `list_accounts` tool) exists; reading mail does not yet. See `CLAUDE.md` for
the design decisions and `docs/project-management/BACKLOG.md` for the plan.

Planned:
- Any provider that supports IMAP with an app password (Gmail with 2-Step Verification, iCloud
  Mail, Fastmail, Yahoo, and others).
- Narrow, typed tools: `list_accounts`, `search_messages`, `get_message`, `create_draft`
  (sending comes later, behind its own permission).
- OAuth for MCP clients (Amazon Cognito), an account allowlist, an audit log that never records
  message content, and app passwords kept in AWS Secrets Manager.

## Secrets after the first deploy

Nothing secret is ever a template parameter. After `sam deploy`:

1. **API key.** Create the SecureString named in the `ApiKeyParameter` output with a random hex
   key (at least 32 characters, no dots: a value with two dots is treated as a JWT):

   ```sh
   aws ssm put-parameter --name /duet-email-mcp/api-key --type SecureString \
     --value "$(openssl rand -hex 32)"
   ```

   A key shorter than 32 characters is treated as not configured (503). Until the key exists,
   every request except `GET /health` gets 503; once created, it works within 30 seconds.
2. **App passwords.** The stack creates the secret named in the `CredentialsSecretName` output
   with no value, so a stack update can never overwrite it. Put one JSON object keyed by account
   alias (write it to a file you delete afterwards, so it stays out of shell history):

   ```sh
   aws secretsmanager put-secret-value --secret-id <stack name>/mailbox-credentials \
     --secret-string file://creds.json      # {"personal": "<app password>", ...}
   ```

   The secret and the log group are kept when the stack is deleted; delete them by hand before
   creating a new stack with the same name.

**Rotating the API key.** Warm containers cache the key for up to 15 minutes. To make a rotation or
revocation take effect at once, change the function configuration, which replaces every
container (for example `aws lambda update-function-configuration --function-name <name>
--description "key rotated"`), or set `EnableApiKey=false` to refuse the key immediately.

Only connect mailboxes you own and control. Mailboxes managed by an employer or client are out of
scope: use the tools their IT approves.

License: MIT.
