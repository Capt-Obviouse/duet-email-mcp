# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project skeleton: CLAUDE.md with the founding decisions, MIT license, planning folders.
- EML-001 architecture and threat-model spike: `docs/architecture/EML-001-architecture.md` (IMAP on Lambda, fan-out, account config, credentials, tool surface, untrusted-content handling, auth, send seams, STRIDE threat model, cost, story revisions).

### Changed
- Recorded the EML-001 operator decisions (2026-11-19): optional reuse of an existing Cognito pool via `ExistingUserPoolId`, draft-only (no send tool planned), one JSON secret for credentials.
- Backlog: EML-003 split into 003a, 003b and 003c; EML-002 grows to include account config, audit and `list_accounts`.
