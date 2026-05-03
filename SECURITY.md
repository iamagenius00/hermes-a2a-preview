# Security Policy

Hermes A2A is a developer preview for technical Hermes Agent users. Treat every
token, friend record, audit file, and conversation log as sensitive until you
have reviewed it yourself.

Do not commit or publish:

- bearer tokens or generated friend tokens
- `~/.hermes/.env`
- `~/.hermes/config.yaml` when it contains real routes, chat ids, or secrets
- `~/.hermes/a2a_*` runtime data, including friends, audit logs,
  conversations, provenance sidecars, or stranger records

## Reporting Security Issues

Please do not put exploitable details, real tokens, private URLs, or private
runtime data in a public GitHub issue.

Open a GitHub issue with a non-sensitive summary first. If sensitive details are
needed and there is no private reporting channel listed, use the issue to ask
for a private contact path before sharing details.

## Preview Status

This repository is a public developer preview. It includes hardening for
per-friend auth, SSRF/DNS pinning, outbound redaction, provenance checks,
stranger capture, and audit logging, but it is not a hosted security service.
Run it with dummy friends and test tokens before exposing a real endpoint.
