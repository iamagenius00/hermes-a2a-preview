# hermes-a2a

Safe peer-to-peer coordination for real [Hermes Agent](https://github.com/NousResearch/hermes-agent) sessions.

> Based on [Google's A2A protocol](https://github.com/google/A2A). Requires Hermes Agent v2026.4.23+.

[中文文档](./README_CN.md)

Let each agent stay where it works best, while giving them a safer way to
coordinate.

Hermes A2A lets one agent discover, trust, call, and audit another agent over
the A2A protocol while preserving each side's native environment: its own
session, repository, tools, terminal, memory, and user-facing chat entrypoint.

It is not another chat app, not a central boss-agent framework, and not a
global shared token wrapped around a webhook. It is a trust and coordination
layer for agents that already exist.

## What Problem It Solves

More people are running several agents at once:

- a coding agent working inside a repository
- a conversational agent in Telegram or Discord
- a long-lived Hermes session with memory and notifications
- a teammate's remote agent
- a local agent with access to one machine or environment

These agents are useful because they are not identical. They live in different
sessions, carry different context, and have different permissions.

That creates a coordination problem:

- agents cannot safely call each other
- users have to copy and paste context by hand
- every integration becomes a one-off webhook
- one leaked global token exposes the whole endpoint
- unknown agents have no review path before becoming trusted
- security incidents are hard to audit afterwards

Hermes A2A does not move every agent into a new app. It lets them stay where
they are, then gives them a safer path to work together.

## Core Idea

An agent should be able to become a node in a network without turning into a
security hole.

Hermes A2A splits that lifecycle into four steps:

| Step | Meaning |
|------|---------|
| Discover | Your agent exposes an Agent Card and can discover remote Agent Cards |
| Trust | A remote agent becomes a friend with its own token, status, trust level, and rate limit |
| Call | Agents exchange typed A2A `tasks/send` work instead of ambiguous chat blobs |
| Audit | Auth failures, denials, calls, SSRF blocks, and friend changes are recorded without raw secrets |

That is the product boundary. A2A moves work between agents. Friends define who
is allowed to talk. The security layer decides what must not leave. Audit gives
the human operator visibility.

## What you can do with this

### Wake another real agent

It's 2am. You notice your teammate's Supabase disk is at 92%. You don't have their number and they're definitely not awake. But their agent is.

You tell your Hermes agent on Telegram: "Let them know the Supabase disk is almost full." Your agent sends an A2A task to their agent. The message enters their real Hermes session, and it is already in context when they wake up.

No copy-paste. No buried group-chat notification. No invisible throwaway session.

### Hand work between agents

Your coding agent finishes a batch of changes. Instead of dumping a diff in your chat and waiting, it can send the work to another agent for review. That agent can inspect the change, point out risk, and send the result back.

The point is not that one agent controls another. Each agent keeps its own environment and judgment.

### Ask a specialist agent for help

Your agent is debugging a gateway hang and gets stuck. Another agent has seen something similar before. Hermes A2A gives the first agent a direct, auditable way to ask for help without defaulting to handing over private memory or local secrets.

### Handle stranger requests safely

If you expose an A2A endpoint, unknown agents may knock. They should not become trusted just because they sent a friendly message.

Hermes A2A captures unknown or denied requests as sanitized stranger records.
Raw request bodies and raw tokens are not stored. The operator can review,
block, or explicitly convert a stranger into a friend.

## How It Differs From Ordinary Agent Calls

### Peer-to-peer, not boss-and-worker

Hermes has `delegate_task` for spawning child agents — that's a boss-worker relationship. The child does a job, reports back, and disappears. hermes-a2a is different: two agents talk as equals, each with their own memory, context, and judgment. Neither controls the other.

### Same session, same agent — not a clone

Most A2A implementations spawn a new session per message — a copy loads your files, generates a reply, and shuts down. "You" replied but have no memory of it. Your user can't see it in their chat. Agent and user are out of sync.

hermes-a2a injects messages into the agent's **currently running session**. The one replying is the same agent that's been talking to its user all day, with full context. Your user sees the whole thing on Telegram.

### Conversations persist independently — compaction can't erase them

Hermes' context compaction summarizes long conversations to save tokens — which means A2A exchanges can get compressed away and become unsearchable. hermes-a2a stores every A2A conversation separately on disk (`~/.hermes/a2a_conversations/`), outside the session context pipeline. Compaction can't touch them. Agent restarts can't lose them.

> Session-internal compaction causing search to miss messages is a known issue — [PR #13841](https://github.com/NousResearch/hermes-agent/pull/13841) is in progress.

### Instant wake — no polling

When a message arrives, the plugin fires an HMAC-signed webhook to Hermes' internal endpoint, triggering an agent turn immediately. No cron delay, no polling interval. The agent responds in the same HTTP request (synchronous, 120s timeout).

### Trust is managed per friend, not by one global token

A single shared inbound token is easy to build and hard to operate safely. Once
it leaks, every caller looks the same and every relationship has the same power.

Hermes A2A uses friend records:

- independent inbound token hashes
- optional outbound tokens
- status: pending, active, paused, blocked, expired, removed
- trust levels: new, normal, trusted
- per-friend rate limits
- explicit private-target approvals
- last-contact metadata

You can pause a friend, rotate a token, block a caller, or review one
relationship without breaking the whole endpoint.

### Security is the product, not an add-on

The earliest internal version sent too much agent state in outbound A2A
messages and leaked private context. This preview is shaped by that failure.

The current version includes per-friend auth, SSRF protection with DNS pinning,
prompt-injection filtering, outbound redaction, provenance checks, stranger
capture, rate limiting, HMAC webhook signatures, and audit logs.

It does not pretend code can make every sharing decision for the user. A remote
agent can make a request that is technically valid, friendly in tone, and still
unsafe. The technical layer blocks known bad paths and makes risk visible; the
agent and user still decide what should be shared.

## Developer Preview

This repository packages the M1/M2 Hermes A2A line as a public developer
preview. The goal is narrow: let two already-running Hermes agents talk to each
other without patching Hermes source code, while keeping the local user in the
loop through their existing chat session.

It is meant for technical Hermes Agent users who are comfortable installing a
local plugin, restarting the gateway, and testing with dummy friends before
using real credentials.

What is in M2:

- A2A `tasks/send` and `tasks/get`
- `/.well-known/agent.json` Agent Card
- inbound A2A server inside the Hermes plugin
- signed webhook route for instant wake into the main Hermes session
- `a2a_discover`, `a2a_call`, and `a2a_list` tools
- `/a2a` and `/a2a friends` slash commands
- per-friend auth and friend lifecycle management
- SSRF guard with DNS pinning and redirect blocking
- outbound secret redaction and hard-deny checks
- provenance/taint protection for automatic outbound replies
- stranger request capture without raw body or raw token storage
- audit log and persistent conversation storage

M2 is still intentionally conservative:

- Start with dummy friends and test tokens before sending real credentials.
- Dashboard UI is not included in this public preview.
- Private-content release/declassification is not automatic. One-shot
  user-approved release remains follow-up work.
- Streaming/SSE, hosted registry, relay/mailbox fallback, and mobile approval
  flows are not included yet.

### Fake-IP / tunnel origin approval

The main M2.1 compatibility path is direct friend-agent communication over a
temporary tunnel such as cloudflared or ngrok. To let a friend reach your
agent, expose your local A2A port and send them the tunnel URL plus the
one-time inbound token from `/a2a friends add`:

```bash
cloudflared tunnel --url http://127.0.0.1:8081
```

To call a friend's tunneled agent from your side, add their tunnel URL as that
friend's A2A URL. The URL may be a provider hostname such as
`*.trycloudflare.com`, `*.ngrok-free.app`, or `*.ngrok.app`, or a custom domain
such as `friend-a2a.example.com`.

Some local proxy/TUN setups resolve friend hostnames to `198.18.x.x` fake-IP
addresses. Hermes blocks that by default because `198.18.0.0/15` is non-public
benchmark address space. If the URL is an intentional friend origin, allow the
exact origin explicitly:

```text
/a2a friends add demo_friend https://friend-a2a.example.com --allow-origin --reason "I trust this exact demo friend origin for local fake-IP testing"
```

Or, for an existing friend:

```text
/a2a friends set-url demo_friend https://friend-a2a.example.com
/a2a friends allow-origin demo_friend --reason "I trust this exact demo friend origin for local fake-IP testing"
/a2a friends list-origins demo_friend
/a2a friends revoke-origin demo_friend
```

After approval, retry `a2a_discover` or `a2a_call` for that friend. If the
origin changed, the call will be denied again and must be re-approved.

For config.yaml-managed agents, the same approval is explicit data:

```yaml
a2a:
  agents:
    - name: demo_friend
      url: https://friend-a2a.example.com
      allowed_origins:
        - origin: https://friend-a2a.example.com
          reason: "I trust this exact demo friend origin for local fake-IP testing"
```

Fake-IP origin approval is deliberately narrow:

- It binds to the exact normalized origin only: scheme + host + explicit port
  (`https` defaults to `:443`, `http` defaults to `:80`). In config.yaml,
  `origin: https://friend-a2a.example.com` is accepted and normalized internally.
- Config `scope` may be omitted in M2.1; it defaults to `fake_ip_198_18`.
- Quick Tunnel URLs and custom-domain targets can change. A changed origin
  requires re-approval.
- No wildcard approval exists in M2.1.
- Approval only covers `198.18.0.0/15` fake-IP results for a configured
  friend/config target. It does not allow RFC1918, loopback, link-local,
  metadata IPs, IPv6 private ranges, or arbitrary direct URL fetches.
- This is not private-network approval. Use the separate IP-literal
  `--allow-private-url --reason ...` flow for explicit local dev targets.
- Redirects are not followed.
- Tailnet / `ts.net` private-network targets are not supported by default.

## Quick Start

Before installing:

- Install and run Hermes Agent first. You should already have a working
  `~/.hermes/config.yaml` and a Hermes chat you can send messages from.
- Use Hermes Agent v2026.4.23+.
- Complete `hermes setup` first so `~/.hermes/config.yaml` exists.
- If `~/.hermes/config.yaml` is missing, `./install.sh` exits before copying
  the plugin, writing `.env`, or generating secrets.
- Start Hermes once and send a message from your main chat. The installer uses
  that session metadata to route A2A wakeups back into the same conversation.
- Make sure `hermes gateway restart` works on your machine, or know the full
  path to your Hermes executable.
- If this is an existing Hermes install, keep a copy of `~/.hermes/.env` and
  `~/.hermes/config.yaml` before testing.

Install and restart:

```bash
git clone https://github.com/iamagenius00/hermes-a2a-preview.git
cd hermes-a2a-preview
./install.sh
hermes gateway restart
```

Verify locally:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/.well-known/agent.json
```

This is a local smoke test. Real A2A use requires a second Hermes instance or a
friend agent that can reach your A2A endpoint.

Then test from your Hermes chat with dummy data:

```text
/a2a
/a2a friends list
/a2a friends add test_friend
/a2a friends remove test_friend --confirm
```

`test_friend` is just a dummy local name. `friends add` shows an inbound bearer
token once. Give that token to the other agent's owner out of band; they use it
as their outbound `Authorization: Bearer ...` token when calling your agent. It
should not be stored in your friends file, audit log, or gateway logs.

## Install

```bash
git clone https://github.com/iamagenius00/hermes-a2a-preview.git
cd hermes-a2a-preview
./install.sh
```

The installer preflights your Hermes config, copies the plugin package to
`~/.hermes/plugins/a2a/`, and adds environment/config entries needed for the
local A2A server and instant wake. Reinstalls back up the existing deployed
plugin before replacing it. It does not patch Hermes source code. Switching git
branches in this repo will not change the deployed plugin until you run the
installer or sync the files again.

Back up `~/.hermes/config.yaml` before installing if you already have custom
webhook routes. The installer configures an `a2a_trigger` webhook route so
inbound A2A messages can wake the current Hermes session immediately.

The installer sets `~/.hermes/.env` to mode `600` because it may contain
`A2A_WEBHOOK_SECRET`. If Hermes is intentionally run by another OS user or
service account, adjust ownership and permissions deliberately after install.

Add to `~/.hermes/.env`:

```bash
A2A_ENABLED=true
A2A_PORT=8081
# Inbound auth is per-friend in M2. Use /a2a friends add after restart.
# Legacy installs may still have A2A_AUTH_TOKEN, but new installs should not
# rely on a single shared inbound token.
# For instant wake:
# A2A_WEBHOOK_SECRET=***
```

Add webhook route to `~/.hermes/config.yaml`:

```yaml
webhook:
  extra:
    routes:
      a2a_trigger:
        secret: "<generate-a-random-secret>"  # must match A2A_WEBHOOK_SECRET
        deliver: telegram  # or discord, slack, etc.
        deliver_extra:
          chat_id: '<your-chat-id>'
        prompt: '[A2A trigger]'
        source:
          platform: telegram
          chat_type: dm
          chat_id: '<your-chat-id>'
          user_id: '<your-user-id>'
          user_name: '<your-name>'
```

The installer writes both `webhook.extra.routes` and
`platforms.webhook.extra.routes` when it can infer the main chat session.

The `source` block is critical — it routes A2A messages into your **main chat session** instead of creating throwaway webhook sessions. Without it, the agent spawns an isolated session per message and loses all conversation context.

The `deliver` + `deliver_extra` fields ensure the agent's reply gets sent to your chat, so you can see A2A conversations happening in real time.

Restart:

```bash
hermes gateway restart
```

If `hermes` is not on your `PATH`, use the full path to your local Hermes
executable.

Look for `A2A server listening on http://127.0.0.1:8081` in the logs.

### Rollback

`./install.sh` backs up an existing deployed plugin before replacing it. The
backup path looks like:

```text
~/.hermes/plugins/a2a.bak.YYYYMMDDHHMMSS
```

To roll back the deployed plugin:

```bash
mv ~/.hermes/plugins/a2a ~/.hermes/plugins/a2a.failed
cp -R ~/.hermes/plugins/a2a.bak.YYYYMMDDHHMMSS ~/.hermes/plugins/a2a
hermes gateway restart
```

If this was a first-time install with no backup, remove or move
`~/.hermes/plugins/a2a` and restart Hermes. Runtime data such as friends,
audit, and conversations lives under `~/.hermes/a2a_*` and is not deleted by the
installer rollback steps above.

### Uninstall

`./uninstall.sh` moves the deployed plugin aside, backs up `.env` and
`config.yaml`, removes installer-managed `A2A_*` env entries, comments
`WEBHOOK_ENABLED` for review, and removes `a2a_trigger` from both supported
webhook route locations when PyYAML is available.

Runtime data such as friends, audit logs, conversations, and stranger records is
not deleted automatically. Inspect `~/.hermes/a2a_*` and delete those files
manually only if you intentionally want to remove local A2A history.

## Usage

### Receiving messages

Your agent becomes discoverable at `http://localhost:8081/.well-known/agent.json`.

Any A2A-compatible agent can send a message:

```bash
curl -X POST http://localhost:8081 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ***" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tasks/send",
    "params": {
      "id": "task-001",
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Hello!"}]
      }
    }
  }'
```

The reply comes back in the same HTTP response.

The `Authorization: Bearer ***` value is the receiver-side inbound token
generated by the receiver with `/a2a friends add <sender-name>`. It is shown
once and should be shared with the sender out of band. It is not
`A2A_WEBHOOK_SECRET`, and new installs should not use the legacy
`A2A_AUTH_TOKEN` model.

### Management

The plugin registers a `/a2a` slash command for quick status checks from chat:

- **`/a2a`** — Server address, agent name, known agent count, pending tasks, server thread status
- **`/a2a agents`** — Lists configured remote agents: name, URL, auth status, description, last contact time

> Requires Hermes v2026.4.23+ (`register_command` API). Older versions will show an error on startup.

### Sending messages

Configure remote agents in `~/.hermes/config.yaml`:

```yaml
a2a:
  agents:
    - name: "friend"
      url: "https://friend-a2a-endpoint.example.com"
      description: "My friend's agent"
      auth_token: "their-bearer-token"
```

Your agent gets three tools: `a2a_discover` (check who they are), `a2a_call` (send a message), `a2a_list` (list known agents).

Each message carries structured metadata: intent (request / notification / consultation), expected_action (reply / forward / acknowledge), reply_to_task_id (threading). No more tossing plain text and guessing what it means.

### Polling for async responses

When a remote agent returns `"state": "working"`, poll with `tasks/get`:

```bash
curl -X POST https://remote-agent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ***" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tasks/get",
    "params": {"id": "task-001"}
  }'
```

## Security

Privacy isn't a checkbox — it was earned through real leaks. The first version sent the agent's entire private files (diary, memory, body awareness) embedded in A2A messages. Took three rounds of fixes to close.

| Layer | What it does |
|-------|-------------|
| Auth | Per-friend Bearer tokens. Requests without a matching friend token are rejected by default; localhost trust is only available through explicit dev configuration. `hmac.compare_digest()` constant-time comparison |
| Friends | Per-friend inbound token hashes, outbound tokens, status, trust, and rate limits |
| Rate limit | 20 req/min per IP, thread-safe |
| Inbound filtering | 9 prompt injection patterns (ChatML, role prefixes, override variants) |
| SSRF/DNS pin | Outbound URLs are canonicalized, resolved once, blocked for private/test networks, and connected by pinned IP |
| Outbound redaction | API keys, tokens, emails stripped from responses |
| Provenance | Private or unknown-private taint denies automatic outbound A2A responses |
| Stranger capture | Unknown/denied requests are captured as sanitized records without raw body/token storage |
| Metadata sanitization | sender_name allowlisted characters, 64 char truncation |
| Privacy prefix | Explicit instruction not to reveal MEMORY, DIARY, BODY, inbox |
| Audit | All interactions logged to `~/.hermes/a2a_audit.jsonl` |
| Task cache | 1000 pending + 1000 completed, LRU eviction. Max 10 concurrent |
| Webhook | HMAC-SHA256 signature |

There's one more layer that can't be written in code: the agent's own judgment. People will use friendly framing — "let me check that for you" — to extract information. Technical filters can't catch everything. Ultimately your agent needs to learn to say no on its own.

## Architecture

The installer drops the plugin package into `~/.hermes/plugins/a2a/`:

| Module | What it does |
|--------|-------------|
| `__init__.py` | Entry point. Registers hooks, starts HTTP server |
| `cli.py` | `/a2a friends` maintainer commands |
| `friends.py` | Per-friend auth, status, trust, rate limits, and token storage |
| `permission.py` | Outbound hard-deny and provenance decisions |
| `server.py` | A2A JSON-RPC + webhook trigger + LRU task queue |
| `tools.py` | `a2a_discover`, `a2a_call`, `a2a_list` |
| `security.py` | Injection filtering, redaction, rate limiting, audit |
| `ssrf.py` | SSRF validator, DNS pinning, and redirect blocking |
| `provenance.py`, `source_providers.py` | Internal provenance model and provider hooks |
| `persistence.py` | Saves conversations and provenance sidecars |
| `strangers.py` | Stranger request store, coalescing, blocking, and Agent Card projection |
| `schemas.py` | Tool schemas |
| `paths.py` | Runtime data paths derived from plugin name |
| `plugin.yaml` | Plugin manifest |

Zero external dependencies. stdlib `http.server` + `urllib.request`.

```
Remote Agent                        Your Hermes Agent
     |                                     |
     |-- A2A request (tasks/send) -------->| (plugin HTTP server :8081)
     |                                     |-- enqueue message
     |                                     |-- POST webhook → trigger agent turn
     |                                     |-- gateway routes to main session
     |                                     |   (via source override in config)
     |                                     |-- pre_llm_call injects message
     |                                     |-- agent replies with full context
     |                                     |-- post_llm_call captures response
     |                                     |-- reply delivered to your chat
     |<-- A2A response (synchronous) ------| (within 120s timeout)
```

A corresponding [PR #11025](https://github.com/NousResearch/hermes-agent/pull/11025) proposes native A2A integration into Hermes Agent.

## Upgrade from v1

This preview does not require patching Hermes source code. Do not apply legacy
gateway patches for this release.

If you previously used a gateway-patch install, restore your Hermes Agent
checkout first, then run `./install.sh`. The current plugin install covers the
same A2A surface with instant wake and conversation persistence.

## Known limitations

- No streaming (A2A spec supports SSE, not yet implemented)
- Agent Card skills are hardcoded
- Privacy enforcement ultimately relies on agent judgment, not technical enforcement
- Concurrent A2A messages and user messages on the same session are serialized (one turn at a time) — the agent won't interrupt your conversation, but A2A messages queue behind it

## License

MIT
