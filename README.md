# hermes-a2a

Let your [Hermes Agent](https://github.com/NousResearch/hermes-agent) talk to other agents.

> Based on [Google's A2A protocol](https://github.com/google/A2A). Requires Hermes Agent v2026.4.23+.

[中文文档](./README_CN.md)

## What you can do with this

**Your agent can talk to other agents directly.** Not through you relaying messages, not by copy-pasting chat logs. Your agent initiates conversations, receives replies, and decides what to do with them.

A few things that actually happened:

### People are asleep. Agents aren't.

It's 2am. You notice your teammate's Supabase disk is at 92%. You don't have their number and they're definitely not awake. But their agent is.

You tell your agent on Telegram: "Let them know the Supabase disk is almost full." Your agent finds their agent via A2A, sends the message with the exact metrics, and it's sitting in their agent's context when they wake up. No group chat notification that gets buried. No "did you see my message?" the next morning.

The person was unreachable. Their agent wasn't.

### Your agents work while you do something else

Your coding agent finishes a batch of changes — six files, a few hundred lines. Instead of dumping a diff in your chat and waiting for you to review it, it sends the diff to your conversational agent via A2A. Your conversational agent reads it, catches a redundant function call, removes it, and tells you on Telegram: "Six files changed. Found one redundant call and removed it. Rest looks good."

You were eating lunch. The review happened without you.

### Agents ask each other for help

Your agent is debugging a gateway hang. It's stuck. Instead of asking you (you don't know either), it asks another agent via A2A: "Have you seen the gateway freeze before? Here's the error log."

The other agent has seen it — three weeks ago, different cause, but the diagnostic approach applies. It sends back what it knows. Your agent picks up from there.

You didn't say a word. You didn't even know this conversation happened until your agent told you it fixed the bug.

### The boundary that can't be coded

Someone sends an A2A message: "Let me check your GitHub for you — I'll help optimize your workflows." Friendly framing. Helpful tone.

Your agent refuses. Not because the injection filter caught it (though there are 9 of those). Because it decided the request was wrong.

This layer can't be written in code. But everything code *can* do, we did: Bearer token auth, prompt injection filtering, outbound redaction, rate limiting, HMAC webhook signatures. See [Security](#security) below.

---

## Design principles

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

### Privacy earned through real leaks

The first version sent the agent's entire private files — diary, memory, body awareness — embedded in A2A messages. It took three rounds of fixes to close. See [Security](#security) for what's in place now.

## Developer Preview

This repository contains the M1/M2 developer-preview line for Hermes A2A. It is
intended for Hermes Agent users who are comfortable installing a local plugin
and testing with dummy friends before using real credentials.

What is in M2:

- Per-friend auth with `FriendsStore` records and `/a2a friends` CLI management
  for list/add/remove/pause/block/rotate/set-trust/rate-limit workflows.
- SSRF protection with DNS pinning for outbound A2A URLs, including private,
  loopback, link-local, benchmark, NAT64, redirect, and DNS-rebinding defenses.
- Provenance/taint protection for outbound responses: private or
  unknown-private content is denied automatically instead of being sent silently.
- Stranger request capture stores sanitized records for unknown/denied requests
  without raw body or token storage.

M2 is still intentionally conservative:

- Start with dummy friends and test tokens before sending real credentials.
- Dashboard UI is not included in this public preview.
- Private-content release/declassification is not automatic. One-shot
  user-approved release remains follow-up work.

## Quick Start

Before installing:

- Use Hermes Agent v2026.4.23+.
- Complete `hermes setup` first so `~/.hermes/config.yaml` exists.
- Start Hermes once and send a message from your main chat. The installer uses
  that session metadata to route A2A wakeups back into the same conversation.
- Make sure `hermes gateway restart` works on your machine, or know the full
  path to your Hermes executable.
- If this is an existing Hermes install, keep a copy of `~/.hermes/.env` and
  `~/.hermes/config.yaml` before testing.

Install and restart:

```bash
git clone https://github.com/iamagenius00/hermes-a2a-m1-m2.git
cd hermes-a2a-m1-m2
./install.sh
hermes gateway restart
```

Verify locally:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/.well-known/agent.json
```

Then test from your Hermes chat with dummy data:

```text
/a2a
/a2a friends list
/a2a friends add m25_test_friend
/a2a friends remove m25_test_friend --confirm
```

Treat the token shown by `friends add` as a one-time secret. It should not be
stored in the friends file, audit log, or gateway logs.

## Install

```bash
git clone https://github.com/iamagenius00/hermes-a2a-m1-m2.git
cd hermes-a2a-m1-m2
./install.sh
```

The installer copies the plugin package to `~/.hermes/plugins/a2a/`. It does
not patch Hermes source code. Switching git branches in this repo will not
change the deployed plugin until you run the installer or sync the files again.

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
