"""A2A outbound permission policy — Issue 7a baseline hard-deny.

This module decides whether an outbound message can be auto-sent. It does
NOT implement the approval queue (Issue 10). 7b provenance is additive on top
of the 7a baseline:

1. **Friend status / trust gating**

   - Pending, paused, blocked, expired, removed friends → deny
   - New friend (trust_level='new') → deny in v1
     (Issue 10 will route these to the approval queue instead)
   - Trusted / normal friends → allow ordinary text auto
   - Stranger / unconfigured target → deny

2. **Baseline secret patterns**

   Best-effort regex match for the most obvious leaks:

   - OpenAI keys (`sk-...`)
   - GitHub tokens (`ghp_...`, `github_pat_...`)
   - AWS access key IDs (`AKIA...`) and common AWS secret-access-key shape
   - Slack tokens (`xoxb-...`, `xoxp-...`, `xoxa-...`)
   - PEM private key blocks
   - Generic `api_key=`, `token=`, `password=`, `secret=`, `credential=`
     forms

   Hits are hard-denied (the message is rejected; nothing leaves). This is
   not a complete secret detector — it's the first net.

3. **Private context markers**

   Scoped detection — we do NOT deny merely because the user typed the
   word "MEMORY" in ordinary prose. We deny when the message appears to
   include private-file content:

   - Literal home-directory paths to private files
     (`~/.hermes/MEMORY.md`, `~/.hermes/DIARY.md`, `~/.hermes/SOUL.md`,
     `~/.hermes/BODY.md`, `~/.hermes/.env`)
   - Section markers that the agent sometimes inserts when reading those
     files (`[MEMORY]`, `[DIARY]`, `[SOUL]`, `[BODY]`,
     `--- BEGIN MEMORY ---`)

4. **Hop-count loop limit**

   If the outbound is a reply to an inbound A2A task and the inbound's
   hop_count exceeds ``HOP_LIMIT`` (default 8), deny. This prevents two
   trusted agents from auto-replying to each other forever and burning
   tokens.

5. **Feature flag**

   ``A2A_HARDDENY_DISABLE=true`` disables all hard-deny checks.
   Emergency rollback only — leaves the friend-status / hop-count gates
   active. Logs a warning so abuse is visible in audit.

Forwarding raw inbound A2A content and private-tainted responses are denied
when internal provenance shows private/unknown-private taint or replay of
untrusted inbound A2A text.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import provenance as provenance_model

logger = logging.getLogger(__name__)


HOP_LIMIT = 8


# ── pattern sets (compiled lazily on first call) ────────────────────────


_SECRET_PATTERNS = [
    # OpenAI / Anthropic / generic sk-<base64>
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    # GitHub classic + fine-grained
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    # AWS access key id
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # AWS secret access key (40 chars base64) — only when keyed
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{30,}"),
    # Slack
    re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}"),
    # Google API key (AIza prefix)
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}"),
    # PEM private key block (multi-line OK; we look for BEGIN line)
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # Generic key=value forms — tightened to require non-trivial value
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|credential)\s*[:=]\s*[\"']?[^\s\"',]{8,}"),
]


# Private context markers. These are SCOPED — no match on the bare words.
_PRIVATE_PATH_PATTERNS = [
    re.compile(r"~?/\.hermes/MEMORY\.md\b"),
    re.compile(r"~?/\.hermes/DIARY\.md\b"),
    re.compile(r"~?/\.hermes/SOUL\.md\b"),
    re.compile(r"~?/\.hermes/BODY\.md\b"),
    re.compile(r"~?/\.hermes/\.env\b"),
    # Plugin-installed memory file under .claude/projects
    re.compile(r"/\.claude/projects/[^/\s]+/memory/"),
]

_PRIVATE_MARKER_PATTERNS = [
    re.compile(r"-{3,}\s*BEGIN\s+(?:MEMORY|DIARY|SOUL|BODY)\s*-{3,}", re.IGNORECASE),
    re.compile(r"\[(?:MEMORY|DIARY|SOUL|BODY)\]\s*$", re.MULTILINE),
    re.compile(r"^\s*##\s+(?:MEMORY|DIARY|SOUL|BODY)\s*$", re.MULTILINE),
]


# ── result type ────────────────────────────────────────────────────────


@dataclass
class Decision:
    allow: bool
    reason: str
    detail: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allowed(cls, *, provenance: dict[str, Any] | None = None) -> "Decision":
        return cls(allow=True, reason="ok", provenance=provenance or {})

    @classmethod
    def denied(cls, reason: str, detail: str = "", *, provenance: dict[str, Any] | None = None) -> "Decision":
        return cls(allow=False, reason=reason, detail=detail, provenance=provenance or {})


# ── friend / status gate ───────────────────────────────────────────────


def _check_friend_policy(friend: Optional[dict]) -> Optional[Decision]:
    """Return a deny Decision if the friend is not eligible for outbound.

    Returns ``None`` if the friend status / trust passes the gate (caller
    should continue to content checks). Returns a ``Decision`` (with
    ``allow=False``) if the friend is rejected up-front.
    """
    if friend is None:
        return Decision.denied(
            reason="friend_unconfigured",
            detail="Target is not a configured friend; outbound to strangers is denied.",
        )

    status = friend.get("status", "")
    if status in {"paused", "blocked", "expired", "removed"}:
        return Decision.denied(
            reason=f"friend_{status}",
            detail=f"Friend status is {status!r}; outbound disabled.",
        )

    # Pending: friend hasn't proven they hold the inbound token yet
    if status == "pending":
        return Decision.denied(
            reason="friend_pending",
            detail="Friend has not completed first inbound contact; cannot send to a pending friend.",
        )

    trust = friend.get("trust_level", "")
    if trust == "new":
        return Decision.denied(
            reason="new_friend",
            detail="New friends cannot receive outbound auto in v1. After Issue 10, this will route to the approval queue.",
        )

    # trusted / normal: status==active is the expected case; let it pass.
    if status not in {"active", ""}:
        # any unrecognised non-listed status — be safe, deny
        return Decision.denied(
            reason=f"friend_status_unknown:{status}",
            detail=f"Friend status {status!r} is not recognised by 7a policy.",
        )

    return None


# ── content gate ───────────────────────────────────────────────────────


def _scan_secret_patterns(message: str) -> Optional[str]:
    """Return the name of the first hit pattern, or None."""
    for pattern in _SECRET_PATTERNS:
        m = pattern.search(message)
        if m:
            return f"secret_pattern:{m.group(0)[:12]}…"
    return None


def _scan_private_context(message: str) -> Optional[str]:
    """Return the name of the first hit pattern, or None.

    Looks for explicit private-file paths and section markers — does NOT
    match bare words like 'memory' or 'diary'.
    """
    for pattern in _PRIVATE_PATH_PATTERNS:
        m = pattern.search(message)
        if m:
            return f"private_path:{m.group(0)}"
    for pattern in _PRIVATE_MARKER_PATTERNS:
        m = pattern.search(message)
        if m:
            return f"private_marker:{m.group(0).strip()[:30]}"
    return None


def _env_true(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}


def _env_false(name: str) -> bool:
    return os.getenv(name, "").lower() in {"0", "false", "no"}


# ── hop-count gate ─────────────────────────────────────────────────────


def _outbound_hop_count(reply_to_task_id: str, lookup_inbound_hop) -> int:
    """Compute hop_count for an outbound message.

    If this outbound is a reply to an inbound task (``reply_to_task_id``
    set), look up that inbound's hop_count via ``lookup_inbound_hop`` and
    increment by 1. Otherwise hop_count starts at 0 (this is a fresh
    outbound chain initiated by the user).

    ``lookup_inbound_hop`` is a callable ``(task_id) -> int | None``; pass
    ``None`` for the lookup (treated as 0) when the caller cannot resolve.
    """
    if not reply_to_task_id:
        return 0
    if lookup_inbound_hop is None:
        return 0
    inbound = lookup_inbound_hop(reply_to_task_id)
    if inbound is None:
        return 0
    return int(inbound) + 1


def _recorded_provenance(
    provenance: Any = None,
    *,
    reply_to_task_id: str = "",
    lookup_provenance=None,
) -> provenance_model.Provenance:
    """Normalize provenance for audit/recording without enforcing it yet."""
    items: list[provenance_model.Provenance] = []
    if provenance is not None:
        items.append(provenance_model.normalize_provenance(provenance))

    if reply_to_task_id and lookup_provenance is not None:
        try:
            items.append(
                provenance_model.normalize_provenance(
                    lookup_provenance(reply_to_task_id),
                    required=True,
                )
            )
        except Exception:
            items.append(provenance_model.Provenance.unknown(evidence=("provenance_lookup_failed",)))

    if not items:
        return provenance_model.Provenance.public_only()
    return provenance_model.merge_provenance(*items)


def _normalized_text(text: str) -> str:
    return " ".join(str(text).lower().split())


def _word_ngrams(text: str, size: int = 5) -> set[tuple[str, ...]]:
    words = re.findall(r"\b\w+\b", _normalized_text(text))
    if len(words) < size:
        return set()
    return {tuple(words[i:i + size]) for i in range(len(words) - size + 1)}


def _quoted_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    in_code = False
    code_lines: list[str] = []
    for raw_line in str(text).splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                blocks.append("\n".join(code_lines))
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.lstrip().startswith(">"):
            current.append(line.lstrip()[1:].strip())
            continue
        if current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    if code_lines:
        blocks.append("\n".join(code_lines))
    return blocks


def _large_quote_replay(message: str, source: str) -> bool:
    source_norm = _normalized_text(source)
    source_lines = [_normalized_text(line) for line in str(source).splitlines() if _normalized_text(line)]
    for block in _quoted_blocks(message):
        block_norm = _normalized_text(block)
        if len(block_norm) >= 200 and block_norm in source_norm:
            return True
        for index in range(0, max(0, len(source_lines) - 2)):
            if all(source_lines[index + offset] and source_lines[index + offset] in block_norm for offset in range(3)):
                return True
    return False


def _a2a_replay_hit(message: str, replay_texts: tuple[str, ...] = ()) -> bool:
    message_norm = _normalized_text(message)
    if not message_norm:
        return False
    message_grams = _word_ngrams(message_norm)
    for source in replay_texts:
        source_norm = _normalized_text(source)
        if not source_norm:
            continue
        if message_norm == source_norm:
            return True
        if _large_quote_replay(message, source):
            return True
        if len(message_grams) >= 30:
            source_grams = _word_ngrams(source_norm)
            if source_grams:
                overlap = len(message_grams & source_grams) / len(message_grams)
                if overlap >= 0.60:
                    return True
    return False


# ── public API ─────────────────────────────────────────────────────────


def evaluate_outbound(
    message: str,
    friend: Optional[dict],
    *,
    reply_to_task_id: str = "",
    lookup_inbound_hop=None,
    provenance: Any = None,
    lookup_provenance=None,
    replay_texts: tuple[str, ...] = (),
) -> tuple[Decision, int]:
    """Evaluate whether an outbound A2A message may be auto-sent.

    Returns ``(decision, hop_count_to_attach)``. The caller should:

    - if ``decision.allow``: proceed, attach ``hop_count_to_attach`` to the
      outbound metadata.
    - else: do not send. Audit the deny with ``decision.reason`` and the
      friendly ``decision.detail``.

    Order of checks:

    1. friend status / trust (cheap, fast-rejects most dev mistakes)
    2. content scan: secret patterns
    3. content scan: private context markers
    4. provenance: private/unknown/untrusted replay
    5. hop-count loop limit

    Feature flag ``A2A_HARDDENY_DISABLE=true`` short-circuits the content
    scans (#2, #3) but leaves friend gating and hop-count gating active.
    ``A2A_PROVENANCE_ENFORCE=false`` skips provenance denies only.
    """
    recorded_provenance = _recorded_provenance(
        provenance,
        reply_to_task_id=reply_to_task_id,
        lookup_provenance=lookup_provenance,
    )
    provenance_audit = recorded_provenance.to_audit_projection()

    decision_friend = _check_friend_policy(friend)
    if decision_friend is not None:
        decision_friend.provenance = provenance_audit
        return decision_friend, 0

    harddeny_disabled = _env_true("A2A_HARDDENY_DISABLE")
    if harddeny_disabled:
        logger.warning(
            "[A2A] A2A_HARDDENY_DISABLE=true — content scans skipped. Outbound "
            "is gated only by friend status and hop-count. Re-enable hard-deny "
            "by unsetting the env var."
        )
    else:
        secret_hit = _scan_secret_patterns(message)
        if secret_hit:
            return Decision.denied(
                reason="secret_pattern",
                detail=(
                    "Message appears to contain a secret. This category cannot "
                    "be approved through A2A. To deliberately share, use a "
                    "channel outside A2A. " + secret_hit
                ),
                provenance=provenance_audit,
            ), 0

        private_hit = _scan_private_context(message)
        if private_hit:
            return Decision.denied(
                reason="private_context",
                detail=(
                    "Message appears to include private memory or local context. "
                    "Refusing to forward. " + private_hit
                ),
                provenance=provenance_audit,
            ), 0

    provenance_enforce = not _env_false("A2A_PROVENANCE_ENFORCE")
    if not provenance_enforce:
        logger.warning("[A2A] A2A_PROVENANCE_ENFORCE=false — provenance denies skipped")
    elif recorded_provenance.unknown_private:
        return Decision.denied(
            reason="unknown_private_provenance",
            detail="Message provenance is missing or invalid for an A2A response path; refusing automatic send.",
            provenance=provenance_audit,
        ), 0
    elif recorded_provenance.private:
        return Decision.denied(
            reason="private_provenance",
            detail="Message includes private-source provenance; refusing automatic A2A send.",
            provenance=provenance_audit,
        ), 0
    elif recorded_provenance.untrusted:
        if not replay_texts:
            return Decision.denied(
                reason="a2a_replay_basis_missing",
                detail="Untrusted inbound A2A provenance has no replay basis; refusing automatic forward.",
                provenance=provenance_audit,
            ), 0
        if _a2a_replay_hit(message, tuple(replay_texts or ())):
            return Decision.denied(
                reason="a2a_replay",
                detail="Message appears to replay untrusted inbound A2A content; refusing automatic forward.",
                provenance=provenance_audit,
            ), 0

    hop = _outbound_hop_count(reply_to_task_id, lookup_inbound_hop)
    if hop > HOP_LIMIT:
        return Decision.denied(
            reason="hop_limit",
            detail=(
                f"Conversation loop limit reached (hop_count={hop} > {HOP_LIMIT}). "
                "Auto-replies paused for this thread."
            ),
            provenance=provenance_audit,
        ), hop

    return Decision.allowed(provenance=provenance_audit), hop
