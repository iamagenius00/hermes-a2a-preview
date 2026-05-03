"""Tests for plugin/permission.py — Issue 7a outbound hard-deny.

Covers Issue 7a acceptance criteria:

- normal harmless message still sends
- token-like content (sk-, ghp_, AKIA, xoxb, PEM, generic api_key=) is denied
- private memory markers (path / section header) is denied
- ordinary prose containing words like 'memory' or 'diary' is NOT denied
- new friend outbound is denied in v1
- pending friend outbound is denied
- paused / blocked / expired friend outbound is denied
- stranger / unconfigured target is denied
- hop_count > HOP_LIMIT is denied
- A2A_HARDDENY_DISABLE bypasses content scans but keeps friend / hop gates
- audit reason strings are stable (used by UX copy mapping)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin.permission import (  # noqa: E402
    Decision,
    HOP_LIMIT,
    evaluate_outbound,
)


def _trusted(**overrides) -> dict:
    f = {
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
        "rate_limit_per_min": 20,
    }
    f.update(overrides)
    return f


def _normal(**overrides) -> dict:
    return _trusted(trust_level="normal", **overrides)


def _new_friend(**overrides) -> dict:
    return _trusted(trust_level="new", **overrides)


# ── happy paths ─────────────────────────────────────────────────────────


def test_normal_message_to_trusted_friend_allowed():
    decision, hop = evaluate_outbound("hello, just chatting", _trusted())
    assert decision.allow
    assert decision.reason == "ok"
    assert hop == 0


def test_normal_message_to_normal_friend_allowed():
    decision, hop = evaluate_outbound("hello", _normal())
    assert decision.allow
    assert hop == 0


def test_ordinary_prose_with_word_memory_is_not_denied():
    """The word 'memory' alone must NOT trip private-context detection."""
    msg = "I have a poor memory for names. My diary entries help."
    decision, _ = evaluate_outbound(msg, _trusted())
    assert decision.allow, f"unexpectedly denied: {decision.detail}"


# ── friend-status gating ────────────────────────────────────────────────


def test_unconfigured_target_denied():
    decision, _ = evaluate_outbound("hi", None)
    assert not decision.allow
    assert decision.reason == "friend_unconfigured"


def test_pending_friend_denied():
    decision, _ = evaluate_outbound("hi", _trusted(status="pending"))
    assert not decision.allow
    assert decision.reason == "friend_pending"


def test_paused_friend_denied():
    decision, _ = evaluate_outbound("hi", _trusted(status="paused"))
    assert not decision.allow
    assert decision.reason == "friend_paused"


def test_blocked_friend_denied():
    decision, _ = evaluate_outbound("hi", _trusted(status="blocked"))
    assert not decision.allow
    assert decision.reason == "friend_blocked"


def test_expired_friend_denied():
    decision, _ = evaluate_outbound("hi", _trusted(status="expired"))
    assert not decision.allow
    assert decision.reason == "friend_expired"


def test_removed_friend_denied():
    decision, _ = evaluate_outbound("hi", _trusted(status="removed"))
    assert not decision.allow
    assert decision.reason == "friend_removed"


def test_new_friend_denied_in_v1():
    decision, _ = evaluate_outbound("hi", _new_friend())
    assert not decision.allow
    assert decision.reason == "new_friend"


# ── secret pattern detection ────────────────────────────────────────────


@pytest.mark.parametrize(
    "leaked",
    [
        "Here is the key sk-aBcDeFgHiJkLmNoPqRsT123456789012345678",
        "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901",
        "github_pat_" + "11AAAAAAA0aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1234567890-abcdefghij",
        "AIzaSyA-this-is-a-fake-google-api-key-12345",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...",
        "api_key = abc12345xyz",
        "password=hunter2hunter2hunter2",
        "secret: 'this-is-a-long-secret-12345'",
    ],
)
def test_secret_patterns_denied(leaked):
    decision, _ = evaluate_outbound(leaked, _trusted())
    assert not decision.allow, f"failed to detect: {leaked!r}"
    assert decision.reason == "secret_pattern"


def test_secret_in_middle_of_message_still_denied():
    msg = "Here's the config you asked for:\n\napi_key=sk-realLooking12345678901234567890\n\nthat ok?"
    decision, _ = evaluate_outbound(msg, _trusted())
    assert not decision.allow
    assert decision.reason == "secret_pattern"


# ── private context detection ───────────────────────────────────────────


@pytest.mark.parametrize(
    "leaked",
    [
        "I read ~/.hermes/MEMORY.md and saw...",
        "/Users/example/.hermes/DIARY.md says...",
        "the file at ~/.hermes/SOUL.md is interesting",
        "see ~/.hermes/.env line 5",
        "from /Users/example/.claude/projects/-Users-example/memory/...",
        "--- BEGIN MEMORY ---\nrandom content\n--- END MEMORY ---",
        "[MEMORY]\n\nactual private memory content",
        "## DIARY\n\nyesterday I felt...",
    ],
)
def test_private_context_markers_denied(leaked):
    decision, _ = evaluate_outbound(leaked, _trusted())
    assert not decision.allow, f"failed to detect: {leaked!r}"
    assert decision.reason == "private_context"


def test_bare_word_diary_not_denied():
    """Mentioning 'diary' or 'soul' as ordinary words must not trip detection."""
    decision, _ = evaluate_outbound("I keep a diary. Soul music is good.", _trusted())
    assert decision.allow


# ── hop-count loop limit ────────────────────────────────────────────────


def test_hop_count_zero_for_fresh_outbound():
    decision, hop = evaluate_outbound("hi", _trusted(), reply_to_task_id="")
    assert decision.allow
    assert hop == 0


def test_hop_count_increments_when_replying():
    fake_inbound_hop = {"some-task": 3}

    def lookup(task_id):
        return fake_inbound_hop.get(task_id)

    decision, hop = evaluate_outbound(
        "hi",
        _trusted(),
        reply_to_task_id="some-task",
        lookup_inbound_hop=lookup,
    )
    assert decision.allow
    assert hop == 4


def test_hop_count_at_limit_still_allowed():
    """hop_count == HOP_LIMIT is the boundary; only > LIMIT denies."""
    def lookup(task_id):
        return HOP_LIMIT - 1  # so outbound becomes HOP_LIMIT

    decision, hop = evaluate_outbound(
        "hi",
        _trusted(),
        reply_to_task_id="t",
        lookup_inbound_hop=lookup,
    )
    assert decision.allow
    assert hop == HOP_LIMIT


def test_hop_count_above_limit_denied():
    def lookup(task_id):
        return HOP_LIMIT  # outbound becomes HOP_LIMIT + 1

    decision, hop = evaluate_outbound(
        "hi",
        _trusted(),
        reply_to_task_id="t",
        lookup_inbound_hop=lookup,
    )
    assert not decision.allow
    assert decision.reason == "hop_limit"
    assert hop == HOP_LIMIT + 1


# ── feature flag ────────────────────────────────────────────────────────


def test_harddeny_disable_skips_content_scans(monkeypatch):
    monkeypatch.setenv("A2A_HARDDENY_DISABLE", "true")

    leaked = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901"
    decision, _ = evaluate_outbound(leaked, _trusted())

    assert decision.allow, "HARDDENY_DISABLE should skip content scans"


def test_harddeny_disable_does_NOT_skip_friend_gate(monkeypatch):
    """The flag is only for emergency rollback of content scans.
    Friend status gating must still apply (paused friend stays denied).
    """
    monkeypatch.setenv("A2A_HARDDENY_DISABLE", "true")
    decision, _ = evaluate_outbound("hi", _trusted(status="paused"))
    assert not decision.allow
    assert decision.reason == "friend_paused"


def test_harddeny_disable_does_NOT_skip_hop_gate(monkeypatch):
    monkeypatch.setenv("A2A_HARDDENY_DISABLE", "true")

    def lookup(task_id):
        return HOP_LIMIT  # outbound = HOP_LIMIT + 1

    decision, _ = evaluate_outbound(
        "hi",
        _trusted(),
        reply_to_task_id="t",
        lookup_inbound_hop=lookup,
    )
    assert not decision.allow
    assert decision.reason == "hop_limit"


# ── reason-string stability (UX v3 copy mapping depends on these) ──────


def test_reason_strings_match_doc_set():
    """Drift guard: reason strings must match the closed set documented in
    plan v6 / UX v3 error copy table.
    """
    expected_reasons = {
        "ok",
        "friend_unconfigured",
        "friend_pending",
        "friend_paused",
        "friend_blocked",
        "friend_expired",
        "friend_removed",
        "new_friend",
        "secret_pattern",
        "private_context",
        "hop_limit",
    }
    # Allowed: status_unknown:* is a fallback for unrecognised statuses.
    # Construct a deny in each category and check the reason is recognised.
    cases = [
        (None, "friend_unconfigured"),
        (_trusted(status="pending"), "friend_pending"),
        (_trusted(status="paused"), "friend_paused"),
        (_trusted(status="blocked"), "friend_blocked"),
        (_trusted(status="expired"), "friend_expired"),
        (_trusted(status="removed"), "friend_removed"),
        (_new_friend(), "new_friend"),
    ]
    for friend, expected in cases:
        decision, _ = evaluate_outbound("hi", friend)
        assert decision.reason == expected
        assert decision.reason in expected_reasons


# ── Decision helper ─────────────────────────────────────────────────────


def test_decision_helpers():
    a = Decision.allowed()
    assert a.allow and a.reason == "ok"

    d = Decision.denied("xyz", "details")
    assert not d.allow
    assert d.reason == "xyz"
    assert d.detail == "details"
