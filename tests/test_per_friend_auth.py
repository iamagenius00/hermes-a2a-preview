"""Tests for Issue 5 — per-friend authentication.

Covers:

- valid friend token → authenticated, friend returned
- invalid token → 401-equivalent, no friend
- paused/blocked/expired/removed friend → rejected with the right reason
- pending friend → accepted (caller transitions to active)
- no bearer + ``A2A_DEV_LOCALHOST_TRUST=true`` from localhost → synthetic friend
- no bearer + no dev trust → rejected
- per-friend rate limit cap honoured by ``RateLimiter.allow``
- ``bootstrap_legacy`` migrates ``A2A_AUTH_TOKEN`` once and is otherwise a no-op
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import server as server_module  # noqa: E402
from plugin.friends import FriendsStore  # noqa: E402
from plugin.security import RateLimiter  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────


@pytest.fixture
def isolated_friends(monkeypatch, tmp_path):
    """Replace the module-level friends singleton in server.py for the test."""
    store = FriendsStore(path=tmp_path / "friends.json")
    monkeypatch.setattr(server_module, "friends", store)
    return store


def _make_handler(headers=None, client="127.0.0.1"):
    """Construct a minimal A2ARequestHandler stand-in to exercise _check_auth."""
    headers = headers or {}
    handler = SimpleNamespace()
    handler.headers = SimpleNamespace(get=lambda key, default="": headers.get(key, default))
    handler.client_address = (client, 12345)
    handler.server = SimpleNamespace(auth_token="")
    handler._check_auth = server_module.A2ARequestHandler._check_auth.__get__(handler)
    return handler


# ── _check_auth happy paths ───────────────────────────────────────────


def test_valid_friend_token_authenticates(isolated_friends):
    _, raw = isolated_friends.add_friend("alice")
    h = _make_handler({"Authorization": f"Bearer {raw}"})

    authed, friend, reason = h._check_auth()

    assert authed is True
    assert friend["name"] == "alice"
    assert reason == "ok"


def test_pending_friend_is_accepted(isolated_friends):
    _, raw = isolated_friends.add_friend("alice")
    assert isolated_friends.get_by_name("alice")["status"] == "pending"

    h = _make_handler({"Authorization": f"Bearer {raw}"})
    authed, friend, reason = h._check_auth()

    assert authed is True
    assert reason == "ok"
    # the returned record reflects the on-disk state at auth time; the caller
    # is responsible for transitioning pending -> active via record_last_contact
    assert friend["status"] == "pending"


# ── _check_auth rejection paths ───────────────────────────────────────


def test_unknown_token_rejected(isolated_friends):
    isolated_friends.add_friend("alice")
    h = _make_handler({"Authorization": "Bearer not-a-real-token"})

    authed, friend, reason = h._check_auth()

    assert authed is False
    assert friend is None
    assert reason == "unknown_token"


def test_paused_friend_rejected(isolated_friends):
    _, raw = isolated_friends.add_friend("alice")
    isolated_friends.pause("alice")
    h = _make_handler({"Authorization": f"Bearer {raw}"})

    authed, friend, reason = h._check_auth()

    assert authed is False
    assert friend["name"] == "alice"
    assert reason == "friend_paused"


def test_blocked_friend_rejected(isolated_friends):
    _, raw = isolated_friends.add_friend("alice")
    isolated_friends.block("alice")
    h = _make_handler({"Authorization": f"Bearer {raw}"})

    authed, friend, reason = h._check_auth()

    assert authed is False
    assert reason == "friend_blocked"


def test_expired_friend_rejected(isolated_friends):
    import json

    _, raw = isolated_friends.add_friend("alice")
    # Backdate expires_at so expire_pending flips alice to expired
    path = isolated_friends.path
    data = json.loads(path.read_text(encoding="utf-8"))
    for f in data["friends"]:
        if f["name"] == "alice":
            f["expires_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(data), encoding="utf-8")
    isolated_friends.expire_pending()

    h = _make_handler({"Authorization": f"Bearer {raw}"})
    authed, friend, reason = h._check_auth()

    assert authed is False
    assert reason == "friend_expired"


# ── localhost dev trust ───────────────────────────────────────────────


def test_no_token_rejected_without_dev_trust(isolated_friends, monkeypatch):
    monkeypatch.delenv("A2A_DEV_LOCALHOST_TRUST", raising=False)
    monkeypatch.delenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", raising=False)
    h = _make_handler({})

    authed, friend, reason = h._check_auth()

    assert authed is False
    assert reason == "no_token"


def test_no_token_accepted_with_dev_trust_from_localhost(isolated_friends, monkeypatch):
    monkeypatch.setenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", "2099-12-31")
    h = _make_handler({}, client="127.0.0.1")

    authed, friend, reason = h._check_auth()

    assert authed is True
    assert friend["name"] == "localhost-dev"
    assert friend.get("_synthetic") is True
    assert reason == "localhost_dev"


def test_dev_trust_rejects_non_localhost(isolated_friends, monkeypatch):
    monkeypatch.setenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", "2099-12-31")
    h = _make_handler({}, client="10.0.0.5")

    authed, friend, reason = h._check_auth()

    assert authed is False


def test_dev_trust_expires_past_until_date(isolated_friends, monkeypatch):
    """Foot-gun guard: an expired _UNTIL date must NOT trust localhost.

    This is the whole point of forcing a date instead of a bare flag — if the
    maintainer forgets they enabled it, time disables it for them.
    """
    monkeypatch.setenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", "2020-01-01")
    h = _make_handler({}, client="127.0.0.1")

    authed, friend, reason = h._check_auth()

    assert authed is False
    assert reason == "no_token"


def test_dev_trust_bare_true_is_ignored(isolated_friends, monkeypatch):
    """The legacy bare ``=true`` form must not be honoured.

    It is too easy to forget on. The function logs a warning telling the
    user to migrate to ``_UNTIL=YYYY-MM-DD``.
    """
    monkeypatch.delenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", raising=False)
    monkeypatch.setenv("A2A_DEV_LOCALHOST_TRUST", "true")
    h = _make_handler({}, client="127.0.0.1")

    authed, friend, reason = h._check_auth()

    assert authed is False


def test_dev_trust_invalid_until_treated_as_off(isolated_friends, monkeypatch):
    monkeypatch.setenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", "not-a-date")
    h = _make_handler({}, client="127.0.0.1")

    authed, friend, reason = h._check_auth()

    assert authed is False


# ── per-friend rate limiter ───────────────────────────────────────────


def test_rate_limiter_per_call_cap_overrides_default():
    rl = RateLimiter(max_requests=100, window_seconds=60)

    assert rl.allow("alice", max_requests=1) is True
    assert rl.allow("alice", max_requests=1) is False
    # Distinct buckets per client_id
    assert rl.allow("bob", max_requests=1) is True


def test_rate_limiter_default_used_when_unspecified():
    rl = RateLimiter(max_requests=2, window_seconds=60)

    assert rl.allow("alice") is True
    assert rl.allow("alice") is True
    assert rl.allow("alice") is False


# ── bootstrap_legacy migration ────────────────────────────────────────


def test_bootstrap_legacy_creates_friend_when_store_empty(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    result = store.bootstrap_legacy("env-token-1234")

    assert result is not None
    assert result["id"] == "f_legacy"
    assert result["name"] == "legacy"
    assert result["status"] == "active"
    assert result["trust_level"] == "normal"

    # The env token is what existing callers carry; it must auth as `legacy`.
    matched = store.get_by_token("env-token-1234")
    assert matched is not None
    assert matched["name"] == "legacy"


def test_bootstrap_legacy_is_noop_when_store_has_records(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")

    result = store.bootstrap_legacy("env-token-1234")

    assert result is None
    # The env token must NOT be valid; friends.json is the source of truth.
    assert store.get_by_token("env-token-1234") is None


def test_bootstrap_legacy_is_noop_when_token_empty(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    assert store.bootstrap_legacy("") is None
    assert store.list_friends() == []


def test_bootstrap_legacy_does_not_leak_raw_token_to_disk(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.bootstrap_legacy("env-token-secret-XYZ")

    on_disk = path.read_text(encoding="utf-8")
    assert "env-token-secret-XYZ" not in on_disk
