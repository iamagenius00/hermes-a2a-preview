"""Tests for plugin/friends.py — FriendsStore (Issue 4).

Covers Issue 4 acceptance criteria:

- adding a friend creates a unique token
- pause/block state persists after reload
- rotating a token invalidates the old token
- inbound tokens are stored only as hashes
- friends file is atomically written and has restrictive permissions
- corrupt JSON is backed up and handled gracefully
- pending friends auto-transition to expired after the configured window
- no server auth behavior changes (covered implicitly: nothing in this issue
  imports from server.py / security.py)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import friends as friends_module, security as security_module, ssrf, tools  # noqa: E402
from plugin.friends import (  # noqa: E402
    FriendsStore,
    VALID_STATUSES,
    VALID_TRUST_LEVELS,
    _hash_token,
    mask_token,
)


def _gai(ip: str):
    family = 2 if "." in ip else 10
    return [(family, 1, 0, "", (ip, 80))]


# ── basic add/list ────────────────────────────────────────────────────


def test_add_friend_returns_unique_token_and_id(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    f1, t1 = store.add_friend("alice")
    f2, t2 = store.add_friend("bob")

    assert t1 != t2
    assert f1["id"] != f2["id"]
    assert f1["status"] == "pending"
    assert f2["status"] == "pending"


def test_add_friend_rejects_empty_name(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    with pytest.raises(ValueError):
        store.add_friend("")


def test_add_friend_rejects_duplicate_name(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    with pytest.raises(ValueError):
        store.add_friend("alice")


def test_add_friend_validates_trust_level(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    with pytest.raises(ValueError):
        store.add_friend("alice", trust_level="root")


def test_list_friends_returns_copies(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    listed = store.list_friends()
    listed[0]["status"] = "tampered"
    fresh = store.list_friends()
    assert fresh[0]["status"] == "pending"


# ── token model: only hash on disk ────────────────────────────────────


def test_inbound_token_only_hash_on_disk(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    _, raw = store.add_friend("alice")

    on_disk = path.read_text(encoding="utf-8")
    assert raw not in on_disk, "raw inbound token leaked into the JSON file"
    assert _hash_token(raw) in on_disk


def test_outbound_token_stored_cleartext(tmp_path):
    """Outbound tokens must be retrievable; we send them in headers when calling."""
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.add_friend("alice", outbound_token="ob-secret-1234")

    on_disk = path.read_text(encoding="utf-8")
    assert "ob-secret-1234" in on_disk

    f = store.get_by_name("alice")
    assert f["outbound_token"] == "ob-secret-1234"


def test_get_by_token_returns_friend(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    _, raw = store.add_friend("alice")

    found = store.get_by_token(raw)
    assert found is not None
    assert found["name"] == "alice"


def test_get_by_token_unknown_returns_none(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.get_by_token("not-a-real-token") is None
    assert store.get_by_token("") is None


def test_get_by_name_url_id(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    f, _ = store.add_friend("alice", url="http://93.184.216.34/")

    assert store.get_by_name("alice")["id"] == f["id"]
    assert store.get_by_url("http://93.184.216.34")["id"] == f["id"]
    assert store.get_by_id(f["id"])["name"] == "alice"
    assert store.get_by_name("nobody") is None


# ── Issue 3 P1.3: SSRF private URL approvals ─────────────────────────


def test_add_friend_public_url_has_no_private_target(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("93.184.216.34"))
    store = FriendsStore(path=tmp_path / "friends.json")

    friend, _ = store.add_friend("alice", url="http://example.com/")

    assert friend["allow_private_target"] == ""
    assert friend["allow_private_reason"] == ""


def test_add_friend_private_url_requires_explicit_approval(tmp_path, monkeypatch):
    monkeypatch.delenv("A2A_ALLOW_PRIVATE_NETWORKS", raising=False)
    monkeypatch.delenv("A2A_ENV", raising=False)
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ssrf.SSRFBlocked):
        store.add_friend("bob", url="http://10.0.0.5/")


@pytest.mark.parametrize("reason", ["", ".", "too short"])
def test_add_friend_private_approval_requires_substantive_reason(tmp_path, reason):
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ValueError, match="reason of at least 20 characters"):
        store.add_friend(
            "bob",
            url="http://10.0.0.5/",
            allow_private_url=True,
            allow_private_reason=reason,
        )


def test_add_friend_private_approval_binds_normalized_target(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    reason = "local LAN dev box for staging A2A pings"

    friend, _ = store.add_friend(
        "bob",
        url="http://10.0.0.5/",
        allow_private_url=True,
        allow_private_reason=reason,
    )

    assert friend["allow_private_target"] == "http://10.0.0.5:80"
    assert friend["allow_private_reason"] == reason


def test_add_friend_private_approval_requires_url(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ValueError, match="requires a url"):
        store.add_friend(
            "local",
            allow_private_url=True,
            allow_private_reason="reason long enough text here",
        )


def test_add_friend_env_private_gate_does_not_create_friend_approval(tmp_path, monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ssrf.SSRFBlocked):
        store.add_friend("bob", url="http://10.0.0.5/")


def test_add_friend_env_private_gate_ignored_without_dev(tmp_path, monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.delenv("A2A_ENV", raising=False)
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ssrf.SSRFBlocked):
        store.add_friend("bob", url="http://10.0.0.5/")


@pytest.mark.parametrize("url", ["http://[::1]/", "http://[::ffff:10.0.0.5]/"])
def test_add_friend_private_approval_accepts_ip_literals_only(tmp_path, url):
    store = FriendsStore(path=tmp_path / "friends.json")

    friend, _ = store.add_friend(
        "local",
        url=url,
        allow_private_url=True,
        allow_private_reason="local loopback IP literal dev box test",
    )

    assert friend["allow_private_target"]


def test_add_friend_private_approval_rejects_hostname_even_if_public(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("93.184.216.34"))
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ValueError, match="requires an IP literal target"):
        store.add_friend(
            "hostname_pub",
            url="http://example.com/",
            allow_private_url=True,
            allow_private_reason="hostname resolves to public but flag is requested",
        )


def test_add_friend_env_private_gate_rejects_hostname(tmp_path, monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("10.0.0.5"))
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ssrf.SSRFBlocked):
        store.add_friend("hostname_priv", url="http://internal-tool.local:8080/")


def test_set_url_clears_private_approval_when_target_changes(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend(
        "bob",
        url="http://10.0.0.5/",
        allow_private_url=True,
        allow_private_reason="local LAN dev box for staging A2A pings",
    )

    assert store.set_url("bob", "http://192.168.0.5/")

    friend = store.get_by_name("bob")
    assert friend["url"] == "http://192.168.0.5/"
    assert friend["allow_private_target"] == ""
    assert friend["allow_private_reason"] == ""


def test_outbound_private_friend_approval_is_target_bound(monkeypatch):
    friend = {
        "name": "bob",
        "url": "http://169.254.169.254/",
        "outbound_token": "",
        "allow_private_target": "http://10.0.0.5:80",
        "allow_private_reason": "local LAN dev box for staging A2A pings",
    }
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [])
    monkeypatch.setattr(friends_module.friends, "get_by_name", lambda name: friend if name == "bob" else None)
    monkeypatch.setattr(friends_module.friends, "get_by_url", lambda url: None)

    url, _, allow_private, is_configured_friend, allow_unconfigured, policy_record = tools._resolve_target("bob", "")

    assert allow_private is False
    assert is_configured_friend is True
    assert allow_unconfigured is False
    assert policy_record == friend
    with pytest.raises(PermissionError, match="SSRF blocked"):
        tools._http_request(
            "GET",
            url,
            allow_private=allow_private,
            is_configured_friend=is_configured_friend,
        )


def test_outbound_tampered_hostname_private_target_does_not_allow_rebind(monkeypatch):
    friend = {
        "name": "tampered",
        "url": "http://example.com/",
        "outbound_token": "",
        "allow_private_target": "http://example.com:80",
        "allow_private_reason": "should never have been allowed but suppose it was",
    }
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("169.254.169.254"))
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [])
    monkeypatch.setattr(friends_module.friends, "get_by_name", lambda name: friend if name == "tampered" else None)
    monkeypatch.setattr(friends_module.friends, "get_by_url", lambda url: None)

    url, _, allow_private, is_configured_friend, _, policy_record = tools._resolve_target("tampered", "")

    assert allow_private is False
    assert policy_record == friend
    with pytest.raises(PermissionError, match="SSRF blocked"):
        tools._http_request(
            "GET",
            url,
            allow_private=allow_private,
            is_configured_friend=is_configured_friend,
        )


def test_env_gate_does_not_allow_friend_hostname_private_without_target(monkeypatch):
    friend = {
        "name": "internal",
        "url": "http://internal-tool.local:8080/",
        "outbound_token": "",
        "allow_private_target": "",
        "allow_private_reason": "",
    }
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("10.0.0.5"))
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [])
    monkeypatch.setattr(friends_module.friends, "get_by_name", lambda name: friend if name == "internal" else None)
    monkeypatch.setattr(friends_module.friends, "get_by_url", lambda url: None)

    url, _, allow_private, is_configured_friend, allow_unconfigured, _ = tools._resolve_target("internal", "")

    assert allow_private is False
    assert is_configured_friend is True
    assert allow_unconfigured is False
    with pytest.raises(PermissionError, match="SSRF blocked"):
        tools._http_request(
            "GET",
            url,
            allow_private=allow_private,
            is_configured_friend=is_configured_friend,
        )


def test_private_approval_audit_excludes_raw_reason(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(security_module.audit, "log", lambda event, data: events.append((event, data)))
    reason = "local LAN dev box for staging A2A pings"
    store = FriendsStore(path=tmp_path / "friends.json")

    friend, _ = store.add_friend(
        "bob",
        url="http://10.0.0.5/",
        allow_private_url=True,
        allow_private_reason=reason,
    )

    event, data = events[-1]
    assert event == "friend_added_with_private_url"
    assert data["friend_id"] == friend["id"]
    assert data["target_repr"] == "http://10.0.0.5:80"
    assert data["reason_present"] is True
    assert data["reason_length_bucket"] == "20-50"
    assert "allow_private_reason" not in data
    assert "reason_hash" not in data
    assert "reason_length" not in data
    assert reason not in json.dumps(data)


@pytest.mark.parametrize(
    ("reason", "bucket"),
    [
        ("x" * 20, "20-50"),
        ("x" * 50, "20-50"),
        ("x" * 51, "51-100"),
        ("x" * 100, "51-100"),
        ("x" * 101, "100+"),
    ],
)
def test_private_approval_audit_reason_buckets(tmp_path, monkeypatch, reason, bucket):
    events = []
    monkeypatch.setattr(security_module.audit, "log", lambda event, data: events.append((event, data)))
    store = FriendsStore(path=tmp_path / "friends.json")

    store.add_friend(
        f"bob-{len(reason)}",
        url="http://10.0.0.5/",
        allow_private_url=True,
        allow_private_reason=reason,
    )

    assert events[-1][1]["reason_length_bucket"] == bucket


def test_rejected_friend_ssrf_emits_audit_without_raw_reason(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(security_module.audit, "log", lambda event, data: events.append((event, data)))
    monkeypatch.delenv("A2A_ALLOW_PRIVATE_NETWORKS", raising=False)
    store = FriendsStore(path=tmp_path / "friends.json")

    with pytest.raises(ssrf.SSRFBlocked):
        store.add_friend("bob", url="http://10.0.0.5/")

    assert events[-1][0] == "ssrf_blocked"
    assert "allow_private_reason" not in events[-1][1]
    assert events[-1][1]["exception_type"] == "SSRFBlocked"


def test_set_url_wraps_deep_url_validation_errors_as_value_error(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")

    with pytest.raises(ValueError, match="invalid A2A URL"):
        store.set_url("alice", "http://127.0.0.1:99999/")


# ── lifecycle: pause / block / remove / persist ───────────────────────


def test_pause_persists_across_reload(tmp_path):
    path = tmp_path / "friends.json"
    s1 = FriendsStore(path=path)
    s1.add_friend("alice")
    assert s1.pause("alice")

    s2 = FriendsStore(path=path)
    assert s2.get_by_name("alice")["status"] == "paused"


def test_block_persists_across_reload(tmp_path):
    path = tmp_path / "friends.json"
    s1 = FriendsStore(path=path)
    s1.add_friend("alice")
    s1.block("alice")

    s2 = FriendsStore(path=path)
    assert s2.get_by_name("alice")["status"] == "blocked"


def test_unpause_returns_active(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    store.pause("alice")
    store.unpause("alice")
    assert store.get_by_name("alice")["status"] == "active"


def test_remove_drops_record(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.add_friend("alice")
    assert store.remove_friend("alice")
    assert store.get_by_name("alice") is None
    assert not store.remove_friend("nobody")


def test_pause_returns_false_for_unknown(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    assert store.pause("ghost") is False


# ── token rotation ────────────────────────────────────────────────────


def test_rotate_token_invalidates_old_and_grants_new(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    _, old_raw = store.add_friend("alice")

    new_raw = store.rotate_token("alice")

    assert new_raw is not None
    assert new_raw != old_raw
    assert store.get_by_token(old_raw) is None, "old token still valid after rotate"
    assert store.get_by_token(new_raw)["name"] == "alice"


def test_rotate_token_unknown_returns_none(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    assert store.rotate_token("ghost") is None


# ── status / trust / rate limit setters ───────────────────────────────


def test_set_trust_level(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.set_trust_level("alice", "trusted")
    assert store.get_by_name("alice")["trust_level"] == "trusted"

    with pytest.raises(ValueError):
        store.set_trust_level("alice", "evil")


def test_set_rate_limit_validates(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.set_rate_limit("alice", 50)
    assert store.get_by_name("alice")["rate_limit_per_min"] == 50

    with pytest.raises(ValueError):
        store.set_rate_limit("alice", 0)
    with pytest.raises(ValueError):
        store.set_rate_limit("alice", -1)


def test_set_outbound_token(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.set_outbound_token("alice", "fresh-outbound")
    assert store.get_by_name("alice")["outbound_token"] == "fresh-outbound"


# ── pending state machine ─────────────────────────────────────────────


def test_record_last_contact_transitions_pending_to_active(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.get_by_name("alice")["status"] == "pending"

    store.record_last_contact("alice")
    f = store.get_by_name("alice")

    assert f["status"] == "active"
    assert f["last_contact"] is not None


def test_record_last_contact_does_not_revive_paused(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    store.pause("alice")
    store.record_last_contact("alice")

    assert store.get_by_name("alice")["status"] == "paused"


def test_expire_pending_sweeps_past_expires_at(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.add_friend("alice")
    store.add_friend("bob")
    store.record_last_contact("bob")  # bob is active, must NOT be expired

    # Backdate alice's expires_at
    data = json.loads(path.read_text(encoding="utf-8"))
    for f in data["friends"]:
        if f["name"] == "alice":
            f["expires_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)

    n = store.expire_pending()

    assert n == 1
    assert store.get_by_name("alice")["status"] == "expired"
    assert store.get_by_name("bob")["status"] == "active"


def test_expire_pending_no_op_when_nothing_to_expire(tmp_path):
    store = FriendsStore(path=tmp_path / "friends.json")
    store.add_friend("alice")
    assert store.expire_pending() == 0
    assert store.get_by_name("alice")["status"] == "pending"


# ── storage hygiene ──────────────────────────────────────────────────


def test_file_mode_is_0600(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.add_friend("alice")

    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_atomic_write_leaves_no_tmp_file(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)
    store.add_friend("alice")
    store.add_friend("bob")
    store.pause("alice")

    leftovers = list(tmp_path.glob("friends.json.tmp"))
    assert leftovers == []


def test_corrupt_json_backed_up_and_starts_empty(tmp_path):
    path = tmp_path / "friends.json"
    path.write_text("not valid json {{{", encoding="utf-8")

    store = FriendsStore(path=path)
    listed = store.list_friends()

    assert listed == []
    backups = list(tmp_path.glob("friends.json.corrupt-*"))
    assert len(backups) == 1


def test_corrupt_backups_keep_at_most_three(tmp_path):
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)

    for i in range(5):
        path.write_text(f"corrupt #{i}", encoding="utf-8")
        # force a fresh read; list_friends triggers the corrupt-handling path
        store.list_friends()

    backups = list(tmp_path.glob("friends.json.corrupt-*"))
    assert len(backups) <= 3


def test_wrong_shape_json_backed_up(tmp_path):
    path = tmp_path / "friends.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    store = FriendsStore(path=path)
    assert store.list_friends() == []
    backups = list(tmp_path.glob("friends.json.corrupt-*"))
    assert len(backups) == 1


# ── helpers ───────────────────────────────────────────────────────────


def test_mask_token_redacts_sensibly():
    assert mask_token("") == ""
    assert mask_token("abc") == "***"
    assert mask_token("abcdef1234") == "***1234"


def test_status_and_trust_constants_match_doc():
    """Drift guard: VALID_STATUSES / VALID_TRUST_LEVELS match plan v6."""
    assert VALID_STATUSES == {
        "pending",
        "active",
        "paused",
        "blocked",
        "expired",
        "removed",
    }
    assert VALID_TRUST_LEVELS == {"trusted", "normal", "new"}
