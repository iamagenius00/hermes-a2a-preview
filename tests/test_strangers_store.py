"""Tests for P4.2.1 stranger request store/helpers."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import strangers  # noqa: E402


KEY = "unit-stranger-key"


def _store(tmp_path, **kwargs):
    return strangers.StrangerStore(path=tmp_path / "strangers.json", digest_key=KEY, **kwargs)


def test_normalize_agent_card_url_strips_query_fragment_and_uses_punycode():
    normalized = strangers.normalize_agent_card_url(
        "https://例え.テスト/.well-known/agent.json?token=secret#frag",
        KEY,
    )

    assert normalized == {
        "agent_card_url": "https://xn--r8jz45g.xn--zckzah/.well-known/agent.json",
        "agent_card_url_digest": strangers.audit_digest(
            "https://xn--r8jz45g.xn--zckzah/.well-known/agent.json",
            KEY,
            prefix_len=16,
        ),
    }
    assert "secret" not in json.dumps(normalized)
    assert "frag" not in json.dumps(normalized)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://agent.example/card",
        "https://user:pass@agent.example/card",
        "https://agent.example:99999/card",
        "https://agent.example/" + ("x" * 600),
        "https://agent.example/" + ("x" * 3000),
    ],
)
def test_normalize_agent_card_url_rejects_unsafe_or_oversized_values(url):
    assert strangers.normalize_agent_card_url(url, KEY) is None


def test_build_request_record_allows_only_known_reasons():
    with pytest.raises(ValueError, match="invalid auth_reason"):
        strangers.build_request_record(
            client_ip="203.0.113.10",
            auth_reason="raw_token=secret",
            digest_key=KEY,
        )


def test_capture_persists_safe_fields_only(tmp_path):
    store = _store(tmp_path)

    result = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/.well-known/agent.json?token=secret#frag",
        agent_card_fetch={
            "status": "ok",
            "claimed_name": "Friend",
            "protocol_version": "0.2",
            "extension_version": "extremely-long-extension-version-that-will-be-truncated",
            "supported_methods": [f"method-{i}" for i in range(30)],
        },
    )

    assert result["stored"] is True
    raw = store.path.read_text(encoding="utf-8")
    assert "secret" not in raw
    assert "frag" not in raw
    assert "sender_name" not in raw
    assert "intent" not in raw
    record = json.loads(raw)["requests"][0]
    assert record["agent_card_url"] == "https://agent.example/.well-known/agent.json"
    assert record["agent_card_fetch"]["claimed_name"] == "Friend"
    assert len(record["agent_card_fetch"]["extension_version"]) == strangers.VERSION_MAX
    assert len(record["agent_card_fetch"]["supported_methods"]) == strangers.MAX_METHODS


def test_repeated_unknown_request_coalesces_by_ip_reason_and_card_url(tmp_path):
    store = _store(tmp_path)

    first = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?one=1",
    )["request"]
    second = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?two=2",
    )["request"]

    assert second["id"] == first["id"]
    assert second["count"] == 2
    assert len(store.list_requests()) == 1


def test_known_denied_friend_coalesce_key_uses_friend_id_not_source_ip(tmp_path):
    store = _store(tmp_path)

    first = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_FRIEND_BLOCKED,
        matched_friend_id="f_a",
        matched_friend_name="alice",
        agent_card_url_header="https://agent.example/card",
    )["request"]
    second = store.capture(
        client_ip="198.51.100.9",
        auth_reason=strangers.AUTH_FRIEND_BLOCKED,
        matched_friend_id="f_a",
        matched_friend_name="alice",
        agent_card_url_header="https://agent.example/card",
    )["request"]
    third = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_FRIEND_BLOCKED,
        matched_friend_id="f_b",
        matched_friend_name="bob",
        agent_card_url_header="https://agent.example/card",
    )["request"]

    assert second["id"] == first["id"]
    assert third["id"] != first["id"]
    assert len(store.list_requests()) == 2


def test_rate_limit_suppresses_new_records_without_persisting_token_hash(tmp_path):
    store = _store(tmp_path, per_ip_per_hour=2)

    assert store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://a.example/card",
    )["stored"]
    assert store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://b.example/card",
    )["stored"]
    third = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://c.example/card",
    )

    assert third["stored"] is False
    assert third["rate_limited"] is True
    data = json.loads(store.path.read_text(encoding="utf-8"))
    assert len(data["requests"]) == 2
    assert sum(r.get("suppressed_count", 0) for r in data["requests"]) == 1
    assert "unknown-token" not in json.dumps(data)
    assert "authorization" not in json.dumps(data).lower()


def test_rate_limit_suppresses_repeated_same_coalesce_key(tmp_path):
    store = _store(tmp_path, per_ip_per_hour=2)

    first = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?one=1",
    )["request"]
    second = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?two=2",
    )["request"]
    third = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?three=3",
    )

    assert second["id"] == first["id"]
    assert second["count"] == 2
    assert third["stored"] is False
    assert third["rate_limited"] is True

    records = store.list_requests()
    assert len(records) == 1
    assert records[0]["count"] == 2
    assert records[0]["rate_window_count"] == 2
    assert records[0]["suppressed_count"] == 1


def test_rate_limit_window_resets_for_coalesced_record(tmp_path):
    store = _store(tmp_path, per_ip_per_hour=2)
    start = datetime(2026, 5, 2, 12, 0, tzinfo=timezone.utc)

    first = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
        now=start,
    )["request"]
    store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
        now=start + timedelta(minutes=1),
    )
    later = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
        now=start + timedelta(hours=1, minutes=1),
    )["request"]

    assert later["id"] == first["id"]
    assert later["count"] == 3
    assert later["rate_window_count"] == 1


def test_block_scope_card_url_and_ip_digest_are_explicit(tmp_path):
    store = _store(tmp_path)
    request = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
    )["request"]

    card_block = store.block(request["id"], scope=strangers.BLOCK_SCOPE_CARD_URL)
    assert card_block["scope"] == strangers.BLOCK_SCOPE_CARD_URL
    blocked_card = store.capture(
        client_ip="198.51.100.9",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?ignored=1",
    )
    assert blocked_card["blocked"] is True

    other = store.capture(
        client_ip="203.0.113.20",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://other.example/card",
    )["request"]
    ip_block = store.block(other["id"], scope=strangers.BLOCK_SCOPE_IP_DIGEST)
    assert ip_block["scope"] == strangers.BLOCK_SCOPE_IP_DIGEST
    blocked_ip = store.capture(
        client_ip="203.0.113.20",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://new.example/card",
    )
    assert blocked_ip["blocked"] is True


def test_card_url_block_requires_card_url_digest(tmp_path):
    store = _store(tmp_path)
    request = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_NO_TOKEN,
    )["request"]

    with pytest.raises(ValueError, match="card_url block requires"):
        store.block(request["id"], scope=strangers.BLOCK_SCOPE_CARD_URL)


def test_audit_projection_excludes_raw_display_strings(tmp_path):
    store = _store(tmp_path)
    request = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card?token=secret#frag",
        agent_card_fetch={
            "status": "ok",
            "claimed_name": "A claimed remote name",
            "supported_methods": ["tasks/send"],
        },
    )["request"]

    projection = store.audit_projection(request["id"])
    dumped = json.dumps(projection, sort_keys=True)
    assert projection["agent_card_fetch_status"] == "ok"
    assert projection["claimed_name_length_bucket"] == "21-80"
    assert "A claimed remote name" not in dumped
    assert "agent.example" not in dumped
    assert "secret" not in dumped
    assert "frag" not in dumped


def test_update_agent_card_fetch_sanitizes_and_persists_projection(tmp_path):
    store = _store(tmp_path)
    request = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
    )["request"]

    updated = store.update_agent_card_fetch(
        request["id"],
        {
            "status": "ok",
            "claimed_name": "Friend<script>",
            "protocol_version": "0.2",
            "extension_version": "x" * 100,
            "supported_methods": ["tasks/send", " "],
            "raw_card": {"token": "secret"},
        },
    )

    assert updated is not None
    assert updated["agent_card_fetch"]["claimed_name"] == "Friend<script>"
    assert len(updated["agent_card_fetch"]["extension_version"]) == strangers.VERSION_MAX
    assert updated["agent_card_fetch"]["supported_methods"] == ["tasks/send"]
    raw = store.path.read_text(encoding="utf-8")
    assert "raw_card" not in raw
    assert "secret" not in raw


def test_retention_prunes_old_requests_and_blocks(tmp_path):
    store = _store(tmp_path, request_retention_days=1, block_retention_days=1)
    old = datetime(2026, 5, 1, tzinfo=timezone.utc)
    now = old + timedelta(days=2)

    request = store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://agent.example/card",
        now=old,
    )["request"]
    store.block(request["id"], scope=strangers.BLOCK_SCOPE_CARD_URL, now=old)

    store.capture(
        client_ip="198.51.100.1",
        auth_reason=strangers.AUTH_NO_TOKEN,
        now=now,
    )

    data = json.loads(store.path.read_text(encoding="utf-8"))
    assert len(data["requests"]) == 1
    assert data["requests"][0]["auth_reason"] == strangers.AUTH_NO_TOKEN
    assert data["blocked"] == []


def test_list_requests_applies_retention_without_new_capture(tmp_path):
    store = _store(tmp_path, request_retention_days=0)
    old = datetime(2026, 5, 1, tzinfo=timezone.utc)

    store.capture(
        client_ip="203.0.113.10",
        auth_reason=strangers.AUTH_UNKNOWN_TOKEN,
        now=old,
    )

    assert store.list_requests() == []
    data = json.loads(store.path.read_text(encoding="utf-8"))
    assert data["requests"] == []
