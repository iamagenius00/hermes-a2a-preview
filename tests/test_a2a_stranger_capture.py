"""Tests for P4.2.2 server-side stranger capture wiring."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import server as server_module  # noqa: E402
from plugin.friends import FriendsStore  # noqa: E402
from plugin.strangers import (  # noqa: E402
    AUTH_FRIEND_BLOCKED,
    AUTH_NO_TOKEN,
    AUTH_UNKNOWN_TOKEN,
    BLOCK_SCOPE_CARD_URL,
    StrangerStore,
)


class _Headers:
    def __init__(self, values: dict[str, str]):
        self._values = values

    def get(self, key: str, default: str = "") -> str:
        return self._values.get(key, default)


class _UnreadableBody:
    def read(self, *_args, **_kwargs):
        raise AssertionError("auth failure path must not read request body")


def _handler(headers=None, *, client="203.0.113.10"):
    handler = SimpleNamespace()
    handler.headers = _Headers(headers or {})
    handler.client_address = (client, 12345)
    handler.server = SimpleNamespace(auth_token="")
    handler.rfile = _UnreadableBody()
    handler._check_auth = server_module.A2ARequestHandler._check_auth.__get__(handler)
    handler._capture_stranger_auth_failure = (
        server_module.A2ARequestHandler._capture_stranger_auth_failure.__get__(handler)
    )
    handler.do_POST = server_module.A2ARequestHandler.do_POST.__get__(handler)

    responses: list[tuple[int, dict]] = []

    def send_json(data: dict, status: int = 200) -> None:
        responses.append((status, data))

    handler._send_json = send_json
    return handler, responses


@pytest.fixture
def stores(tmp_path, monkeypatch):
    friend_store = FriendsStore(path=tmp_path / "friends.json")
    stranger_store = StrangerStore(path=tmp_path / "strangers.json", digest_key="stranger-test-key")
    monkeypatch.setattr(server_module, "friends", friend_store)
    monkeypatch.setattr(server_module, "_stranger_store", stranger_store)
    monkeypatch.delenv("A2A_DEV_LOCALHOST_TRUST", raising=False)
    monkeypatch.delenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", raising=False)
    monkeypatch.delenv("A2A_STRANGER_CAPTURE", raising=False)
    monkeypatch.setenv("A2A_STRANGER_CARD_FETCH", "false")
    return friend_store, stranger_store


def test_no_token_post_captures_stranger_without_reading_body(stores):
    _friend_store, stranger_store = stores
    handler, responses = _handler(
        {
            "Agent-Card-URL": "https://例え.テスト/.well-known/agent.json?token=secret#frag",
            "Authorization": "Basic attacker-controlled",
        }
    )

    handler.do_POST()

    assert responses == [
        (401, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Unauthorized"}, "id": None})
    ]
    records = stranger_store.list_requests()
    assert len(records) == 1
    assert records[0]["auth_reason"] == AUTH_NO_TOKEN
    assert records[0]["agent_card_url"] == "https://xn--r8jz45g.xn--zckzah/.well-known/agent.json"

    raw = stranger_store.path.read_text(encoding="utf-8")
    assert "secret" not in raw
    assert "frag" not in raw
    assert "Basic attacker-controlled" not in raw
    assert "Authorization" not in raw


def test_unknown_token_captures_without_raw_token_or_hash(stores):
    _friend_store, stranger_store = stores
    handler, responses = _handler(
        {
            "Authorization": "Bearer raw-unknown-token",
            "A2A-Agent-Card-URL": "https://agent.example/card?raw=token",
        }
    )

    handler.do_POST()

    assert responses[0][0] == 401
    records = stranger_store.list_requests()
    assert len(records) == 1
    assert records[0]["auth_reason"] == AUTH_UNKNOWN_TOKEN
    assert records[0]["matched_friend_id"] == ""

    raw = stranger_store.path.read_text(encoding="utf-8")
    stored = json.loads(raw)["requests"][0]
    assert "raw-unknown-token" not in raw
    assert "raw=token" not in raw
    assert "Authorization" not in raw
    assert "token_hash" not in stored
    assert "unknown_token_digest" not in stored


def test_auth_fail_fetches_agent_card_after_visible_capture(stores, monkeypatch):
    _friend_store, stranger_store = stores
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {
            "status": "ok",
            "claimed_name": "Friend",
            "supported_methods": ["tasks/send"],
        }

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    handler, responses = _handler({
        "Agent-Card-URL": "https://agent.example/card?token=secret#frag",
    })

    handler.do_POST()

    assert responses[0][0] == 401
    assert calls == ["https://agent.example/card"]
    records = stranger_store.list_requests()
    assert records[0]["agent_card_fetch"] == {
        "status": "ok",
        "claimed_name": "Friend",
        "protocol_version": "",
        "extension_version": "",
        "supported_methods": ["tasks/send"],
    }
    raw = stranger_store.path.read_text(encoding="utf-8")
    assert "secret" not in raw
    assert "frag" not in raw


def test_agent_card_fetch_feature_flag_skips_fetch(stores, monkeypatch):
    _friend_store, stranger_store = stores
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {"status": "ok", "claimed_name": "Friend"}

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    handler, responses = _handler({"Agent-Card-URL": "https://agent.example/card"})

    handler.do_POST()

    assert responses[0][0] == 401
    assert calls == []
    assert stranger_store.list_requests()[0]["agent_card_fetch"] == {"status": "none"}


def test_no_agent_card_url_does_not_fetch(stores, monkeypatch):
    _friend_store, _stranger_store = stores
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {"status": "ok", "claimed_name": "Friend"}

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    handler, responses = _handler({"Authorization": "Bearer raw-unknown-token"})

    handler.do_POST()

    assert responses[0][0] == 401
    assert calls == []


def test_rate_limited_capture_does_not_fetch_agent_card(stores, monkeypatch):
    _friend_store, stranger_store = stores
    stranger_store.per_ip_per_hour = 1
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {"status": "ok", "claimed_name": "Friend"}

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    first, first_responses = _handler({"Agent-Card-URL": "https://agent.example/card"})
    second, second_responses = _handler({"Agent-Card-URL": "https://agent.example/card"})

    first.do_POST()
    second.do_POST()

    assert first_responses[0][0] == 401
    assert second_responses[0][0] == 401
    assert calls == ["https://agent.example/card"]
    records = stranger_store.list_requests()
    assert len(records) == 1
    assert records[0]["count"] == 1
    assert records[0]["suppressed_count"] == 1


def test_coalesced_capture_with_existing_fetch_does_not_refetch(stores, monkeypatch):
    _friend_store, stranger_store = stores
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {"status": "ok", "claimed_name": "Friend"}

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    first, _first_responses = _handler({"Agent-Card-URL": "https://agent.example/card?one=1"})
    second, _second_responses = _handler({"Agent-Card-URL": "https://agent.example/card?two=2"})

    first.do_POST()
    second.do_POST()

    assert calls == ["https://agent.example/card"]
    records = stranger_store.list_requests()
    assert len(records) == 1
    assert records[0]["count"] == 2
    assert records[0]["agent_card_fetch"]["status"] == "ok"


def test_blocked_capture_does_not_fetch_agent_card(stores, monkeypatch):
    _friend_store, stranger_store = stores
    existing = stranger_store.capture(
        client_ip="198.51.100.20",
        auth_reason=AUTH_UNKNOWN_TOKEN,
        agent_card_url_header="https://blocked.example/card?first=1",
    )["request"]
    stranger_store.block(existing["id"], scope=BLOCK_SCOPE_CARD_URL)
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)
    calls: list[str] = []

    def fake_fetch(url: str) -> dict:
        calls.append(url)
        return {"status": "ok", "claimed_name": "Friend"}

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    handler, responses = _handler(
        {"Agent-Card-URL": "https://blocked.example/card?second=2"},
        client="203.0.113.30",
    )

    handler.do_POST()

    assert responses[0][0] == 401
    assert calls == []


def test_agent_card_fetch_exception_does_not_change_auth_failure_response(stores, monkeypatch):
    _friend_store, stranger_store = stores
    monkeypatch.delenv("A2A_STRANGER_CARD_FETCH", raising=False)

    def fake_fetch(_url: str) -> dict:
        raise RuntimeError("fetch unavailable")

    monkeypatch.setattr(server_module, "_fetch_stranger_agent_card", fake_fetch)
    handler, responses = _handler({"Agent-Card-URL": "https://agent.example/card"})

    handler.do_POST()

    assert responses == [
        (401, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Unauthorized"}, "id": None})
    ]
    assert stranger_store.list_requests()[0]["agent_card_fetch"] == {
        "status": "error",
        "reason_class": "RuntimeError",
    }


def test_blocked_friend_captures_matched_friend_identity(stores):
    friend_store, stranger_store = stores
    friend, raw_token = friend_store.add_friend("alice")
    friend_store.block("alice")
    handler, responses = _handler({"Authorization": f"Bearer {raw_token}"})

    handler.do_POST()

    assert responses[0][0] == 401
    records = stranger_store.list_requests()
    assert len(records) == 1
    assert records[0]["auth_reason"] == AUTH_FRIEND_BLOCKED
    assert records[0]["matched_friend_id"] == friend["id"]
    assert records[0]["matched_friend_name"] == "alice"
    assert raw_token not in stranger_store.path.read_text(encoding="utf-8")


def test_capture_exception_does_not_change_auth_failure_response(stores, monkeypatch):
    class BrokenStore:
        def capture(self, **_kwargs):
            raise RuntimeError("store unavailable")

    monkeypatch.setattr(server_module, "_stranger_store", BrokenStore())
    handler, responses = _handler({"Authorization": "Bearer raw-unknown-token"})

    handler.do_POST()

    assert responses == [
        (401, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Unauthorized"}, "id": None})
    ]


def test_stranger_capture_feature_flag_preserves_401_without_store_write(stores, monkeypatch):
    _friend_store, stranger_store = stores
    monkeypatch.setenv("A2A_STRANGER_CAPTURE", "false")
    handler, responses = _handler({"Authorization": "Bearer raw-unknown-token"})

    handler.do_POST()

    assert responses[0][0] == 401
    assert stranger_store.list_requests() == []


def test_auth_fail_audit_still_uses_existing_payload(stores, monkeypatch):
    captured: list[tuple[str, dict]] = []

    class Audit:
        def log(self, event, data):
            captured.append((event, data))

    monkeypatch.setattr(server_module, "audit", Audit())
    handler, _responses = _handler({"Authorization": "Bearer raw-unknown-token"})

    handler.do_POST()

    assert captured == [("auth_fail", {"client": "203.0.113.10", "reason": AUTH_UNKNOWN_TOKEN})]
    assert "raw-unknown-token" not in json.dumps(captured)
