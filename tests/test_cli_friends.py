from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugin as a2a_plugin  # noqa: E402
from plugin import cli, ssrf  # noqa: E402
from plugin.friends import FriendsStore  # noqa: E402


def _store(tmp_path):
    return FriendsStore(path=tmp_path / "friends.json")


def _gai(ip: str):
    family = 2 if "." in ip else 10
    return [(family, 1, 0, "", (ip, 80))]


def test_friends_list_empty(tmp_path):
    result = cli.handle_friends_command("", store=_store(tmp_path))

    assert result == "No A2A friends configured."


def test_add_friend_outputs_token_once_and_persists_hash_only(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("93.184.216.34"))
    path = tmp_path / "friends.json"
    store = FriendsStore(path=path)

    result = cli.handle_friends_command(
        'add alice http://example.com --display-name "Alice Agent" --outbound-token out-secret',
        store=store,
    )
    raw_token = result.split("out-of-band:\n", 1)[1].split("\n", 1)[0]

    assert "Added friend Alice Agent." in result
    assert "trust_level: new" in result
    assert raw_token
    assert raw_token not in path.read_text(encoding="utf-8")
    assert store.get_by_name("alice")["outbound_token"] == "out-secret"


def test_add_private_url_requires_ip_literal_and_reason(tmp_path):
    result = cli.handle_friends_command(
        'add local http://10.0.0.5 --allow-private-url --reason "local LAN dev box for staging A2A"',
        store=_store(tmp_path),
    )

    assert "Added friend local." in result


def test_add_private_url_rejects_hostname(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("93.184.216.34"))

    result = cli.handle_friends_command(
        'add host http://example.com --allow-private-url --reason "hostname is not allowed for private approval"',
        store=_store(tmp_path),
    )

    assert "requires an IP literal target" in result


def test_add_reason_requires_private_url_flag(tmp_path):
    result = cli.handle_friends_command(
        'add alice http://example.com --reason "this should not be silently ignored"',
        store=_store(tmp_path),
    )

    assert result == "--reason requires --allow-private-url"


def test_add_public_hostname_resolving_blocked_returns_controlled_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("198.18.0.139"))

    result = cli.handle_friends_command("add friend https://friend-a2a-endpoint.example.com", store=_store(tmp_path))

    assert result.startswith("SSRF blocked:")
    assert "198.18.0.139" in result


def test_list_shows_private_target_but_no_tokens(tmp_path):
    store = _store(tmp_path)
    store.add_friend(
        "local",
        url="http://10.0.0.5",
        outbound_token="out-secret-token",
        allow_private_url=True,
        allow_private_reason="local LAN dev box for staging A2A",
    )

    result = cli.handle_friends_command("list", store=store)

    assert "private target: http://10.0.0.5:80" in result
    assert "out-secret-token" not in result


def test_clear_private_url_revokes_approval(tmp_path):
    store = _store(tmp_path)
    store.add_friend(
        "local",
        url="http://10.0.0.5",
        allow_private_url=True,
        allow_private_reason="local LAN dev box for staging A2A",
    )

    result = cli.handle_friends_command("clear-private-url local", store=store)

    assert result == "Cleared private URL approval for local."
    assert store.get_by_name("local")["allow_private_target"] == ""


def test_status_commands_and_remove_confirmation(tmp_path):
    store = _store(tmp_path)
    store.add_friend("alice")

    assert cli.handle_friends_command("pause alice", store=store) == "Paused friend alice."
    assert store.get_by_name("alice")["status"] == "paused"
    assert cli.handle_friends_command("unpause alice", store=store) == "Unpaused friend alice."
    assert cli.handle_friends_command("block alice", store=store) == "Blocked friend alice."
    assert cli.handle_friends_command("unblock alice", store=store) == "Unblocked friend alice."
    assert cli.handle_friends_command("remove alice", store=store) == "Refusing to remove friend without --confirm"
    assert cli.handle_friends_command("remove alice --confirm", store=store) == "Removed friend alice."
    assert store.get_by_name("alice") is None


def test_rotate_token_requires_confirm_and_invalidates_old(tmp_path):
    store = _store(tmp_path)
    _friend, old_token = store.add_friend("alice")

    assert cli.handle_friends_command("rotate-token alice", store=store) == "Refusing to rotate token without --confirm"
    result = cli.handle_friends_command("rotate-token alice --confirm", store=store)
    new_token = result.split("New token:\n", 1)[1].split("\n", 1)[0]

    assert new_token
    assert new_token != old_token
    assert store.get_by_token(old_token) is None
    assert store.get_by_token(new_token)["name"] == "alice"


def test_set_trust_trusted_requires_confirm(tmp_path):
    store = _store(tmp_path)
    store.add_friend("alice")

    assert cli.handle_friends_command("set-trust alice trusted", store=store) == (
        "Refusing to set trust_level=trusted without --confirm"
    )
    assert cli.handle_friends_command("set-trust alice trusted --confirm", store=store) == (
        "Set trust_level for alice to trusted."
    )
    assert store.get_by_name("alice")["trust_level"] == "trusted"


def test_set_rate_url_and_outbound_token(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("93.184.216.34"))
    store = _store(tmp_path)
    store.add_friend("alice")

    assert cli.handle_friends_command("set-rate-limit alice 7", store=store) == (
        "Set rate_limit_per_min for alice to 7."
    )
    assert cli.handle_friends_command("set-url alice http://example.com", store=store).startswith("Set URL")
    token_result = cli.handle_friends_command("set-outbound-token alice fresh-secret-1234", store=store)

    friend = store.get_by_name("alice")
    assert friend["rate_limit_per_min"] == 7
    assert friend["url"] == "http://example.com"
    assert friend["outbound_token"] == "fresh-secret-1234"
    assert "fresh-secret-1234" not in token_result
    assert "***1234" in token_result


def test_set_url_blocks_private_resolution(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: _gai("10.0.0.5"))
    store = _store(tmp_path)
    store.add_friend("alice")

    result = cli.handle_friends_command("set-url alice http://internal.local", store=store)

    assert result.startswith("SSRF blocked:")
    assert "10.0.0.5" in result


def test_unknown_command_and_option_are_clear(tmp_path):
    store = _store(tmp_path)

    assert cli.handle_friends_command("wat", store=store) == "Unknown friends command: wat. Try /a2a friends help"
    assert cli.handle_friends_command("add alice --wat", store=store) == "Unknown option: --wat"


def test_unexpected_store_error_is_controlled(caplog):
    class BrokenStore:
        def list_friends(self):
            raise RuntimeError("disk unavailable")

    with caplog.at_level("ERROR", logger="plugin.cli"):
        result = cli.handle_friends_command("list", store=BrokenStore())

    assert result == "Command failed: disk unavailable"
    assert "A2A friends command failed" in caplog.text


def test_a2a_command_dispatches_to_friends(monkeypatch):
    monkeypatch.setattr("plugin.cli.handle_friends_command", lambda raw: f"friends:{raw}")

    assert a2a_plugin._handle_a2a_command("friends list") == "friends:list"
