"""Tests for P4.2.3 SSRF-safe stranger Agent Card fetch helper."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import strangers  # noqa: E402


class _Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size):
        return self.payload


class _Opener:
    def __init__(self, payload: bytes, captured: dict):
        self.payload = payload
        self.captured = captured

    def open(self, req, timeout):
        self.captured["request_url"] = req.full_url
        self.captured["headers"] = dict(req.header_items())
        self.captured["timeout"] = timeout
        return _Response(self.payload)


def test_fetch_uses_strict_ssrf_contract_and_target_canonical_url(monkeypatch):
    captured: dict = {}
    payload = json.dumps({
        "name": "Friend",
        "protocolVersion": "0.2",
        "extensionVersion": "1.0",
        "supported_methods": ["tasks/send", "tasks/get"],
        "description": "raw card field must not be returned",
    }).encode()

    def fake_validate(url, **kwargs):
        captured["validate_url"] = url
        captured["validate_kwargs"] = kwargs
        return SimpleNamespace(canonical_url="https://agent.example/.well-known/agent.json")

    def fake_opener(target):
        captured["opener_target"] = target
        return _Opener(payload, captured)

    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(strangers.ssrf, "build_ssrf_opener", fake_opener)

    result = strangers.fetch_stranger_agent_card(
        "https://agent.example/.well-known/agent.json?token=secret#frag",
        timeout=7,
    )

    assert captured["validate_url"] == "https://agent.example/.well-known/agent.json"
    assert captured["validate_kwargs"] == {
        "allow_private": False,
        "allow_unconfigured": True,
        "is_configured_friend": False,
        "allow_env_private": False,
    }
    assert captured["request_url"] == "https://agent.example/.well-known/agent.json"
    assert captured["timeout"] == 7
    assert result == {
        "status": "ok",
        "claimed_name": "Friend",
        "protocol_version": "0.2",
        "extension_version": "1.0",
        "supported_methods": ["tasks/send", "tasks/get"],
    }
    assert "description" not in result
    assert "secret" not in json.dumps(result)
    assert "frag" not in json.dumps(result)


def test_fetch_uses_punycode_no_query_fragment_before_validator(monkeypatch):
    captured = {}

    def fake_validate(url, **_kwargs):
        captured["url"] = url
        return SimpleNamespace(canonical_url=url)

    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(
        strangers.ssrf,
        "build_ssrf_opener",
        lambda _target: _Opener(b'{"name": "ok"}', captured),
    )

    result = strangers.fetch_stranger_agent_card("https://例え.テスト/card?x=1#frag")

    assert captured["url"] == "https://xn--r8jz45g.xn--zckzah/card"
    assert result["status"] == "ok"


def test_fetch_invalid_url_does_not_call_validator(monkeypatch):
    called = False

    def fake_validate(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("validator should not run for invalid URL shape")

    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)

    result = strangers.fetch_stranger_agent_card("ftp://agent.example/card")

    assert result == {"status": "invalid", "reason_class": "invalid_url"}
    assert called is False


def test_fetch_ssrf_blocked_returns_controlled_projection(monkeypatch):
    def fake_validate(*_args, **_kwargs):
        raise strangers.ssrf.SSRFBlocked("private address should not leak")

    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)

    result = strangers.fetch_stranger_agent_card("https://agent.example/card")

    assert result == {"status": "blocked", "reason_class": "SSRFBlocked"}
    assert "private address" not in json.dumps(result)


def test_fetch_redirect_blocked_returns_controlled_projection(monkeypatch):
    def fake_validate(url, **_kwargs):
        return SimpleNamespace(canonical_url=url)

    class RedirectingOpener:
        def open(self, *_args, **_kwargs):
            raise strangers.ssrf.RedirectBlocked("redirect to private target")

    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(strangers.ssrf, "build_ssrf_opener", lambda _target: RedirectingOpener())

    result = strangers.fetch_stranger_agent_card("https://agent.example/card")

    assert result == {"status": "blocked", "reason_class": "RedirectBlocked"}
    assert "private target" not in json.dumps(result)


def test_fetch_invalid_json_returns_invalid(monkeypatch):
    def fake_validate(url, **_kwargs):
        return SimpleNamespace(canonical_url=url)

    captured = {}
    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(strangers.ssrf, "build_ssrf_opener", lambda _target: _Opener(b"not json", captured))

    result = strangers.fetch_stranger_agent_card("https://agent.example/card")

    assert result == {"status": "invalid", "reason_class": "invalid_json"}


def test_fetch_response_too_large_returns_error(monkeypatch):
    def fake_validate(url, **_kwargs):
        return SimpleNamespace(canonical_url=url)

    captured = {}
    monkeypatch.setattr(strangers.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(strangers.ssrf, "build_ssrf_opener", lambda _target: _Opener(b"abcdef", captured))

    result = strangers.fetch_stranger_agent_card("https://agent.example/card", max_response_size=5)

    assert result == {"status": "error", "reason_class": "response_too_large"}


def test_project_agent_card_limits_methods_and_card_derived_strings():
    result = strangers.project_agent_card({
        "name": "<b>" + ("x" * 200),
        "version": "v" * 100,
        "extension_version": "e" * 100,
        "capabilities": {"methods": [f"method-{i}-" + ("y" * 100) for i in range(30)]},
        "description": "do not include me",
    })

    assert result["status"] == "ok"
    assert len(result["claimed_name"]) == strangers.CLAIMED_NAME_MAX
    assert len(result["protocol_version"]) == strangers.VERSION_MAX
    assert len(result["extension_version"]) == strangers.VERSION_MAX
    assert len(result["supported_methods"]) == strangers.MAX_METHODS
    assert all(len(method) <= strangers.METHOD_MAX for method in result["supported_methods"])
    assert "description" not in result
