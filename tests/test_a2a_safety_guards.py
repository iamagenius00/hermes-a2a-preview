import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugin as a2a_plugin  # noqa: E402
import plugin.persistence as persistence  # noqa: E402
from plugin import provenance, server, ssrf, tools  # noqa: E402


class _FakeResponse:
    status = 200

    def __init__(self, body=None):
        self._body = body or {"ok": True}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, _size=-1):
        return json.dumps(self._body).encode()


def test_outbound_rate_limit_check_and_append_are_atomic(monkeypatch):
    tools._call_timestamps.clear()
    monkeypatch.setattr(tools, "_RATE_LIMIT_MAX_CALLS", 1)

    assert tools._consume_rate_limit() is True
    assert tools._consume_rate_limit() is False
    assert len(tools._call_timestamps) == 1


def test_direct_url_requires_configured_target(monkeypatch):
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [])
    monkeypatch.delenv("A2A_ALLOW_UNCONFIGURED_URLS", raising=False)

    result = json.loads(tools.handle_discover({"url": "http://127.0.0.1:8081"}))

    assert "error" in result
    assert "not configured" in result["error"]


def test_configured_direct_url_is_allowed(monkeypatch):
    monkeypatch.setattr(
        tools,
        "_load_configured_agents",
        lambda: [{"name": "local", "url": "http://127.0.0.1:8081", "auth_token": "tok"}],
    )
    monkeypatch.setattr(
        tools,
        "_http_request",
        lambda *args, **kwargs: {"name": "local", "skills": [], "capabilities": {}},
    )

    result = json.loads(tools.handle_discover({"url": "http://127.0.0.1:8081"}))

    assert result["agent_name"] == "local"


def test_http_request_validates_and_uses_canonical_url(monkeypatch):
    calls = {}
    target = SimpleNamespace(
        canonical_url="http://example.com/encoded%20path",
        scheme="http",
        pinned_ip="93.184.216.34",
    )

    def fake_validate(url, **kwargs):
        calls["validate"] = (url, kwargs)
        return target

    class FakeOpener:
        def open(self, req, timeout):
            calls["open"] = (req.full_url, timeout)
            return _FakeResponse({"name": "ok"})

    monkeypatch.setattr(tools.ssrf, "validate_outbound_url", fake_validate)
    monkeypatch.setattr(tools.ssrf, "build_ssrf_opener", lambda validated: FakeOpener())

    result = tools._http_request(
        "GET",
        "http://example.com/raw path",
        allow_private=True,
        allow_unconfigured=False,
        is_configured_friend=True,
    )

    assert result == {"name": "ok"}
    assert calls["validate"] == (
        "http://example.com/raw path",
        {
            "allow_private": True,
            "allow_unconfigured": False,
            "is_configured_friend": True,
            "allow_env_private": False,
        },
    )
    assert calls["open"] == ("http://example.com/encoded%20path", tools._DEFAULT_TIMEOUT)


def test_configured_private_agent_without_declared_target_is_static_valid():
    agents = [{"name": "foo", "url": "http://10.0.0.5/"}]

    assert tools._validate_configured_agents(agents) == agents


def test_config_hostname_resolving_private_is_static_valid(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 0, "", ("10.0.0.5", 80))])
    agents = [{"name": "foo", "url": "http://internal-tool.local:8080/"}]

    assert tools._validate_configured_agents(agents) == agents


def test_env_gate_does_not_allow_config_hostname_private_at_runtime(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "foo",
        "url": "http://internal-tool.local:8080",
    }])
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 0, "", ("10.0.0.5", 80))])

    result = json.loads(tools.handle_discover({"name": "foo"}))

    assert result["error"].startswith("SSRF blocked:")
    assert "10.0.0.5" in result["error"]


def test_configured_private_agent_declared_target_is_allowed():
    agents = [{
        "name": "foo",
        "url": "http://10.0.0.5/",
        "allow_private_target": "http://10.0.0.5:80",
        "allow_private_reason": "long enough internal LAN reason text",
    }]

    assert tools._validate_configured_agents(agents) == agents


def test_handle_list_returns_json_error_for_invalid_config(monkeypatch):
    monkeypatch.setattr(
        tools,
        "_load_configured_agents",
        lambda: (_ for _ in ()).throw(ssrf.SSRFBlocked("blocked config target")),
    )

    result = json.loads(tools.handle_list({}))

    assert result == {"error": "SSRF blocked: blocked config target"}


def test_runtime_config_validation_drops_agents_softly(monkeypatch, caplog):
    fake_config = SimpleNamespace(load_config=lambda: {"a2a": {"agents": [{
        "name": "bad",
        "url": "http://10.0.0.5/",
        "allow_private_target": "http://10.0.0.5:80",
        "allow_private_reason": "too short",
    }]}})
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake_config)

    with caplog.at_level("ERROR", logger="plugin.tools"):
        assert tools._load_configured_agents() == []

    assert "config invalid at runtime, dropping agents" in caplog.text


def test_configured_private_agent_rejects_short_reason():
    with pytest.raises(ValueError, match="reason of at least 20"):
        tools._validate_configured_agents([{
            "name": "foo",
            "url": "http://10.0.0.5/",
            "allow_private_target": "http://10.0.0.5:80",
            "allow_private_reason": "too short",
        }])


def test_configured_private_agent_rejects_mismatched_target():
    with pytest.raises(ValueError, match="must match url"):
        tools._validate_configured_agents([{
            "name": "foo",
            "url": "http://10.0.0.5/",
            "allow_private_target": "http://10.0.0.6:80",
            "allow_private_reason": "long enough internal LAN reason text",
        }])


def test_handle_call_direct_config_url_uses_policy_record(monkeypatch):
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "local",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: {
        "result": {
            "id": "task-1",
            "status": {"state": "completed"},
            "artifacts": [{"parts": [{"type": "text", "text": "ok"}]}],
        }
    })
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)

    result = json.loads(tools.handle_call({
        "url": "http://93.184.216.34:8081",
        "message": "hello",
        "task_id": "task-1",
    }))

    assert result["state"] == "completed"
    assert result["response"] == "ok"


def test_handle_call_denies_private_active_task_provenance(monkeypatch):
    events = []
    a2a_plugin._active_a2a_tasks.clear()
    a2a_plugin._active_a2a_tasks["inbound-1"] = {
        "text": "private source text",
        "metadata": provenance.attach_internal_provenance(
            {"sender_name": "alice"},
            provenance.Provenance.private_source(
                "memory",
                source_digest_prefixes=(provenance.audit_digest("private source text", "audit-key"),),
            ),
        ),
    }
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "marker-free response",
        "task_id": "task-1",
        "reply_to_task_id": "inbound-1",
    }))

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert "error" in result
    assert "private-source provenance" in result["error"]
    assert denied["reason"] == "private_provenance"
    assert denied["provenance"]["source_classes"] == [provenance.STATE_PRIVATE]
    assert denied["provenance"]["source_buckets"] == ["core_memory"]
    assert '"memory"' not in json.dumps(denied["provenance"], sort_keys=True)
    a2a_plugin._active_a2a_tasks.clear()


def test_handle_call_records_saved_sidecar_provenance_without_denial(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("remote text", "audit-key"),
    )
    persistence.save_exchange(
        agent_name="alice",
        task_id="inbound-2",
        inbound_text="remote text",
        outbound_text="old reply",
        metadata=metadata,
    )
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: {
        "result": {
            "id": "task-1",
            "status": {"state": "completed"},
            "artifacts": [{"parts": [{"type": "text", "text": "ok"}]}],
        }
    })
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "fresh response",
        "task_id": "task-1",
        "reply_to_task_id": "inbound-2",
    }))

    outbound = [data for event, data in events if event == "call_outbound"][0]
    assert result["state"] == "completed"
    assert outbound["provenance"]["source_classes"] == [provenance.STATE_PUBLIC]
    assert outbound["provenance"]["source_buckets"] == ["remote_a2a"]
    assert outbound["provenance"]["untrusted"] is True


def test_handle_call_denies_saved_sidecar_exact_replay(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("saved replay text", "audit-key"),
    )
    persistence.save_exchange(
        agent_name="alice",
        task_id="inbound-replay",
        inbound_text="saved replay text",
        outbound_text="old reply",
        metadata=metadata,
    )
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "saved replay text",
        "task_id": "task-1",
        "reply_to_task_id": "inbound-replay",
    }))

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert "error" in result
    assert denied["reason"] == "a2a_replay"


def test_handle_call_denies_saved_sidecar_without_replay_basis(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("remote text", "audit-key"),
    )
    persistence.save_exchange(
        agent_name="alice",
        task_id="basis-missing",
        inbound_text="remote text",
        outbound_text="old reply",
        metadata=metadata,
    )
    markdown = tmp_path / "alice" / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md"
    markdown.unlink()
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "ordinary response",
        "task_id": "task-1",
        "reply_to_task_id": "basis-missing",
    }))

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert "error" in result
    assert "no replay basis" in result["error"]
    assert denied["reason"] == "a2a_replay_basis_missing"


def test_handle_call_denies_missing_reply_provenance(monkeypatch):
    events = []
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "ordinary reply",
        "task_id": "task-1",
        "reply_to_task_id": "missing-inbound",
    }))

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert "error" in result
    assert "missing or invalid" in result["error"]
    assert denied["reason"] == "unknown_private_provenance"
    assert denied["provenance"]["source_classes"] == [provenance.STATE_UNKNOWN_PRIVATE]


def test_handle_call_denies_active_a2a_replay(monkeypatch):
    events = []
    a2a_plugin._active_a2a_tasks.clear()
    a2a_plugin._active_a2a_tasks["inbound-3"] = {
        "text": "repeat this remote text",
        "metadata": provenance.attach_internal_provenance(
            {"sender_name": "alice"},
            provenance.Provenance.a2a_inbound("repeat this remote text", "audit-key"),
        ),
    }
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "alice",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr("plugin.security.audit.log", lambda event, data: events.append((event, data)))

    result = json.loads(tools.handle_call({
        "name": "alice",
        "message": "repeat this remote text",
        "task_id": "task-1",
        "reply_to_task_id": "inbound-3",
    }))

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert "error" in result
    assert "replay untrusted inbound A2A content" in result["error"]
    assert denied["reason"] == "a2a_replay"
    assert denied["provenance"]["source_buckets"] == ["remote_a2a"]
    a2a_plugin._active_a2a_tasks.clear()


@pytest.mark.parametrize("status", ["paused", "blocked"])
def test_handle_call_direct_friend_url_denies_paused_or_blocked(monkeypatch, status):
    friend = {
        "id": "f_1",
        "name": "bob",
        "url": "http://93.184.216.34:8081",
        "status": status,
        "trust_level": "normal",
        "outbound_token": "",
        "allow_private_target": "",
        "allow_private_reason": "",
    }
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [])
    monkeypatch.setattr(tools, "_friend_by_url", lambda url: friend)
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)

    result = json.loads(tools.handle_call({
        "url": "http://93.184.216.34:8081",
        "message": "hello",
        "task_id": "task-1",
    }))

    assert "error" in result
    assert f"Friend status is '{status}'" in result["error"]


@pytest.mark.parametrize("status", ["paused", "blocked"])
def test_handle_call_direct_friend_url_policy_wins_over_matching_config(monkeypatch, status):
    friend = {
        "id": "f_1",
        "name": "bob",
        "url": "http://93.184.216.34:8081",
        "status": status,
        "trust_level": "normal",
        "outbound_token": "",
        "allow_private_target": "",
        "allow_private_reason": "",
    }
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "local",
        "url": "http://93.184.216.34:8081",
        "auth_token": "tok",
    }])
    monkeypatch.setattr(tools, "_friend_by_url", lambda url: friend)
    monkeypatch.setattr(tools, "_http_request", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call")))
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)

    result = json.loads(tools.handle_call({
        "url": "http://93.184.216.34:8081",
        "message": "hello",
        "task_id": "task-1",
    }))

    assert "error" in result
    assert f"Friend status is '{status}'" in result["error"]


def test_register_allows_configured_agent_resolving_blocked_address(monkeypatch):
    fake_config = SimpleNamespace(load_config=lambda: {"a2a": {"agents": [{
        "name": "friend",
        "url": "http://friend-a2a-endpoint.example.com",
    }]}})
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake_config)
    monkeypatch.setenv("A2A_ENABLED", "true")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 0, "", ("198.18.0.139", 80))])
    monkeypatch.setattr(a2a_plugin.ssrf, "log_env_state", lambda: None)
    monkeypatch.setattr(a2a_plugin, "_bootstrap_friends_from_legacy_token", lambda: None)
    monkeypatch.setattr(a2a_plugin, "_start_server", lambda: None)

    class FakeContext:
        def __init__(self):
            self.tools = []

        def register_tool(self, name, *_args):
            self.tools.append(name)

        def register_hook(self, *_args):
            pass

        def register_command(self, *_args, **_kwargs):
            pass

    ctx = FakeContext()

    a2a_plugin.register(ctx)

    assert {"a2a_discover", "a2a_call", "a2a_list"}.issubset(set(ctx.tools))


def test_configured_agent_blocked_dns_returns_controlled_discover_error(monkeypatch):
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "friend",
        "url": "http://friend-a2a-endpoint.example.com",
    }])
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 0, "", ("198.18.0.139", 80))])

    result = json.loads(tools.handle_discover({"name": "friend"}))

    assert result["error"].startswith("SSRF blocked:")
    assert "198.18.0.139" in result["error"]


def test_configured_agent_blocked_dns_returns_controlled_call_error(monkeypatch):
    monkeypatch.setattr(tools, "_load_configured_agents", lambda: [{
        "name": "friend",
        "url": "http://friend-a2a-endpoint.example.com",
    }])
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 0, "", ("198.18.0.139", 80))])
    monkeypatch.setattr(tools, "_consume_rate_limit", lambda: True)
    monkeypatch.setattr(persistence, "save_exchange", lambda *args, **kwargs: None)
    monkeypatch.setattr(persistence, "update_exchange", lambda *args, **kwargs: None)

    result = json.loads(tools.handle_call({
        "name": "friend",
        "message": "hello",
        "task_id": "task-1",
    }))

    assert result["error"].startswith("SSRF blocked:")
    assert "198.18.0.139" in result["error"]


def test_trigger_webhook_bypasses_ssrf_validator(monkeypatch):
    opened = []
    monkeypatch.setenv("A2A_WEBHOOK_SECRET", "secret")
    monkeypatch.setenv("WEBHOOK_PORT", "8644")
    monkeypatch.setattr(ssrf, "validate_outbound_url", lambda *a, **k: (_ for _ in ()).throw(AssertionError("validator called")))
    monkeypatch.setattr(server.urllib.request, "urlopen", lambda req, timeout: opened.append((req.full_url, timeout)) or _FakeResponse())

    server._trigger_webhook()

    assert opened == [("http://127.0.0.1:8644/webhooks/a2a_trigger", 5)]


def test_trigger_webhook_rejects_modified_internal_url(monkeypatch, caplog):
    opened = []
    monkeypatch.setenv("A2A_WEBHOOK_SECRET", "secret")
    monkeypatch.setattr(server, "_internal_webhook_url", lambda port: "http://169.254.169.254/webhooks/a2a_trigger")
    monkeypatch.setattr(server.urllib.request, "urlopen", lambda req, timeout: opened.append(req.full_url) or _FakeResponse())

    with caplog.at_level("WARNING", logger="plugin.server"):
        server._trigger_webhook()

    assert opened == []
    assert "Skipping internal webhook trigger" in caplog.text


def test_active_task_blocks_new_gateway_trigger(monkeypatch):
    a2a_plugin._active_a2a_tasks.clear()
    a2a_plugin._active_a2a_tasks["task-1"] = {"text": "first", "metadata": {}}
    fake_queue = MagicMock()
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_queue)

    event = SimpleNamespace(text="[A2A trigger]")
    result = a2a_plugin._on_pre_gateway_dispatch(event)

    assert result["action"] == "skip"
    fake_queue.drain_pending.assert_not_called()
    a2a_plugin._active_a2a_tasks.clear()


def test_gateway_dispatch_activates_rewritten_task(monkeypatch):
    task = MagicMock()
    task.task_id = "task-1"
    task.text = "hello"
    task.metadata = {}
    fake_queue = MagicMock()
    fake_queue.drain_pending.return_value = [task]
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_queue)
    a2a_plugin._active_a2a_tasks.clear()

    event = SimpleNamespace(text="[A2A trigger]")
    result = a2a_plugin._on_pre_gateway_dispatch(event)

    assert result["action"] == "rewrite"
    assert "task:task-1" in result["text"]
    assert list(a2a_plugin._active_a2a_tasks) == ["task-1"]
    a2a_plugin._active_a2a_tasks.clear()


def test_pre_llm_double_check_prevents_second_activation(monkeypatch):
    task = MagicMock()
    task.task_id = "task-2"
    task.text = "second"
    task.metadata = {}
    fake_queue = MagicMock()
    fake_queue.drain_pending.return_value = [task]
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_queue)
    a2a_plugin._active_a2a_tasks.clear()

    original_activate = a2a_plugin._activate_task_if_idle

    def activate_after_race(_task):
        a2a_plugin._active_a2a_tasks["task-1"] = {"text": "first", "metadata": {}}
        return original_activate(_task)

    monkeypatch.setattr(a2a_plugin, "_activate_task_if_idle", activate_after_race)

    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")

    assert result is None
    assert list(a2a_plugin._active_a2a_tasks) == ["task-1"]
    a2a_plugin._active_a2a_tasks.clear()


def test_pre_llm_holds_pending_tasks_while_active(monkeypatch):
    a2a_plugin._active_a2a_tasks.clear()
    a2a_plugin._active_a2a_tasks["task-1"] = {"text": "first", "metadata": {}}
    fake_queue = MagicMock()
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_queue)

    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")

    assert result is None
    fake_queue.drain_pending.assert_not_called()
    a2a_plugin._active_a2a_tasks.clear()


def test_post_llm_completes_only_one_active_task(monkeypatch):
    completed = []
    fake_queue = MagicMock()
    fake_queue.complete.side_effect = lambda task_id, response: completed.append((task_id, response))
    fake_queue.pending_count.return_value = 0
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_queue)
    monkeypatch.setattr(a2a_plugin, "save_exchange", MagicMock())

    a2a_plugin._active_a2a_tasks.clear()
    a2a_plugin._active_a2a_tasks["task-1"] = {"text": "first", "metadata": {}}
    a2a_plugin._active_a2a_tasks["task-2"] = {"text": "second", "metadata": {}}

    a2a_plugin._on_post_llm_call(assistant_response="reply")

    assert completed == [("task-1", "reply")]
    a2a_plugin._active_a2a_tasks.clear()
