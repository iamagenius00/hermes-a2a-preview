from __future__ import annotations

import sys
from pathlib import Path
from threading import Event
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugin as a2a_plugin  # noqa: E402
from plugin import provenance, server  # noqa: E402


class _FakeTask:
    def __init__(self):
        self.response = None
        self.ready = Event()
        self.ready.set()


class _FakeQueue:
    def __init__(self):
        self.enqueued = []

    def pending_count(self):
        return 0

    def enqueue(self, task_id, text, metadata):
        self.enqueued.append((task_id, text, metadata))
        return _FakeTask()


def _send_task(monkeypatch, metadata):
    queue = _FakeQueue()
    monkeypatch.setattr(server, "task_queue", queue)
    monkeypatch.setattr(server, "_trigger_webhook", lambda: None)
    handler = SimpleNamespace(client_address=("203.0.113.9", 12345))

    result = server.A2ARequestHandler._handle_task_send(handler, {
        "id": "task-1",
        "message": {
            "parts": [{"type": "text", "text": "hello"}],
            "metadata": metadata,
        },
    })

    assert result["status"]["state"] == "working"
    assert len(queue.enqueued) == 1
    return queue.enqueued[0][2]


def test_inbound_task_ignores_remote_provenance_spoof(monkeypatch):
    monkeypatch.setenv("A2A_PROVENANCE_DIGEST_KEY", "unit-replay-key")
    metadata = _send_task(monkeypatch, {
        "sender_name": "remote",
        "provenance": {"state": "public", "sources": ["public_user"]},
        provenance.INTERNAL_PROVENANCE_KEY: {"state": "private", "sources": ["memory"]},
    })

    assert "provenance" not in metadata
    trusted = provenance.trusted_from_metadata(metadata, required=True)
    assert trusted.state == provenance.STATE_PUBLIC
    assert trusted.sources == ("a2a_inbound",)
    assert trusted.untrusted is True
    assert trusted.source_digest_prefixes == (provenance.audit_digest("hello", "unit-replay-key"),)
    assert "server_a2a_inbound" in trusted.evidence


def test_inbound_task_gets_server_written_internal_provenance(monkeypatch):
    monkeypatch.setenv("A2A_PROVENANCE_DIGEST_KEY", "unit-replay-key")
    metadata = _send_task(monkeypatch, {"agent_name": "alice"})

    assert provenance.INTERNAL_PROVENANCE_KEY in metadata
    trusted = provenance.trusted_from_metadata(metadata, required=True)
    assert trusted.state == provenance.STATE_PUBLIC
    assert trusted.sources == ("a2a_inbound",)
    assert trusted.untrusted is True
    assert trusted.source_digest_prefixes == (provenance.audit_digest("hello", "unit-replay-key"),)
    assert metadata["sender_name"] == "alice"


def test_active_task_preserves_internal_provenance():
    a2a_plugin._active_a2a_tasks.clear()
    metadata = provenance.attach_internal_provenance(
        {"sender_name": "alice"},
        provenance.Provenance(state=provenance.STATE_PUBLIC, sources=("a2a_inbound",)),
    )
    task = SimpleNamespace(task_id="task-1", text="hello", metadata=metadata)

    assert a2a_plugin._activate_task_if_idle(task) is True

    active = a2a_plugin._active_a2a_tasks["task-1"]["metadata"]
    trusted = provenance.trusted_from_metadata(active, required=True)
    assert trusted.state == provenance.STATE_PUBLIC
    assert trusted.sources == ("a2a_inbound",)
    assert trusted.untrusted is True
    assert active["sender_name"] == "alice"
    a2a_plugin._active_a2a_tasks.clear()


def test_active_task_missing_internal_provenance_becomes_unknown_private():
    a2a_plugin._active_a2a_tasks.clear()
    task = SimpleNamespace(task_id="task-1", text="hello", metadata={})

    assert a2a_plugin._activate_task_if_idle(task) is True

    active = a2a_plugin._active_a2a_tasks["task-1"]["metadata"]
    trusted = provenance.trusted_from_metadata(active, required=True)
    assert trusted.state == provenance.STATE_UNKNOWN_PRIVATE
    assert trusted.sources == ("unknown_private",)
    assert "missing_provenance" in trusted.evidence
    a2a_plugin._active_a2a_tasks.clear()


def test_active_task_malformed_internal_provenance_becomes_unknown_private():
    a2a_plugin._active_a2a_tasks.clear()
    task = SimpleNamespace(
        task_id="task-1",
        text="hello",
        metadata={provenance.INTERNAL_PROVENANCE_KEY: {"state": "root", "sources": ["public_user"]}},
    )

    assert a2a_plugin._activate_task_if_idle(task) is True

    active = a2a_plugin._active_a2a_tasks["task-1"]["metadata"]
    trusted = provenance.trusted_from_metadata(active, required=True)
    assert trusted.state == provenance.STATE_UNKNOWN_PRIVATE
    assert trusted.sources == ("unknown_private",)
    assert "invalid_provenance_state" in trusted.evidence
    a2a_plugin._active_a2a_tasks.clear()


def test_server_completion_denies_private_provenance(monkeypatch):
    events = []
    monkeypatch.setattr(server.audit, "log", lambda event, data: events.append((event, data)))
    handler = SimpleNamespace(_friend={
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
    })
    metadata = provenance.attach_internal_provenance(
        {"sender_name": "alice"},
        provenance.Provenance.private_source("memory"),
    )
    task = SimpleNamespace(task_id="task-1", text="remote text", response="private reply", metadata=metadata)

    result = server.A2ARequestHandler._completion_result_for_task(handler, task)

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert result["status"]["state"] == "failed"
    assert "private-source provenance" in result["artifacts"][0]["parts"][0]["text"]
    assert denied["reason"] == "private_provenance"
    assert denied["provenance"]["source_buckets"] == ["core_memory"]


def test_server_completion_denies_a2a_replay(monkeypatch):
    events = []
    monkeypatch.setattr(server.audit, "log", lambda event, data: events.append((event, data)))
    handler = SimpleNamespace(_friend={
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
    })
    metadata = provenance.attach_internal_provenance(
        {"sender_name": "alice"},
        provenance.Provenance.a2a_inbound("remote text", "audit-key"),
    )
    task = SimpleNamespace(task_id="task-1", text="remote text", response="remote text", metadata=metadata)

    result = server.A2ARequestHandler._completion_result_for_task(handler, task)

    denied = [data for event, data in events if event == "outbound_denied"][0]
    assert result["status"]["state"] == "failed"
    assert "replay untrusted inbound A2A content" in result["artifacts"][0]["parts"][0]["text"]
    assert denied["reason"] == "a2a_replay"


def test_server_completion_allows_public_provenance(monkeypatch):
    events = []
    monkeypatch.setattr(server.audit, "log", lambda event, data: events.append((event, data)))
    handler = SimpleNamespace(_friend={
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
    })
    metadata = provenance.attach_internal_provenance(
        {"sender_name": "alice"},
        provenance.Provenance.public_only(),
    )
    task = SimpleNamespace(task_id="task-1", text="remote text", response="public reply", metadata=metadata)

    result = server.A2ARequestHandler._completion_result_for_task(handler, task)

    completed = [data for event, data in events if event == "task_completed"][0]
    assert result["status"]["state"] == "completed"
    assert result["artifacts"][0]["parts"][0]["text"] == "public reply"
    assert completed["provenance"]["source_classes"] == [provenance.STATE_PUBLIC]
