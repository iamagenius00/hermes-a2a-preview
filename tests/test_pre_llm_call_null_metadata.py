"""Regression test for the silent-crash bug in _on_pre_llm_call.

When an A2A task arrives with metadata containing explicit `None` for
`reply_to_task_id`, `intent`, `expected_action`, or `context_scope`,
the hook used to crash with TypeError (`NoneType[:64]`). The crash was
swallowed by run_agent.py's broad except, so the task appeared
successful (server.complete called via post hook state) but the LLM
never saw the message body.

These tests verify each None metadata field is normalized to its default
without raising.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Plugin directory contains relative imports (`from .schemas import ...`),
# so we must import it as a package. Add its parent to sys.path and
# import as `plugin`.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugin as a2a_plugin  # noqa: E402


def _make_task(metadata):
    t = MagicMock()
    t.task_id = "task-test-001"
    t.text = "hello body"
    t.metadata = metadata
    return t


def _patch_queue_with_task(monkeypatch, task):
    fake_q = MagicMock()
    fake_q.drain_pending.return_value = [task]
    monkeypatch.setattr(a2a_plugin.a2a_server, "task_queue", fake_q)
    a2a_plugin._active_a2a_tasks.clear()


def test_none_reply_to_task_id_does_not_crash(monkeypatch):
    task = _make_task({"reply_to_task_id": None})
    _patch_queue_with_task(monkeypatch, task)
    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")
    assert isinstance(result, dict)
    assert "hello body" in result["context"]
    assert "reply_to:" not in result["context"]


def test_none_intent_normalized_to_unknown(monkeypatch):
    task = _make_task({"intent": None})
    _patch_queue_with_task(monkeypatch, task)
    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")
    assert "intent:unknown" in result["context"]


def test_none_expected_action_normalized_to_reply(monkeypatch):
    task = _make_task({"expected_action": None})
    _patch_queue_with_task(monkeypatch, task)
    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")
    assert "expected:reply" in result["context"]


def test_none_context_scope_normalized_to_full(monkeypatch):
    task = _make_task({"context_scope": None})
    _patch_queue_with_task(monkeypatch, task)
    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")
    assert "scope:full" in result["context"]


def test_all_metadata_fields_none(monkeypatch):
    """Worst case: every optional field explicitly None — all defaults applied."""
    task = _make_task({
        "intent": None,
        "expected_action": None,
        "context_scope": None,
        "reply_to_task_id": None,
    })
    _patch_queue_with_task(monkeypatch, task)
    result = a2a_plugin._on_pre_llm_call(conversation_history=[], user_message="[A2A trigger]")
    ctx = result["context"]
    assert "intent:unknown" in ctx
    assert "expected:reply" in ctx
    assert "scope:full" in ctx
    assert "reply_to:" not in ctx
    assert "hello body" in ctx
