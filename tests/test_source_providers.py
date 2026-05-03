from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugin as a2a_plugin  # noqa: E402
from plugin import provenance, source_providers  # noqa: E402
from plugin.permission import evaluate_outbound  # noqa: E402


def _trusted() -> dict:
    return {
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
    }


def test_provider_inventory_maps_private_sources():
    mapping = {item.name: item.source for item in source_providers.provider_inventory()}

    assert mapping["memory"] == "memory"
    assert mapping["diary"] == "diary"
    assert mapping["soul"] == "soul"
    assert mapping["body"] == "body"
    assert mapping["env"] == "env"
    assert mapping["inbox"] == "inbox"
    assert mapping["wakeup"] == "wakeup"
    assert mapping["tool_private"] == "tool_private"


def test_provider_missing_provenance_becomes_unknown_private_deny():
    prov = source_providers.trusted_provider_provenance({}, provider="memory", required=True)

    decision, _ = evaluate_outbound("ordinary text", _trusted(), provenance=prov)

    assert prov.state == provenance.STATE_UNKNOWN_PRIVATE
    assert decision.allow is False
    assert decision.reason == "unknown_private_provenance"


def test_provider_attached_provenance_becomes_private_deny_without_leaking_label():
    metadata = source_providers.attach_provider_provenance(
        {},
        "diary",
        content="private diary content",
        digest_key="audit-key",
    )
    prov = source_providers.trusted_provider_provenance(metadata, provider="diary", required=True)

    decision, _ = evaluate_outbound("ordinary text", _trusted(), provenance=prov)

    assert prov.state == provenance.STATE_PRIVATE
    assert prov.sources == ("diary",)
    assert decision.allow is False
    assert decision.reason == "private_provenance"
    rendered = json.dumps(decision.provenance, sort_keys=True)
    assert decision.provenance["source_buckets"] == ["core_memory"]
    assert '"diary"' not in rendered


def test_public_only_provenance_is_not_affected_by_provider_mapping():
    decision, _ = evaluate_outbound(
        "ordinary public text",
        _trusted(),
        provenance=provenance.Provenance.public_only(),
    )

    assert decision.allow is True
    assert decision.reason == "ok"


def test_active_task_provider_missing_provenance_merges_unknown_private():
    a2a_plugin._active_a2a_tasks.clear()
    task = SimpleNamespace(
        task_id="task-1",
        text="remote text",
        metadata=provenance.attach_internal_provenance({}, provenance.Provenance.a2a_inbound("remote text", "key")),
    )

    assert a2a_plugin._activate_task_if_idle(task) is True
    assert a2a_plugin._merge_active_task_provider_provenance("task-1", {}, provider="memory") is True

    active = a2a_plugin._active_a2a_tasks["task-1"]["metadata"]
    trusted = provenance.trusted_from_metadata(active, required=True)
    assert trusted.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "missing_provider_provenance" in trusted.evidence
    a2a_plugin._active_a2a_tasks.clear()


def test_active_task_provider_private_provenance_merges_private():
    a2a_plugin._active_a2a_tasks.clear()
    task = SimpleNamespace(
        task_id="task-1",
        text="remote text",
        metadata=provenance.attach_internal_provenance({}, provenance.Provenance.public_only()),
    )
    provider_metadata = source_providers.attach_provider_provenance(
        {},
        "inbox",
        content="saved context",
        digest_key="audit-key",
    )

    assert a2a_plugin._activate_task_if_idle(task) is True
    assert a2a_plugin._merge_active_task_provider_provenance("task-1", provider_metadata, provider="inbox") is True

    active = a2a_plugin._active_a2a_tasks["task-1"]["metadata"]
    trusted = provenance.trusted_from_metadata(active, required=True)
    assert trusted.state == provenance.STATE_PRIVATE
    assert set(trusted.sources) == {"inbox", "public_user"}
    a2a_plugin._active_a2a_tasks.clear()
