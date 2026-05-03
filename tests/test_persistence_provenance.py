from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import persistence, provenance  # noqa: E402


def test_save_exchange_writes_provenance_sidecar_without_markdown_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    prov = provenance.Provenance.a2a_inbound("remote text", "sidecar-key")
    metadata = provenance.attach_internal_provenance({"sender_name": "alice"}, prov)

    markdown_path = persistence.save_exchange(
        agent_name="Alice Agent",
        task_id="task-1",
        inbound_text="remote text",
        outbound_text="local reply",
        metadata=metadata,
    )

    sidecar_path = persistence.provenance_sidecar_path("Alice Agent")
    markdown = markdown_path.read_text(encoding="utf-8")
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))

    assert provenance.INTERNAL_PROVENANCE_KEY not in markdown
    assert "a2a_inbound" not in markdown
    assert sidecar["schema_version"] == 1
    assert len(sidecar["records"]) == 1
    occurrence_id = sidecar["task_index"]["task-1"][0]
    assert sidecar["records"][occurrence_id]["task_id"] == "task-1"
    restored = provenance.normalize_provenance(sidecar["records"][occurrence_id]["provenance"], required=True)
    assert restored.state == prov.state
    assert restored.sources == prov.sources
    assert restored.source_digest_prefixes == prov.source_digest_prefixes
    assert restored.untrusted is True


def test_load_exchange_provenance_round_trips_sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    prov = provenance.Provenance.private_source(
        "diary",
        source_digest_prefixes=(provenance.audit_digest("/Users/example/.hermes/DIARY.md", "key"),),
        evidence=("/Users/example/.hermes/DIARY.md",),
    )
    metadata = provenance.attach_internal_provenance({}, prov)

    persistence.save_exchange(
        agent_name="alice",
        task_id="task-2",
        inbound_text="remote text",
        outbound_text="local reply",
        metadata=metadata,
    )

    restored = persistence.load_exchange_provenance("alice", "task-2", required=True)

    assert restored.state == prov.state
    assert restored.sources == prov.sources
    assert restored.source_digest_prefixes == prov.source_digest_prefixes
    assert restored.evidence == ()
    rendered = persistence.provenance_sidecar_path("alice").read_text(encoding="utf-8")
    assert "remote text" not in rendered
    assert "local reply" not in rendered
    assert "/Users/example" not in rendered
    assert "DIARY.md" not in rendered


def test_load_exchange_replay_texts_reads_unique_saved_inbound_text(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("remote text", "key"),
    )
    persistence.save_exchange(
        agent_name="alice",
        task_id="task-3",
        inbound_text="remote text",
        outbound_text="local reply",
        metadata=metadata,
    )

    assert persistence.load_exchange_replay_texts("alice", "task-3") == ("remote text",)


def test_load_exchange_replay_texts_returns_empty_for_ambiguous_task_id(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("remote text", "key"),
    )
    for inbound in ("first remote text", "second remote text"):
        persistence.save_exchange(
            agent_name="alice",
            task_id="dup-task",
            inbound_text=inbound,
            outbound_text="local reply",
            metadata=metadata,
        )

    assert persistence.load_exchange_replay_texts("alice", "dup-task") == ()


def test_missing_sidecar_fails_closed_when_required(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)

    restored = persistence.load_exchange_provenance("alice", "missing", required=True)

    assert restored.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "missing_provenance" in restored.evidence


def test_duplicate_task_id_sidecar_lookup_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    public_metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.a2a_inbound("first remote text", "key-a"),
    )
    private_metadata = provenance.attach_internal_provenance(
        {},
        provenance.Provenance.private_source("diary", source_digest_prefixes=(provenance.audit_digest("secret", "key-b"),)),
    )

    persistence.save_exchange(
        agent_name="alice",
        task_id="caller-controlled-id",
        inbound_text="first remote text",
        outbound_text="local reply",
        metadata=public_metadata,
    )
    persistence.save_exchange(
        agent_name="alice",
        task_id="caller-controlled-id",
        inbound_text="second remote text",
        outbound_text="second reply",
        metadata=private_metadata,
    )

    sidecar = json.loads(persistence.provenance_sidecar_path("alice").read_text(encoding="utf-8"))
    restored = persistence.load_exchange_provenance("alice", "caller-controlled-id", required=True)

    assert len(sidecar["records"]) == 2
    assert len(sidecar["task_index"]["caller-controlled-id"]) == 2
    assert restored.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "ambiguous_provenance_sidecar" in restored.evidence


def test_corrupt_sidecar_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "_CONV_DIR", tmp_path)
    path = persistence.provenance_sidecar_path("alice")
    path.parent.mkdir(parents=True)
    path.write_text("{bad json", encoding="utf-8")

    restored = persistence.load_exchange_provenance("alice", "task-1", required=True)

    assert restored.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "invalid_provenance_sidecar" in restored.evidence
