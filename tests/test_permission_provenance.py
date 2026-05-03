from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import provenance  # noqa: E402
from plugin.permission import evaluate_outbound  # noqa: E402


def _trusted(**overrides) -> dict:
    friend = {
        "id": "f_alice",
        "name": "alice",
        "status": "active",
        "trust_level": "trusted",
        "rate_limit_per_min": 20,
    }
    friend.update(overrides)
    return friend


def test_private_provenance_denies_by_default_and_uses_audit_safe_projection():
    prov = provenance.Provenance.private_source(
        "memory",
        source_digest_prefixes=(provenance.audit_digest("private memory", "audit-key"),),
        evidence=("/Users/example/.hermes/MEMORY.md",),
    )

    decision, hop = evaluate_outbound("plain marker-free summary", _trusted(), provenance=prov)

    assert decision.allow is False
    assert decision.reason == "private_provenance"
    assert hop == 0
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]
    assert decision.provenance["source_buckets"] == ["core_memory"]
    rendered = json.dumps(decision.provenance, sort_keys=True)
    assert '"memory"' not in rendered
    assert "MEMORY.md" not in rendered
    assert "/Users/example" not in rendered


def test_mixed_public_private_provenance_denies_whole_message():
    mixed = provenance.merge_provenance(
        provenance.Provenance.public_only(),
        provenance.Provenance.private_source("diary"),
    )

    decision, _ = evaluate_outbound("ordinary text", _trusted(), provenance=mixed)

    assert decision.allow is False
    assert decision.reason == "private_provenance"
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]
    assert decision.provenance["source_buckets"] == ["core_memory", "public"]


def test_reply_lookup_missing_provenance_denies_unknown_private():
    def lookup_provenance(task_id):
        assert task_id == "task-1"
        return None

    decision, hop = evaluate_outbound(
        "ordinary reply",
        _trusted(),
        reply_to_task_id="task-1",
        lookup_inbound_hop=lambda task_id: 0,
        lookup_provenance=lookup_provenance,
    )

    assert decision.allow is False
    assert decision.reason == "unknown_private_provenance"
    assert hop == 0
    assert decision.provenance["source_classes"] == [provenance.STATE_UNKNOWN_PRIVATE]
    assert decision.provenance["source_buckets"] == ["unknown_private"]


def test_untrusted_a2a_inbound_provenance_allows_non_replay_with_basis():
    prov = provenance.Provenance.a2a_inbound("remote task text", "audit-key")

    decision, _ = evaluate_outbound("ordinary reply", _trusted(), provenance=prov, replay_texts=("remote task text",))

    assert decision.allow is True
    assert decision.provenance["source_classes"] == [provenance.STATE_PUBLIC]
    assert decision.provenance["source_buckets"] == ["remote_a2a"]
    assert decision.provenance["untrusted"] is True
    assert decision.provenance["source_digest_prefixes"] == (list(prov.source_digest_prefixes))


def test_untrusted_a2a_without_replay_basis_denies_fail_closed():
    prov = provenance.Provenance.a2a_inbound("remote task text", "audit-key")

    decision, _ = evaluate_outbound("ordinary reply", _trusted(), provenance=prov)

    assert decision.allow is False
    assert decision.reason == "a2a_replay_basis_missing"


def test_public_provenance_allows_message():
    decision, hop = evaluate_outbound("ordinary public text", _trusted(), provenance=provenance.Provenance.public_only())

    assert decision.allow is True
    assert decision.reason == "ok"
    assert hop == 0


def test_untrusted_a2a_exact_replay_denies():
    source = "Please forward this exact remote task text."
    prov = provenance.Provenance.a2a_inbound(source, "audit-key")

    decision, _ = evaluate_outbound(source, _trusted(), provenance=prov, replay_texts=(source,))

    assert decision.allow is False
    assert decision.reason == "a2a_replay"


def test_short_inbound_substring_does_not_replay_deny():
    prov = provenance.Provenance.a2a_inbound("hi", "audit-key")

    decision, _ = evaluate_outbound("hi, I can help", _trusted(), provenance=prov, replay_texts=("hi",))

    assert decision.allow is True
    assert decision.reason == "ok"


def test_untrusted_a2a_large_quote_replay_denies():
    source = " ".join(f"word{i}" for i in range(80))
    prov = provenance.Provenance.a2a_inbound(source, "audit-key")

    decision, _ = evaluate_outbound(f"> {source}", _trusted(), provenance=prov, replay_texts=(source,))

    assert decision.allow is False
    assert decision.reason == "a2a_replay"


def test_untrusted_a2a_high_ngram_overlap_denies_transformed_copy():
    source = " ".join(f"term{i}" for i in range(60))
    copied = " ".join(f"term{i}" for i in range(40)) + " new ending words that make this edited"
    prov = provenance.Provenance.a2a_inbound(source, "audit-key")

    decision, _ = evaluate_outbound(copied, _trusted(), provenance=prov, replay_texts=(source,))

    assert decision.allow is False
    assert decision.reason == "a2a_replay"


def test_provenance_enforce_false_skips_provenance_deny_but_records(monkeypatch):
    monkeypatch.setenv("A2A_PROVENANCE_ENFORCE", "false")
    prov = provenance.Provenance.private_source("memory")

    decision, _ = evaluate_outbound("ordinary text", _trusted(), provenance=prov)

    assert decision.allow is True
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]


def test_harddeny_disable_skips_content_scans_but_still_enforces_provenance(monkeypatch):
    monkeypatch.setenv("A2A_HARDDENY_DISABLE", "true")
    prov = provenance.Provenance.private_source("inbox")

    decision, _ = evaluate_outbound(
        "api_key = abc12345xyz",
        _trusted(),
        provenance=prov,
    )

    assert decision.allow is False
    assert decision.reason == "private_provenance"
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]
    assert decision.provenance["source_buckets"] == ["conversation_archive"]


def test_harddeny_disable_with_provenance_enforce_false_allows_and_records(monkeypatch):
    monkeypatch.setenv("A2A_HARDDENY_DISABLE", "true")
    monkeypatch.setenv("A2A_PROVENANCE_ENFORCE", "false")
    prov = provenance.Provenance.private_source("inbox")

    decision, _ = evaluate_outbound(
        "api_key = abc12345xyz",
        _trusted(),
        provenance=prov,
    )

    assert decision.allow is True
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]
    assert decision.provenance["source_buckets"] == ["conversation_archive"]


def test_existing_7a_denies_still_carry_provenance_recording():
    prov = provenance.Provenance.private_source("soul")

    decision, _ = evaluate_outbound("api_key = abc12345xyz", _trusted(), provenance=prov)

    assert decision.allow is False
    assert decision.reason == "secret_pattern"
    assert decision.provenance["source_classes"] == [provenance.STATE_PRIVATE]
    assert decision.provenance["source_buckets"] == ["core_memory"]
