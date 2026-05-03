from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import provenance  # noqa: E402


def test_public_private_unknown_provenance_validate():
    public = provenance.Provenance.public_only()
    private = provenance.Provenance.private_source("memory")
    unknown = provenance.Provenance.unknown()

    assert public.state == provenance.STATE_PUBLIC
    assert public.public is True
    assert private.state == provenance.STATE_PRIVATE
    assert private.private is True
    assert unknown.state == provenance.STATE_UNKNOWN_PRIVATE
    assert unknown.unknown_private is True


def test_a2a_inbound_is_public_but_untrusted_with_replay_digest():
    prov = provenance.Provenance.a2a_inbound("hello   from remote", b"replay-key")

    assert prov.state == provenance.STATE_PUBLIC
    assert prov.public is True
    assert prov.private is False
    assert prov.trusted_public is False
    assert prov.untrusted is True
    assert prov.sources == ("a2a_inbound",)
    assert prov.source_digest_prefixes == (provenance.audit_digest("hello from remote", b"replay-key"),)


def test_a2a_inbound_source_is_untrusted_even_if_flag_missing():
    prov = provenance.Provenance(state=provenance.STATE_PUBLIC, sources=("a2a_inbound",))

    assert prov.state == provenance.STATE_PUBLIC
    assert prov.untrusted is True


def test_private_source_dominates_requested_public_state():
    prov = provenance.Provenance(state=provenance.STATE_PUBLIC, sources=("diary",))

    assert prov.state == provenance.STATE_PRIVATE


def test_unknown_source_label_fails_closed():
    prov = provenance.Provenance(state=provenance.STATE_PUBLIC, sources=("memory_v2",))

    assert prov.state == provenance.STATE_UNKNOWN_PRIVATE
    assert prov.sources == ("memory_v2",)


def test_missing_provenance_normalizes_to_public_when_not_required():
    prov = provenance.normalize_provenance(None)

    assert prov.state == provenance.STATE_PUBLIC


def test_missing_provenance_normalizes_to_unknown_private_when_required():
    prov = provenance.normalize_provenance(None, required=True)

    assert prov.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "missing_provenance" in prov.evidence


def test_invalid_provenance_normalizes_to_unknown_private():
    assert provenance.normalize_provenance("bad").state == provenance.STATE_UNKNOWN_PRIVATE
    assert provenance.normalize_provenance({"state": "root"}).state == provenance.STATE_UNKNOWN_PRIVATE
    assert provenance.normalize_provenance({"sources": "memory"}).state == provenance.STATE_UNKNOWN_PRIVATE
    assert provenance.normalize_provenance({"sources": ["public_user"], "untrusted": "yes"}).state == provenance.STATE_UNKNOWN_PRIVATE


def test_remote_metadata_provenance_is_ignored():
    metadata = {
        "provenance": {"state": "public", "sources": ["public_user"]},
        provenance.INTERNAL_PROVENANCE_KEY: {"state": "public", "sources": ["public_user"]},
        "sender_name": "remote",
    }

    clean = provenance.sanitize_remote_metadata(metadata)

    assert "provenance" not in clean
    assert provenance.INTERNAL_PROVENANCE_KEY not in clean
    assert clean["sender_name"] == "remote"


def test_attach_internal_provenance_uses_trusted_namespace_and_drops_remote():
    metadata = {
        "provenance": {"state": "public"},
        provenance.INTERNAL_PROVENANCE_KEY: {"state": "public"},
    }
    private = provenance.Provenance.private_source("memory")

    clean = provenance.attach_internal_provenance(metadata, private)

    assert "provenance" not in clean
    assert provenance.INTERNAL_PROVENANCE_KEY in clean
    trusted = provenance.trusted_from_metadata(clean, required=True)
    assert trusted.state == provenance.STATE_PRIVATE
    assert trusted.sources == ("memory",)


def test_merge_public_private_returns_private():
    merged = provenance.merge_provenance(
        provenance.Provenance.public_only(),
        provenance.Provenance.private_source("memory"),
    )

    assert merged.state == provenance.STATE_PRIVATE
    assert set(merged.sources) == {"memory", "public_user"}


def test_merge_public_unknown_private_returns_unknown_private():
    merged = provenance.merge_provenance(
        provenance.Provenance.public_only(),
        provenance.Provenance.unknown(),
    )

    assert merged.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "unknown_private" in merged.sources


def test_merge_public_untrusted_preserves_untrusted_risk():
    merged = provenance.merge_provenance(
        provenance.Provenance.public_only(),
        provenance.Provenance.a2a_inbound("remote text", "key"),
    )

    assert merged.state == provenance.STATE_PUBLIC
    assert merged.untrusted is True
    assert "a2a_inbound" in merged.sources


def test_derive_from_preserves_private_taint():
    derived = provenance.derive_from(provenance.Provenance.private_source("inbox"))

    assert derived.state == provenance.STATE_PRIVATE
    assert "inbox" in derived.sources
    assert "derived" in derived.evidence


def test_audit_digest_is_keyed_and_deterministic_with_same_key():
    d1 = provenance.audit_digest("private snippet", b"key-a")
    d2 = provenance.audit_digest("private   snippet", b"key-a")

    assert d1 == d2
    assert d1.startswith("ksha256:")


def test_audit_digest_changes_with_different_key():
    d1 = provenance.audit_digest("private snippet", b"key-a")
    d2 = provenance.audit_digest("private snippet", b"key-b")

    assert d1 != d2


def test_audit_digest_requires_key():
    try:
        provenance.audit_digest("private snippet", b"")
    except ValueError as exc:
        assert "key is required" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_invalid_audit_digest_prefix_is_dropped_from_projection():
    prov = provenance.Provenance.private_source(
        "diary",
        source_digest_prefixes=(
            "ksha256:/Users/example/.hermes/DIARY.md",
            "ksha256:not-hex",
            "sha256:abcdef12",
            "ksha256:abcdef12",
        ),
    )

    audit = prov.to_audit_projection()
    rendered = json.dumps(audit, sort_keys=True)

    assert audit["source_digest_prefixes"] == ["ksha256:abcdef12"]
    assert "/Users/example" not in rendered
    assert "not-hex" not in rendered


def test_public_audit_projection_does_not_leak_raw_source_paths_or_exact_labels():
    digest = provenance.audit_digest("/Users/example/.hermes/DIARY.md secret line", b"audit-key")
    prov = provenance.Provenance.private_source(
        "diary",
        source_digest_prefixes=(digest,),
        evidence=("/Users/example/.hermes/DIARY.md",),
    )

    audit = prov.to_audit_projection()
    rendered = json.dumps(audit, sort_keys=True)

    assert audit["source_buckets"] == ["core_memory"]
    assert "diary" not in rendered
    assert "DIARY.md" not in rendered
    assert "/Users/example" not in rendered
    assert digest in rendered


def test_serialization_round_trip_for_metadata_and_sidecar_json():
    prov = provenance.Provenance.private_source(
        "wakeup",
        source_digest_prefixes=(provenance.audit_digest("wake up content", "key"),),
        evidence=("unit_test",),
    )
    payload = provenance.serialize_for_json(prov)

    restored = provenance.deserialize_from_json(json.dumps(payload), required=True)

    assert restored == prov


def test_deserialize_invalid_json_fails_closed():
    restored = provenance.deserialize_from_json("{bad json", required=True)

    assert restored.state == provenance.STATE_UNKNOWN_PRIVATE
    assert "invalid_provenance_json" in restored.evidence
