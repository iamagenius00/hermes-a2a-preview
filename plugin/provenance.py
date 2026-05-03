"""Internal provenance helpers for A2A outbound safety.

This module is intentionally callsite-free in P3.2.1. It defines the data model
and pure helpers that later slices will wire into server/tools/permission paths.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


INTERNAL_PROVENANCE_KEY = "_a2a_internal_provenance"
REMOTE_PROVENANCE_KEY = "provenance"

STATE_PUBLIC = "public"
STATE_PRIVATE = "private"
STATE_UNKNOWN_PRIVATE = "unknown_private"
VALID_STATES = {STATE_PUBLIC, STATE_PRIVATE, STATE_UNKNOWN_PRIVATE}

BUCKET_PUBLIC = "public"
BUCKET_CORE_MEMORY = "core_memory"
BUCKET_LOCAL_SECRET = "local_secret"
BUCKET_CONVERSATION_ARCHIVE = "conversation_archive"
BUCKET_AUTOMATION_CONTEXT = "automation_context"
BUCKET_REMOTE_A2A = "remote_a2a"
BUCKET_PRIVATE_TOOL = "private_tool"
BUCKET_UNKNOWN_PRIVATE = "unknown_private"

SOURCE_BUCKETS = {
    "public_user": BUCKET_PUBLIC,
    "memory": BUCKET_CORE_MEMORY,
    "diary": BUCKET_CORE_MEMORY,
    "soul": BUCKET_CORE_MEMORY,
    "body": BUCKET_CORE_MEMORY,
    "env": BUCKET_LOCAL_SECRET,
    "private_file": BUCKET_LOCAL_SECRET,
    "inbox": BUCKET_CONVERSATION_ARCHIVE,
    "wakeup": BUCKET_AUTOMATION_CONTEXT,
    "a2a_inbound": BUCKET_REMOTE_A2A,
    "tool_private": BUCKET_PRIVATE_TOOL,
    "unknown_private": BUCKET_UNKNOWN_PRIVATE,
}

UNTRUSTED_SOURCES = {"a2a_inbound"}

PRIVATE_SOURCES = {
    "memory",
    "diary",
    "soul",
    "body",
    "env",
    "inbox",
    "wakeup",
    "private_file",
    "tool_private",
    "unknown_private",
}

VALID_SOURCES = frozenset(SOURCE_BUCKETS)
_AUDIT_DIGEST_RE = re.compile(r"^ksha256:[0-9a-f]{8,64}$")


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values if str(v)}))


def _state_for_sources(sources: Iterable[str], requested_state: str = "") -> str:
    source_set = set(sources)
    if source_set - VALID_SOURCES:
        return STATE_UNKNOWN_PRIVATE
    if "unknown_private" in source_set or requested_state == STATE_UNKNOWN_PRIVATE:
        return STATE_UNKNOWN_PRIVATE
    if source_set & PRIVATE_SOURCES or requested_state == STATE_PRIVATE:
        return STATE_PRIVATE
    return STATE_PUBLIC


def _normalize_digest_prefix(value: str) -> str:
    value = str(value)
    if _AUDIT_DIGEST_RE.fullmatch(value):
        return value
    return ""


@dataclass(frozen=True)
class Provenance:
    """Validated internal provenance metadata.

    `state` is one of public/private/unknown_private. `sources` may contain
    exact internal labels, but public audit projection only emits coarse buckets.
    """

    state: str = STATE_PUBLIC
    sources: tuple[str, ...] = field(default_factory=tuple)
    source_digest_prefixes: tuple[str, ...] = field(default_factory=tuple)
    evidence: tuple[str, ...] = field(default_factory=tuple)
    untrusted: bool = False

    def __post_init__(self) -> None:
        sources = _unique_sorted(self.sources)
        normalized_state = _state_for_sources(sources, self.state)
        untrusted = bool(self.untrusted) or bool(set(sources) & UNTRUSTED_SOURCES)
        digests = _unique_sorted(
            digest for digest in (self.source_digest_prefixes or ()) if _normalize_digest_prefix(digest)
        )
        evidence = _unique_sorted(self.evidence)
        object.__setattr__(self, "sources", sources)
        object.__setattr__(self, "state", normalized_state)
        object.__setattr__(self, "source_digest_prefixes", digests)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "untrusted", untrusted)

    @property
    def private(self) -> bool:
        return self.state in {STATE_PRIVATE, STATE_UNKNOWN_PRIVATE}

    @property
    def unknown_private(self) -> bool:
        return self.state == STATE_UNKNOWN_PRIVATE

    @property
    def public(self) -> bool:
        return self.state == STATE_PUBLIC

    @property
    def trusted_public(self) -> bool:
        return self.public and not self.untrusted

    @classmethod
    def public_only(cls) -> "Provenance":
        return cls(state=STATE_PUBLIC, sources=("public_user",))

    @classmethod
    def private_source(
        cls,
        source: str,
        *,
        source_digest_prefixes: Iterable[str] = (),
        evidence: Iterable[str] = (),
    ) -> "Provenance":
        return cls(
            state=STATE_PRIVATE,
            sources=(source,),
            source_digest_prefixes=tuple(source_digest_prefixes),
            evidence=tuple(evidence),
        )

    @classmethod
    def unknown(cls, *, evidence: Iterable[str] = ()) -> "Provenance":
        return cls(state=STATE_UNKNOWN_PRIVATE, sources=("unknown_private",), evidence=tuple(evidence))

    @classmethod
    def a2a_inbound(
        cls,
        text: str,
        key: bytes | str,
        *,
        evidence: Iterable[str] = ("server_a2a_inbound",),
    ) -> "Provenance":
        return cls(
            state=STATE_PUBLIC,
            sources=("a2a_inbound",),
            source_digest_prefixes=(audit_digest(text, key),),
            evidence=tuple(evidence),
            untrusted=True,
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "sources": list(self.sources),
            "source_digest_prefixes": list(self.source_digest_prefixes),
            "evidence": list(self.evidence),
            "untrusted": self.untrusted,
        }

    def to_audit_projection(self) -> dict[str, Any]:
        buckets = _unique_sorted(SOURCE_BUCKETS.get(source, BUCKET_UNKNOWN_PRIVATE) for source in self.sources)
        return {
            "source_classes": [self.state],
            "source_buckets": list(buckets),
            "source_digest_prefixes": list(self.source_digest_prefixes),
            "untrusted": self.untrusted,
        }


def normalize_provenance(value: Any, *, required: bool = False) -> Provenance:
    """Return a valid Provenance, failing closed when required.

    `required=True` is for A2A-originated response paths. Missing or malformed
    data becomes unknown_private instead of silently becoming public.
    """
    if isinstance(value, Provenance):
        return value
    if value is None:
        return Provenance.unknown(evidence=("missing_provenance",)) if required else Provenance.public_only()
    if not isinstance(value, Mapping):
        return Provenance.unknown(evidence=("invalid_provenance_shape",))
    try:
        state = str(value.get("state") or "")
        sources = value.get("sources") or ()
        digests = value.get("source_digest_prefixes") or value.get("source_ids") or ()
        evidence = value.get("evidence") or ()
        untrusted = value.get("untrusted", False)
        if state and state not in VALID_STATES:
            return Provenance.unknown(evidence=("invalid_provenance_state",))
        if not isinstance(sources, (list, tuple, set)):
            return Provenance.unknown(evidence=("invalid_provenance_sources",))
        if not isinstance(digests, (list, tuple, set)):
            return Provenance.unknown(evidence=("invalid_provenance_digests",))
        if not isinstance(evidence, (list, tuple, set)):
            return Provenance.unknown(evidence=("invalid_provenance_evidence",))
        if not isinstance(untrusted, bool):
            return Provenance.unknown(evidence=("invalid_provenance_untrusted",))
        return Provenance(
            state=state or STATE_PUBLIC,
            sources=tuple(str(source) for source in sources),
            source_digest_prefixes=tuple(str(digest) for digest in digests),
            evidence=tuple(str(item) for item in evidence),
            untrusted=untrusted,
        )
    except Exception:
        return Provenance.unknown(evidence=("invalid_provenance",))


def sanitize_remote_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Drop caller-controlled provenance while preserving other metadata."""
    clean = dict(metadata or {})
    clean.pop(REMOTE_PROVENANCE_KEY, None)
    clean.pop(INTERNAL_PROVENANCE_KEY, None)
    return clean


def trusted_from_metadata(metadata: Mapping[str, Any] | None, *, required: bool = False) -> Provenance:
    return normalize_provenance((metadata or {}).get(INTERNAL_PROVENANCE_KEY), required=required)


def attach_internal_provenance(metadata: Mapping[str, Any] | None, provenance: Provenance) -> dict[str, Any]:
    clean = sanitize_remote_metadata(metadata)
    clean[INTERNAL_PROVENANCE_KEY] = normalize_provenance(provenance, required=True).to_metadata()
    return clean


def merge_provenance(*items: Any) -> Provenance:
    normalized = [normalize_provenance(item) for item in items if item is not None]
    if not normalized:
        return Provenance.public_only()
    state = STATE_PUBLIC
    sources: list[str] = []
    digests: list[str] = []
    evidence: list[str] = []
    untrusted = False
    for item in normalized:
        if item.state == STATE_UNKNOWN_PRIVATE:
            state = STATE_UNKNOWN_PRIVATE
        elif item.state == STATE_PRIVATE and state != STATE_UNKNOWN_PRIVATE:
            state = STATE_PRIVATE
        sources.extend(item.sources)
        digests.extend(item.source_digest_prefixes)
        evidence.extend(item.evidence)
        untrusted = untrusted or item.untrusted
    return Provenance(
        state=state,
        sources=tuple(sources),
        source_digest_prefixes=tuple(digests),
        evidence=tuple(evidence),
        untrusted=untrusted,
    )


def derive_from(*items: Any, evidence: Iterable[str] = ("derived",)) -> Provenance:
    merged = merge_provenance(*items)
    return Provenance(
        state=merged.state,
        sources=merged.sources,
        source_digest_prefixes=merged.source_digest_prefixes,
        evidence=merged.evidence + tuple(evidence),
        untrusted=merged.untrusted,
    )


def audit_digest(text: str, key: bytes | str, *, prefix_len: int = 12) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise ValueError("audit digest key is required")
    normalized = " ".join(str(text).split()).encode("utf-8")
    digest = hmac.new(key, normalized, hashlib.sha256).hexdigest()
    return "ksha256:" + digest[:prefix_len]


def serialize_for_json(provenance: Any) -> dict[str, Any]:
    return normalize_provenance(provenance, required=True).to_metadata()


def deserialize_from_json(data: str | Mapping[str, Any] | None, *, required: bool = False) -> Provenance:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return Provenance.unknown(evidence=("invalid_provenance_json",))
    return normalize_provenance(data, required=required)
