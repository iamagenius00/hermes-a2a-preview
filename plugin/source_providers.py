"""Private source provider provenance mapping.

P3.2.6 keeps this as conservative plumbing: provider hooks can use these
helpers to write internal provenance, and A2A response paths can fail closed
when a private-source-capable hook reports content without provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from . import provenance


@dataclass(frozen=True)
class SourceProvider:
    name: str
    source: str
    hook_location: str
    writer: str
    failure_mode: str = "missing provenance becomes unknown_private"


PROVIDER_HOOKS: dict[str, SourceProvider] = {
    "memory": SourceProvider("memory", "memory", "MEMORY reader", "attach_provider_provenance"),
    "diary": SourceProvider("diary", "diary", "DIARY reader", "attach_provider_provenance"),
    "soul": SourceProvider("soul", "soul", "SOUL reader", "attach_provider_provenance"),
    "body": SourceProvider("body", "body", "BODY reader", "attach_provider_provenance"),
    "env": SourceProvider("env", "env", ".env/process secret reader", "attach_provider_provenance"),
    "inbox": SourceProvider("inbox", "inbox", "inbox/conversation reader", "attach_provider_provenance"),
    "wakeup": SourceProvider("wakeup", "wakeup", "wakeup/context injector", "attach_provider_provenance"),
    "tool_private": SourceProvider("tool_private", "tool_private", "private tool result", "attach_provider_provenance"),
}


def provider_inventory() -> tuple[SourceProvider, ...]:
    return tuple(PROVIDER_HOOKS[name] for name in sorted(PROVIDER_HOOKS))


def provider_source(provider: str) -> str:
    hook = PROVIDER_HOOKS.get((provider or "").strip().lower())
    return hook.source if hook is not None else "unknown_private"


def build_provider_provenance(
    provider: str,
    *,
    content: str = "",
    digest_key: bytes | str | None = None,
    evidence: tuple[str, ...] = (),
) -> provenance.Provenance:
    source = provider_source(provider)
    if source == "unknown_private":
        return provenance.Provenance.unknown(evidence=("unknown_provider",) + tuple(evidence))

    digests = ()
    if content and digest_key:
        digests = (provenance.audit_digest(content, digest_key),)
    return provenance.Provenance.private_source(
        source,
        source_digest_prefixes=digests,
        evidence=(f"provider:{(provider or '').strip().lower()}",) + tuple(evidence),
    )


def attach_provider_provenance(
    metadata: Mapping[str, Any] | None,
    provider: str,
    *,
    content: str = "",
    digest_key: bytes | str | None = None,
    evidence: tuple[str, ...] = (),
) -> dict[str, Any]:
    return provenance.attach_internal_provenance(
        metadata,
        build_provider_provenance(
            provider,
            content=content,
            digest_key=digest_key,
            evidence=evidence,
        ),
    )


def trusted_provider_provenance(
    metadata: Mapping[str, Any] | None,
    *,
    provider: str = "",
    required: bool = True,
) -> provenance.Provenance:
    if not metadata or provenance.INTERNAL_PROVENANCE_KEY not in metadata:
        evidence = ("missing_provider_provenance",)
        if provider:
            evidence += (f"provider:{(provider or '').strip().lower()}",)
        return provenance.Provenance.unknown(evidence=evidence) if required else provenance.Provenance.public_only()
    return provenance.trusted_from_metadata(metadata, required=required)
