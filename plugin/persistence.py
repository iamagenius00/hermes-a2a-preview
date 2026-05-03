"""A2A conversation persistence — stores interactions to disk so compaction can't erase them.

Format matches ~/inbox/conversations/{agent}/{date}.md for consistency.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from . import provenance
from .paths import conversations_dir

_CONV_DIR = conversations_dir()
_SIDECAR_SCHEMA_VERSION = 1
_lock = Lock()


def _safe_agent_name(agent_name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_name.lower())


def provenance_sidecar_path(agent_name: str, date: str | None = None) -> Path:
    today = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _CONV_DIR / _safe_agent_name(agent_name) / f"{today}.provenance.json"


def _read_sidecar(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": _SIDECAR_SCHEMA_VERSION, "records": {}, "task_index": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": _SIDECAR_SCHEMA_VERSION, "records": {}, "task_index": {}}
    if not isinstance(data, dict) or not isinstance(data.get("records"), dict):
        return {"schema_version": _SIDECAR_SCHEMA_VERSION, "records": {}, "task_index": {}}
    data["schema_version"] = _SIDECAR_SCHEMA_VERSION
    if not isinstance(data.get("task_index"), dict):
        data["task_index"] = {}
    return data


def _new_occurrence_id(records: dict[str, Any], task_id: str, now: datetime) -> str:
    base = f"{now.strftime('%Y%m%dT%H%M%S.%fZ')}:{task_id}"
    occurrence_id = base
    counter = 2
    while occurrence_id in records:
        occurrence_id = f"{base}:{counter}"
        counter += 1
    return occurrence_id


def _write_provenance_sidecar(
    agent_name: str,
    task_id: str,
    metadata: dict | None,
    direction: str,
    now: datetime,
) -> None:
    if not isinstance(metadata, dict) or provenance.INTERNAL_PROVENANCE_KEY not in metadata:
        return

    prov = provenance.trusted_from_metadata(metadata, required=True)
    sidecar_prov = provenance.Provenance(
        state=prov.state,
        sources=prov.sources,
        source_digest_prefixes=prov.source_digest_prefixes,
        untrusted=prov.untrusted,
    )
    path = provenance_sidecar_path(agent_name, now.strftime("%Y-%m-%d"))
    data = _read_sidecar(path)
    records = data.setdefault("records", {})
    task_index = data.setdefault("task_index", {})
    occurrence_id = _new_occurrence_id(records, task_id, now)
    records[occurrence_id] = {
        "occurrence_id": occurrence_id,
        "task_id": task_id,
        "direction": direction,
        "updated_at": now.isoformat(),
        "provenance": provenance.serialize_for_json(sidecar_prov),
    }
    existing = task_index.get(task_id, [])
    if not isinstance(existing, list):
        existing = []
    existing.append(occurrence_id)
    task_index[task_id] = existing
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_exchange_provenance(
    agent_name: str,
    task_id: str,
    *,
    date: str | None = None,
    required: bool = False,
) -> provenance.Provenance:
    path = provenance_sidecar_path(agent_name, date)
    if not path.exists():
        return provenance.normalize_provenance(None, required=required)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        records = data.get("records", {})
        task_index = data.get("task_index", {})
        if not isinstance(records, dict):
            return provenance.Provenance.unknown(evidence=("invalid_provenance_sidecar",))

        if isinstance(task_index, dict) and task_id in task_index:
            occurrence_ids = task_index.get(task_id)
            if not isinstance(occurrence_ids, list):
                return provenance.Provenance.unknown(evidence=("invalid_provenance_sidecar",))
            matching = [records.get(str(item)) for item in occurrence_ids if isinstance(records.get(str(item)), dict)]
            if len(matching) != 1:
                return provenance.Provenance.unknown(evidence=("ambiguous_provenance_sidecar",))
            record = matching[0]
        else:
            record = records.get(task_id)
        if not isinstance(record, dict):
            return provenance.normalize_provenance(None, required=required)
        return provenance.normalize_provenance(record.get("provenance"), required=required)
    except Exception:
        return provenance.Provenance.unknown(evidence=("invalid_provenance_sidecar",))


def _exchange_blocks_for_task(markdown: str, task_id: str) -> list[str]:
    blocks: list[str] = []
    marker = f"task:{task_id}"
    start = 0
    while True:
        marker_pos = markdown.find(marker, start)
        if marker_pos == -1:
            return blocks
        block_start = markdown.rfind("## ", 0, marker_pos)
        if block_start == -1:
            start = marker_pos + len(marker)
            continue
        block_end = markdown.find("\n---\n", block_start)
        if block_end == -1:
            block_end = len(markdown)
        blocks.append(markdown[block_start:block_end])
        start = marker_pos + len(marker)


def _extract_saved_inbound_text(block: str, safe_name: str) -> str:
    prefix = f"**← {safe_name}:** "
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        captured = [line[len(prefix):]]
        for follow in lines[index + 1:]:
            if not follow or follow.startswith("**→ ") or follow.startswith("**← ") or follow.startswith("## "):
                break
            captured.append(follow)
        return "\n".join(captured).strip()
    return ""


def load_exchange_replay_texts(
    agent_name: str,
    task_id: str,
    *,
    date: str | None = None,
) -> tuple[str, ...]:
    today = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_name = _safe_agent_name(agent_name)
    path = _CONV_DIR / safe_name / f"{today}.md"
    if not path.exists():
        return ()
    try:
        blocks = _exchange_blocks_for_task(path.read_text(encoding="utf-8"), task_id)
    except OSError:
        return ()
    if len(blocks) != 1:
        return ()
    text = _extract_saved_inbound_text(blocks[0], safe_name)
    return (text,) if text else ()


def save_exchange(
    agent_name: str,
    task_id: str,
    inbound_text: str,
    outbound_text: str,
    metadata: dict | None = None,
    direction: str = "inbound",
) -> Path:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    timestamp = now.strftime("%H:%M:%S")
    safe_name = _safe_agent_name(agent_name)
    directory = _CONV_DIR / safe_name
    filepath = directory / f"{today}.md"

    intent = (metadata or {}).get("intent", "")
    reply_to = (metadata or {}).get("reply_to_task_id", "")

    entry_lines = [f"## {timestamp} | task:{task_id}"]
    if intent:
        entry_lines[0] += f" | {intent}"
    if reply_to:
        entry_lines[0] += f" | reply_to:{reply_to}"
    entry_lines.append("")

    if direction == "outbound":
        entry_lines.append(f"**→ me:** {outbound_text}")
        entry_lines.append("")
        entry_lines.append(f"**← {safe_name}:** {inbound_text}")
    else:
        entry_lines.append(f"**← {safe_name}:** {inbound_text}")
        entry_lines.append("")
        entry_lines.append(f"**→ reply:** {outbound_text}")

    entry_lines.append("")
    entry_lines.append("---")
    entry_lines.append("")

    with _lock:
        directory.mkdir(parents=True, exist_ok=True)
        with open(filepath, "a", encoding="utf-8") as f:
            f.write("\n".join(entry_lines))
        _write_provenance_sidecar(agent_name, task_id, metadata, direction, now)

    return filepath


def update_exchange(
    agent_name: str,
    task_id: str,
    inbound_text: str,
) -> bool:
    """Update the inbound text of an existing exchange (e.g. replace 'waiting' with actual reply)."""
    safe_name = _safe_agent_name(agent_name)
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    filepath = _CONV_DIR / safe_name / f"{today}.md"

    if not filepath.exists():
        return False

    with _lock:
        content = filepath.read_text(encoding="utf-8")
        # Find the entry with this task_id and replace the waiting placeholder
        marker = f"task:{task_id}"
        start = content.find(marker)
        if start == -1:
            return False
        block_start = content.rfind("## ", 0, start)
        if block_start == -1:
            return False
        block_end = content.find("\n---\n", block_start)
        if block_end == -1:
            block_end = len(content)
        else:
            block_end += len("\n---\n")

        block = content[block_start:block_end]
        updated_block = block.replace(
            f"**← {safe_name}:** (waiting for reply…)",
            f"**← {safe_name}:** {inbound_text}",
            1,
        )
        if updated_block == block:
            return False
        updated = content[:block_start] + updated_block + content[block_end:]
        filepath.write_text(updated, encoding="utf-8")
    return True
