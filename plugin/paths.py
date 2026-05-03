"""Centralized runtime path resolution for the A2A plugin.

All on-disk paths (audit log, conversation directory, friends store,
future SQLite files) derive from the plugin's `name` field in
`plugin.yaml`. Multiple plugin instances can therefore coexist on the same
host without colliding on shared files — for example a production install
named `a2a` writing to `~/.hermes/a2a_*` while a hardening dev install named
`a2a-dev` writes to `~/.hermes/a2a-dev_*`.

This module is the single source of truth for these paths. Do not reintroduce
literal paths like `Path.home() / ".hermes" / "a2a_audit.jsonl"` elsewhere in
the plugin; import from here instead.
"""

from __future__ import annotations

from pathlib import Path

_PLUGIN_DIR = Path(__file__).resolve().parent


def _hermes_home() -> Path:
    return Path.home() / ".hermes"


def _read_plugin_name(plugin_dir: Path) -> str:
    """Read `name:` from plugin.yaml; fall back to the directory name."""
    yaml_path = plugin_dir / "plugin.yaml"
    if yaml_path.exists():
        try:
            for line in yaml_path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("name:"):
                    value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
        except OSError:
            pass
    return plugin_dir.name


_PLUGIN_NAME = _read_plugin_name(_PLUGIN_DIR)


def plugin_name() -> str:
    return _PLUGIN_NAME


def audit_log_path() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}_audit.jsonl"


def conversations_dir() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}_conversations"


def friends_path() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}_friends.json"


def stranger_requests_path() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}_stranger_requests.json"


def provenance_key_path() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}_provenance.key"


def db_path() -> Path:
    return _hermes_home() / f"{_PLUGIN_NAME}.db"


def compute_paths_for(plugin_dir: Path, hermes_home: Path | None = None) -> dict:
    """Pure helper used by tests and external callers.

    Computes the path set for an arbitrary plugin directory and Hermes home,
    bypassing the module-level state captured at import time. This lets tests
    verify the helper's behaviour for at least two plugin names without
    monkeypatching module globals.
    """
    name = _read_plugin_name(plugin_dir)
    home = hermes_home if hermes_home is not None else _hermes_home()
    return {
        "plugin_name": name,
        "audit_log": home / f"{name}_audit.jsonl",
        "conversations": home / f"{name}_conversations",
        "friends": home / f"{name}_friends.json",
        "stranger_requests": home / f"{name}_stranger_requests.json",
        "provenance_key": home / f"{name}_provenance.key",
        "db": home / f"{name}.db",
    }
