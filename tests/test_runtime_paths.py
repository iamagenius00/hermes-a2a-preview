"""Tests for plugin/paths.py — runtime path resolution.

Covers Issue 0 acceptance criteria:

- The default install (`a2a`) writes to the same paths it does today.
- A different plugin name (e.g. `a2a-dev`) yields fully isolated paths.
- The helper is the single source of truth (other plugin modules import it).
- Tests cover at least two plugin names.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin.paths import compute_paths_for  # noqa: E402


def _make_plugin_dir(parent: Path, name: str | None, dir_name: str | None = None) -> Path:
    """Create a fake plugin directory with an optional plugin.yaml.

    `name` is what gets written into plugin.yaml as `name:`. If None, no
    plugin.yaml is created (so the helper falls back to the directory name).
    `dir_name` overrides the filesystem directory name; defaults to `name` or
    `"a2a"`.
    """
    final_dir_name = dir_name if dir_name is not None else (name or "a2a")
    plugin_dir = parent / final_dir_name
    plugin_dir.mkdir()
    if name is not None:
        (plugin_dir / "plugin.yaml").write_text(
            f'name: {name}\nversion: "0.0.0"\n',
            encoding="utf-8",
        )
    return plugin_dir


def test_default_plugin_name_yields_historical_paths(tmp_path):
    """Acceptance: the default install (`a2a`) writes to today's paths exactly."""
    plugin_dir = _make_plugin_dir(tmp_path, "a2a")
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    paths = compute_paths_for(plugin_dir, hermes_home=fake_home)

    assert paths["plugin_name"] == "a2a"
    assert paths["audit_log"] == fake_home / "a2a_audit.jsonl"
    assert paths["conversations"] == fake_home / "a2a_conversations"


def test_dev_plugin_name_yields_isolated_paths(tmp_path):
    """Acceptance: a plugin named `a2a-dev` writes to disjoint files."""
    plugin_dir = _make_plugin_dir(tmp_path, "a2a-dev")
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    paths = compute_paths_for(plugin_dir, hermes_home=fake_home)

    assert paths["plugin_name"] == "a2a-dev"
    assert paths["audit_log"] == fake_home / "a2a-dev_audit.jsonl"
    assert paths["conversations"] == fake_home / "a2a-dev_conversations"


def test_two_instances_do_not_share_files(tmp_path):
    """Acceptance: prod and dev plugins must not collide on any runtime file."""
    prod_dir = _make_plugin_dir(tmp_path, "a2a", dir_name="a2a")
    dev_dir = _make_plugin_dir(tmp_path, "a2a-dev", dir_name="a2a-dev")
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    prod = compute_paths_for(prod_dir, hermes_home=fake_home)
    dev = compute_paths_for(dev_dir, hermes_home=fake_home)

    overlapping_keys = (
        "audit_log",
        "conversations",
        "friends",
        "stranger_requests",
        "provenance_key",
        "db",
    )
    for key in overlapping_keys:
        assert prod[key] != dev[key], f"{key} collides between prod and dev"


def test_missing_plugin_yaml_falls_back_to_directory_name(tmp_path):
    plugin_dir = _make_plugin_dir(tmp_path, name=None, dir_name="a2a-fallback")
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    paths = compute_paths_for(plugin_dir, hermes_home=fake_home)

    assert paths["plugin_name"] == "a2a-fallback"
    assert paths["audit_log"] == fake_home / "a2a-fallback_audit.jsonl"


def test_quoted_name_is_unquoted(tmp_path):
    """plugin.yaml may quote the name; the helper should strip quotes."""
    plugin_dir = tmp_path / "a2a"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(
        'name: "a2a-quoted"\nversion: "0.0.0"\n',
        encoding="utf-8",
    )
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    paths = compute_paths_for(plugin_dir, hermes_home=fake_home)

    assert paths["plugin_name"] == "a2a-quoted"


def test_future_paths_also_isolated(tmp_path):
    """Issue 4 (friends.json) and Issue 11 (sqlite db) paths must also derive from
    plugin name, not a hard-coded prefix.
    """
    prod_dir = _make_plugin_dir(tmp_path, "a2a", dir_name="a2a")
    dev_dir = _make_plugin_dir(tmp_path, "a2a-dev", dir_name="a2a-dev")
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    prod = compute_paths_for(prod_dir, hermes_home=fake_home)
    dev = compute_paths_for(dev_dir, hermes_home=fake_home)

    assert prod["friends"] == fake_home / "a2a_friends.json"
    assert dev["friends"] == fake_home / "a2a-dev_friends.json"
    assert prod["stranger_requests"] == fake_home / "a2a_stranger_requests.json"
    assert dev["stranger_requests"] == fake_home / "a2a-dev_stranger_requests.json"
    assert prod["provenance_key"] == fake_home / "a2a_provenance.key"
    assert dev["provenance_key"] == fake_home / "a2a-dev_provenance.key"
    assert prod["db"] == fake_home / "a2a.db"
    assert dev["db"] == fake_home / "a2a-dev.db"


def test_module_level_constants_match_real_plugin(tmp_path):
    """The real plugin (`name: a2a` in plugin.yaml) must yield the historical paths.

    This is the strongest "no behavior change for prod" check: it imports the
    actual paths module and asserts its module-level resolution matches what
    the plugin used to write before Issue 0.
    """
    from plugin import paths as real_paths

    home = Path.home() / ".hermes"
    assert real_paths.plugin_name() == "a2a"
    assert real_paths.audit_log_path() == home / "a2a_audit.jsonl"
    assert real_paths.conversations_dir() == home / "a2a_conversations"
    assert real_paths.stranger_requests_path() == home / "a2a_stranger_requests.json"
    assert real_paths.provenance_key_path() == home / "a2a_provenance.key"
