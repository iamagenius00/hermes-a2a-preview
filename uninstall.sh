#!/bin/bash
# Uninstall hermes-a2a plugin files and installer-managed config.

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/a2a"
ENV_FILE="$HERMES_HOME/.env"
CONFIG_FILE="$HERMES_HOME/config.yaml"

_timestamp() {
    date +%Y%m%d%H%M%S
}

_unique_path() {
    local base="$1"
    local candidate="$base"
    local n=1
    while [ -e "$candidate" ]; do
        candidate="${base}.${n}"
        n=$((n + 1))
    done
    printf '%s\n' "$candidate"
}

_backup_file() {
    local path="$1"
    if [ -f "$path" ]; then
        local backup
        backup="$(_unique_path "$path.bak.$(_timestamp)")"
        cp -p "$path" "$backup"
        echo "Backed up $path to $backup"
    fi
}

_move_plugin() {
    if [ -d "$PLUGIN_DIR" ]; then
        local backup
        backup="$(_unique_path "$PLUGIN_DIR.uninstalled.$(_timestamp)")"
        mv "$PLUGIN_DIR" "$backup"
        echo "Moved plugin to $backup"
    else
        echo "Plugin not found at $PLUGIN_DIR"
    fi
}

_clean_env() {
    if [ ! -f "$ENV_FILE" ]; then
        echo "$ENV_FILE not found; no env cleanup needed"
        return
    fi

    local tmp="$ENV_FILE.a2a-uninstall.$$"
    awk '
        /^[[:space:]]*#/ { print; next }
        /^[[:space:]]*A2A_ENABLED[[:space:]]*=/ { next }
        /^[[:space:]]*A2A_PORT[[:space:]]*=/ { next }
        /^[[:space:]]*A2A_WEBHOOK_SECRET[[:space:]]*=/ { next }
        /^[[:space:]]*WEBHOOK_ENABLED[[:space:]]*=/ {
            print "# " $0 " # commented by hermes-a2a uninstall; verify before deleting"
            next
        }
        { print }
    ' "$ENV_FILE" > "$tmp"
    mv "$tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "Removed A2A_* env entries and commented WEBHOOK_ENABLED in $ENV_FILE"
}

_manual_config_cleanup() {
    echo ""
    echo "WARNING: Could not auto-clean $CONFIG_FILE."
    echo "Remove a2a_trigger manually from both locations if present:"
    echo "  webhook.extra.routes.a2a_trigger"
    echo "  platforms.webhook.extra.routes.a2a_trigger"
    echo ""
}

_clean_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "$CONFIG_FILE not found; no config cleanup needed"
        return
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        _manual_config_cleanup
        return
    fi

    local config_result
    if config_result=$(A2A_UNINSTALL_CONFIG_FILE="$CONFIG_FILE" python3 <<'PYEOF'
import os
import stat
import sys

try:
    import yaml
except ImportError:
    print("PyYAML not found; manual config cleanup is required", file=sys.stderr)
    sys.exit(2)

config_path = os.environ["A2A_UNINSTALL_CONFIG_FILE"]

def fail(message, code=3):
    print(message, file=sys.stderr)
    sys.exit(code)

try:
    with open(config_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
except Exception as exc:
    fail(f"Could not parse {config_path}: {exc}")

if not isinstance(cfg, dict):
    fail(f"{config_path} must contain a YAML mapping at the top level")

changed = False

for path in (
    ("webhook", "extra", "routes"),
    ("platforms", "webhook", "extra", "routes"),
):
    node = cfg
    for key in path:
        if not isinstance(node, dict) or key not in node:
            node = None
            break
        node = node[key]
    if isinstance(node, dict) and "a2a_trigger" in node:
        del node["a2a_trigger"]
        changed = True

if changed:
    mode = stat.S_IMODE(os.stat(config_path).st_mode)
    tmp_path = f"{config_path}.a2a-uninstall.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, config_path)
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        fail(f"Could not write {config_path}: {exc}", code=4)
    print("REMOVED")
else:
    print("ABSENT")
PYEOF
    ); then
        case "$config_result" in
            REMOVED)
                echo "Removed a2a_trigger routes from $CONFIG_FILE"
                ;;
            ABSENT)
                echo "No a2a_trigger routes found in $CONFIG_FILE"
                ;;
            *)
                echo "$config_result"
                ;;
        esac
    else
        _manual_config_cleanup
    fi
}

_preserve_runtime_notice() {
    echo ""
    echo "Runtime data was not deleted."
    echo "If you intentionally want to remove friends, audit logs, conversations, or stranger records, inspect and delete matching paths manually:"
    echo "  $HERMES_HOME/a2a_*"
}

_backup_file "$ENV_FILE"
_backup_file "$CONFIG_FILE"
_move_plugin
_clean_env
_clean_config
_preserve_runtime_notice

echo ""
echo "Done. Restart Hermes to finish uninstalling A2A:"
echo "  hermes gateway restart"
