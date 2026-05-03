#!/bin/bash
# Install hermes-a2a as a Hermes plugin.
# Usage: ./install.sh

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/a2a"
PLUGIN_TMP="$HERMES_HOME/plugins/.a2a.install.$$"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/plugin"
ENV_FILE="$HERMES_HOME/.env"
CONFIG_FILE="$HERMES_HOME/config.yaml"
SESSIONS_FILE="$HERMES_HOME/sessions/sessions.json"

trap 'rm -rf "$PLUGIN_TMP"' EXIT

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

_fail() {
    echo "ERROR: $*" >&2
    exit 1
}

_warn() {
    echo "WARNING: $*" >&2
}

_env_active_exists() {
    local key="$1"
    grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$ENV_FILE" 2>/dev/null
}

_env_commented_exists() {
    local key="$1"
    grep -Eq "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "$ENV_FILE" 2>/dev/null
}

_env_value() {
    local key="$1"
    awk -v key="$key" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, "")
            print
            exit
        }
    ' "$ENV_FILE" 2>/dev/null
}

_port_in_use() {
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    else
        return 1
    fi
}

_preflight() {
    [ -d "$SOURCE_DIR" ] || _fail "plugin/ directory not found at $SOURCE_DIR"
    command -v python3 >/dev/null 2>&1 || _fail "python3 is required"

    if [ ! -f "$CONFIG_FILE" ]; then
        _fail "$CONFIG_FILE not found. Run 'hermes setup' first, then re-run ./install.sh. Nothing was installed or written."
    fi

    if [ -f "$ENV_FILE" ] && _env_active_exists "A2A_WEBHOOK_SECRET" && [ -z "$(_env_value A2A_WEBHOOK_SECRET)" ]; then
        _fail "A2A_WEBHOOK_SECRET exists in $ENV_FILE but is empty; set it or remove that line and re-run ./install.sh"
    fi

    if ! command -v hermes >/dev/null 2>&1; then
        _warn "'hermes' is not on PATH. Install can continue, but restart with the full Hermes executable path."
    fi

    for port in 8081 8644; do
        if _port_in_use "$port"; then
            _warn "Port $port appears to be in use. After restart, check Hermes logs if A2A or webhook startup fails."
        fi
    done
}

_generate_secret() {
    python3 - <<'PYEOF'
import secrets
print(secrets.token_hex(24))
PYEOF
}

_ensure_env_var() {
    local key="$1"
    local value="$2"
    local comment="${3:-}"

    if _env_active_exists "$key"; then
        return
    fi

    if _env_commented_exists "$key"; then
        _warn "$ENV_FILE contains only a commented $key entry; appending an active value"
    fi

    if [ -n "$comment" ]; then
        printf '# %s\n' "$comment" >> "$ENV_FILE"
    fi
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
}

_detect_home_session() {
    HOME_PLATFORM=""
    HOME_CHAT_ID=""
    HOME_USER_ID=""
    HOME_USER_NAME=""

    if [ ! -f "$SESSIONS_FILE" ]; then
        return
    fi

    if IFS= read -r -d '' HOME_PLATFORM &&
       IFS= read -r -d '' HOME_CHAT_ID &&
       IFS= read -r -d '' HOME_USER_ID &&
       IFS= read -r -d '' HOME_USER_NAME
    then
        :
    fi < <(python3 - "$SESSIONS_FILE" <<'PYEOF'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    for platform in ("telegram", "discord", "slack"):
        for key, entry in data.items():
            if platform in key and "dm" in key:
                origin = entry.get("origin", {})
                for field in ("platform", "chat_id", "user_id", "user_name"):
                    sys.stdout.write(str(origin.get(field, "")))
                    sys.stdout.write("\0")
                sys.exit(0)
except Exception as exc:
    print(f"auto-detect failed: {exc}", file=sys.stderr)
PYEOF
    )

    return 0
}

_explain_home_session() {
    if [ -z "$HOME_PLATFORM" ] || [ -z "$HOME_CHAT_ID" ]; then
        echo ""
        echo "WARNING: Could not auto-detect your home chat session."
        echo "A2A messages may open separate webhook sessions instead of joining your main chat."
        echo "Start Hermes, send one message from your main chat, then re-run ./install.sh to let the installer infer source routing."
        echo ""
    else
        echo "Detected home session: $HOME_PLATFORM DM ($HOME_USER_NAME, chat $HOME_CHAT_ID)"
    fi
}

_install_plugin() {
    mkdir -p "$HERMES_HOME/plugins"
    rm -rf "$PLUGIN_TMP"
    cp -R "$SOURCE_DIR" "$PLUGIN_TMP"

    if [ -d "$PLUGIN_DIR" ]; then
        local backup_dir
        backup_dir="$(_unique_path "$PLUGIN_DIR.bak.$(_timestamp)")"
        echo "Backing up existing plugin to $backup_dir"
        mv "$PLUGIN_DIR" "$backup_dir"
    fi

    mv "$PLUGIN_TMP" "$PLUGIN_DIR"
    echo "Installed plugin to $PLUGIN_DIR"
}

_prepare_env() {
    local old_umask
    old_umask="$(umask)"
    umask 077
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    if _env_active_exists "A2A_WEBHOOK_SECRET"; then
        A2A_SECRET="$(_env_value A2A_WEBHOOK_SECRET)"
        echo "A2A_WEBHOOK_SECRET already set"
    else
        A2A_SECRET="$(_generate_secret)"
        _ensure_env_var "A2A_WEBHOOK_SECRET" "$A2A_SECRET"
        echo "Generated A2A_WEBHOOK_SECRET"
    fi

    _ensure_env_var "A2A_ENABLED" "true" "A2A plugin"
    _ensure_env_var "A2A_PORT" "8081"
    _ensure_env_var "WEBHOOK_ENABLED" "true" "Required for A2A instant wake"
    chmod 600 "$ENV_FILE"
    umask "$old_umask"
    echo "Updated $ENV_FILE (mode 600)"
}

_manual_config_instructions() {
    echo ""
    echo "WARNING: Could not auto-configure $CONFIG_FILE."
    echo "The plugin was installed and $ENV_FILE was updated, but instant wake still needs an a2a_trigger route."
    echo ""
    echo "Add a route like this under BOTH webhook.extra.routes and platforms.webhook.extra.routes:"
    echo ""
    echo "webhook:"
    echo "  extra:"
    echo "    routes:"
    echo "      a2a_trigger:"
    echo "        secret: \"$A2A_SECRET\""
    echo "        prompt: '[A2A trigger]'"
    echo "        deliver: telegram"
    echo "        deliver_extra:"
    echo "          chat_id: '<your-chat-id>'"
    echo "        source:"
    echo "          platform: telegram"
    echo "          chat_type: dm"
    echo "          chat_id: '<your-chat-id>'"
    echo "          user_id: '<your-user-id>'"
    echo "          user_name: '<your-name>'"
    echo ""
    echo "platforms:"
    echo "  webhook:"
    echo "    extra:"
    echo "      routes:"
    echo "        a2a_trigger:"
    echo "          secret: \"$A2A_SECRET\""
    echo "          prompt: '[A2A trigger]'"
    echo "          deliver: telegram"
    echo "          deliver_extra:"
    echo "            chat_id: '<your-chat-id>'"
    echo "          source:"
    echo "            platform: telegram"
    echo "            chat_type: dm"
    echo "            chat_id: '<your-chat-id>'"
    echo "            user_id: '<your-user-id>'"
    echo "            user_name: '<your-name>'"
    echo ""
    echo "If PyYAML is unavailable, install it for your Hermes Python environment or edit config.yaml manually."
    echo ""
}

_configure_webhook_route() {
    local config_result

    if config_result=$(A2A_INSTALL_CONFIG_FILE="$CONFIG_FILE" \
        A2A_INSTALL_SECRET="$A2A_SECRET" \
        A2A_INSTALL_HOME_PLATFORM="$HOME_PLATFORM" \
        A2A_INSTALL_HOME_CHAT_ID="$HOME_CHAT_ID" \
        A2A_INSTALL_HOME_USER_ID="$HOME_USER_ID" \
        A2A_INSTALL_HOME_USER_NAME="$HOME_USER_NAME" \
        python3 <<'PYEOF'
import os
import stat
import sys

try:
    import yaml
except ImportError:
    print("PyYAML not found; manual config is required", file=sys.stderr)
    sys.exit(2)

config_path = os.environ["A2A_INSTALL_CONFIG_FILE"]
secret = os.environ["A2A_INSTALL_SECRET"]
platform = os.environ.get("A2A_INSTALL_HOME_PLATFORM", "")
chat_id = os.environ.get("A2A_INSTALL_HOME_CHAT_ID", "")
user_id = os.environ.get("A2A_INSTALL_HOME_USER_ID", "")
user_name = os.environ.get("A2A_INSTALL_HOME_USER_NAME", "")

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

changed = {"value": False}

def ensure_mapping(parent, key, path):
    current = parent.get(key)
    if current is None:
        current = {}
        parent[key] = current
        changed["value"] = True
    if not isinstance(current, dict):
        fail(f"{path} must be a YAML mapping; not overwriting it")
    return current

webhook = ensure_mapping(cfg, "webhook", "webhook")
webhook_extra = ensure_mapping(webhook, "extra", "webhook.extra")
webhook_routes = ensure_mapping(webhook_extra, "routes", "webhook.extra.routes")

platforms = ensure_mapping(cfg, "platforms", "platforms")
platforms_webhook = ensure_mapping(platforms, "webhook", "platforms.webhook")
platforms_extra = ensure_mapping(platforms_webhook, "extra", "platforms.webhook.extra")
platforms_routes = ensure_mapping(platforms_extra, "routes", "platforms.webhook.extra.routes")

existing = None
if "a2a_trigger" in webhook_routes:
    existing = webhook_routes["a2a_trigger"]
elif "a2a_trigger" in platforms_routes:
    existing = platforms_routes["a2a_trigger"]

if existing is None:
    route = {
        "secret": secret,
        "prompt": "[A2A trigger]",
    }
    if platform and chat_id:
        route["deliver"] = platform
        route["deliver_extra"] = {"chat_id": str(chat_id)}
        route["source"] = {
            "platform": platform,
            "chat_type": "dm",
            "chat_id": str(chat_id),
            "user_id": str(user_id or chat_id),
            "user_name": user_name or "user",
        }
    webhook_routes["a2a_trigger"] = route
    platforms_routes["a2a_trigger"] = dict(route)
    webhook["enabled"] = True
    webhook_extra.setdefault("port", 8644)
    webhook_extra.setdefault("secret", secret)
    changed["value"] = True
    status = "ADDED"
else:
    if not isinstance(existing, dict):
        fail("Existing a2a_trigger route is not a YAML mapping; not overwriting it")
    if "a2a_trigger" not in webhook_routes:
        webhook_routes["a2a_trigger"] = dict(existing)
        changed["value"] = True
    if "a2a_trigger" not in platforms_routes:
        platforms_routes["a2a_trigger"] = dict(existing)
        changed["value"] = True
    status = "NORMALIZED" if changed["value"] else "EXISTS"

if changed["value"]:
    mode = stat.S_IMODE(os.stat(config_path).st_mode)
    tmp_path = f"{config_path}.a2a.tmp.{os.getpid()}"
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

print(status)
PYEOF
    ); then
        case "$config_result" in
            ADDED)
                echo "Added a2a_trigger route to config.yaml"
                ;;
            EXISTS)
                echo "a2a_trigger route already exists in config.yaml"
                ;;
            NORMALIZED)
                echo "a2a_trigger route already existed; mirrored it into both webhook config locations"
                ;;
            *)
                echo "$config_result"
                ;;
        esac
    else
        _manual_config_instructions
    fi
}

_preflight
_detect_home_session
_explain_home_session
_install_plugin
_prepare_env
_configure_webhook_route

echo ""
echo "Done. Restart Hermes to activate:"
echo "  hermes gateway restart"
echo ""
echo "Look for 'A2A server listening on http://127.0.0.1:8081' in the logs."
