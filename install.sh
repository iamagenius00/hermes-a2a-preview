#!/bin/bash
# Install hermes-a2a as a Hermes plugin.
# Usage: ./install.sh

set -e

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/a2a"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/plugin"
ENV_FILE="$HERMES_HOME/.env"
CONFIG_FILE="$HERMES_HOME/config.yaml"
SESSIONS_FILE="$HERMES_HOME/sessions/sessions.json"

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: plugin/ directory not found"
    exit 1
fi

# ── 1. Copy plugin files ──────────────────────────────────────────────

if [ -d "$PLUGIN_DIR" ]; then
    BACKUP_DIR="$PLUGIN_DIR.bak.$(date +%Y%m%d%H%M%S)"
    echo "Backing up existing plugin to $BACKUP_DIR"
    cp -r "$PLUGIN_DIR" "$BACKUP_DIR"
    rm -rf "$PLUGIN_DIR"
fi

mkdir -p "$HERMES_HOME/plugins"
cp -r "$SOURCE_DIR" "$PLUGIN_DIR"
echo "✓ Installed plugin to $PLUGIN_DIR"

# ── 2. Configure .env ─────────────────────────────────────────────────

_ensure_env_var() {
    local key="$1" value="$2" comment="$3"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        return  # already set, don't overwrite
    fi
    [ -n "$comment" ] && echo "# $comment" >> "$ENV_FILE"
    echo "${key}=${value}" >> "$ENV_FILE"
}

_generate_secret() {
    python3 -c "import secrets; print(secrets.token_hex(24))" 2>/dev/null \
        || openssl rand -hex 24 2>/dev/null \
        || head -c 48 /dev/urandom | xxd -p | head -c 48
}

touch "$ENV_FILE"

_ensure_env_var "A2A_ENABLED" "true" "A2A plugin"
_ensure_env_var "A2A_PORT" "8081"

# Generate webhook secret if not set
if ! grep -q "^A2A_WEBHOOK_SECRET=" "$ENV_FILE" 2>/dev/null; then
    A2A_SECRET=$(_generate_secret)
    _ensure_env_var "A2A_WEBHOOK_SECRET" "$A2A_SECRET"
    echo "✓ Generated A2A_WEBHOOK_SECRET"
else
    A2A_SECRET=$(grep "^A2A_WEBHOOK_SECRET=" "$ENV_FILE" | head -1 | cut -d= -f2-)
    echo "✓ A2A_WEBHOOK_SECRET already set"
fi

echo "✓ Updated $ENV_FILE"

# ── 3. Auto-detect home session ───────────────────────────────────────

HOME_PLATFORM=""
HOME_CHAT_ID=""
HOME_USER_ID=""
HOME_USER_NAME=""

if [ -f "$SESSIONS_FILE" ]; then
    # Find the first telegram DM session (most common home platform)
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
    # Priority: telegram dm > discord dm > any dm
    for platform in ["telegram", "discord", "slack"]:
        for key, entry in data.items():
            if platform in key and "dm" in key:
                o = entry.get("origin", {})
                for field in ("platform", "chat_id", "user_id", "user_name"):
                    sys.stdout.write(str(o.get(field, "")))
                    sys.stdout.write("\0")
                sys.exit(0)
except Exception as e:
    print(f"auto-detect failed: {e}", file=sys.stderr)
PYEOF
    )
fi

if [ -z "$HOME_PLATFORM" ] || [ -z "$HOME_CHAT_ID" ]; then
    echo ""
    echo "⚠  Could not auto-detect your home chat session."
    echo "   A2A messages will open separate sessions instead of joining your main chat."
    echo ""
    echo "   To fix this, add to $CONFIG_FILE under webhook.extra.routes.a2a_trigger:"
    echo "     source:"
    echo "       platform: telegram  # or discord, slack"
    echo "       chat_type: dm"
    echo "       chat_id: '<your-chat-id>'"
    echo "       user_id: '<your-user-id>'"
    echo ""
    echo "   Or start Hermes, send a message, then re-run ./install.sh"
    echo ""
else
    echo "✓ Detected home session: $HOME_PLATFORM DM ($HOME_USER_NAME, chat $HOME_CHAT_ID)"
fi

# ── 4. Configure webhook route in config.yaml ─────────────────────────

if [ ! -f "$CONFIG_FILE" ]; then
    echo "⚠  $CONFIG_FILE not found. Skipping webhook route setup."
    echo "   Run 'hermes setup' first, then re-run ./install.sh"
    exit 0
fi

# Check if a2a_trigger route already exists
if grep -q "a2a_trigger:" "$CONFIG_FILE" 2>/dev/null; then
    echo "✓ a2a_trigger route already in config.yaml (not overwriting)"
else
    # We need to add the route. Use python for safe YAML manipulation.
    if A2A_INSTALL_CONFIG_FILE="$CONFIG_FILE" \
       A2A_INSTALL_SECRET="$A2A_SECRET" \
       A2A_INSTALL_HOME_PLATFORM="$HOME_PLATFORM" \
       A2A_INSTALL_HOME_CHAT_ID="$HOME_CHAT_ID" \
       A2A_INSTALL_HOME_USER_ID="$HOME_USER_ID" \
       A2A_INSTALL_HOME_USER_NAME="$HOME_USER_NAME" \
       python3 <<'PYEOF'
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML not found; manual config is required", file=sys.stderr)
    sys.exit(1)

config_path = os.environ["A2A_INSTALL_CONFIG_FILE"]
secret = os.environ["A2A_INSTALL_SECRET"]
platform = os.environ.get("A2A_INSTALL_HOME_PLATFORM", "")
chat_id = os.environ.get("A2A_INSTALL_HOME_CHAT_ID", "")
user_id = os.environ.get("A2A_INSTALL_HOME_USER_ID", "")
user_name = os.environ.get("A2A_INSTALL_HOME_USER_NAME", "")

with open(config_path) as f:
    cfg = yaml.safe_load(f) or {}

# Ensure webhook.extra.routes exists
wh = cfg.setdefault("webhook", {})
extra = wh.setdefault("extra", {})
routes = extra.setdefault("routes", {})

# Build route config
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

routes["a2a_trigger"] = route

# Also ensure webhook is enabled
wh["enabled"] = True
if "port" not in extra:
    extra["port"] = 8644
if "secret" not in extra:
    extra["secret"] = secret

# Also set in platforms.webhook.extra.routes (Hermes reads both locations)
platforms = cfg.setdefault("platforms", {})
pw = platforms.setdefault("webhook", {})
pe = pw.setdefault("extra", {})
pr = pe.setdefault("routes", {})
pr["a2a_trigger"] = route.copy()

with open(config_path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

print("OK")
PYEOF
    then
        echo "✓ Added a2a_trigger route to config.yaml"
    else
        # Fallback: just tell the user
        echo ""
        echo "⚠  Could not auto-configure config.yaml (PyYAML not available)."
        echo "   Add this to $CONFIG_FILE under webhook.extra.routes:"
        echo ""
        echo "      a2a_trigger:"
        echo "        secret: $A2A_SECRET"
        echo "        deliver: ${HOME_PLATFORM:-telegram}"
        [ -n "$HOME_CHAT_ID" ] && echo "        deliver_extra:"
        [ -n "$HOME_CHAT_ID" ] && echo "          chat_id: '$HOME_CHAT_ID'"
        echo "        prompt: '[A2A trigger]'"
        if [ -n "$HOME_PLATFORM" ] && [ -n "$HOME_CHAT_ID" ]; then
            echo "        source:"
            echo "          platform: $HOME_PLATFORM"
            echo "          chat_type: dm"
            echo "          chat_id: '$HOME_CHAT_ID'"
            echo "          user_id: '${HOME_USER_ID:-$HOME_CHAT_ID}'"
            echo "          user_name: ${HOME_USER_NAME:-user}"
        fi
        echo ""
    fi
fi

# ── 5. Ensure WEBHOOK_ENABLED in .env ─────────────────────────────────

_ensure_env_var "WEBHOOK_ENABLED" "true" "Required for A2A instant wake"

# ── Done ──────────────────────────────────────────────────────────────

echo ""
echo "Done. Restart Hermes to activate:"
echo "  hermes gateway restart"
echo ""
echo "Look for 'A2A server listening on http://127.0.0.1:8081' in the logs."
