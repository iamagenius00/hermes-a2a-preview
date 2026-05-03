#!/bin/bash
# Uninstall hermes-a2a plugin.

set -e

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DIR="$HERMES_HOME/plugins/a2a"
ENV_FILE="$HERMES_HOME/.env"

if [ -d "$PLUGIN_DIR" ]; then
    rm -rf "$PLUGIN_DIR"
    echo "Removed $PLUGIN_DIR"
else
    echo "Plugin not found at $PLUGIN_DIR"
fi

echo "Remove A2A_ENABLED from $ENV_FILE and restart Hermes."
