#!/usr/bin/env bash
set -euo pipefail

HOOK_NAME="permission-hook.py"
HOOK_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo "Uninstalling Claude Code permission hook..."

# 1. Remove hook script
if [ -f "$HOOK_DIR/$HOOK_NAME" ]; then
    rm "$HOOK_DIR/$HOOK_NAME"
    echo "  Removed $HOOK_DIR/$HOOK_NAME"
else
    echo "  Hook script not found (skipped)"
fi

# 2. Remove hook config from settings.json
if [ -f "$SETTINGS_FILE" ]; then
    python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

pr_hooks = settings.get('hooks', {}).get('PermissionRequest', [])
settings['hooks']['PermissionRequest'] = [
    h for h in pr_hooks
    if not any('permission-hook.py' in hk.get('command', '')
               for hk in h.get('hooks', []))
]

# Clean up empty lists/dicts
if not settings['hooks']['PermissionRequest']:
    del settings['hooks']['PermissionRequest']
if not settings.get('hooks'):
    del settings['hooks']

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
"
    echo "  Removed hook config from $SETTINGS_FILE"
fi

echo ""
echo "Done! Restart Claude Code for changes to take effect."
