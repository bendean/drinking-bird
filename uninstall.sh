#!/usr/bin/env bash
set -euo pipefail

HOOK_NAME="permission-hook.py"
STOP_HOOK_NAME="stop-hook.py"
HOOK_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo "Uninstalling Claude Code hooks..."

# 1. Remove hook scripts
if [ -f "$HOOK_DIR/$HOOK_NAME" ]; then
    rm "$HOOK_DIR/$HOOK_NAME"
    echo "  Removed $HOOK_DIR/$HOOK_NAME"
else
    echo "  Permission hook script not found (skipped)"
fi

if [ -f "$HOOK_DIR/$STOP_HOOK_NAME" ]; then
    rm "$HOOK_DIR/$STOP_HOOK_NAME"
    echo "  Removed $HOOK_DIR/$STOP_HOOK_NAME"
else
    echo "  Stop hook script not found (skipped)"
fi

# 2. Remove hook configs from settings.json
if [ -f "$SETTINGS_FILE" ]; then
    python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

# Remove PermissionRequest hook
pr_hooks = settings.get('hooks', {}).get('PermissionRequest', [])
if pr_hooks:
    settings['hooks']['PermissionRequest'] = [
        h for h in pr_hooks
        if not any('permission-hook.py' in hk.get('command', '')
                   for hk in h.get('hooks', []))
    ]
    if not settings['hooks']['PermissionRequest']:
        del settings['hooks']['PermissionRequest']

# Remove Stop hook
stop_hooks = settings.get('hooks', {}).get('Stop', [])
if stop_hooks:
    settings['hooks']['Stop'] = [
        h for h in stop_hooks
        if not any('stop-hook.py' in hk.get('command', '')
                   for hk in h.get('hooks', []))
    ]
    if not settings['hooks']['Stop']:
        del settings['hooks']['Stop']

# Clean up empty hooks dict
if not settings.get('hooks'):
    del settings['hooks']

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
"
    echo "  Removed hook configs from $SETTINGS_FILE"
fi

echo ""
echo "Done! Restart Claude Code for changes to take effect."
