#!/usr/bin/env bash
set -euo pipefail

HOOK_NAME="permission-hook.py"
STOP_HOOK_NAME="stop-hook.py"
HOOK_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Claude Code hooks..."

# 1. Create hooks directory
mkdir -p "$HOOK_DIR"

# 2. Copy hook scripts
cp "$SCRIPT_DIR/hooks/permission-hook.py" "$HOOK_DIR/$HOOK_NAME"
chmod +x "$HOOK_DIR/$HOOK_NAME"
echo "  Copied $HOOK_NAME to $HOOK_DIR/"

cp "$SCRIPT_DIR/hooks/stop-hook.py" "$HOOK_DIR/$STOP_HOOK_NAME"
chmod +x "$HOOK_DIR/$STOP_HOOK_NAME"
echo "  Copied $STOP_HOOK_NAME to $HOOK_DIR/"

# 3. Merge hook configs into settings.json
HOOK_CONFIG='{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/permission-hook.py"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/stop-hook.py"
          }
        ]
      }
    ]
  }
}'

if [ ! -f "$SETTINGS_FILE" ]; then
    echo "$HOOK_CONFIG" > "$SETTINGS_FILE"
    echo "  Created $SETTINGS_FILE with hook config"
else
    # Check if PermissionRequest hook is already configured
    if python3 -c "
import json, sys
with open('$SETTINGS_FILE') as f:
    settings = json.load(f)
hooks = settings.get('hooks', {}).get('PermissionRequest', [])
for h in hooks:
    for hk in h.get('hooks', []):
        if 'permission-hook.py' in hk.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  PermissionRequest hook already configured (skipped)"
    else
        python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

hook_entry = {
    'matcher': '*',
    'hooks': [{
        'type': 'command',
        'command': 'python3 ~/.claude/hooks/permission-hook.py'
    }]
}

settings.setdefault('hooks', {})
settings['hooks'].setdefault('PermissionRequest', [])
settings['hooks']['PermissionRequest'].append(hook_entry)

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
"
        echo "  Added PermissionRequest hook config to $SETTINGS_FILE"
    fi

    # Check if Stop hook is already configured
    if python3 -c "
import json, sys
with open('$SETTINGS_FILE') as f:
    settings = json.load(f)
hooks = settings.get('hooks', {}).get('Stop', [])
for h in hooks:
    for hk in h.get('hooks', []):
        if 'stop-hook.py' in hk.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  Stop hook already configured (skipped)"
    else
        python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

hook_entry = {
    'hooks': [{
        'type': 'command',
        'command': 'python3 ~/.claude/hooks/stop-hook.py'
    }]
}

settings.setdefault('hooks', {})
settings['hooks'].setdefault('Stop', [])
settings['hooks']['Stop'].append(hook_entry)

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
"
        echo "  Added Stop hook config to $SETTINGS_FILE"
    fi
fi

echo ""
echo "Done! Restart Claude Code for hooks to take effect."
echo "Run /hooks in Claude Code to verify they're registered."
