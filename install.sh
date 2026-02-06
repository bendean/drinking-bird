#!/usr/bin/env bash
set -euo pipefail

HOOK_NAME="permission-hook.py"
HOOK_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Claude Code permission hook..."

# 1. Create hooks directory
mkdir -p "$HOOK_DIR"

# 2. Copy hook script
cp "$SCRIPT_DIR/hooks/permission-hook.py" "$HOOK_DIR/$HOOK_NAME"
chmod +x "$HOOK_DIR/$HOOK_NAME"
echo "  Copied $HOOK_NAME to $HOOK_DIR/"

# 3. Merge hook config into settings.json
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
        echo "  Hook already configured in $SETTINGS_FILE (skipped)"
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
        echo "  Added hook config to $SETTINGS_FILE"
    fi
fi

echo ""
echo "Done! Restart Claude Code for the hook to take effect."
echo "Run /hooks in Claude Code to verify it's registered."
