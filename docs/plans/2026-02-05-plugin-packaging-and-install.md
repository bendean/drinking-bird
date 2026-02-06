# Plugin Packaging & Install Script Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Package the permission hook as a Claude Code plugin (for one-command install) and add a fallback install script for manual setup.

**Architecture:** Restructure the project into a Claude Code plugin by adding `.claude-plugin/plugin.json` and `hooks/hooks.json`. The hook script moves into the plugin's standard `hooks/` directory. A standalone `install.sh` script is provided as a fallback that copies the hook to `~/.claude/hooks/` and merges config into `~/.claude/settings.json`. The README is updated to document both install methods.

**Tech Stack:** Bash (install script), JSON (plugin manifest, hooks config)

---

### Task 1: Create Plugin Manifest

**Files:**
- Create: `.claude-plugin/plugin.json`

**Step 1: Create the plugin manifest**

```json
{
  "name": "approval-hook",
  "description": "Routes Claude Code permission requests through a tiered approval system: auto-approve safe ops, auto-deny dangerous ops, ask Claude for ambiguous cases",
  "version": "0.1.0",
  "author": {
    "name": "Ben"
  },
  "license": "MIT",
  "keywords": ["hooks", "permissions", "security", "approval"]
}
```

**Step 2: Commit**

```bash
git add .claude-plugin/plugin.json
git commit -m "feat: add plugin manifest for Claude Code plugin distribution"
```

---

### Task 2: Create hooks.json for Plugin Hook Registration

**Files:**
- Create: `hooks/hooks.json`

When installed as a plugin, Claude Code reads `hooks/hooks.json` and auto-registers the hooks. The `${CLAUDE_PLUGIN_ROOT}` variable is expanded at runtime to the plugin's install directory.

**Step 1: Create hooks/hooks.json**

```json
{
  "description": "Tiered permission approval: auto-approve safe ops, auto-deny dangerous ops, ask Claude for ambiguous cases",
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/permission-hook.py"
          }
        ]
      }
    ]
  }
}
```

**Step 2: Copy permission-hook.py into hooks/ directory**

The plugin convention is for hook scripts to live inside `hooks/`. Copy the script there — keep the root copy for now (the install script will use it).

```bash
cp permission-hook.py hooks/permission-hook.py
```

**Step 3: Verify the plugin structure looks right**

Run: `find .claude-plugin hooks/ -type f`
Expected:
```
.claude-plugin/plugin.json
hooks/hooks.json
hooks/permission-hook.py
```

**Step 4: Commit**

```bash
git add hooks/
git commit -m "feat: add hooks.json and hook script for plugin auto-registration"
```

---

### Task 3: Create Fallback Install Script

**Files:**
- Create: `install.sh`

For users who don't want to use the plugin system, this script:
1. Copies `permission-hook.py` to `~/.claude/hooks/`
2. Merges the hook config into `~/.claude/settings.json` (creates if missing, merges if exists)
3. Prints success message

**Step 1: Write install.sh**

```bash
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
cp "$SCRIPT_DIR/permission-hook.py" "$HOOK_DIR/$HOOK_NAME"
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
            sys.exit(0)  # Already installed
sys.exit(1)
" 2>/dev/null; then
        echo "  Hook already configured in $SETTINGS_FILE (skipped)"
    else
        # Merge using Python for safe JSON handling
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
```

**Step 2: Make executable and test dry-run**

```bash
chmod +x install.sh
# Verify it parses without syntax errors
bash -n install.sh
```

**Step 3: Commit**

```bash
git add install.sh
git commit -m "feat: add install.sh for manual hook installation"
```

---

### Task 4: Add Uninstall Script

**Files:**
- Create: `uninstall.sh`

**Step 1: Write uninstall.sh**

```bash
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
```

**Step 2: Make executable**

```bash
chmod +x uninstall.sh
bash -n uninstall.sh
```

**Step 3: Commit**

```bash
git add uninstall.sh
git commit -m "feat: add uninstall.sh to cleanly remove hook"
```

---

### Task 5: Update README with Both Install Methods

**Files:**
- Modify: `README.md`

**Step 1: Rewrite the Install section of README.md**

Replace the current `## Install` section with:

```markdown
## Install

### Option A: Claude Code Plugin (recommended)

If you have a plugin marketplace configured:

```bash
/install-plugin approval-hook
```

The hook registers automatically — no manual config needed.

### Option B: Install Script

```bash
git clone <repo-url> && cd approval-hook
./install.sh
```

This copies the hook to `~/.claude/hooks/` and adds the config to `~/.claude/settings.json`.

### Option C: Manual

```bash
# 1. Copy the hook script
mkdir -p ~/.claude/hooks
cp permission-hook.py ~/.claude/hooks/permission-hook.py
chmod +x ~/.claude/hooks/permission-hook.py

# 2. Add to ~/.claude/settings.json (merge if file exists):
```

```json
{
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
}
```

### Uninstall

```bash
./uninstall.sh
```

Or manually: remove `~/.claude/hooks/permission-hook.py` and delete the `PermissionRequest` hook entry from `~/.claude/settings.json`.

Restart Claude Code after installing or uninstalling. Run `/hooks` to verify.
```

**Step 2: Remove the old `## Settings config` section** (now covered by install instructions)

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README with plugin, script, and manual install methods"
```

---

### Task 6: Move Root permission-hook.py to Avoid Duplication

**Files:**
- Remove: `permission-hook.py` (root)
- Modify: `tests/test_permission_hook.py` (update HOOK_PATH)
- Modify: `tests/smoke_test.sh` (update path)
- Modify: `install.sh` (update source path)

Now that the canonical copy lives at `hooks/permission-hook.py`, remove the root duplicate and update all references.

**Step 1: Update test file HOOK_PATH**

In `tests/test_permission_hook.py`, change:
```python
HOOK_PATH = Path(__file__).parent.parent / "permission-hook.py"
```
to:
```python
HOOK_PATH = Path(__file__).parent.parent / "hooks" / "permission-hook.py"
```

**Step 2: Update smoke test path**

In `tests/smoke_test.sh`, change:
```bash
HOOK="python3 $(dirname "$0")/../permission-hook.py"
```
to:
```bash
HOOK="python3 $(dirname "$0")/../hooks/permission-hook.py"
```

**Step 3: Update install.sh source path**

In `install.sh`, change:
```bash
cp "$SCRIPT_DIR/permission-hook.py" "$HOOK_DIR/$HOOK_NAME"
```
to:
```bash
cp "$SCRIPT_DIR/hooks/permission-hook.py" "$HOOK_DIR/$HOOK_NAME"
```

**Step 4: Remove root copy**

```bash
git rm permission-hook.py
```

**Step 5: Run tests to verify nothing broke**

```bash
python3 -m pytest tests/test_permission_hook.py -v
bash tests/smoke_test.sh
```
Expected: All pass.

**Step 6: Commit**

```bash
git add -A
git commit -m "refactor: move permission-hook.py to hooks/ to match plugin convention"
```

---

### Task 7: Final Verification

**Step 1: Verify plugin structure**

```bash
find . -not -path './.git/*' -not -path './.pytest_cache/*' -not -path './__pycache__/*' -not -name '.DS_Store' | sort
```

Expected:
```
.
./.claude-plugin/plugin.json
./docs/plans/...
./hooks/hooks.json
./hooks/permission-hook.py
./install.sh
./uninstall.sh
./pyproject.toml
./README.md
./sample-settings.json
./tests/__init__.py
./tests/smoke_test.sh
./tests/test_permission_hook.py
./.gitignore
```

**Step 2: Run full test suite**

```bash
python3 -m pytest tests/test_permission_hook.py -v
bash tests/smoke_test.sh
```

**Step 3: Verify install.sh parses correctly**

```bash
bash -n install.sh && echo "OK"
bash -n uninstall.sh && echo "OK"
```

**Step 4: Commit any final fixups**

```bash
git add -A && git status
# Only commit if there are changes
```
