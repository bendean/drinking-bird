# Claude Code Permission Hook (Subscription-Powered)

Routes permission requests through Claude itself using your existing subscription — no API key, no OpenRouter, no extra billing.

## How it works

```
Permission Request → Tier 1: Safe? Auto-approve (instant)
                   → Tier 2: Dangerous? Auto-deny (instant)
                   → Tier 3: Ambiguous? Ask Claude via CLI (~2-5s)
                   → Fallback: Can't decide? Show normal prompt
```

The hook calls `claude -p` (print mode) for ambiguous cases, which authenticates with your existing Claude Pro/Max subscription.

## Install

### Option A: Claude Code Plugin (recommended)

If you have a plugin marketplace configured:

```
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
cp hooks/permission-hook.py ~/.claude/hooks/permission-hook.py
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

## Uninstall

```bash
./uninstall.sh
```

Or manually: remove `~/.claude/hooks/permission-hook.py` and delete the `PermissionRequest` hook entry from `~/.claude/settings.json`.

Restart Claude Code after installing or uninstalling. Run `/hooks` to verify.

## What gets auto-approved (Tier 1, instant)

- **Read-only tools**: Read, Glob, Grep, LS, WebFetch
- **Safe bash commands**: git status/log/diff, npm test/run/build, pytest, cargo test, linters, formatters, cat/head/tail, find/grep, etc.
- **File writes within your project directory** (unless targeting sensitive files)

## What gets auto-denied (Tier 2, instant)

- `rm -rf /`, `rm -rf ~`, fork bombs, `dd if=`
- `sudo rm/chmod/chown`
- Piping curl/wget to sh/bash
- Reading `/etc/shadow`, `/etc/passwd`
- Any read/write to files matching: `.env`, `secrets/`, `credentials`, `.aws/credentials`, `.ssh/id_*`

## What goes to Claude (Tier 3, ~2-5s)

Everything else — Docker commands, npm install, git push, unfamiliar bash commands, file operations outside the project directory, MCP tool calls, etc.

Claude sees the tool name, full input, and working directory, and responds ALLOW / DENY / ASK. If it says ASK (or times out, or errors), you get the normal permission prompt.

## Customization

Edit the lists at the top of `hooks/permission-hook.py`:

- `SAFE_TOOLS` — tools to always approve
- `SAFE_BASH_PREFIXES` — bash command prefixes to always approve
- `DANGEROUS_BASH_PATTERNS` — bash patterns to always block
- `SENSITIVE_PATH_PATTERNS` / `SENSITIVE_BASENAME_PATTERNS` — file paths to always block read/write

## Costs

Zero additional cost. The `claude -p` command uses your existing Pro or Max subscription. Each Tier 3 evaluation is a small, fast prompt (~200 input tokens, 1 output token).

## Troubleshooting

**Hook not firing**: Run `/hooks` in Claude Code to verify the hook is registered. You may need to restart Claude Code after editing settings.

**"claude: command not found"**: Make sure the Claude CLI is in your PATH. The hook will fall through to manual approval if it can't find the CLI.

**Slow evaluations**: The 15-second timeout ensures the hook never hangs. If Claude is slow, it falls through to manual approval. You can adjust the timeout in the script.
