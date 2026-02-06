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

```bash
# 1. Create the hooks directory
mkdir -p ~/.claude/hooks

# 2. Copy the hook script
cp permission-hook.py ~/.claude/hooks/permission-hook.py
chmod +x ~/.claude/hooks/permission-hook.py

# 3. Add to your Claude Code settings
#    Edit ~/.claude/settings.json and merge in the hooks config below
```

## Settings config

Add this to your `~/.claude/settings.json`:

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

If you already have other settings in that file, just merge the `hooks` key in.

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

Edit the lists at the top of `permission-hook.py`:

- `SAFE_TOOLS` — tools to always approve
- `SAFE_BASH_PREFIXES` — bash command prefixes to always approve
- `DANGEROUS_BASH_PATTERNS` — bash patterns to always block
- `SENSITIVE_FILE_PATTERNS` — file paths to always block read/write

## Costs

Zero additional cost. The `claude -p` command uses your existing Pro or Max subscription. Each Tier 3 evaluation is a small, fast prompt (~200 input tokens, 1 output token).

## Troubleshooting

**Hook not firing**: Run `/hooks` in Claude Code to verify the hook is registered. You may need to restart Claude Code after editing settings.

**"claude: command not found"**: Make sure the Claude CLI is in your PATH. The hook will fall through to manual approval if it can't find the CLI.

**Slow evaluations**: The 15-second timeout ensures the hook never hangs. If Claude is slow, it falls through to manual approval. You can adjust the timeout in the script.
