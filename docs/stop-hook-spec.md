# Stop Hook Spec: Smart "Session Idle" Detection

## Problem
When Claude Code finishes a turn and returns to the `>` prompt, there are two types of "done":
1. **Actionable** — Claude needs the user to do something ("Run the app and check if the header shows")
2. **Informational** — Claude is just reporting results ("Git push completed successfully")

The HUD should only alert the user for actionable stops.

## Architecture

```
Claude finishes turn → Stop hook fires
  → stop-hook.py reads last assistant message from transcript
  → Asks Claude to classify: NOTIFY or SILENT
  → NOTIFY → POST to HUD /session-idle endpoint
  → SILENT → exit, do nothing
```

## Hook Input (from Claude Code)

The Stop hook receives on stdin:
```json
{
  "session_id": "abc123",
  "transcript_path": "/Users/.../.claude/projects/.../transcript.jsonl",
  "cwd": "/Users/ben/projects/my-project",
  "hook_event_name": "Stop",
  "stop_hook_active": false
}
```

## Implementation: `hooks/stop-hook.py`

### 1. Read last assistant message
- Parse `transcript_path` (JSONL format — one JSON object per line)
- Read backwards to find the last assistant message
- Extract the text content (last ~500 chars is enough for classification)

### 2. Classify with `claude -p`
Reuse the same pattern as `ask_claude()` in permission-hook.py:

```python
prompt = f"""You are evaluating whether a Claude Code session needs user attention.

Here is Claude's last message to the user:
---
{last_message}
---

Does the user need to take action (test something, make a decision, provide input)?
Or is this just an informational status update (task complete, results shown)?

Respond with EXACTLY one word: NOTIFY or SILENT
- NOTIFY: User needs to do something or make a decision
- SILENT: Just informational, no action needed"""

result = subprocess.run(
    ["claude", "-p", prompt],
    capture_output=True, text=True, timeout=10
)
```

### 3. Notify HUD if actionable
If NOTIFY, POST to `http://127.0.0.1:9999/session-idle`:

```json
{
  "session_id": "abc123",
  "cwd": "/Users/ben/projects/my-project",
  "summary": "<first ~80 chars of last message>",
  "transcript_path": "/Users/...transcript.jsonl",
  "tty": "/dev/ttys003"
}
```

TTY capture: reuse `get_tty()` from permission-hook.py (walk process tree via `ps -o tty=`).

### 4. Logging
Log to `~/.claude/hooks/stop-hook.log`:
```
[2026-02-07 09:40:00]    NOTIFY  my-project  "Running. Tap Start a Multie..."
[2026-02-07 09:41:12]    SILENT  my-project  "Git push completed successfully"
```

## Hook Configuration

Add to `~/.claude/settings.json`:
```json
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
```

## HUD Side (drinking-bird-hud will handle separately)

The HUD needs a new endpoint `POST /session-idle` that:
- Tracks idle sessions separately from permission-pending sessions
- Uses a distinct visual state (less urgent than permission prompts)
- Still supports Cmd+Esc focusing via TTY-based window matching

The HUD changes will be made in the drinking-bird-hud repo — this spec only covers the hook.

## Shared Code

These functions from `permission-hook.py` should be reused (import or copy):
- `get_tty()` — terminal TTY discovery
- `_summarize_input()` / message truncation
- `notify_hud()` pattern — fire-and-forget POST
- Logging pattern

Consider extracting shared utilities to a `hooks/lib/` module if the duplication becomes unwieldy.

## Edge Cases
- **Empty transcript**: Exit silently (session just started)
- **Claude timed out on classification**: Default to NOTIFY (better to over-alert)
- **HUD not running**: Silent failure (same as permission hook)
- **stop_hook_active is true**: This means the Stop hook already fired once and Claude continued. Evaluate again normally.
- **Very long last message**: Truncate to ~500 chars for the classification prompt
