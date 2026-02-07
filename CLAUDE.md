# Drinking Bird

Claude Code hooks for smart permission handling and session-idle detection. The `PermissionRequest` hook auto-approves safe operations, auto-denies dangerous ones, and routes ambiguous cases to Claude via `claude -p`. The `Stop` hook detects when Claude needs user attention and notifies the HUD.

## Project Structure

- `hooks/permission-hook.py` — permission hook with 3-tier logic (safe/dangerous/ambiguous)
- `hooks/stop-hook.py` — stop hook for session-idle detection (NOTIFY/SILENT)
- `install.sh` / `uninstall.sh` — global install to `~/.claude/hooks/` and config merge into `~/.claude/settings.json`
- `.claude-plugin/plugin.json` + `hooks/hooks.json` — Claude Code plugin distribution format
- `tests/` — pytest unit tests
- `sample-settings.json` — example settings.json config for reference

## How it works

1. **Tier 1 (instant)**: Auto-approve known safe tools (`Read`, `Glob`, etc.) and safe bash commands (`git status`, `pytest`, etc.)
2. **Tier 2 (instant)**: Auto-deny dangerous patterns (`rm -rf /`, `sudo rm`, pipe to `sh`, sensitive file access)
3. **Tier 3 (~2-5s)**: Everything else goes to `claude -p` which returns ALLOW/DENY/ASK
4. **Fallback**: If Claude can't decide, times out, or errors, fall through to normal permission prompt

## Stop Hook (session-idle detection)

The stop hook (`hooks/stop-hook.py`) fires when Claude finishes each turn:
1. Reads the last assistant message from the transcript JSONL
2. Classifies via `claude -p`: NOTIFY (user needs to act) or SILENT (informational)
3. If NOTIFY, POSTs to `http://127.0.0.1:9999/session-idle` for the HUD
4. Logs all decisions to `~/.claude/hooks/stop-hook.log`

Edge cases: empty transcript = SILENT, claude timeout = NOTIFY (over-alert), HUD not running = silent failure.

## Development

```bash
python3 -m pytest tests/
```

## Installation

The hooks install globally to `~/.claude/hooks/`. Run `./install.sh` to install or `./uninstall.sh` to remove.

## Testing the hook

Say "run drinking-bird-test" to verify the hook is running. This triggers an `AskUserQuestion` prompt that always reaches the user (can't be session-cached). The hook logs it as PASSTHROUGH, confirming it fired.

You can also check the log directly:
```bash
tail -5 ~/.claude/hooks/permission-hook.log
```

Note: Bash-based test commands (`PASSTHROUGH_BASH_COMMANDS`) only verify via logs — they can't force a visible prompt because Claude Code defers to existing session permissions when a hook returns no decision.

## Drinking Bird HUD (optional)

The sibling project `../drinking-bird-hud` is a macOS menu bar app that shows pending permission requests. This hook notifies the HUD via `notify_hud()` — a fire-and-forget POST to `http://127.0.0.1:9999/notify` with `{session_id, cwd, tool_name, summary, transcript_path}`. The call has a 0.5s timeout and fails silently if the HUD isn't running.

The HUD is notified on every PASSTHROUGH decision (user-interactive tools, Tier 3 deferrals, test passthroughs). It is never notified on ALLOW or DENY.

## Known behaviors

- PermissionRequest hooks that auto-approve are silent — no user-visible feedback in the terminal
- The `message` field in hook decisions is only meaningful for `deny` (fed to Claude, not user-visible)
- Tier 3 evaluations cause the permission prompt to briefly flash in the UI while the hook evaluates
- Hook passthrough (`{}` response) defers to session permissions — it cannot force a prompt if Bash is already approved
- The hook may not appear in `/hooks` output but still fires correctly
