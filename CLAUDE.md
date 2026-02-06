# Drinking Bird

A Claude Code `PermissionRequest` hook that auto-approves safe operations, auto-denies dangerous ones, and routes ambiguous cases to Claude via `claude -p`.

## Project Structure

- `hooks/permission-hook.py` — main hook script with 3-tier logic (safe/dangerous/ambiguous)
- `install.sh` / `uninstall.sh` — global install to `~/.claude/hooks/` and config merge into `~/.claude/settings.json`
- `.claude-plugin/plugin.json` + `hooks/hooks.json` — Claude Code plugin distribution format
- `tests/` — pytest unit tests
- `sample-settings.json` — example settings.json config for reference

## How it works

1. **Tier 1 (instant)**: Auto-approve known safe tools (`Read`, `Glob`, etc.) and safe bash commands (`git status`, `pytest`, etc.)
2. **Tier 2 (instant)**: Auto-deny dangerous patterns (`rm -rf /`, `sudo rm`, pipe to `sh`, sensitive file access)
3. **Tier 3 (~2-5s)**: Everything else goes to `claude -p` which returns ALLOW/DENY/ASK
4. **Fallback**: If Claude can't decide, times out, or errors, fall through to normal permission prompt

## Development

```bash
python3 -m pytest tests/
```

## Installation

The hook installs globally to `~/.claude/hooks/permission-hook.py`. Run `./install.sh` to install or `./uninstall.sh` to remove.

## Known behaviors

- PermissionRequest hooks that auto-approve are silent — no user-visible feedback in the terminal
- The `message` field in hook decisions is only meaningful for `deny` (fed to Claude, not user-visible)
- Tier 3 evaluations cause the permission prompt to briefly flash in the UI while the hook evaluates
- The hook may not appear in `/hooks` output but still fires correctly
