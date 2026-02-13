#!/usr/bin/env python3
"""
Claude Code Stop Hook
Fires when Claude finishes a turn. Classifies the last assistant message
as NOTIFY (user needs to act) or SILENT (informational), and notifies
the HUD if actionable.

Install:
  1. Copy this file to ~/.claude/hooks/stop-hook.py
  2. chmod +x ~/.claude/hooks/stop-hook.py
  3. Add the Stop hook config to ~/.claude/settings.json (see README)
"""

import json
import sys
import subprocess
import os
import urllib.request
from datetime import datetime

# ============================================================================
# LOGGING
# ============================================================================

LOG_FILE = os.path.expanduser("~/.claude/hooks/stop-hook.log")


def log(decision: str, project: str, summary: str):
    """Append a log entry for every hook decision."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {decision:>10}  {project:<20}  {summary}\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass  # Never let logging break the hook


# ============================================================================
# TTY DISCOVERY
# ============================================================================


def get_tty():
    """Discover the terminal TTY by walking up the process tree."""
    try:
        pid = os.getppid()
        # Try parent, then grandparent (hook may be launched via intermediate shell)
        for _ in range(3):
            result = subprocess.run(
                ["ps", "-o", "tty=", "-p", str(pid)],
                capture_output=True, text=True, timeout=0.5,
            )
            tty = result.stdout.strip()
            if tty and tty != "??":
                return f"/dev/{tty}"
            # Walk up to parent
            result = subprocess.run(
                ["ps", "-o", "ppid=", "-p", str(pid)],
                capture_output=True, text=True, timeout=0.5,
            )
            pid = int(result.stdout.strip())
    except Exception:
        pass
    return None


# ============================================================================
# HUD NOTIFICATION
# ============================================================================


def notify_hud_session_idle(session_id, cwd, summary, transcript_path, tty=None):
    """Fire-and-forget POST to /session-idle. Fails silently if HUD not running."""
    try:
        data = {
            "session_id": session_id,
            "cwd": cwd,
            "summary": summary,
            "transcript_path": transcript_path,
        }
        if tty:
            data["tty"] = tty
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:9999/session-idle",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.5)
    except Exception:
        pass  # HUD not running — totally fine


# ============================================================================
# TRANSCRIPT PARSING
# ============================================================================


def get_last_assistant_text(transcript_path: str):
    """Read the transcript JSONL backwards and extract the last assistant text message.
    Returns the text content (str) or None if not found."""
    try:
        with open(transcript_path, "r") as f:
            lines = f.readlines()
        # Walk backwards to find last assistant message with text content
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") != "assistant":
                continue
            content = entry.get("message", {}).get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block["text"]
        return None
    except Exception:
        return None


# ============================================================================
# CLASSIFICATION VIA CLAUDE
# ============================================================================


def classify_message(last_message: str) -> str:
    """Ask Claude to classify the message as NOTIFY or SILENT.
    Returns 'NOTIFY' or 'SILENT'. Defaults to NOTIFY on error/timeout."""
    # Truncate to ~500 chars for the classification prompt
    truncated = last_message[:500]
    if len(last_message) > 500:
        truncated += "..."

    prompt = f"""You are evaluating whether a Claude Code session needs user attention.

Here is Claude's last message to the user:
---
{truncated}
---

Does the user need to take action (test something, make a decision, provide input)?
Or is this just an informational status update (task complete, results shown)?

Respond with EXACTLY one word: NOTIFY or SILENT
- NOTIFY: User needs to do something or make a decision
- SILENT: Just informational, no action needed"""

    try:
        result = subprocess.run(
            ["claude", "-p", "--no-session-persistence", prompt],
            capture_output=True,
            text=True,
            timeout=10,
        )
        response = result.stdout.strip().upper()
        if "SILENT" in response:
            return "SILENT"
        # Default to NOTIFY if ambiguous (better to over-alert)
        return "NOTIFY"
    except subprocess.TimeoutExpired:
        return "NOTIFY"
    except FileNotFoundError:
        return "NOTIFY"
    except Exception:
        return "NOTIFY"


# ============================================================================
# LOCAL CLASSIFICATION (skip Claude for obvious cases)
# ============================================================================

COMPLETION_PREFIXES = [
    "Done.", "Done!", "Committed", "Created", "Updated", "Deleted",
    "Fixed", "Added", "Removed", "Merged", "Pushed", "Deployed",
    "Installed", "Built", "Passed", "Completed", "Finished",
    "All tests pass", "All done",
]

# "Ball is in your court" messages — Claude is idle, user was already notified.
# These fire repeatedly when background tasks complete and cause notification loops.
IDLE_PATTERNS = [
    "Standing by",
    "Ready when you are",
    "Your call",
    "All clear",
    "Whenever you're ready",
    "Waiting on your",
    "Waiting for your",
    "Over to you",
    "Up to you",
    "No rush",
    "Take your time",
    "No action needed",
]


def classify_local(last_message: str):
    """Fast local classification. Returns 'NOTIFY', 'SILENT', or None (fall through to Claude)."""
    if not last_message or not last_message.strip():
        return None
    text = last_message.strip()
    # Idle/standing-by patterns — Claude is waiting, user was already notified.
    # Check BEFORE "?" so "Waiting for your call — X or Y?" is still SILENT.
    for pattern in IDLE_PATTERNS:
        if text.startswith(pattern):
            return "SILENT"
    # Question mark anywhere = user needs to respond
    if "?" in text:
        return "NOTIFY"
    # "Ready for" near the end = user needs to act
    tail = text[-100:]
    if "Ready for" in tail or "ready for" in tail:
        return "NOTIFY"
    # Starts with completion word and no question = informational
    for prefix in COMPLETION_PREFIXES:
        if text.startswith(prefix):
            return "SILENT"
    # Ambiguous — fall through to Claude
    return None


# ============================================================================
# DEBOUNCE
# ============================================================================

DEBOUNCE_FILE = os.path.expanduser("~/.claude/hooks/.stop-hook-debounce")
DEBOUNCE_SECONDS = 3


def _should_debounce(project: str) -> bool:
    """Return True if this project was classified within DEBOUNCE_SECONDS."""
    try:
        with open(DEBOUNCE_FILE, "r") as f:
            line = f.read().strip()
        parts = line.split("\t", 1)
        if len(parts) != 2:
            return False
        stored_project, ts_str = parts
        if stored_project != project:
            return False
        last_ts = float(ts_str)
        import time
        return (time.time() - last_ts) < DEBOUNCE_SECONDS
    except Exception:
        return False


def _update_debounce(project: str):
    """Write current timestamp for this project."""
    try:
        import time
        with open(DEBOUNCE_FILE, "w") as f:
            f.write(f"{project}\t{time.time()}")
    except Exception:
        pass


# ============================================================================
# MAIN
# ============================================================================


def main():
    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)  # Can't parse, exit silently

    session_id = input_data.get("session_id", "")
    transcript_path = input_data.get("transcript_path", "")
    cwd = input_data.get("cwd", os.getcwd())
    project = os.path.basename(cwd) if cwd else "unknown"

    # Debounce: skip if same project was classified recently
    if _should_debounce(project):
        log("SILENT", project, "(debounced)")
        sys.exit(0)
    _update_debounce(project)

    # Edge case: no transcript path
    if not transcript_path:
        log("SILENT", project, "(no transcript)")
        sys.exit(0)

    # Read last assistant message
    last_message = get_last_assistant_text(transcript_path)
    if not last_message:
        log("SILENT", project, "(empty transcript or no text)")
        sys.exit(0)

    # Truncate for logging/summary
    summary = last_message[:80].replace("\n", " ")
    if len(last_message) > 80:
        summary += "..."

    # Fast local classification (skip Claude for obvious cases)
    local_decision = classify_local(last_message)
    if local_decision:
        log(local_decision, project, f'"{summary}" (local)')
        if local_decision == "NOTIFY":
            tty = get_tty()
            notify_hud_session_idle(session_id, cwd, summary, transcript_path, tty)
        sys.exit(0)

    # Classify via Claude
    decision = classify_message(last_message)
    log(decision, project, f'"{summary}"')

    if decision == "NOTIFY":
        tty = get_tty()
        notify_hud_session_idle(session_id, cwd, summary, transcript_path, tty)

    sys.exit(0)


if __name__ == "__main__":
    main()
