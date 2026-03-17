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
import re
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
    "Done", "Committed", "Created", "Updated", "Deleted",
    "Fixed", "Added", "Removed", "Merged", "Pushed", "Deployed",
    "Installed", "Built", "Passed", "Completed", "Finished",
    "All tests pass", "All done", "All set", "Copied", "Opened",
    "Plan saved", "Plan complete",
]

# Regex for messages that start with "All N ..." (e.g. "All 6 tasks complete")
_ALL_N_RE = re.compile(r"^All \d+\s", re.IGNORECASE)

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


_IMPERATIVE_RE = re.compile(
    r"^(Please |Run |Try |Check |Test |Start |Stop |Open |Go |Fill |Copy |Paste "
    r"|Refresh |Take |Look "
    r"|Now\s*[—–\-:,]?\s*(?:run |try |check |test |start |stop |open |go |fill |copy |paste |refresh |take |look ))",
    re.IGNORECASE,
)


def _has_imperative(text: str) -> bool:
    """Check if text (or any sentence within it) starts with an imperative verb."""
    # Check the text itself
    if _IMPERATIVE_RE.match(text):
        return True
    # Check sentences after sentence-ending punctuation
    for sent in re.split(r"(?<=[.!])\s+", text):
        if _IMPERATIVE_RE.match(sent.strip()):
            return True
    return False


def _split_sentences(text: str):
    """Split text into sentences on .!? + whitespace or newlines."""
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text.strip()) if s.strip()]


def _last_sentence_has_question(text: str) -> bool:
    """Check if the last sentence contains a '?'."""
    sentences = _split_sentences(text)
    return bool(sentences) and "?" in sentences[-1]


def _ends_or_starts_with_question(text: str) -> bool:
    """Check if the first or last sentence contains a question mark.
    Middle sentences are ignored — a '?' buried in paragraph 3 of a status
    report is noise, not a signal."""
    sentences = _split_sentences(text)
    if not sentences:
        return False
    if "?" in sentences[-1]:
        return True
    if "?" in sentences[0]:
        return True
    return False


def classify_local(last_message: str):
    """Fast local classification. Returns 'NOTIFY', 'SILENT', or None (fall through to Claude)."""
    if not last_message or not last_message.strip():
        return None
    text = last_message.strip()
    # Idle/standing-by patterns — Claude is waiting, user was already notified.
    # Check BEFORE everything else so "Waiting for your call — X or Y?" is still SILENT.
    for pattern in IDLE_PATTERNS:
        if text.startswith(pattern):
            return "SILENT"
    # Completion prefixes — checked BEFORE the global "?" rule so that
    # "Pushed. The only diff is..." with a stray ? in the body is SILENT.
    # BUT: if the REST of the message has a direct question (last sentence)
    # or an imperative, the user still needs to act → NOTIFY.
    for prefix in COMPLETION_PREFIXES:
        if text.startswith(prefix):
            rest = text[len(prefix):].lstrip(".:!,;—–- ").strip()
            if rest and _has_imperative(rest):
                return "NOTIFY"
            if rest and _last_sentence_has_question(rest):
                return "NOTIFY"
            rest_tail = rest[-100:] if rest else ""
            if "Ready for" in rest_tail or "ready for" in rest_tail:
                return "NOTIFY"
            return "SILENT"
    # "All N ..." pattern (e.g. "All 6 tasks complete") — treat like completion
    if _ALL_N_RE.match(text):
        return "SILENT"
    # Question in last sentence = user needs to respond.
    # Only the LAST sentence matters — a ? buried in a status report body is noise.
    if _ends_or_starts_with_question(text):
        return "NOTIFY"
    # "Ready for" near the end = user needs to act
    tail = text[-100:]
    if "Ready for" in tail or "ready for" in tail:
        return "NOTIFY"
    # Imperative instruction: "Run the build", "Please restart", "Now run tests"
    # "Now " is narrowed to "Now <verb>" to avoid false positives when Claude
    # narrates its own actions ("Now let me verify...", "Now add the gap...").
    if _IMPERATIVE_RE.match(text):
        return "NOTIFY"
    # Ambiguous — fall through to Claude
    return None


# ============================================================================
# SESSION ACTIVITY CHECK
# ============================================================================

ACTIVITY_WINDOW_SECONDS = 120


def _is_session_active(transcript_path: str, window_seconds: int = None) -> bool:
    """Check if the user sent a message recently, indicating an active session.
    Returns True if the last user message timestamp is within window_seconds of now."""
    if window_seconds is None:
        window_seconds = ACTIVITY_WINDOW_SECONDS
    try:
        with open(transcript_path, "r") as f:
            lines = f.readlines()
        # Walk backwards to find last user message with a timestamp
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") == "user" and entry.get("timestamp"):
                ts_str = entry["timestamp"]
                # Parse ISO 8601 timestamp
                ts_str = ts_str.replace("Z", "+00:00")
                from datetime import timezone
                ts = datetime.fromisoformat(ts_str)
                now = datetime.now(timezone.utc)
                age = (now - ts).total_seconds()
                return age < window_seconds
        return False
    except Exception:
        return False


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
        sys.exit(0)  # Tool-only turns — don't log, just exit

    # Truncate for logging/summary
    summary = last_message[:80].replace("\n", " ")
    if len(last_message) > 80:
        summary += "..."

    # Activity window: if user sent a message recently, session is active — skip NOTIFY
    if _is_session_active(transcript_path):
        log("SILENT", project, f'"{summary}" (active)')
        sys.exit(0)

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
