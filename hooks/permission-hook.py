#!/usr/bin/env python3
"""
Claude Code PermissionRequest Hook
Routes permission requests through a tiered system:
  Tier 1: Auto-approve known safe operations (instant)
  Tier 2: Auto-deny known dangerous operations (instant)
  Tier 3: Ask Claude via CLI for ambiguous cases (~2-5s)

Uses your existing Claude subscription via `claude --print` — no API key needed.

Install:
  1. Copy this file to ~/.claude/hooks/permission-hook.py
  2. chmod +x ~/.claude/hooks/permission-hook.py
  3. Add the hook config to ~/.claude/settings.json (see README)
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

LOG_FILE = os.path.expanduser("~/.claude/hooks/permission-hook.log")


def log(decision: str, tool_name: str, reason: str, tool_input: dict = None):
    """Append a log entry for every hook decision."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = _summarize_input(tool_name, tool_input or {})
        line = f"[{ts}] {decision:>10}  {tool_name:<20}  {summary}  ({reason})\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass  # Never let logging break the hook


def _summarize_input(tool_name: str, tool_input: dict) -> str:
    """One-line summary of what the tool is doing."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if len(cmd) > 120:
            cmd = cmd[:117] + "..."
        return cmd
    if tool_name in {"Read", "Write", "Edit", "MultiEdit", "Glob", "Grep"}:
        path = tool_input.get("file_path", "") or tool_input.get("path", "") or tool_input.get("pattern", "")
        return path
    if tool_name == "AskUserQuestion":
        questions = tool_input.get("questions", [])
        if questions:
            return questions[0].get("question", "")[:100]
        return str(tool_input)[:100]
    # Fallback: first 100 chars of JSON
    return json.dumps(tool_input)[:100]

# ============================================================================
# TIER 1: Auto-approve (instant, no LLM call)
# ============================================================================

# Tools that are always safe (read-only operations)
SAFE_TOOLS = {"Read", "Glob", "Grep", "LS", "WebFetch"}

# Tools that require user interaction — never auto-approve or auto-deny.
# Auto-approving these silently answers with empty input instead of showing the prompt.
# EnterPlanMode/ExitPlanMode: user must consent to plan mode and approve plans.
USER_INTERACTIVE_TOOLS = {"AskUserQuestion", "EnterPlanMode", "ExitPlanMode"}

# Bash commands that always fall through (log-level verification only).
# Note: passthrough can't force a visible prompt — session permissions take over.
# For a visible test, use AskUserQuestion instead (say "run drinking-bird-test").
PASSTHROUGH_BASH_COMMANDS = {"drinking-bird-test"}

# Bash commands that are always safe (prefix match)
SAFE_BASH_PREFIXES = [
    "npm run ",
    "npm test",
    "npm run test",
    "npm run lint",
    "npm run build",
    "npm run dev",
    "npm run start",
    "yarn ",
    "pnpm ",
    "node --version",
    "python3 -m pytest",
    "python -m pytest",
    "pip list",
    "pip show",
    "git log",
    "git diff",
    "git status",
    "git branch",
    "git show",
    "git stash list",
    "git remote -v",
    "git tag",
    "cat ",
    "head ",
    "tail ",
    "wc ",
    "ls ",
    "ls",
    "pwd",
    "echo ",
    "which ",
    "whoami",
    "date",
    "find ",
    "grep ",
    "rg ",
    "ag ",
    "fd ",
    "tree ",
    "file ",
    "stat ",
    "du ",
    "df ",
    "env",
    "printenv",
    "uname",
    "cargo check",
    "cargo test",
    "cargo build",
    "cargo clippy",
    "go test",
    "go build",
    "go vet",
    "make test",
    "make lint",
    "make check",
    "pytest",
    "jest ",
    "vitest ",
    "tsc ",
    "eslint ",
    "prettier ",
    "black ",
    "ruff ",
    "mypy ",
    "flake8 ",
    "rustfmt ",
]

# Exact-match safe bash commands
SAFE_BASH_EXACT = {
    "ls",
    "pwd",
    "whoami",
    "date",
    "env",
    "printenv",
    "uname",
    "git status",
    "git branch",
    "npm test",
    "pytest",
}

# ============================================================================
# TIER 2: Auto-deny (instant, no LLM call)
# ============================================================================

# Bash patterns that are always blocked (simple substring match).
# Note: "rm -rf /" and "rm -rf ~" are handled by regex in is_dangerous_bash()
# to avoid false positives on paths like "rm -rf /tmp/foo".
DANGEROUS_BASH_PATTERNS = [
    "rm -rf /*",
    "sudo rm ",
    "sudo chmod ",
    "sudo chown ",
    "mkfs.",
    "dd if=",
    ":(){:|:&};:",      # fork bomb
    "chmod 777 ",
    "chmod -R 777",
    "> /dev/sda",
    # Sensitive file access
    "cat /etc/shadow",
    "cat /etc/passwd",
    # Crypto / exfiltration
    "base64 /etc/",
    "nc -e ",
    "ncat -e ",
]

# Substring patterns — match anywhere in the path
SENSITIVE_PATH_PATTERNS = [
    ".env",
    ".env.",
    "secrets/",
    ".aws/credentials",
    ".ssh/id_",
    ".gnupg/",
]

# Basename patterns — match against filename only (exact name or name without extension)
SENSITIVE_BASENAME_PATTERNS = [
    "credentials",
    "token",
    "api_key",
    "apikey",
]


def approve(reason="Auto-approved"):
    """Output approval JSON and exit."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "allow",
                "message": reason
            }
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def deny(reason="Auto-denied"):
    """Output denial JSON and exit."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason
            }
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def ask_user(reason="Requires manual approval"):
    """Fall through to normal permission prompt."""
    # Exit 0 with no decision = fall through to normal prompt
    print(json.dumps({}))
    sys.exit(0)


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


def notify_hud_hook_start(session_id, tty=None):
    """Tell HUD the permission hook is evaluating. Fire-and-forget."""
    try:
        data = {"session_id": session_id}
        if tty:
            data["tty"] = tty
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:9999/hook-start",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.3)
    except Exception:
        pass


def notify_hud_tier3(session_id, tty=None):
    """Tell HUD the hook escalated to Tier 3 (Claude evaluation). Fire-and-forget."""
    try:
        data = {"session_id": session_id}
        if tty:
            data["tty"] = tty
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:9999/hook-tier3",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.3)
    except Exception:
        pass


def notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty=None):
    """Fire-and-forget notification to drinking-bird-hud if running. Fails silently."""
    try:
        data = {
            "session_id": session_id,
            "cwd": cwd,
            "tool_name": tool_name,
            "summary": _summarize_input(tool_name, tool_input or {}),
            "transcript_path": transcript_path,
        }
        if tty:
            data["tty"] = tty
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:9999/notify",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.5)
    except Exception:
        pass  # HUD not running — totally fine


# Shell meta-characters that indicate chaining, piping, or redirection.
# Commands containing these are never auto-approved — they fall through to Tier 3.
SHELL_META_CHARS = ["|", ";", "&&", "||", "`", "$(", ">", "<"]


def is_safe_bash(command: str) -> bool:
    """Check if a bash command matches safe patterns."""
    cmd = command.strip()
    # Compound/piped/redirected commands are never auto-approved.
    if any(meta in cmd for meta in SHELL_META_CHARS):
        return False
    if cmd in SAFE_BASH_EXACT:
        return True
    return any(cmd.startswith(prefix) for prefix in SAFE_BASH_PREFIXES)


def is_dangerous_bash(command: str) -> bool:
    """Check if a bash command matches dangerous patterns."""
    cmd = command.strip().lower()
    if any(pattern in cmd for pattern in DANGEROUS_BASH_PATTERNS):
        return True
    # Path-boundary checks for rm -rf with root/home targets.
    # Uses negative lookahead so "rm -rf /tmp/foo" is NOT matched,
    # but "rm -rf /", "rm -rf / ", "rm -rf /;" ARE matched.
    if re.search(r"\brm\s+-rf\s+/(?![a-z0-9._\-])", cmd):
        return True
    if re.search(r"\brm\s+-rf\s+~(?!/[a-z0-9._\-])", cmd):
        return True
    if re.search(r"\brm\s+-rf\s+\$home(?!/[a-z0-9._\-])", cmd):
        return True
    # Pipe-chain detection: curl/wget ... | sh/bash
    if re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash)\b", cmd):
        return True
    # Eval subshell detection: eval $(curl ...) / eval $(wget ...)
    if re.search(r"\beval\s+\$\((curl|wget)\b", cmd):
        return True
    return False


def is_sensitive_file(path: str) -> bool:
    """Check if a file path looks like it contains secrets."""
    path_lower = path.lower()
    # Substring patterns (path components like .env, secrets/)
    if any(pattern in path_lower for pattern in SENSITIVE_PATH_PATTERNS):
        return True
    # Basename patterns — check filename without extension
    basename = os.path.basename(path_lower)
    name_no_ext = os.path.splitext(basename)[0]
    # Also handle dotfiles like .token -> token
    basename_no_dot = basename.lstrip(".")
    name_no_ext_no_dot = name_no_ext.lstrip(".")
    if any(name_no_ext == pattern or basename == pattern
           or basename_no_dot == pattern or name_no_ext_no_dot == pattern
           for pattern in SENSITIVE_BASENAME_PATTERNS):
        return True
    return False


def ask_claude(tool_name: str, tool_input: dict, cwd: str) -> str:
    """
    Ask Claude via CLI to evaluate a permission request.
    Returns 'allow', 'deny', or 'ask'.
    """
    prompt = f"""You are a security reviewer for Claude Code. A coding agent wants to perform this action:

Tool: {tool_name}
Input: {json.dumps(tool_input, indent=2)}
Working Directory: {cwd}

Evaluate if this is safe. Consider:
- Could this cause data loss or system damage?
- Does this access sensitive files or credentials?
- Is this a normal development operation?
- Could this exfiltrate data or install malware?

Respond with EXACTLY one word: ALLOW, DENY, or ASK
- ALLOW: Safe development operation, auto-approve
- DENY: Dangerous or suspicious, block it
- ASK: Ambiguous, let the human decide"""

    try:
        result = subprocess.run(
            ["claude", "-p", "--no-session-persistence", prompt],
            capture_output=True,
            text=True,
            timeout=15,  # Don't hang forever
            cwd=cwd,
        )
        response = result.stdout.strip().upper()

        if "ALLOW" in response:
            return "allow"
        elif "DENY" in response:
            return "deny"
        else:
            return "ask"

    except subprocess.TimeoutExpired:
        # If Claude takes too long, fall through to manual
        return "ask"
    except FileNotFoundError:
        # claude CLI not found
        return "ask"
    except Exception:
        # Any other error, fall through to manual
        return "ask"


def main():
    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # Can't parse input, fall through to manual
        ask_user("Could not parse hook input")
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    cwd = input_data.get("cwd", os.getcwd())
    session_id = input_data.get("session_id", "")
    transcript_path = input_data.get("transcript_path", "")

    # Discover terminal TTY for window matching
    tty = get_tty()

    # Signal HUD that hook is evaluating (amber flash)
    notify_hud_hook_start(session_id, tty)

    # --- User-interactive tools: always fall through ---
    # These tools exist to interact with the user; auto-approving them
    # silently swallows the prompt and returns empty input to Claude.
    if tool_name in USER_INTERACTIVE_TOOLS:
        reason = f"User-interactive tool: {tool_name}"
        log("PASSTHROUGH", tool_name, reason, tool_input)
        notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
        ask_user(reason)
        return

    # --- TIER 1: Auto-approve safe tools ---
    if tool_name in SAFE_TOOLS:
        # Check if reading sensitive files
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        if file_path and is_sensitive_file(file_path):
            reason = f"Blocked read of sensitive file: {file_path}"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
            return
        reason = f"Safe tool: {tool_name}"
        log("ALLOW", tool_name, reason, tool_input)
        approve(reason)
        return

    # --- TIER 1/2: Bash command evaluation ---
    if tool_name == "Bash":
        command = tool_input.get("command", "").strip()

        # Test passthrough: always fall through to manual prompt
        if command in PASSTHROUGH_BASH_COMMANDS:
            reason = f"Test passthrough: {command}"
            log("PASSTHROUGH", tool_name, reason, tool_input)
            notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
            ask_user(reason)
            return

        # Tier 2: Block dangerous commands immediately
        if is_dangerous_bash(command):
            reason = f"Blocked dangerous command: {command}"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
            return

        # Tier 1: Approve safe commands immediately
        if is_safe_bash(command):
            reason = f"Safe command: {command}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return

        # Tier 3: Ambiguous — ask Claude
        notify_hud_tier3(session_id, tty)
        decision = ask_claude(tool_name, tool_input, cwd)
        if decision == "allow":
            reason = "Claude approved this operation"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
        elif decision == "deny":
            reason = "Claude flagged this as unsafe"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
        else:
            reason = "Claude deferred to human judgment"
            log("PASSTHROUGH", tool_name, reason, tool_input)
            notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
            ask_user(reason)
        return

    # --- TIER 1: Auto-approve Write/Edit within project ---
    if tool_name in {"Write", "Edit", "MultiEdit"}:
        file_path = tool_input.get("file_path", "")
        if file_path and is_sensitive_file(file_path):
            reason = f"Blocked write to sensitive file: {file_path}"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
            return
        # Auto-approve writes within the working directory
        if file_path and (file_path.startswith("./") or file_path.startswith(cwd)):
            reason = f"Project file edit: {file_path}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return
        # For writes outside project, ask Claude
        notify_hud_tier3(session_id, tty)
        decision = ask_claude(tool_name, tool_input, cwd)
        if decision == "allow":
            reason = "Claude approved this file operation"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
        elif decision == "deny":
            reason = "Claude flagged this file operation as unsafe"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
        else:
            reason = "Claude deferred to human judgment"
            log("PASSTHROUGH", tool_name, reason, tool_input)
            notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
            ask_user(reason)
        return

    # --- TIER 3: Everything else — ask Claude ---
    notify_hud_tier3(session_id, tty)
    decision = ask_claude(tool_name, tool_input, cwd)
    if decision == "allow":
        reason = f"Claude approved: {tool_name}"
        log("ALLOW", tool_name, reason, tool_input)
        approve(reason)
    elif decision == "deny":
        reason = f"Claude denied: {tool_name}"
        log("DENY", tool_name, reason, tool_input)
        deny(reason)
    else:
        reason = f"Claude deferred: {tool_name}"
        log("PASSTHROUGH", tool_name, reason, tool_input)
        notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
        ask_user(reason)


if __name__ == "__main__":
    main()
