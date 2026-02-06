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

# ============================================================================
# TIER 1: Auto-approve (instant, no LLM call)
# ============================================================================

# Tools that are always safe (read-only operations)
SAFE_TOOLS = {"Read", "Glob", "Grep", "LS", "WebFetch"}

# Bash commands that are always safe (prefix match)
SAFE_BASH_PREFIXES = [
    "npm run ",
    "npm test",
    "npm run test",
    "npm run lint",
    "npm run build",
    "npm run dev",
    "npm run start",
    "npx ",
    "yarn ",
    "pnpm ",
    "node ",
    "python ",
    "python3 ",
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

# Bash patterns that are always blocked
DANGEROUS_BASH_PATTERNS = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf $HOME",
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


def is_safe_bash(command: str) -> bool:
    """Check if a bash command matches safe patterns."""
    cmd = command.strip()
    if cmd in SAFE_BASH_EXACT:
        return True
    return any(cmd.startswith(prefix) for prefix in SAFE_BASH_PREFIXES)


def is_dangerous_bash(command: str) -> bool:
    """Check if a bash command matches dangerous patterns."""
    cmd = command.strip().lower()
    if any(pattern in cmd for pattern in DANGEROUS_BASH_PATTERNS):
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
            ["claude", "-p", prompt],
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

    # --- TIER 1: Auto-approve safe tools ---
    if tool_name in SAFE_TOOLS:
        # Check if reading sensitive files
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        if file_path and is_sensitive_file(file_path):
            deny(f"Blocked read of sensitive file: {file_path}")
            return
        approve(f"Safe tool: {tool_name}")
        return

    # --- TIER 1/2: Bash command evaluation ---
    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # Tier 2: Block dangerous commands immediately
        if is_dangerous_bash(command):
            deny(f"Blocked dangerous command: {command}")
            return

        # Tier 1: Approve safe commands immediately
        if is_safe_bash(command):
            approve(f"Safe command: {command}")
            return

        # Tier 3: Ambiguous — ask Claude
        decision = ask_claude(tool_name, tool_input, cwd)
        if decision == "allow":
            approve("Claude approved this operation")
        elif decision == "deny":
            deny("Claude flagged this as unsafe")
        else:
            ask_user("Claude deferred to human judgment")
        return

    # --- TIER 1: Auto-approve Write/Edit within project ---
    if tool_name in {"Write", "Edit", "MultiEdit"}:
        file_path = tool_input.get("file_path", "")
        if file_path and is_sensitive_file(file_path):
            deny(f"Blocked write to sensitive file: {file_path}")
            return
        # Auto-approve writes within the working directory
        if file_path and (file_path.startswith("./") or file_path.startswith(cwd)):
            approve(f"Project file edit: {file_path}")
            return
        # For writes outside project, ask Claude
        decision = ask_claude(tool_name, tool_input, cwd)
        if decision == "allow":
            approve("Claude approved this file operation")
        elif decision == "deny":
            deny("Claude flagged this file operation as unsafe")
        else:
            ask_user("Claude deferred to human judgment")
        return

    # --- TIER 3: Everything else — ask Claude ---
    decision = ask_claude(tool_name, tool_input, cwd)
    if decision == "allow":
        approve(f"Claude approved: {tool_name}")
    elif decision == "deny":
        deny(f"Claude denied: {tool_name}")
    else:
        ask_user(f"Claude deferred: {tool_name}")


if __name__ == "__main__":
    main()
