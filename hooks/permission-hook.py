#!/usr/bin/env python3
"""
Claude Code PermissionRequest Hook
Routes permission requests through a tiered system:
  Tier 1: Auto-approve known safe operations (instant)
  Tier 2: Auto-deny known dangerous operations (instant)
  Tier 3: Ask Claude via CLI for ambiguous cases (~2-5s)

Autonomous mode (DISPATCH_MODE=autonomous):
  Tier 1 and Tier 2 unchanged. Tier 3 auto-approves instead of asking
  Claude or the user. Set via environment variable in dispatch.sh.

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

CREDENTIAL_PATTERN = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|DB_PASSWORD|PRIVATE_KEY)=[^\s]+",
    re.IGNORECASE,
)

# ============================================================================
# LOGGING
# ============================================================================

LOG_FILE = os.path.expanduser("~/.claude/hooks/permission-hook.log")


def log(decision: str, tool_name: str, reason: str, tool_input: dict = None):
    """Append a log entry for every hook decision."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = _summarize_input(tool_name, tool_input or {})
        reason = _redact_credentials(reason)
        line = f"[{ts}] {decision:>10}  {tool_name:<20}  {summary}  ({reason})\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass  # Never let logging break the hook


def _redact_credentials(text: str) -> str:
    """Replace credential values with *** in log output."""
    return CREDENTIAL_PATTERN.sub(lambda m: m.group().split("=", 1)[0] + "=***", text)


def _summarize_input(tool_name: str, tool_input: dict) -> str:
    """One-line summary of what the tool is doing."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if len(cmd) > 120:
            cmd = cmd[:117] + "..."
        return _redact_credentials(cmd.replace("\n", " "))
    if tool_name in {"Read", "Write", "Edit", "MultiEdit", "Glob", "Grep"}:
        path = tool_input.get("file_path", "") or tool_input.get("path", "") or tool_input.get("pattern", "")
        return path
    if tool_name == "AskUserQuestion":
        questions = tool_input.get("questions", [])
        if questions:
            return questions[0].get("question", "")[:100]
        return str(tool_input)[:100]
    # Fallback: first 100 chars of JSON
    return _redact_credentials(json.dumps(tool_input)[:100].replace("\n", " "))

# ============================================================================
# TIER 1: Auto-approve (instant, no LLM call)
# ============================================================================

# Tools that are always safe (read-only operations)
# Skill: loads pre-registered skill content for Claude to read. Any actions
# the skill prescribes go through their own permission checks.
SAFE_TOOLS = {"Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "Skill"}

# Tools that require user interaction — never auto-approve or auto-deny.
# Auto-approving these silently answers with empty input instead of showing the prompt.
# EnterPlanMode/ExitPlanMode: user must consent to plan mode and approve plans.
USER_INTERACTIVE_TOOLS = {"AskUserQuestion", "EnterPlanMode", "ExitPlanMode"}

# Bash commands that always fall through (log-level verification only).
# Note: passthrough can't force a visible prompt — session permissions take over.
# For a visible test, use AskUserQuestion instead (say "run drinking-bird-test").
PASSTHROUGH_BASH_COMMANDS = {"drinking-bird-test"}

# Bash patterns that always require user confirmation — never auto-approved or auto-denied.
ALWAYS_ASK_BASH_PATTERNS = [
    "git push",
    "git merge ",
    "git branch -d ",
    "git branch -D ",
    "git branch --delete",
    "osascript",
    "pkill ",
    "kill ",
]


def _matches_always_ask(command: str) -> bool:
    """Check if command matches any always-ask pattern with word boundaries.

    Uses \\b so 'kill ' matches 'kill -9 1234' but not 'grep -i skill'.
    """
    for pattern in ALWAYS_ASK_BASH_PATTERNS:
        if re.search(r"\b" + re.escape(pattern), command):
            return True
    return False

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
    ".venv/bin/python -m pytest",
    ".venv/bin/python3 -m pytest",
    ".venv/bin/pytest",
    "pip list",
    "pip show",
    "git log",
    "git diff",
    "git status",
    "git init",
    "git add ",
    "git add .",
    "git branch -a",
    "git branch -v",
    "git branch -r",
    "git branch --list",
    "git branch --show-current",
    "git show",
    "git stash list",
    "git remote -v",
    "git tag",
    "mkdir ",
    "cp ",
    "cat ",
    "head ",
    "tail ",
    "wc ",
    "ls ",
    "ls",
    "pwd",
    "echo ",
    "printf ",
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
    "npx jest",
    "npx vitest",
    "npx next build",
    "npx next dev",
    "npx next lint",
    "npx tsc",
    "npx eslint",
    "npx prettier",
    "black ",
    "ruff ",
    "mypy ",
    "flake8 ",
    "rustfmt ",
    "swift --version",
    "xcodebuild -version",
    "flutter --version",
    "java --version",
    "ruby --version",
    "python3 --version",
    "python --version",
    "brew list",
    "brew info",
    "brew --version",
    "lsof ",
    "id ",
    "strings ",
    "ln ",
    "claude mcp list",
    "claude help",
    "claude skills",
    "git ls-files",
    "git check-ignore",
    "git worktree list",
    "git rev-parse",
    "git commit ",
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
    "git init",
    "git add .",
    "git add -A",
    "git add --all",
    "git add -u",
    "git branch",
    "git branch -a",
    "git branch -v",
    "git branch -r",
    "npm test",
    "pytest",
    "sw_vers",
    "uname -a",
    "hostname",
    "brew list",
    "python3 -V",
    "python -V",
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
    "secrets/",
    ".aws/credentials",
    ".ssh/id_",
    ".gnupg/",
]

# .env files that are NOT sensitive (templates, examples)
ENV_SAFE_SUFFIXES = (".example", ".sample", ".template")

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
SHELL_META_CHARS = ["|", ";", "&&", "||", "`", "$(", ">", "<", "&"]

# Read-only filter commands safe as pipe targets.
# These read from stdin, write to stdout, no side effects.
SAFE_PIPE_FILTERS = {
    "head", "tail", "grep", "egrep", "fgrep",
    "sort", "wc", "cut", "uniq", "tr", "column",
    "cat", "rev", "tac", "nl", "fold", "fmt",
}

# Curl data flags — indicate POST body normally, but become GET query params
# when -G/--get is present. Safe in GET mode.
CURL_DATA_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
}

# Curl flags that always indicate a write operation, even with -G.
CURL_WRITE_ONLY_FLAGS = {
    "-X", "--request", "-F", "--form", "-T", "--upload-file",
}

# Interpreters safe for single-quoted heredoc auto-approval.
# These run inline code in the same security context. Shell interpreters
# (bash, sh, zsh) are excluded — they can do anything.
SAFE_HEREDOC_INTERPRETERS = {"python3", "python", "node", "ruby", "perl"}


# GitHub CLI (gh) read-only subcommand operations
# Format: gh <resource> <operation> — only these operations are safe per resource
GH_READ_ONLY_OPS = {
    "auth":    {"status", "token"},
    "pr":      {"list", "view", "status", "checks", "diff"},
    "issue":   {"list", "view", "status"},
    "repo":    {"list", "view"},
    "release": {"list", "view"},
    "run":     {"list", "view"},
    "workflow": {"list", "view"},
    "api":     True,  # gh api is read-only (GET) by default
}


# AWS CLI read-only operation prefixes (e.g., describe-instances, list-buckets, get-object)
AWS_READ_ONLY_VERBS = ("describe-", "list-", "get-", "head-", "batch-get-")

# AWS CLI read-only exact operations (don't follow the verb-noun pattern)
AWS_READ_ONLY_EXACT = {"help", "ls", "wait"}


def is_safe_aws(command: str) -> bool:
    """Check if an AWS CLI command is read-only.

    Parses `aws [flags] <service> <operation>` and checks if the operation
    is a known read-only verb. Conservative — if flag values confuse the
    parser, returns False (falls through to Tier 3, not auto-approved).
    """
    tokens = command.split()
    if len(tokens) < 2:
        return False

    # Extract non-flag tokens after 'aws' — best-effort service + operation
    non_flag = [t for t in tokens[1:] if not t.startswith("-")]
    if not non_flag:
        return False

    # 'aws help' or 'aws <service> help'
    if non_flag[0] == "help" or (len(non_flag) > 1 and non_flag[1] == "help"):
        return True

    if len(non_flag) < 2:
        return False

    operation = non_flag[1]

    # Read-only verb prefixes
    if operation.startswith(AWS_READ_ONLY_VERBS):
        return True

    # Exact read-only operations (e.g., 'aws s3 ls', 'aws ec2 wait')
    if operation in AWS_READ_ONLY_EXACT:
        return True

    return False


def is_safe_gh(command: str) -> bool:
    """Check if a GitHub CLI command is read-only.

    Parses `gh [flags] <resource> <operation>` and checks against
    GH_READ_ONLY_OPS. Conservative — unknown resources/operations
    fall through to Tier 3.
    """
    tokens = command.split()
    if len(tokens) < 2:
        return False

    # Extract non-flag tokens after 'gh'
    non_flag = [t for t in tokens[1:] if not t.startswith("-")]
    if not non_flag:
        return False

    resource = non_flag[0]

    # 'gh help' is always safe
    if resource == "help":
        return True

    allowed_ops = GH_READ_ONLY_OPS.get(resource)
    if allowed_ops is None:
        return False

    # gh api is always safe (GET by default)
    if allowed_ops is True:
        return True

    if len(non_flag) < 2:
        return False

    operation = non_flag[1]
    return operation in allowed_ops


def _strip_cd_prefix(command: str) -> str:
    """Strip a leading 'cd <path> &&' from a compound command.

    `cd` in a subprocess only sets the working directory for the rest of the
    command — it has no side effects. Stripping it lets safe-pattern matching
    work on commands like 'cd ~/project && git add ... && git commit ...'.
    """
    m = re.match(r"cd\s+\S+\s*&&\s*", command)
    return command[m.end():] if m else command


def _is_safe_heredoc(command: str) -> bool:
    """Recognize safe interpreter heredoc commands like python3 << 'PYEOF'.

    Single-quoted heredocs prevent shell variable expansion, and the interpreter
    runs inline code in the same security context as writing a temp file.
    Only safe interpreters are allowed — bash/sh/zsh are excluded.
    """
    return bool(re.match(
        r"(" + "|".join(re.escape(i) for i in SAFE_HEREDOC_INTERPRETERS) + r")"
        r"\s+<<\s*'[A-Za-z_]+'\s*\n",
        command,
    ))


def _is_safe_filter_heredoc(command: str) -> bool:
    """Recognize single-quoted heredocs fed to read-only filters.

    Pattern: cat <<'EOF' [| wc -c | ...]\n<body>\nEOF
    The leading command and every pipe target must be read-only stdin/stdout
    filters (cat, wc, head, grep, ...). The single-quoted delimiter makes the
    body literal data — no command substitution or variable expansion — so the
    only executable parts are the filter commands, which have no side effects.
    Common in char-counting workflows: `cat <<'EOF' | wc -c`.
    """
    # Only the first line is a pipeline; everything after is literal heredoc body.
    first_line = command.split("\n", 1)[0]
    # Split the first line at the heredoc redirect `<<'DELIM'`. The left part is
    # the command consuming the heredoc on stdin (e.g. `cat`, or `awk 'script'`);
    # the right part is an optional `| filter ...` pipeline. Matching `<<` anywhere
    # (not just abutting the command word) lets `awk '…' <<'EOF'` qualify the same
    # way `cat <<'EOF' | awk '…'` already does — both are read-only.
    m = re.match(r"\s*(.*?)\s*<<\s*'[A-Za-z_]+'\s*(.*)$", first_line)
    if not m:
        return False
    lead_cmd, rest = m.group(1).strip(), m.group(2).strip()
    # The heredoc-consuming command must itself be a read-only filter. Reuse the
    # pipe-filter validator so awk (no system/getline/redirect), while-read loops,
    # and the plain filters (cat, head, grep, ...) are all accepted consistently.
    if not _is_safe_pipe_filter(lead_cmd):
        return False
    # Bare `cat <<'EOF'` with no trailing pipeline is safe.
    if not rest:
        return True
    # Otherwise the remainder must be `| filter [| filter ...]`.
    if not rest.startswith("|"):
        return False
    for seg in _split_top_level_pipes(rest):
        seg = seg.strip()
        if not seg:
            continue
        if not _is_safe_pipe_filter(seg):
            return False
    return True


def _is_safe_git_compound(command: str) -> bool:
    """Recognize safe compound git commands like 'git add ... && git commit -m ...'

    The standard Claude Code commit pattern chains git add with git commit
    using a heredoc for the message: git add files && git commit -m "$(cat <<'EOF'...)"
    This contains &&, $(, and < which trigger shell meta-char detection, but the
    pattern is safe — the single-quoted heredoc prevents expansion.
    """
    # Must contain git add chained into git commit. Optional cd prefix.
    return bool(re.match(
        r"(cd\s+[^&]+&&\s*)?git\s+add\s+.+&&\s*git\s+commit\s",
        command,
    ))


def _is_safe_git_commit_heredoc(command: str) -> bool:
    """Recognize git commit with heredoc message pattern as safe.

    Pattern: git commit -m "$(cat <<'EOF' ... EOF)"
    Contains shell meta-chars ($( and <<) that are heredoc syntax for the
    commit message, not command chaining. Safe because git commit is local-only.
    """
    return bool(re.match(r"^git\s+commit\s", command) and "<<" in command)


def _is_safe_curl(command: str) -> bool:
    """Recognize read-only curl commands as safe (pre meta-char check).

    URL query parameters contain & which triggers the shell meta-char guard.
    A standalone curl GET without pipes, redirects, or write flags is safe.
    Checked before meta-char detection to avoid URL & false positives.
    """
    if not command.startswith("curl "):
        return False
    # Shell operators that indicate chaining/piping (bare & is OK — it's in URLs)
    for meta in ["|", ";", "&&", "||", "`", "$(", ">", "<"]:
        if meta in command:
            return False
    tokens = command.split()
    is_get_mode = "-G" in tokens or "--get" in tokens
    for token in tokens[1:]:
        # Always-write flags (explicit method, form upload) block regardless of -G
        if token in CURL_WRITE_ONLY_FLAGS:
            return False
        # Data flags are write ops unless -G converts them to query params
        if not is_get_mode and token in CURL_DATA_FLAGS:
            return False
    return True


# Awk substrings that indicate side effects.
# awk's system() runs shell commands; getline can read files/commands;
# `print >`, `print |` write files or pipe to commands.
AWK_UNSAFE_TOKENS = (
    "system(", "system (",
    "getline",
    "> \"", "> '",
    "| \"", "| '",
)


def _is_safe_awk(segment: str) -> bool:
    """Check if an awk command segment is read-only.

    Common safe shape: `awk '{ print length, $0 }'`. We allow awk only
    when its script contains none of system()/getline/output-redirect.
    """
    return not any(t in segment for t in AWK_UNSAFE_TOKENS)


def _is_safe_read_loop(segment: str) -> bool:
    """Recognize a read-only `while read` line-processing loop.

    Safe idiom for measuring/numbering lines from stdin:
        while IFS= read -r line; do printf '%3d  %s\n' "${#line}" "$line"; done
    Only printf/echo bodies are allowed, and the body must contain no command
    substitution, redirects, pipes, or extra command separators — so the loop
    writes to stdout and nothing else. Common in char-counting workflows where
    each draft line's length is printed.
    """
    seg = segment.strip()
    m = re.match(
        r"^while\s+(?:IFS=\S*\s+)?read\s+(?:-r\s+)?\w+\s*;\s*do\s+(.*?)\s*;?\s*done$",
        seg,
    )
    if not m:
        return False
    body = m.group(1).strip()
    # Body must be only printf/echo — no other commands.
    if not re.match(r"^(printf|echo)\b", body):
        return False
    # Reject anything that could escape the loop or touch the filesystem:
    # command substitution, backticks, redirects, pipes, background, chaining.
    for bad in ("$(", "`", ">", "<", "|", "&", ";"):
        if bad in body:
            return False
    return True


# Shell-control characters that must not appear in a (non-while) pipe-filter
# segment. A filter is a single read-only command; chaining (;), backgrounding
# (&), command substitution ($(, `), or redirects (>, <) hidden after the filter
# word would otherwise ride along unchecked — e.g. `cat x | head; rm -rf ~`.
PIPE_FILTER_FORBIDDEN = (";", "&", "`", "$(", ">", "<")


def _is_safe_pipe_filter(segment: str) -> bool:
    """Check if a pipe segment is a read-only filter command."""
    seg = segment.strip()
    if not seg:
        return False
    tokens = seg.split()
    cmd = tokens[0]
    # `while read` line-measuring loop with a printf/echo-only body (no side effects).
    # Checked first because its body legitimately contains ';' (do ... done); the
    # helper self-validates with an anchored full-match regex.
    if cmd == "while":
        return _is_safe_read_loop(seg)
    # Every other filter must be a single command with nothing chained, substituted,
    # backgrounded, or redirected after it. Quoted data is neutralized first so a
    # literal ';' or '>' inside an argument (e.g. grep 'a;b') doesn't trip the guard.
    if any(ch in _strip_quoted_strings(seg) for ch in PIPE_FILTER_FORBIDDEN):
        return False
    if cmd in SAFE_PIPE_FILTERS:
        return True
    # awk is read-only by default, but system()/getline/redirect can have side effects
    if cmd == "awk":
        return _is_safe_awk(seg)
    # python3 -m json.tool is a read-only JSON formatter
    if cmd in ("python3", "python") and len(tokens) >= 3 and tokens[1] == "-m" and tokens[2] == "json.tool":
        return True
    return False


def _strip_quoted_strings(command: str) -> str:
    """Replace contents of quoted strings with empty placeholders.

    Used before meta-char detection so that quoted argument data (regex
    alternation, special chars in URLs, etc.) doesn't trigger the guard.
    Quotes themselves are kept as the placeholder. Backslash-escaped quotes
    inside double-quotes are respected.
    """
    out = []
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch == "'":
            # Single quotes — no escapes, find closing quote
            out.append("''")
            i += 1
            while i < n and command[i] != "'":
                i += 1
            i += 1  # skip closing quote (or run off end)
        elif ch == '"':
            # Double quotes — backslash escapes the next char
            out.append('""')
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_top_level_pipes(command: str) -> list:
    """Split on `|` only at the top level — outside quotes and not `||`.

    A naive split breaks quoted regex like `grep "a\\|b" file | head` into
    bogus segments. This walker tracks single/double-quote state and skips
    `||` (logical or, which is not a pipe).
    """
    segments = []
    buf = []
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif ch == "|" and not in_single and not in_double:
            # `||` is logical-or, not a pipe — leave untouched
            if i + 1 < len(command) and command[i + 1] == "|":
                buf.append("||")
                i += 2
                continue
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return segments


def _is_safe_piped_command(command: str) -> bool:
    """Check if a piped command is safe: safe source | safe filter(s).

    Handles the common pattern: find ... | head -20, grep ... | wc -l, etc.
    The source command must be a safe bash command, and all subsequent pipe
    segments must be read-only filter commands.
    """
    segments = _split_top_level_pipes(command)
    if len(segments) < 2:
        return False
    # First segment must be a safe command
    first = segments[0].strip()
    if not first or not is_safe_bash(first):
        return False
    # All subsequent segments must be read-only filters
    for seg in segments[1:]:
        if not _is_safe_pipe_filter(seg):
            return False
    return True


def _is_safe_compound_command(command: str) -> bool:
    """Check if a &&-separated compound command is entirely safe.

    Handles the common pattern: cd <path> && git status && git log --oneline
    Each segment is checked independently. `cd <path>` is always safe.
    Returns True only if ALL segments are individually safe.
    """
    segments = command.split("&&")
    if len(segments) < 2:
        return False  # Not a compound command
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        # cd <path> is always safe (just changes directory)
        if re.match(r"^cd\s+", seg):
            continue
        # source <path>/bin/activate (venv activation) — sets env vars, always safe
        if re.match(r"^source\s+\S*/bin/activate\s*$", seg):
            continue
        # Check each segment through normal safe patterns
        if not is_safe_bash(seg):
            return False
    return True


def _split_top_level_seq(command: str) -> list:
    """Split on top-level command separators `;`, `&&`, `||` — outside quotes.

    Single `|` (pipe) and single `&` (background) are NOT separators here — pipes
    are validated within a segment by is_safe_bash, and a bare `&` makes the
    segment fall through to Tier 3. Quote-aware so a separator inside a string
    (e.g. echo "a; b") is left intact.
    """
    segments = []
    buf = []
    in_single = in_double = False
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif not in_single and not in_double and ch == ";":
            segments.append("".join(buf))
            buf = []
        elif not in_single and not in_double and command[i:i + 2] in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return segments


def _is_safe_sequence(command: str) -> bool:
    """Check if a `;`/`&&`/`||`-separated sequence is entirely safe.

    Generalizes _is_safe_compound_command to unconditional (`;`) and short-circuit
    (`||`) separators. Each segment is validated independently via is_safe_bash
    (which itself handles single pipes and stderr redirects), so the sequence is
    safe iff every segment is safe — running read-only commands in any order has
    no side effects. `cd <path>` and venv activation are always-safe segments.
    Common shape: `ls foo 2>/dev/null | head; echo "---"; ls bar`.
    """
    segments = _split_top_level_seq(command)
    if len(segments) < 2:
        return False
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        if re.match(r"^cd\s+\S+$", seg):
            continue
        if re.match(r"^source\s+\S*/bin/activate\s*$", seg):
            continue
        if not is_safe_bash(seg):
            return False
    return True


def _is_safe_print_segment(segment: str) -> bool:
    """A read-only print statement: printf/echo, optionally piped to safe filters.

    Used inside char-counting scripts. No redirects, backgrounding, or command
    substitution — only stdout output, optionally measured by a filter (wc, etc.).
    """
    seg = segment.strip()
    if not seg:
        return True
    if any(ch in seg for ch in (">", "<", "&")):
        return False
    parts = _split_top_level_pipes(seg)
    if not re.match(r"^(printf|echo)\b", parts[0].strip()):
        return False
    return all(_is_safe_pipe_filter(p) for p in parts[1:])


def _is_safe_measure_script(command: str) -> bool:
    """Recognize read-only character-counting scripts used to size draft text.

    Shape: optional `VAR="literal"` assignments, then either
        for V in "draft1" "draft2" ...; do printf '%s' "$V" | wc -c; done
    or plain `printf/echo ... | wc -c` statements. The loop operands must be
    quoted string literals (pure data) and the body only printf/echo piped to
    read-only filters. Rejects command substitution, backticks, redirects, globs,
    and any non-print command — so it cannot run or mutate anything. Common in
    social-post workflows that check drafts against a character limit.
    """
    cmd = command.strip()
    # Command substitution could run anything — never auto-approve.
    if "$(" in cmd or "`" in cmd:
        return False
    # Neutralize quoted data so structure checks ignore arbitrary draft text.
    stripped = _strip_quoted_strings(cmd)
    stripped = re.sub(r"\\\s*\n", " ", stripped)        # join line continuations
    stripped = re.sub(r"\s*\n\s*", " ; ", stripped)     # newlines separate statements
    stripped = re.sub(r"\s+", " ", stripped).strip()
    # Peel optional leading `VAR=""` / `VAR=''` literal assignments.
    while True:
        m = re.match(r"^[A-Za-z_]\w*=(?:\"\"|'')\s*(?:;\s*)?", stripped)
        if not m:
            break
        stripped = stripped[m.end():].strip()
    if not stripped:
        return False
    # Case A: a for-loop over quoted literals with a printf/echo measuring body.
    m = re.match(r"^for\s+[A-Za-z_]\w*\s+in\s+(.*?)\s*;\s*do\s+(.*?)\s*;?\s*done$", stripped)
    if m:
        operands, body = m.group(1), m.group(2)
        # Operands must be only quoted-string placeholders (pure data, no globs/vars).
        if re.sub(r"(\"\"|'')|\s+", "", operands) != "":
            return False
        return all(_is_safe_print_segment(s) for s in body.split(";"))
    # Case B: plain printf/echo measuring statements (no loop).
    return all(_is_safe_print_segment(s) for s in stripped.split(";"))


def is_safe_bash(command: str) -> bool:
    """Check if a bash command matches safe patterns."""
    cmd = command.strip()
    # Strip safe stderr redirections before meta-char check.
    # 2>&1 and 2>/dev/null don't change command safety.
    cmd_for_meta = re.sub(r"\s*2>&1\s*$", "", cmd)
    cmd_for_meta = re.sub(r"\s*2>/dev/null\s*$", "", cmd_for_meta)
    # Strip leading `cd <path> &&` — just sets working directory, no side effects.
    cmd_for_meta = _strip_cd_prefix(cmd_for_meta)
    # Safe piped commands (find ... | head, grep ... | wc -l) — checked before
    # meta-char detection because | triggers the guard.
    if "|" in cmd_for_meta and _is_safe_piped_command(cmd_for_meta):
        return True
    # Read-only curl commands — checked before meta-char detection because
    # URL query parameters contain & which triggers the shell meta-char guard.
    if _is_safe_curl(cmd_for_meta):
        return True
    # Safe compound git commands (git add && git commit) — checked before
    # meta-char detection because the heredoc commit pattern contains $( and &&.
    if _is_safe_git_compound(cmd_for_meta):
        return True
    # Safe interpreter heredocs (python3 << 'EOF') — checked before meta-char
    # detection because << triggers the < meta-char. Only single-quoted
    # delimiters (no shell expansion) with safe interpreters.
    if _is_safe_heredoc(cmd_for_meta):
        return True
    # Safe filter heredocs (cat <<'EOF' | wc -c) — literal body piped to
    # read-only filters. Checked before meta-char detection because << and |
    # trigger the guard.
    if _is_safe_filter_heredoc(cmd_for_meta):
        return True
    # Read-only char-counting scripts (printf/echo | wc loops over literal drafts).
    # Checked before meta-char detection because ; and | trigger the guard.
    if _is_safe_measure_script(cmd_for_meta):
        return True
    # Safe compound commands (cd <path> && git status && git log) — checked
    # before meta-char detection because && triggers the guard.
    if "&&" in cmd_for_meta and _is_safe_compound_command(cmd_for_meta):
        return True
    # Safe sequences joined by ; or || (and &&) where every segment is safe —
    # checked before meta-char detection because the separators trigger the guard.
    if any(op in cmd_for_meta for op in (";", "&&", "||")) and _is_safe_sequence(cmd_for_meta):
        return True
    # Standalone git commit with heredoc — meta-chars are heredoc syntax, not chaining
    if _is_safe_git_commit_heredoc(cmd_for_meta):
        return True
    # Compound/piped/redirected commands are never auto-approved.
    # Quoted strings are pure data (e.g. `grep "a|b" file`), so strip them
    # before meta-char detection to avoid false-positives on regex alternation
    # or special chars inside arguments.
    cmd_for_meta_check = _strip_quoted_strings(cmd_for_meta)
    if any(meta in cmd_for_meta_check for meta in SHELL_META_CHARS):
        return False
    # Use the cleaned command for all further checks
    cmd = cmd_for_meta.strip()
    # Normalize `git -C <path>` to `git <subcommand>` before matching.
    # The -C flag only changes the repo directory — doesn't affect safety.
    cmd_for_match = re.sub(r"^(git)\s+-C\s+\S+\s+", r"\1 ", cmd)
    # Generic --version / -version / --help is always safe (read-only introspection)
    if cmd.endswith(" --version") or cmd.endswith(" -version") or cmd == "--version":
        return True
    if cmd.endswith(" --help") or cmd.endswith(" -help") or cmd == "--help":
        return True
    if cmd_for_match in SAFE_BASH_EXACT:
        return True
    if any(cmd_for_match.startswith(prefix) for prefix in SAFE_BASH_PREFIXES):
        return True
    # AWS CLI read-only commands
    if cmd_for_match.startswith("aws ") and is_safe_aws(cmd_for_match):
        return True
    # GitHub CLI read-only commands
    if cmd_for_match.startswith("gh ") and is_safe_gh(cmd_for_match):
        return True
    # sed without -i/--in-place is read-only (output to stdout, no file modification)
    if cmd_for_match.startswith("sed ") and " -i" not in cmd_for_match and "--in-place" not in cmd_for_match:
        return True
    return False


def is_doomsday_bash(command: str) -> bool:
    """Block only catastrophic commands — the last-resort safety net.

    These are things no legitimate session should ever run. Used in
    autonomous mode where everything else is auto-approved.
    """
    cmd = command.strip().lower()
    # Wipe root or home directory
    if re.search(r"\brm\s+-rf\s+/(?![a-z0-9._\-])", cmd):
        return True
    if re.search(r"\brm\s+-rf\s+~(?!/[a-z0-9._\-])", cmd):
        return True
    if re.search(r"\brm\s+-rf\s+\$home(?!/[a-z0-9._\-])", cmd):
        return True
    # Fork bomb
    if ":(){:|:&};:" in cmd:
        return True
    # Remote code execution via pipe
    if re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash)\b", cmd):
        return True
    if re.search(r"\beval\s+\$\((curl|wget)\b", cmd):
        return True
    # Disk destruction
    if "mkfs." in cmd or "> /dev/sda" in cmd or "dd if=" in cmd:
        return True
    return False


def is_dangerous_bash(command: str) -> bool:
    """Check if a bash command matches dangerous patterns (interactive mode).

    Broader than is_doomsday_bash — includes sudo, sensitive file access,
    chmod 777, etc. that are legitimate in autonomous sessions but warrant
    user confirmation in interactive ones.
    """
    cmd = command.strip().lower()
    if any(pattern in cmd for pattern in DANGEROUS_BASH_PATTERNS):
        return True
    if is_doomsday_bash(command):
        return True
    return False


def is_sensitive_file(path: str) -> bool:
    """Check if a file path looks like it contains secrets."""
    path_lower = path.lower()
    # Substring patterns (path components like .env, secrets/)
    if any(pattern in path_lower for pattern in SENSITIVE_PATH_PATTERNS):
        # Exclude known-safe .env templates (.env.example, .env.sample, .env.template)
        if path_lower.endswith(ENV_SAFE_SUFFIXES):
            pass  # Not sensitive — fall through to other checks
        else:
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


def is_autonomous_mode():
    """Check if running in autonomous dispatch mode.

    When DISPATCH_MODE=autonomous, Tier 3 decisions auto-approve instead of
    asking Claude or the user. Tier 1 (safe) and Tier 2 (dangerous) are
    unchanged — destructive commands are still blocked.
    """
    return os.environ.get("DISPATCH_MODE") == "autonomous"


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
    autonomous = is_autonomous_mode()

    # Discover terminal TTY for window matching
    tty = get_tty()

    # Signal HUD that hook is evaluating (amber flash)
    notify_hud_hook_start(session_id, tty)

    # --- User-interactive tools: always fall through ---
    # These tools exist to interact with the user; auto-approving them
    # silently swallows the prompt and returns empty input to Claude.
    # In autonomous mode, auto-approve (no user to interact with).
    if tool_name in USER_INTERACTIVE_TOOLS:
        if autonomous:
            reason = f"Autonomous: auto-approve user-interactive tool: {tool_name}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return
        reason = f"User-interactive tool: {tool_name}"
        log("PASSTHROUGH", tool_name, reason, tool_input)
        notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
        ask_user(reason)
        return

    # --- MCP tools: always fall through ---
    # MCP tools are external integrations with unpredictable side effects.
    # Tier 3 Claude rubber-stamps them, so let the user decide.
    # In autonomous mode, auto-approve.
    if tool_name.startswith("mcp__"):
        if autonomous:
            reason = f"Autonomous: auto-approve MCP tool: {tool_name}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return
        reason = f"MCP tool: {tool_name}"
        log("PASSTHROUGH", tool_name, reason, tool_input)
        notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
        ask_user(reason)
        return

    # --- TIER 1: Auto-approve safe tools ---
    if tool_name in SAFE_TOOLS:
        # Check if reading sensitive files (skip in autonomous mode —
        # trusted sessions need .env, credentials, etc.)
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        if file_path and not autonomous and is_sensitive_file(file_path):
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

        # Always-ask: commands that require user confirmation every time
        # In autonomous mode, auto-approve (Tier 2 dangerous check above still blocks)
        if _matches_always_ask(command):
            if autonomous:
                reason = f"Autonomous: auto-approve always-ask: {command}"
                log("ALLOW", tool_name, reason, tool_input)
                approve(reason)
                return
            reason = f"Always-ask pattern: {command}"
            log("PASSTHROUGH", tool_name, reason, tool_input)
            notify_hud(session_id, cwd, tool_name, tool_input, transcript_path, tty)
            ask_user(reason)
            return

        # Tier 2: Block dangerous commands
        # Autonomous mode: only block doomsday commands (rm -rf /, fork bomb, pipe-to-shell)
        # Interactive mode: broader set (sudo, chmod 777, sensitive file access, etc.)
        if autonomous and is_doomsday_bash(command):
            reason = f"Blocked doomsday command: {command}"
            log("DENY", tool_name, reason, tool_input)
            deny(reason)
            return
        if not autonomous and is_dangerous_bash(command):
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

        # Tier 3: Ambiguous — ask Claude (or auto-approve in autonomous mode)
        if autonomous:
            reason = f"Autonomous: auto-approve ambiguous command: {command}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return
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
        # Skip sensitive file check in autonomous mode — trusted sessions
        # need to write .env, config files, etc.
        if file_path and not autonomous and is_sensitive_file(file_path):
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
        # For writes outside project, ask Claude (or auto-approve in autonomous mode)
        if autonomous:
            reason = f"Autonomous: auto-approve file operation: {file_path}"
            log("ALLOW", tool_name, reason, tool_input)
            approve(reason)
            return
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

    # --- TIER 3: Everything else — ask Claude (or auto-approve in autonomous mode) ---
    if autonomous:
        reason = f"Autonomous: auto-approve: {tool_name}"
        log("ALLOW", tool_name, reason, tool_input)
        approve(reason)
        return
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
