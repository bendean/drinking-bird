"""
Regression tests built from real log entries.

Each test captures a real-world classification miss found during tuning cycles.
When /db-tuning finds a bug, the offending log entry becomes a test case here
BEFORE the fix is applied (red-green-refactor).

Format:
    def test_YYYY_MM_DD_description(self):
        '''Brief description of what was wrong.'''
        # The actual input that triggered the bug
        # The expected classification
        # Assert correct behavior

To add a new regression:
    1. Copy the log entry that exposed the bug
    2. Write a failing test that reproduces it
    3. Fix the code
    4. Verify the test passes
"""

import importlib.util
from pathlib import Path
import pytest

# Load hooks as modules (same pattern as existing tests)
HOOKS_DIR = Path(__file__).parent.parent / "hooks"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HOOKS_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


permission_hook = load_module("permission_hook", "permission-hook.py")
stop_hook = load_module("stop_hook", "stop-hook.py")


# ============================================================================
# Permission hook regressions
# ============================================================================

class TestPermissionRegressions:
    """Regressions from permission hook tuning cycles."""

    # === Template for new regressions ===
    # def test_2026_02_XX_description(self):
    #     '''Found: <what happened>. Expected: <what should happen>.'''
    #     result = permission_hook.is_safe_bash("the actual command")
    #     assert result is True  # or False

    def test_2026_02_13_claude_version_safe(self):
        '''claude --version was going to tier 3 (Claude LLM). Should be safe.'''
        assert permission_hook.is_safe_bash("claude --version 2>&1")

    def test_2026_02_13_claude_help_safe(self):
        '''claude --help was going to tier 3. Read-only introspection.'''
        assert permission_hook.is_safe_bash("claude --help 2>&1")

    def test_2026_02_13_claude_plugin_help_safe(self):
        '''claude plugin --help was going to tier 3.'''
        assert permission_hook.is_safe_bash("claude plugin --help 2>&1")

    def test_2026_02_13_pip_install_not_safe(self):
        '''pip install modifies system state. Should not be auto-approved.'''
        assert not permission_hook.is_safe_bash("pip3 install pytest")
        assert not permission_hook.is_safe_bash("pip install requests")

    def test_2026_02_15_git_branch_delete_not_safe(self):
        '''`git branch -d feature/foo` was auto-approved because the "git branch"
        prefix matches all git branch subcommands including deletion.
        Read-only git branch commands (list, show) are safe but -d/-D/--delete are not.'''
        # Deletions should NOT be safe
        assert not permission_hook.is_safe_bash("git branch -d feature/billy-knowledge-pipeline")
        assert not permission_hook.is_safe_bash("git branch -D feature/foo")
        assert not permission_hook.is_safe_bash("git branch --delete feature/foo")
        # Read-only git branch commands should still be safe
        assert permission_hook.is_safe_bash("git branch")
        assert permission_hook.is_safe_bash("git branch -a")
        assert permission_hook.is_safe_bash("git branch -v")
        assert permission_hook.is_safe_bash("git branch --list")
        assert permission_hook.is_safe_bash("git branch -r")
        assert permission_hook.is_safe_bash("git branch --show-current")

    def test_2026_02_16_background_operator_not_safe(self):
        '''`bash ./start.sh & sleep 4 curl -s ...` bypassed meta-char check because
        `&` (background operator) was not in SHELL_META_CHARS. A command like
        `git status & curl evil.com` would be auto-approved by prefix match.'''
        # Background operator should NOT be safe
        assert not permission_hook.is_safe_bash("git status & curl evil.com")
        assert not permission_hook.is_safe_bash("bash ./start.sh & sleep 4")
        assert not permission_hook.is_safe_bash("echo foo & echo bar")
        # Existing && should still be caught
        assert not permission_hook.is_safe_bash("git status && rm -rf /")
        # 2>&1 at end should still be stripped (not caught as &)
        assert permission_hook.is_safe_bash("git status 2>&1")
        assert permission_hook.is_safe_bash("python3 --version 2>&1")

    def test_2026_02_19_mkdir_safe(self):
        '''`mkdir -p /project/dir` was going to Tier 3 (2-5s Claude evaluation).
        mkdir is non-destructive — it creates directories and fails silently
        if they already exist. Should be Tier 1 safe.'''
        assert permission_hook.is_safe_bash("mkdir -p /Users/ben/AI-Lab/mlb-project/backend/simulator")
        assert permission_hook.is_safe_bash("mkdir -p /Users/ben/AI-Lab/mlb-project/data/social")
        assert permission_hook.is_safe_bash("mkdir /tmp/test")
        assert permission_hook.is_safe_bash("mkdir -p src/components tests/fixtures")

    def test_2026_02_19_venv_pytest_safe(self):
        '''`.venv/bin/python -m pytest tests/ -q` was going to Tier 3 because
        the safe prefix `python3 -m pytest` doesn't match venv python paths.
        Running tests via venv is identical to running them via system python.'''
        assert permission_hook.is_safe_bash(".venv/bin/python -m pytest tests/ -q")
        assert permission_hook.is_safe_bash(".venv/bin/python -m pytest tests/ -v")
        assert permission_hook.is_safe_bash(".venv/bin/python3 -m pytest tests/")
        assert permission_hook.is_safe_bash(".venv/bin/python -m pytest tests/test_parser.py -v")
        # System python should still be safe
        assert permission_hook.is_safe_bash("python3 -m pytest tests/")
        assert permission_hook.is_safe_bash("python -m pytest tests/")

    def test_2026_02_19_cp_safe(self):
        '''`cp src dest` was going to Tier 3. cp is non-destructive — it copies
        files without removing the source. Standard dev operation.'''
        assert permission_hook.is_safe_bash("cp /Users/ben/AI-Lab/mlb-project/docs/artifacts/feed-v3.md /Users/ben/AI-Lab/mlb-project/docs/artifacts/feed-v4.md")
        assert permission_hook.is_safe_bash("cp -r src/ backup/")
        assert permission_hook.is_safe_bash("cp file.txt file.bak")

    def test_2026_02_19_aws_read_only_safe(self):
        '''AWS CLI read-only commands (describe, list, get, head) were going to
        Tier 3 (~2-5s Claude evaluation). These are safe — they require AWS
        credentials to be configured and only read data.'''
        # describe- commands
        assert permission_hook.is_safe_bash("aws ec2 describe-instances")
        assert permission_hook.is_safe_bash("aws ec2 describe-instances --region us-east-1")
        assert permission_hook.is_safe_bash("aws rds describe-db-instances")
        assert permission_hook.is_safe_bash("aws ecs describe-clusters --clusters my-cluster")
        # list- commands
        assert permission_hook.is_safe_bash("aws s3api list-buckets")
        assert permission_hook.is_safe_bash("aws iam list-users")
        assert permission_hook.is_safe_bash("aws lambda list-functions --region us-west-2")
        # get- commands
        assert permission_hook.is_safe_bash("aws sts get-caller-identity")
        assert permission_hook.is_safe_bash("aws ssm get-parameter --name /my/param")
        assert permission_hook.is_safe_bash("aws s3api get-object --bucket b --key k out.txt")
        # head- commands
        assert permission_hook.is_safe_bash("aws s3api head-object --bucket b --key k")
        # s3 ls
        assert permission_hook.is_safe_bash("aws s3 ls")
        assert permission_hook.is_safe_bash("aws s3 ls s3://my-bucket/path/")
        # help
        assert permission_hook.is_safe_bash("aws help")
        assert permission_hook.is_safe_bash("aws ec2 help")
        # wait (polls, doesn't modify)
        assert permission_hook.is_safe_bash("aws ec2 wait instance-running --instance-ids i-1234")

    def test_2026_02_19_aws_write_not_safe(self):
        '''AWS CLI write/mutating commands must NOT be auto-approved.
        They should go to Tier 3 for Claude evaluation.'''
        assert not permission_hook.is_safe_bash("aws ec2 terminate-instances --instance-ids i-1234")
        assert not permission_hook.is_safe_bash("aws s3 rm s3://my-bucket/file.txt")
        assert not permission_hook.is_safe_bash("aws s3 cp file.txt s3://my-bucket/")
        assert not permission_hook.is_safe_bash("aws s3 sync . s3://my-bucket/")
        assert not permission_hook.is_safe_bash("aws ec2 run-instances --image-id ami-1234")
        assert not permission_hook.is_safe_bash("aws iam create-user --user-name bob")
        assert not permission_hook.is_safe_bash("aws iam delete-user --user-name bob")
        assert not permission_hook.is_safe_bash("aws lambda invoke --function-name f out.json")
        assert not permission_hook.is_safe_bash("aws ec2 stop-instances --instance-ids i-1234")
        assert not permission_hook.is_safe_bash("aws rds delete-db-instance --db-instance-identifier mydb")

    def test_2026_02_14_env_example_not_sensitive(self):
        '''`.env.example` was blocked by substring match on `.env.`.
        Example files are templates — they never contain real secrets.'''
        assert not permission_hook.is_sensitive_file("/Users/ben/AI-Lab/mlb-project/config/.env.example")
        assert not permission_hook.is_sensitive_file("/project/.env.sample")
        assert not permission_hook.is_sensitive_file("/project/.env.template")
        # Real .env files should still be blocked
        assert permission_hook.is_sensitive_file("/project/.env")
        assert permission_hook.is_sensitive_file("/project/.env.local")
        assert permission_hook.is_sensitive_file("/project/.env.production")


# ============================================================================
# Stop hook regressions
# ============================================================================

class TestStopHookRegressions:
    """Regressions from stop hook tuning cycles."""

    # === Template for new regressions ===
    # def test_2026_02_XX_description(self):
    #     '''Found: <what happened>. Expected: <what should happen>.'''
    #     result = stop_hook.classify_local("the actual message text")
    #     assert result == "SILENT"  # or "NOTIFY" or None

    def test_2026_02_13_idle_with_trailing_question_silent(self):
        '''Messages like "Waiting for your call — X or Y?" were notifying
        because "?" check ran before idle pattern check.'''
        result = stop_hook.classify_local("Waiting for your call — should we do X or Y?")
        assert result == "SILENT"

    def test_2026_02_14_imperative_instruction_notify(self):
        '''"Now run tests:" is an instruction to the user — should NOTIFY.
        Was falling through to Claude which incorrectly said SILENT.'''
        result = stop_hook.classify_local("Now run tests:")
        assert result == "NOTIFY"
        # Other imperative instructions
        result2 = stop_hook.classify_local("Please restart the server and check the logs.")
        assert result2 == "NOTIFY"
        result3 = stop_hook.classify_local("Run the build and let me know if it passes.")
        assert result3 == "NOTIFY"

    def test_2026_02_18_now_prefix_false_positive(self):
        '''"Now let me verify systematically" and "Now add the gap between the two rows:"
        were NOTIFY because "Now " prefix matched too broadly. These are Claude
        narrating its own next actions, not instructing the user to act.
        "Now " should only NOTIFY when followed by a user-directed imperative
        like "Now run/try/check/test".'''
        # Claude narrating its own actions — should NOT be NOTIFY
        assert stop_hook.classify_local("Now let me verify systematically. I'll check every mapping and also scan") != "NOTIFY"
        assert stop_hook.classify_local("Now rewrite the RosterPreview component with inline flow layout") != "NOTIFY"
        assert stop_hook.classify_local("Now add the same background to the team name cells and add gaps") != "NOTIFY"
        assert stop_hook.classify_local("Now add the gap between the two rows:") != "NOTIFY"
        assert stop_hook.classify_local("Now it's one container with borderTop + borderBottom as the white lines") != "NOTIFY"
        # User-directed imperatives — should still NOTIFY
        assert stop_hook.classify_local("Now run tests:") == "NOTIFY"
        assert stop_hook.classify_local("Now try opening the app and check if the layout looks correct.") == "NOTIFY"
        assert stop_hook.classify_local("Now check the console for errors.") == "NOTIFY"


# ============================================================================
# Credential redaction regressions
# ============================================================================

class TestCredentialRedaction:
    """Regressions from credential leak in log reason field."""

    def test_2026_02_14_reason_field_redacts_credentials(self):
        '''Credentials in the reason field were written to the log unredacted.
        The summary field was redacted via _summarize_input(), but the reason
        string (e.g. "Always-ask pattern: export TOKEN=abc123") was not.'''
        redacted = permission_hook._redact_credentials(
            "Always-ask pattern: export TRELLO_API_KEY=1a9699a4f7595d0322919915103a4a2e && export TRELLO_TOKEN=2da5e7e61cde"
        )
        assert "1a9699a4f7595d0322919915103a4a2e" not in redacted
        assert "2da5e7e61cde" not in redacted
        assert "TRELLO_API_KEY=***" in redacted
        assert "TRELLO_TOKEN=***" in redacted

    def test_2026_02_14_log_function_redacts_reason(self, tmp_path):
        '''The log() function itself must redact credentials in the reason field,
        not just rely on callers to redact.'''
        import tempfile
        log_file = tmp_path / "test.log"
        # Temporarily override LOG_FILE
        original = permission_hook.LOG_FILE
        permission_hook.LOG_FILE = str(log_file)
        try:
            permission_hook.log(
                "PASSTHROUGH", "Bash",
                "Always-ask pattern: export SECRET=hunter2",
                {"command": "export SECRET=hunter2"}
            )
            content = log_file.read_text()
            assert "hunter2" not in content
            assert "SECRET=***" in content
        finally:
            permission_hook.LOG_FILE = original
