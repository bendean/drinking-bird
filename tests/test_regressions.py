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

    def test_2026_03_01_hostname_safe(self):
        '''`hostname` was going to Tier 3 (Claude evaluation). It's a read-only
        command that shows the machine hostname. Recommended in CLAUDE.md for
        determining which machine you're on.'''
        assert permission_hook.is_safe_bash("hostname")

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

    def test_2026_02_20_git_dash_C_safe(self):
        '''`git -C /path/to/repo log`, `git -C /path status`, etc. went to Tier 3
        because -C <path> between `git` and the subcommand prevented prefix matching.
        These are the same read-only git operations — the -C flag just changes the
        repo directory. Should be Tier 1 safe.'''
        # Read-only git commands with -C should be safe
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab/custom-tools/ai-lab-kanban log --oneline -20")
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab/custom-tools/ai-lab-kanban status")
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab/custom-tools/ai-lab-kanban diff --stat")
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab/custom-tools/ai-lab-kanban diff TODO.md")
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab/custom-tools/ai-lab-kanban show --stat 098583b")
        assert permission_hook.is_safe_bash("git -C /some/path branch -a")
        assert permission_hook.is_safe_bash("git -C /some/path branch -v")
        assert permission_hook.is_safe_bash("git -C /some/path tag")
        assert permission_hook.is_safe_bash("git -C /some/path remote -v")
        assert permission_hook.is_safe_bash("git -C /some/path stash list")
        # Dangerous git commands with -C should NOT be safe (should still hit always-ask or Tier 3)
        assert not permission_hook.is_safe_bash("git -C /some/path push")
        assert not permission_hook.is_safe_bash("git -C /some/path reset --hard HEAD")

    def test_2026_02_20_git_add_safe(self):
        '''`git add server.py static/app.js ...` went to Tier 3. Staging files is
        safe — it doesn't modify history, doesn't touch the network, and is
        trivially reversible with `git reset`. Should be Tier 1 safe.'''
        assert permission_hook.is_safe_bash("git add server.py static/app.js static/style.css tests/test_file_matching.py TODO.md")
        assert permission_hook.is_safe_bash("git add .")
        assert permission_hook.is_safe_bash("git add -A")
        assert permission_hook.is_safe_bash("git add --all")
        assert permission_hook.is_safe_bash("git add -u")
        assert permission_hook.is_safe_bash("git add src/components/Button.tsx")

    def test_2026_02_21_gh_read_only_safe(self):
        '''`gh auth status 2>&1` went to Tier 3 (Claude evaluation). GitHub CLI
        read-only commands like auth status, pr list, pr view, repo list, repo view
        are safe — they only read data and don't modify anything.'''
        # auth status
        assert permission_hook.is_safe_bash("gh auth status")
        assert permission_hook.is_safe_bash("gh auth status 2>&1")
        # pr read-only
        assert permission_hook.is_safe_bash("gh pr list")
        assert permission_hook.is_safe_bash("gh pr list --state open")
        assert permission_hook.is_safe_bash("gh pr view 123")
        assert permission_hook.is_safe_bash("gh pr view --web")
        assert permission_hook.is_safe_bash("gh pr status")
        assert permission_hook.is_safe_bash("gh pr checks 42")
        assert permission_hook.is_safe_bash("gh pr diff 42")
        # repo read-only
        assert permission_hook.is_safe_bash("gh repo list")
        assert permission_hook.is_safe_bash("gh repo list myorg")
        assert permission_hook.is_safe_bash("gh repo view")
        assert permission_hook.is_safe_bash("gh repo view owner/repo")
        # issue read-only
        assert permission_hook.is_safe_bash("gh issue list")
        assert permission_hook.is_safe_bash("gh issue view 42")
        assert permission_hook.is_safe_bash("gh issue status")
        # release read-only
        assert permission_hook.is_safe_bash("gh release list")
        assert permission_hook.is_safe_bash("gh release view v1.0")
        # api (read-only GET requests)
        assert permission_hook.is_safe_bash("gh api repos/owner/repo/pulls/123/comments")
        # help/version
        assert permission_hook.is_safe_bash("gh --version")
        assert permission_hook.is_safe_bash("gh help")

    def test_2026_02_21_gh_write_not_safe(self):
        '''GitHub CLI mutating commands must NOT be auto-approved.
        They should go to Tier 3 for Claude evaluation.'''
        assert not permission_hook.is_safe_bash("gh pr create --title 'fix' --body 'done'")
        assert not permission_hook.is_safe_bash("gh pr merge 42")
        assert not permission_hook.is_safe_bash("gh pr close 42")
        assert not permission_hook.is_safe_bash("gh repo create my-repo --private")
        assert not permission_hook.is_safe_bash("gh repo delete owner/repo")
        assert not permission_hook.is_safe_bash("gh repo edit --visibility public")
        assert not permission_hook.is_safe_bash("gh repo clone owner/repo")
        assert not permission_hook.is_safe_bash("gh issue create --title 'bug'")
        assert not permission_hook.is_safe_bash("gh issue close 42")
        assert not permission_hook.is_safe_bash("gh release create v1.0")
        assert not permission_hook.is_safe_bash("gh release delete v1.0")

    def test_2026_02_21_git_init_safe(self):
        '''`git init` went to Tier 3 (Claude evaluation). git init creates a new
        .git directory — non-destructive, standard dev operation similar to mkdir.
        Should be Tier 1 safe.'''
        assert permission_hook.is_safe_bash("git init")
        assert permission_hook.is_safe_bash("git init .")
        assert permission_hook.is_safe_bash("git init /path/to/project")

    def test_2026_02_22_ln_symlink_safe(self):
        '''`ln -sf source target` went to Tier 3 (Claude evaluation). Symlink
        creation is non-destructive — the source file is never modified. Even
        with -f (force), only the symlink itself is overwritten. Common dev
        operation for linking data files, configs, etc.'''
        assert permission_hook.is_safe_bash("ln -sf /Users/ben/AI-Lab/mlb-project/backend/data/game_cache/831732.json /Users/ben/AI-Lab/mlb-project/.claude/worktrees/phase-a/data/")
        assert permission_hook.is_safe_bash("ln -s source.txt link.txt")
        assert permission_hook.is_safe_bash("ln -sf /path/to/target /path/to/link")
        assert permission_hook.is_safe_bash("ln target link")

    def test_2026_02_22_git_ls_files_safe(self):
        '''`git ls-files` went to Tier 3 (Claude evaluation). git ls-files is
        a read-only command that lists tracked files. No modification capability.'''
        assert permission_hook.is_safe_bash("git ls-files")
        assert permission_hook.is_safe_bash("git ls-files backend/data/game_cache/")
        assert permission_hook.is_safe_bash("git ls-files --others --ignored --exclude-standard")

    def test_2026_02_22_git_check_ignore_safe(self):
        '''`git check-ignore -q .claude/worktrees` went to Tier 3 (Claude evaluation).
        git check-ignore is a read-only command that queries .gitignore rules.'''
        assert permission_hook.is_safe_bash("git check-ignore -q .claude/worktrees")
        assert permission_hook.is_safe_bash("git check-ignore src/file.txt")
        assert permission_hook.is_safe_bash("git check-ignore -v path/to/file")

    def test_2026_02_22_git_worktree_list_safe(self):
        '''`git worktree list` is read-only — just lists existing worktrees.
        But `git worktree add/remove/prune` create or destroy state, so they
        should NOT be auto-approved.'''
        # List is read-only — safe
        assert permission_hook.is_safe_bash("git worktree list")
        assert permission_hook.is_safe_bash("git worktree list --porcelain")
        # Add/remove/prune are NOT safe — they create/destroy state
        assert not permission_hook.is_safe_bash("git worktree add .claude/worktrees/feature -b feature/x")
        assert not permission_hook.is_safe_bash("git worktree remove .claude/worktrees/feature")
        assert not permission_hook.is_safe_bash("git worktree prune")

    def test_2026_02_23_git_rev_parse_safe(self):
        '''`git -C /path rev-parse HEAD` went to Tier 3 (Claude evaluation).
        git rev-parse is a read-only plumbing command — it prints commit SHAs,
        branch names, and repo paths. Zero modification capability.
        Should be Tier 1 safe.'''
        assert permission_hook.is_safe_bash("git rev-parse HEAD")
        assert permission_hook.is_safe_bash("git rev-parse --abbrev-ref HEAD")
        assert permission_hook.is_safe_bash("git rev-parse --show-toplevel")
        assert permission_hook.is_safe_bash("git rev-parse --git-dir")
        assert permission_hook.is_safe_bash("git rev-parse --short HEAD")
        # With -C flag (should normalize and still match)
        assert permission_hook.is_safe_bash("git -C /Users/ben/AI-Lab rev-parse HEAD")

    def test_2026_02_25_git_merge_base_not_always_ask(self):
        '''`git merge-base` inside $(…) triggered ALWAYS_ASK "git merge" substring match.
        `git merge-base` is a read-only plumbing command — it prints commit SHAs.
        It should NOT be caught by the "git merge" always-ask pattern.
        Commands like `git merge feature-branch` should still always-ask.'''
        # git merge-base is read-only — should NOT match always-ask
        # (These commands also have shell meta-chars, so they won't be Tier 1 safe.
        #  The test verifies they don't hit ALWAYS_ASK, allowing them to reach Tier 3.)
        cmd1 = "cd /Users/ben/project && git log branch --not $(git merge-base main branch)"
        assert not any(p in cmd1 for p in permission_hook.ALWAYS_ASK_BASH_PATTERNS), \
            "git merge-base should not trigger always-ask 'git merge' pattern"
        cmd2 = "cd /Users/ben/project && git diff $(git merge-base main branch) branch --name-status"
        assert not any(p in cmd2 for p in permission_hook.ALWAYS_ASK_BASH_PATTERNS), \
            "git merge-base should not trigger always-ask 'git merge' pattern"
        # Actual git merge commands should still match always-ask
        assert any(p in "git merge feature-branch" for p in permission_hook.ALWAYS_ASK_BASH_PATTERNS)
        assert any(p in "git merge --no-ff feature" for p in permission_hook.ALWAYS_ASK_BASH_PATTERNS)
        assert any(p in "git merge main" for p in permission_hook.ALWAYS_ASK_BASH_PATTERNS)

    def test_2026_02_26_venv_pytest_direct_safe(self):
        '''`.venv/bin/pytest tests/ -v` went to Tier 3 (Claude evaluation).
        We already have `.venv/bin/python -m pytest` and bare `pytest` as safe,
        but the direct `.venv/bin/pytest` binary invocation was missing.
        Running pytest from a venv is identical in safety to running it directly.'''
        assert permission_hook.is_safe_bash(".venv/bin/pytest tests/ -v")
        assert permission_hook.is_safe_bash(".venv/bin/pytest tests/ -q")
        assert permission_hook.is_safe_bash(".venv/bin/pytest tests/test_hooks.py -v")
        assert permission_hook.is_safe_bash(".venv/bin/pytest")
        # Existing venv python -m pytest should still work
        assert permission_hook.is_safe_bash(".venv/bin/python -m pytest tests/")
        assert permission_hook.is_safe_bash(".venv/bin/python3 -m pytest tests/")

    def test_2026_02_24_npx_dev_tools_safe(self):
        '''`npx jest lib/github/parse-url.test.ts 2>&1` went to Tier 3 ~6 times.
        `npx next build 2>&1` went to Tier 3 ~5 times. These are standard dev
        tool invocations equivalent to `jest `, `npm run build`, `npm run dev`
        which are already Tier 1 safe. npx runs locally-installed node packages
        — same as running the command directly. Should be Tier 1 safe.'''
        # npx jest (test runner — equivalent to `jest ` which is already safe)
        assert permission_hook.is_safe_bash("npx jest lib/github/parse-url.test.ts 2>&1")
        assert permission_hook.is_safe_bash("npx jest lib/github/api.test.ts 2>&1")
        assert permission_hook.is_safe_bash("npx jest --verbose 2>&1")
        assert permission_hook.is_safe_bash("npx jest")
        # npx vitest (test runner — equivalent to `vitest ` which is already safe)
        assert permission_hook.is_safe_bash("npx vitest run")
        assert permission_hook.is_safe_bash("npx vitest --watch")
        # npx next build/dev/lint (equivalent to npm run build/dev/lint)
        assert permission_hook.is_safe_bash("npx next build 2>&1")
        assert permission_hook.is_safe_bash("npx next dev -p 3001")
        assert permission_hook.is_safe_bash("npx next lint 2>&1")
        # npx tsc (TypeScript compiler — equivalent to `tsc ` which is already safe)
        assert permission_hook.is_safe_bash("npx tsc --noEmit")
        assert permission_hook.is_safe_bash("npx tsc --version")
        # npx eslint/prettier (linters — equivalents already safe)
        assert permission_hook.is_safe_bash("npx eslint src/")
        assert permission_hook.is_safe_bash("npx prettier --check src/")
        # npx with unknown packages should NOT be safe (falls to Tier 3)
        assert not permission_hook.is_safe_bash("npx cowsay hello")
        assert not permission_hook.is_safe_bash("npx create-react-app my-app")


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

    def test_2026_03_01_all_set_completion_silent(self):
        '''`"All set. Here's what I did: 1. Created a Python 3.13 venv..."` was
        classified as NOTIFY by Tier 3 Claude. "All set" is a common completion
        phrase — should be SILENT locally.'''
        result = stop_hook.classify_local("All set. Here's what I did: 1. Created a Python 3.13 venv at mlb-project/backend/.venv")
        assert result == "SILENT"

    def test_2026_03_01_completion_followed_by_instruction_notify(self):
        '''`"Done. Now fill in the three placeholders..."` was classified SILENT
        because "Done." matched COMPLETION_PREFIXES and returned early. But the
        rest of the message is an instruction. Completion prefix should not
        short-circuit when followed by imperative instructions.'''
        # Completion followed by instruction — should NOTIFY
        result = stop_hook.classify_local("Done. Now fill in the three placeholders: nano ~/.openclaw/openclaw.json")
        assert result == "NOTIFY"
        result2 = stop_hook.classify_local("Fixed. Please restart the server and check the logs.")
        assert result2 == "NOTIFY"
        result3 = stop_hook.classify_local("Updated. Now run the build to verify.")
        assert result3 == "NOTIFY"
        result4 = stop_hook.classify_local("Installed. Try opening the app and check if the layout looks correct.")
        assert result4 == "NOTIFY"
        # Pure completion — should still be SILENT
        result5 = stop_hook.classify_local("Done.")
        assert result5 == "SILENT"
        result6 = stop_hook.classify_local("Done. All tests pass.")
        assert result6 == "SILENT"
        result7 = stop_hook.classify_local("Fixed the authentication bug.")
        assert result7 == "SILENT"

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

    def test_2026_02_28_copied_opened_completion(self):
        '''"Copied. 16 games with results..." and "Opened. Here's what you'll see:..."
        went to Tier 3 Claude instead of being locally classified as SILENT.
        "Copied" and "Opened" are completion actions like "Created", "Updated",
        "Pushed" — they indicate a task was done. Should be SILENT (local).'''
        # Completion actions — should be SILENT
        assert stop_hook.classify_local("Copied. 16 games with results, reviews, and scorecards in run-20260228.") == "SILENT"
        assert stop_hook.classify_local("Opened. Here's what you'll see: Chat area with day separators.") == "SILENT"
        assert stop_hook.classify_local("Copied the files to the M1 successfully.") == "SILENT"
        assert stop_hook.classify_local("Opened the viewer at localhost:5174.") == "SILENT"
        # With question mark, should still NOTIFY (question check runs first)
        assert stop_hook.classify_local("Copied. Should I also deploy?") == "NOTIFY"
        assert stop_hook.classify_local("Opened the file. Does it look right?") == "NOTIFY"

    def test_2026_02_28_refresh_imperative(self):
        '''"Refresh /audit. The card detail meta strip now shows the game date..."
        went to Tier 3 Claude instead of being locally classified as NOTIFY.
        "Refresh" is an imperative telling the user to reload a page/view,
        like "Run", "Check", "Open" which are already caught locally.'''
        # Imperative — should be NOTIFY
        assert stop_hook.classify_local("Refresh /audit. The card detail meta strip now shows the game date.") == "NOTIFY"
        assert stop_hook.classify_local("Refresh the page to see the changes.") == "NOTIFY"
        assert stop_hook.classify_local("Refresh your browser and check the layout.") == "NOTIFY"


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
