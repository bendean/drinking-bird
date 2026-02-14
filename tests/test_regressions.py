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
