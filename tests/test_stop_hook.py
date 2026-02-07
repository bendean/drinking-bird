"""Tests for stop-hook.py"""
import json
import sys
import io
import subprocess
import importlib.util
import tempfile
import os
from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest

# Import the hook script as a module (it's not a package)
HOOK_PATH = Path(__file__).parent.parent / "hooks" / "stop-hook.py"


def load_hook():
    spec = importlib.util.spec_from_file_location("stop_hook", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = load_hook()


# ============================================================================
# Helpers
# ============================================================================


def make_transcript(messages):
    """Build JSONL content from a list of (role, content_type, content_value) tuples.

    Examples:
        make_transcript([
            ("user", "text", "Hello"),
            ("assistant", "text", "Hi there!"),
        ])
    """
    lines = []
    for role, content_type, content_value in messages:
        if content_type == "text":
            content = [{"type": "text", "text": content_value}]
        elif content_type == "tool_use":
            content = [{"type": "tool_use", "id": "x", "name": "Bash", "input": {}}]
        elif content_type == "thinking":
            content = [{"type": "thinking", "thinking": "..."}]
        else:
            content = [{"type": content_type}]
        entry = {
            "type": role,
            "message": {"role": role, "content": content},
        }
        lines.append(json.dumps(entry))
    return "\n".join(lines) + "\n"


def write_transcript(tmp_path, messages):
    """Write transcript JSONL to a temp file and return the path."""
    content = make_transcript(messages)
    path = tmp_path / "transcript.jsonl"
    path.write_text(content)
    return str(path)


def run_main(input_data, mock_classify="SILENT", mock_last_text=None):
    """Helper: run main() with mocked stdin and optional mocks for classify/transcript."""
    captured_stdout = io.StringIO()
    patches = [
        patch("sys.stdin", io.StringIO(json.dumps(input_data))),
        patch("sys.stdout", captured_stdout),
        patch.object(hook, "log"),
    ]

    if mock_last_text is not None:
        patches.append(patch.object(hook, "get_last_assistant_text", return_value=mock_last_text))
    if mock_classify:
        patches.append(patch.object(hook, "classify_message", return_value=mock_classify))

    with pytest.raises(SystemExit) as exc_info:
        for p in patches:
            p.start()
        try:
            hook.main()
        finally:
            for p in patches:
                p.stop()

    return exc_info.value.code, captured_stdout.getvalue()


# ============================================================================
# Tests for get_last_assistant_text()
# ============================================================================


class TestGetLastAssistantText:
    """Transcript JSONL parsing."""

    def test_returns_text_from_last_assistant_message(self, tmp_path):
        path = write_transcript(tmp_path, [
            ("user", "text", "Hello"),
            ("assistant", "text", "First response"),
            ("user", "text", "Another question"),
            ("assistant", "text", "Second response"),
        ])
        assert hook.get_last_assistant_text(path) == "Second response"

    def test_skips_tool_use_only_messages(self, tmp_path):
        path = write_transcript(tmp_path, [
            ("assistant", "text", "Here is my answer"),
            ("user", "text", "Thanks"),
            ("assistant", "tool_use", None),
        ])
        assert hook.get_last_assistant_text(path) == "Here is my answer"

    def test_skips_thinking_only_messages(self, tmp_path):
        path = write_transcript(tmp_path, [
            ("assistant", "text", "Visible message"),
            ("assistant", "thinking", None),
        ])
        assert hook.get_last_assistant_text(path) == "Visible message"

    def test_returns_none_for_empty_file(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        assert hook.get_last_assistant_text(str(path)) is None

    def test_returns_none_for_missing_file(self):
        assert hook.get_last_assistant_text("/nonexistent/path.jsonl") is None

    def test_returns_none_for_no_assistant_messages(self, tmp_path):
        path = write_transcript(tmp_path, [
            ("user", "text", "Hello"),
            ("user", "text", "Anyone there?"),
        ])
        assert hook.get_last_assistant_text(path) is None

    def test_handles_malformed_json_lines(self, tmp_path):
        path = tmp_path / "mixed.jsonl"
        good_line = json.dumps({
            "type": "assistant",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "Good line"}]},
        })
        path.write_text(f"not valid json\n{good_line}\nalso bad\n")
        assert hook.get_last_assistant_text(str(path)) == "Good line"


# ============================================================================
# Tests for classify_message()
# ============================================================================


class TestClassifyMessage:
    """Claude classification via subprocess."""

    @patch.object(hook.subprocess, "run")
    def test_silent_response(self, mock_run):
        mock_run.return_value = MagicMock(stdout="SILENT", returncode=0)
        assert hook.classify_message("Git push completed.") == "SILENT"

    @patch.object(hook.subprocess, "run")
    def test_notify_response(self, mock_run):
        mock_run.return_value = MagicMock(stdout="NOTIFY", returncode=0)
        assert hook.classify_message("Please test the app.") == "NOTIFY"

    @patch.object(hook.subprocess, "run")
    def test_ambiguous_defaults_to_notify(self, mock_run):
        mock_run.return_value = MagicMock(stdout="I'm not sure", returncode=0)
        assert hook.classify_message("Some message") == "NOTIFY"

    @patch.object(hook.subprocess, "run")
    def test_timeout_defaults_to_notify(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="claude", timeout=10)
        assert hook.classify_message("Some message") == "NOTIFY"

    @patch.object(hook.subprocess, "run")
    def test_claude_not_found_defaults_to_notify(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        assert hook.classify_message("Some message") == "NOTIFY"

    @patch.object(hook.subprocess, "run")
    def test_generic_error_defaults_to_notify(self, mock_run):
        mock_run.side_effect = RuntimeError("unexpected")
        assert hook.classify_message("Some message") == "NOTIFY"

    @patch.object(hook.subprocess, "run")
    def test_message_truncated_to_500_chars(self, mock_run):
        mock_run.return_value = MagicMock(stdout="SILENT", returncode=0)
        long_message = "x" * 1000
        hook.classify_message(long_message)
        prompt_arg = mock_run.call_args[0][0][2]  # ["claude", "-p", prompt]
        assert "x" * 500 + "..." in prompt_arg
        assert "x" * 501 not in prompt_arg

    @patch.object(hook.subprocess, "run")
    def test_timeout_is_10_seconds(self, mock_run):
        mock_run.return_value = MagicMock(stdout="SILENT", returncode=0)
        hook.classify_message("test")
        _, kwargs = mock_run.call_args
        assert kwargs.get("timeout") == 10


# ============================================================================
# Tests for notify_hud_session_idle()
# ============================================================================


class TestNotifyHudSessionIdle:
    """HUD session-idle notification."""

    @patch.object(hook.urllib.request, "urlopen")
    def test_sends_correct_payload(self, mock_urlopen):
        hook.notify_hud_session_idle("sess-1", "/home/user/project",
                                     "Please test the app", "/tmp/t.jsonl")
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data)
        assert payload["session_id"] == "sess-1"
        assert payload["cwd"] == "/home/user/project"
        assert payload["summary"] == "Please test the app"
        assert payload["transcript_path"] == "/tmp/t.jsonl"
        assert "tty" not in payload

    @patch.object(hook.urllib.request, "urlopen")
    def test_includes_tty_when_provided(self, mock_urlopen):
        hook.notify_hud_session_idle("s", "/tmp", "msg", "/tmp/t.jsonl", tty="/dev/ttys003")
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data)
        assert payload["tty"] == "/dev/ttys003"

    @patch.object(hook.urllib.request, "urlopen")
    def test_posts_to_session_idle_endpoint(self, mock_urlopen):
        hook.notify_hud_session_idle("s", "/tmp", "msg", "/tmp/t.jsonl")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://127.0.0.1:9999/session-idle"

    @patch.object(hook.urllib.request, "urlopen")
    def test_timeout_is_half_second(self, mock_urlopen):
        hook.notify_hud_session_idle("s", "/tmp", "msg", "/tmp/t.jsonl")
        _, kwargs = mock_urlopen.call_args
        assert kwargs.get("timeout") == 0.5

    @patch.object(hook.urllib.request, "urlopen")
    def test_silently_ignores_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionRefusedError()
        # Should not raise
        hook.notify_hud_session_idle("s", "/tmp", "msg", "/tmp/t.jsonl")

    @patch.object(hook.urllib.request, "urlopen")
    def test_silently_ignores_url_error(self, mock_urlopen):
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("connection refused")
        hook.notify_hud_session_idle("s", "/tmp", "msg", "/tmp/t.jsonl")


# ============================================================================
# Tests for main()
# ============================================================================


class TestMain:
    """Integration tests for the full stop hook flow."""

    def test_no_transcript_path_exits_silent(self):
        exit_code, stdout = run_main(
            {"session_id": "s", "cwd": "/tmp", "transcript_path": ""},
            mock_classify=None, mock_last_text=None,
        )
        assert exit_code == 0
        assert stdout == ""

    def test_empty_transcript_exits_silent(self):
        exit_code, stdout = run_main(
            {"session_id": "s", "cwd": "/tmp", "transcript_path": "/tmp/t.jsonl"},
            mock_last_text=None,
        )
        assert exit_code == 0
        assert stdout == ""

    def test_notify_decision_calls_hud(self):
        input_data = {
            "session_id": "sess-1",
            "cwd": "/home/user/project",
            "transcript_path": "/tmp/t.jsonl",
        }
        with patch.object(hook, "notify_hud_session_idle") as mock_hud, \
             patch.object(hook, "get_tty", return_value="/dev/ttys003"):
            exit_code, stdout = run_main(input_data, mock_classify="NOTIFY",
                                         mock_last_text="Please test the app and verify the header shows correctly.")
        mock_hud.assert_called_once()
        call_kwargs = mock_hud.call_args
        assert call_kwargs[0][0] == "sess-1"  # session_id
        assert exit_code == 0

    def test_silent_decision_does_not_call_hud(self):
        input_data = {
            "session_id": "sess-1",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        }
        with patch.object(hook, "notify_hud_session_idle") as mock_hud:
            exit_code, stdout = run_main(input_data, mock_classify="SILENT",
                                         mock_last_text="Git push completed successfully.")
        mock_hud.assert_not_called()
        assert exit_code == 0

    def test_no_stdout_output(self):
        """Stop hook should produce no stdout output."""
        input_data = {
            "session_id": "s",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        }
        with patch.object(hook, "notify_hud_session_idle"):
            _, stdout = run_main(input_data, mock_classify="NOTIFY",
                                 mock_last_text="Test message")
        assert stdout == ""

    def test_invalid_json_stdin_exits_cleanly(self):
        captured = io.StringIO()
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.stdin", io.StringIO("not json")), \
                 patch("sys.stdout", captured):
                hook.main()
        assert exc_info.value.code == 0
        assert captured.getvalue() == ""

    def test_empty_stdin_exits_cleanly(self):
        captured = io.StringIO()
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.stdin", io.StringIO("")), \
                 patch("sys.stdout", captured):
                hook.main()
        assert exc_info.value.code == 0

    def test_always_exits_zero_on_notify(self):
        input_data = {
            "session_id": "s",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        }
        with patch.object(hook, "notify_hud_session_idle"):
            exit_code, _ = run_main(input_data, mock_classify="NOTIFY",
                                    mock_last_text="Do something")
        assert exit_code == 0

    def test_summary_truncated_to_80_chars(self):
        input_data = {
            "session_id": "s",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        }
        long_text = "a" * 200
        with patch.object(hook, "notify_hud_session_idle") as mock_hud, \
             patch.object(hook, "get_tty", return_value=None):
            run_main(input_data, mock_classify="NOTIFY", mock_last_text=long_text)
        summary = mock_hud.call_args[0][2]  # 3rd positional arg
        assert len(summary) == 83  # 80 chars + "..."
        assert summary.endswith("...")
