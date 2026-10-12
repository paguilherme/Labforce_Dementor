from __future__ import annotations

import json
import subprocess
import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforce_dementor.local_ai import LocalAiError, detect_local_ai, invoke_local_ai


def test_detects_only_installed_local_assistants() -> None:
    with patch("labforce_dementor.local_ai.shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name in {"codex", "claude"} else None):
        assert [row["provider"] for row in detect_local_ai()] == ["codex-local", "claude-local"]


def test_codex_uses_authenticated_cli_without_api_keys() -> None:
    captured = {}

    def runner(command, **kwargs):
        if command[1:3] == ["login", "status"]:
            return SimpleNamespace(returncode=0, stdout="Logged in using ChatGPT", stderr="")
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, stdout='{"executive_summary":"ok","correlations":[],"recommendations":[],"limitations":[]}', stderr="")

    with patch("labforce_dementor.local_ai.shutil.which", return_value="/usr/bin/codex"), patch.dict("os.environ", {"OPENAI_API_KEY": "must-not-pass"}, clear=False):
        text, _, reference = invoke_local_ai(provider="codex-local", model="default", prompt="sanitized", runner=runner)
    assert json.loads(text)["executive_summary"] == "ok"
    assert captured["input"] == "sanitized"
    assert "OPENAI_API_KEY" not in captured["env"]
    assert captured["command"][-1] == "-"
    assert "--ignore-user-config" in captured["command"]
    assert "features.shell_tool=false" in captured["command"]
    assert "features.apps=false" in captured["command"]
    assert reference == "local-session:codex"


def test_claude_extracts_result_from_json_envelope() -> None:
    response = json.dumps({"result": '{"executive_summary":"ok","correlations":[],"recommendations":[],"limitations":[]}', "usage": {"input_tokens": 10}})

    def runner(command, **kwargs):
        if command[1:3] == ["auth", "status"]:
            return SimpleNamespace(returncode=0, stdout='{"authMethod":"claude.ai"}', stderr="")
        assert command[command.index("--tools") + 1] == ""
        assert "--strict-mcp-config" in command
        return SimpleNamespace(returncode=0, stdout=response, stderr="")

    with patch("labforce_dementor.local_ai.shutil.which", return_value="/usr/bin/claude"):
        text, usage, reference = invoke_local_ai(provider="claude-local", model="sonnet", prompt="sanitized", runner=runner)
    assert json.loads(text)["executive_summary"] == "ok"
    assert usage["input_tokens"] == 10
    assert reference == "local-session:claude"


@pytest.mark.parametrize("provider,auth", [("codex-local", "Logged in using an API key"), ("claude-local", '{"authMethod":"api_key"}')])
def test_api_authentication_is_rejected_before_generation(provider, auth):
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=auth, stderr="")
    with patch("labforce_dementor.local_ai.shutil.which", return_value="/bin/cli"), pytest.raises(LocalAiError, match="API"):
        invoke_local_ai(provider=provider, model="default", prompt="sanitized", runner=runner)
    assert len(calls) == 1


def test_gemini_receives_stdin_and_oauth_configuration_without_tools():
    def runner(command, **kwargs):
        settings = json.loads((Path(kwargs["cwd"]) / ".gemini" / "settings.json").read_text())
        assert settings["security"]["auth"]["enforcedType"] == "oauth-personal"
        assert settings["tools"]["core"] == ["__dementor_no_tools__"]
        assert settings["hooksConfig"]["enabled"] is False
        assert kwargs["input"] == "sanitized"
        assert command[command.index("-e") + 1] == "none"
        return SimpleNamespace(returncode=0, stdout='{"response":"{}","stats":{}}', stderr="")
    with patch("labforce_dementor.local_ai.shutil.which", return_value="/bin/gemini"):
        assert invoke_local_ai(provider="gemini-local", model="default", prompt="sanitized", runner=runner)[0] == "{}"


def test_timeout_never_echoes_assessment_or_secrets():
    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 30, output="secret-assessment")
    with patch("labforce_dementor.local_ai.shutil.which", return_value="/bin/cli"), pytest.raises(LocalAiError) as error:
        invoke_local_ai(provider="codex-local", model="default", prompt="secret-assessment", runner=runner)
    assert "secret-assessment" not in str(error.value)


@pytest.mark.parametrize("stdout", ["[]", '{"is_error":true,"result":"problem"}', "invalid"])
def test_invalid_or_error_envelopes_fail_cleanly(stdout):
    def runner(command, **kwargs):
        if command[1:3] == ["auth", "status"]:
            return SimpleNamespace(returncode=0, stdout='{"authMethod":"claude.ai"}', stderr="")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
    with patch("labforce_dementor.local_ai.shutil.which", return_value="/bin/cli"), pytest.raises(LocalAiError):
        invoke_local_ai(provider="claude-local", model="default", prompt="sanitized", runner=runner)
