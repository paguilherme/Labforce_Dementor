from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


LOCAL_AI_PROVIDERS = ("codex-local", "claude-local", "gemini-local")
_EXECUTABLES = {
    "codex-local": "codex",
    "claude-local": "claude",
    "gemini-local": "gemini",
}


class LocalAiError(RuntimeError):
    pass


def detect_local_ai() -> list[dict[str, str]]:
    detected = []
    for provider in LOCAL_AI_PROVIDERS:
        executable = _EXECUTABLES[provider]
        path = shutil.which(executable)
        if path:
            detected.append({
                "provider": provider,
                "label": {
                    "codex-local": "Codex autenticado localmente",
                    "claude-local": "Claude Code autenticado localmente",
                    "gemini-local": "Gemini CLI autenticado localmente",
                }[provider],
                "executable": executable,
                "path": path,
            })
    return detected


def _command(provider: str, executable: str, model: str) -> list[str]:
    use_default = not model.strip() or model.strip().lower() in {"default", "padrão", "padrao"}
    if provider == "codex-local":
        command = [executable, "exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--ignore-user-config", "--ignore-rules"]
        for setting in ("approval_policy=\"never\"", "web_search=\"disabled\"", "mcp_servers={}",
                        "features.shell_tool=false", "features.unified_exec=false", "features.apps=false",
                        "features.hooks=false", "features.multi_agent=false", "features.memories=false"):
            command.extend(["-c", setting])
        if not use_default:
            command.extend(["--model", model.strip()])
        command.append("-")
        return command
    if provider == "claude-local":
        command = [
            executable, "-p", "--input-format", "text", "--output-format", "json",
            "--permission-mode", "plan", "--max-turns", "1",
            "--tools", "", "--disallowedTools", "mcp__*", "--strict-mcp-config",
            "--mcp-config", '{"mcpServers":{}}', "--setting-sources", "",
            "--settings", '{"disableAllHooks":true}', "--no-session-persistence", "--safe-mode",
        ]
        if not use_default:
            command.extend(["--model", model.strip()])
        return command
    if provider == "gemini-local":
        command = [executable, "--output-format", "json", "--approval-mode", "plan", "-e", "none", "--allowed-mcp-server-names", "__dementor_none__", "-p", "Analyze the sanitized assessment supplied on standard input. Return only the requested JSON."]
        if not use_default:
            command.extend(["--model", model.strip()])
        return command
    raise LocalAiError(f"Assistente local não suportado: {provider}")


def _response(provider: str, stdout: str) -> tuple[str, dict[str, Any]]:
    if provider == "codex-local":
        if not stdout.strip():
            raise LocalAiError("Codex local não retornou conteúdo")
        return stdout.strip(), {}
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise LocalAiError("O assistente local retornou uma resposta de controle inválida") from exc
    if not isinstance(value, dict) or value.get("is_error") or value.get("error"):
        raise LocalAiError("O assistente local retornou uma falha ou resposta de controle inválida")
    if provider == "claude-local":
        text = value.get("result") or value.get("response") or ""
        usage = value.get("usage") or {}
    else:
        text = value.get("response") or value.get("result") or ""
        usage = value.get("stats") or value.get("usage") or {}
    if not isinstance(text, str) or not text.strip():
        raise LocalAiError("O assistente local não retornou conteúdo")
    return text, usage if isinstance(usage, dict) else {}


def invoke_local_ai(
    *,
    provider: str,
    model: str,
    prompt: str,
    timeout: int = 600,
    runner: Any = None,
) -> tuple[str, dict[str, Any], str]:
    runner = runner or subprocess.run
    executable_name = _EXECUTABLES.get(provider)
    if not executable_name:
        raise LocalAiError(f"Assistente local não suportado: {provider}")
    executable = shutil.which(executable_name)
    if not executable:
        raise LocalAiError(
            f"O executável '{executable_name}' não foi encontrado. Instale-o e autentique-o no mesmo usuário do VS Code."
        )
    command = _command(provider, executable, model)
    inherited_keys = {"PATH", "HOME", "USER", "LOGNAME", "SystemRoot", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA",
                      "CODEX_HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                      "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TERM",
                      "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"}
    clean_env = {key: value for key, value in os.environ.items() if key in inherited_keys}
    # A autenticação pertence ao próprio CLI. O Dementor não lê nem injeta chaves de API.
    for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_GENAI_USE_VERTEXAI", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"):
        clean_env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="labforce-dementor-ai-") as temp_dir:
        try:
            if provider == "gemini-local":
                config_dir = Path(temp_dir) / ".gemini"
                config_dir.mkdir()
                (config_dir / "settings.json").write_text(json.dumps({
                    "security": {"auth": {"selectedType": "oauth-personal", "enforcedType": "oauth-personal"}},
                    "tools": {"core": ["__dementor_no_tools__"]},
                    "mcp": {"allowed": ["__dementor_none__"]},
                    "context": {"fileName": "__dementor_no_context__.md", "includeDirectoryTree": False},
                    "hooksConfig": {"enabled": False},
                }), encoding="utf-8")
            else:
                auth_cmd = [executable, "login", "status"] if provider == "codex-local" else [executable, "auth", "status"]
                auth = runner(auth_cmd, text=True, capture_output=True, timeout=30, cwd=Path(temp_dir), env=clean_env, check=False)
                if auth.returncode != 0:
                    raise LocalAiError(f"Autentique {executable_name} antes de gerar o complemento; nenhuma geração foi iniciada.")
                if provider == "codex-local":
                    if "chatgpt" not in (auth.stdout + auth.stderr).lower():
                        raise LocalAiError("Codex local exige login com ChatGPT; autenticação por API não é aceita neste modo.")
                else:
                    auth_info = json.loads(auth.stdout)
                    if not isinstance(auth_info, dict) or auth_info.get("authMethod") not in {"claude.ai", "oauth_token"}:
                        raise LocalAiError("Claude local exige login OAuth; autenticação por API não é aceita neste modo.")
            completed = runner(
                command,
                input=prompt,
                text=True,
                capture_output=True,
                timeout=timeout,
                cwd=Path(temp_dir),
                env=clean_env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            # TimeoutExpired can contain the complete prompt; never echo exception payloads.
            raise LocalAiError(f"Falha ou timeout ao executar {executable_name}; confira autenticação e versão do CLI.") from exc
    if completed.returncode != 0:
        raise LocalAiError(
            f"{executable_name} não concluiu a geração (código {completed.returncode}). Confirme autenticação, quota e suporte aos flags documentados. Nenhuma API alternativa será usada."
        )
    text, usage = _response(provider, completed.stdout)
    return text, usage, f"local-session:{executable_name}"
