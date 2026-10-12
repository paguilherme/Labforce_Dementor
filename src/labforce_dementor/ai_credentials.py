from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from .ai_complement import AiComplementError


PROVIDER_KEYS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


@dataclass(frozen=True)
class AiCredentialLease:
    api_key: str | None
    reference: str


def _find_base_root(start: Path) -> Path:
    for candidate in (start.resolve(), *start.resolve().parents):
        if (candidate / "platform" / "credentials" / "secret_broker.py").is_file():
            return candidate
    raise AiComplementError("Labforce Base credential broker was not found")


def _load_secret_broker(root: Path) -> ModuleType:
    path = root / "platform" / "credentials" / "secret_broker.py"
    spec = importlib.util.spec_from_file_location("labforce_base_secret_broker", path)
    if spec is None or spec.loader is None:
        raise AiComplementError("Labforce Base credential broker could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def resolve_ai_credential(
    provider: str,
    *,
    source: str,
    organization: str | None,
    client: str | None = None,
    project: str | None = None,
    base_root: Path | None = None,
) -> AiCredentialLease:
    if provider == "ollama":
        return AiCredentialLease(api_key=None, reference="local-loopback:ollama")
    key_name = PROVIDER_KEYS.get(provider)
    if not key_name:
        raise AiComplementError(f"unsupported AI provider: {provider}")

    if source == "environment":
        value = os.environ.get(key_name, "")
        if not value:
            raise AiComplementError(f"credential {key_name} is unavailable")
        return AiCredentialLease(api_key=value, reference=f"environment:{key_name}")

    if source != "labforce-base":
        raise AiComplementError(f"unsupported credential source: {source}")
    if not organization:
        raise AiComplementError("organization is required for the Labforce Base credential vault")
    root = base_root.resolve() if base_root else _find_base_root(Path.cwd())
    broker_module = _load_secret_broker(root)
    broker = broker_module.SecretBroker(root)
    tool = f"ai_{provider}"
    try:
        lease = broker.lease_environment(
            tool=tool,
            organization=organization,
            client=client,
            project=project,
        )
    except Exception as exc:
        raise AiComplementError(
            f"AI credential is unavailable for provider {provider} in the requested scope"
        ) from exc
    value = lease.environment.get(key_name)
    if not value:
        raise AiComplementError(f"credential {key_name} is unavailable in the requested scope")
    return AiCredentialLease(api_key=value, reference=lease.reference)
