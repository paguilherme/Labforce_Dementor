from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .safety import ReadOnlyCommandGuard
from .resilience import RateLimiter, is_transient_error


class SFCLIError(RuntimeError):
    def __init__(self, message: str, command: list[str] | None = None, payload: Any = None):
        super().__init__(message)
        self.command = command or []
        self.payload = payload


class SFCLI:
    def __init__(self, target_org: str, cwd: Path, audit: dict[str, Any], config: dict[str, Any] | None = None):
        self.target_org = target_org
        self.cwd = cwd
        self.audit = audit
        safety = (config or {}).get("safety", {})
        self.max_retries = max(0, int(safety.get("max_retries", 3)))
        self.retry_base_seconds = max(0.0, float(safety.get("retry_base_seconds", 1.5)))
        self.rate_limiter = RateLimiter(max(0.0, float(safety.get("min_seconds_between_cli_calls", 0.15))))

    @staticmethod
    def ensure_available() -> None:
        if shutil.which("sf") is None:
            raise SFCLIError("Salesforce CLI ('sf') was not found in PATH.")

    def run(self, args: list[str], *, tolerate_failure: bool = False, timeout: int = 900, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
        cmd = ["sf", *args]
        ReadOnlyCommandGuard.validate(cmd)
        self.audit.setdefault("commands", []).append(" ".join(cmd))
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        last_error: dict[str, Any] | None = None
        for attempt in range(self.max_retries + 1):
            self.rate_limiter.wait()
            self.audit["read_operations"] = self.audit.get("read_operations", 0) + 1
            try:
                proc = subprocess.run(
                    cmd, cwd=self.cwd, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout, env=env,
                )
                stdout = proc.stdout.strip()
                stderr = proc.stderr.strip()
            except subprocess.TimeoutExpired as exc:
                stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                stderr = f"timeout after {timeout}s"
                proc = None

            payload: dict[str, Any] = {}
            if stdout:
                try:
                    payload = json.loads(stdout)
                except json.JSONDecodeError:
                    payload = {"raw": stdout}

            if proc is not None and proc.returncode == 0:
                if attempt:
                    self.audit.setdefault("retries", []).append({"command": " ".join(cmd), "attempts": attempt + 1, "recovered": True})
                return {"ok": True, "payload": payload, "stderr": stderr}

            returncode = proc.returncode if proc is not None else -1
            last_error = {
                "command": " ".join(cmd),
                "returncode": returncode,
                "stderr": stderr,
                "stdout": stdout[:4000],
                "attempt": attempt + 1,
            }
            transient = is_transient_error(stderr, stdout)
            if transient and attempt < self.max_retries:
                sleep_for = self.retry_base_seconds * (2 ** attempt)
                self.audit.setdefault("retries", []).append({"command": " ".join(cmd), "attempt": attempt + 1, "sleep_seconds": sleep_for})
                time.sleep(sleep_for)
                continue
            break

        self.audit.setdefault("read_errors", []).append(last_error or {"command": " ".join(cmd), "stderr": "unknown"})
        if tolerate_failure:
            return {"ok": False, "error": last_error, "payload": payload}
        raise SFCLIError((last_error or {}).get("stderr") or (last_error or {}).get("stdout") or "Salesforce CLI command failed", cmd, payload)

    def org_display(self) -> dict[str, Any]:
        return self.run(["org", "display", "--target-org", self.target_org, "--json"])["payload"]

    def limits(self) -> dict[str, Any]:
        return self.run(["org", "list", "limits", "--target-org", self.target_org, "--json"])["payload"]

    def query(self, soql: str, *, tooling: bool = False, tolerate_failure: bool = True) -> dict[str, Any]:
        args = ["data", "query", "--target-org", self.target_org, "--query", soql, "--json"]
        if tooling:
            args.insert(2, "--use-tooling-api")
        return self.run(args, tolerate_failure=tolerate_failure, timeout=300)


    def rest_get(self, url: str, *, stream_to: Path | None = None, tolerate_failure: bool = True) -> dict[str, Any]:
        args = [
            "api", "request", "rest", url,
            "--target-org", self.target_org,
            "--method", "GET",
        ]
        if stream_to is not None:
            stream_to.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["--stream-to-file", str(stream_to)])
        else:
            args.append("--json")
        return self.run(args, tolerate_failure=tolerate_failure, timeout=900)

    def generate_manifest(
        self,
        metadata_types: list[str] | None,
        manifest_dir: Path,
        batch_size: int = 10,
        include_packages: list[str] | None = None,
    ) -> dict[str, Any]:
        manifest_dir.mkdir(parents=True, exist_ok=True)
        args = [
            "project", "generate", "manifest",
            "--from-org", self.target_org,
            "--name", "package",
            "--output-dir", str(manifest_dir),
        ]
        for item in metadata_types or []:
            args.extend(["--metadata", item])
        for package_type in include_packages or []:
            if package_type not in {"managed", "unlocked"}:
                raise SFCLIError(f"Unsupported package type for manifest discovery: {package_type}")
            args.extend(["--include-packages", package_type])
        args.append("--json")
        return self.run(args, timeout=1800, extra_env={"SF_LIST_METADATA_BATCH_SIZE": str(batch_size)})["payload"]

    def retrieve(self, manifest_path: Path) -> dict[str, Any]:
        args = [
            "project", "retrieve", "start",
            "--manifest", str(manifest_path),
            "--target-org", self.target_org,
            "--wait", "60",
            "--json",
        ]
        return self.run(args, timeout=4200)["payload"]

    def code_analyzer(self, workspace: Path, output_file: Path, rule_selector: str = "Recommended") -> dict[str, Any]:
        args = [
            "code-analyzer", "run",
            "--workspace", str(workspace),
            "--rule-selector", rule_selector,
            "--view", "detail",
            "--output-file", str(output_file),
            "--include-fixes",
            "--include-suggestions",
            "--json",
        ]
        # Code Analyzer can return a nonzero status depending on configuration/violations.
        return self.run(args, tolerate_failure=True, timeout=3600)
