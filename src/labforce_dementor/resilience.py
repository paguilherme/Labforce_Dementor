from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TRANSIENT_MARKERS = (
    "request_limit_exceeded",
    "server unavailable",
    "service unavailable",
    "temporarily unavailable",
    "timeout",
    "timed out",
    "connection reset",
    "connection aborted",
    "socket hang up",
    "ecconnreset",
    "econnreset",
    "503",
    "502",
    "504",
    "429",
)


def is_transient_error(stderr: str, stdout: str = "") -> bool:
    text = f"{stderr}\n{stdout}".lower()
    return any(marker in text for marker in TRANSIENT_MARKERS)


@dataclass
class RateLimiter:
    min_interval_seconds: float = 0.0
    _last_call: float = 0.0

    def wait(self) -> None:
        if self.min_interval_seconds <= 0:
            return
        now = time.monotonic()
        remaining = self.min_interval_seconds - (now - self._last_call)
        if remaining > 0:
            time.sleep(remaining)
        self._last_call = time.monotonic()


class CheckpointStore:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, Any] = {"schema": 1, "stages": {}}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except Exception:
                pass

    def done(self, stage: str) -> bool:
        return self.data.get("stages", {}).get(stage, {}).get("status") == "done"

    def mark(self, stage: str, status: str, **extra: Any) -> None:
        self.data.setdefault("stages", {})[stage] = {
            "status": status,
            "timestamp": time.time(),
            **extra,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def integrity_manifest(directory: Path, *, exclude_names: set[str] | None = None) -> dict[str, Any]:
    exclude_names = exclude_names or set()
    files = []
    for p in sorted(directory.rglob("*")):
        if not p.is_file() or p.name in exclude_names:
            continue
        files.append({
            "path": str(p.relative_to(directory)),
            "bytes": p.stat().st_size,
            "sha256": sha256_file(p),
        })
    return {"algorithm": "SHA-256", "files": files, "count": len(files)}
