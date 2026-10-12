from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _cmd_version(args: list[str]) -> dict[str, Any]:
    try:
        p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return {"available": p.returncode == 0, "stdout": p.stdout.strip()[:1000], "stderr": p.stderr.strip()[:1000], "returncode": p.returncode}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def doctor() -> dict[str, Any]:
    sf_path = shutil.which("sf")
    python_pdf = importlib.util.find_spec("weasyprint") is not None
    matplotlib = importlib.util.find_spec("matplotlib") is not None
    jinja = importlib.util.find_spec("jinja2") is not None

    result = {
        "salesforce_cli": {"available": bool(sf_path), "path": sf_path},
        "salesforce_cli_version": _cmd_version(["sf", "version", "--json"]) if sf_path else {"available": False},
        "code_analyzer": _cmd_version(["sf", "code-analyzer", "rules", "--json"]) if sf_path else {"available": False},
        "python_dependencies": {
            "weasyprint": python_pdf,
            "matplotlib": matplotlib,
            "jinja2": jinja,
        },
    }
    result["ready_for_full_assessment"] = bool(sf_path and matplotlib and jinja)
    result["pdf_ready"] = bool(python_pdf)
    return result
