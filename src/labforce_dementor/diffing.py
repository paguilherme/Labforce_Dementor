from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .branding import with_report_metadata


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_assessments(before_path: Path, after_path: Path) -> dict[str, Any]:
    before = _load(before_path)
    after = _load(after_path)
    inv_b, inv_a = before.get("inventory", {}), after.get("inventory", {})
    inventory_delta = {k: int(inv_a.get(k, 0) or 0) - int(inv_b.get(k, 0) or 0) for k in sorted(set(inv_b) | set(inv_a))}
    hb, ha = before.get("health", {}), after.get("health", {})
    categories = {}
    for k in sorted(set(hb.get("categories", {})) | set(ha.get("categories", {}))):
        b, a = hb.get("categories", {}).get(k), ha.get("categories", {}).get(k)
        categories[k] = {"before": b, "after": a, "delta": round(a-b, 2) if isinstance(a, (int,float)) and isinstance(b, (int,float)) else None}
    fb = {f.get("id"): f for f in before.get("findings", []) if f.get("id")}
    fa = {f.get("id"): f for f in after.get("findings", []) if f.get("id")}
    return {
        "before": str(before_path), "after": str(after_path),
        "overall_health": {"before": hb.get("overall"), "after": ha.get("overall"), "delta": round((ha.get("overall") or 0)-(hb.get("overall") or 0), 2) if isinstance(ha.get("overall"), (int,float)) and isinstance(hb.get("overall"), (int,float)) else None},
        "health_categories": categories,
        "inventory_delta": inventory_delta,
        "new_findings": [fa[k] for k in sorted(set(fa)-set(fb))],
        "resolved_findings": [fb[k] for k in sorted(set(fb)-set(fa))],
        "persistent_findings": len(set(fa) & set(fb)),
    }


def write_diff(before: Path, after: Path, output: Path) -> dict[str, Any]:
    result = diff_assessments(before, after)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(with_report_metadata(result), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return result
