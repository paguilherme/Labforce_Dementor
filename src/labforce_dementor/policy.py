from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import yaml


DEFAULT_POLICY = {
    "name": "default",
    "fail_on": {
        "new_critical_findings": 1,
        "new_high_findings": None,
        "health_drop_points": 10,
        "max_change_risk": 90,
        "drift": False,
    }
}


def load_policy(path: Path | None) -> dict[str, Any]:
    if path is None:
        return DEFAULT_POLICY.copy()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = DEFAULT_POLICY.copy()
    out["fail_on"] = {**DEFAULT_POLICY["fail_on"], **data.get("fail_on", {})}
    out["name"] = data.get("name", path.stem)
    return out


def evaluate_policy(current: dict[str, Any], *, before: dict[str, Any] | None = None,
                    drift: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or DEFAULT_POLICY
    rules = policy.get("fail_on", {})
    violations = []

    current_findings = current.get("findings", [])
    before_ids = {f.get("id") for f in (before or {}).get("findings", [])}
    new = [f for f in current_findings if f.get("id") not in before_ids] if before is not None else current_findings
    new_critical = sum(1 for f in new if str(f.get("severity","")).lower() == "critical")
    new_high = sum(1 for f in new if str(f.get("severity","")).lower() == "high")

    limit = rules.get("new_critical_findings")
    if limit is not None and new_critical >= int(limit):
        violations.append({"rule":"new_critical_findings","actual":new_critical,"threshold":limit})
    limit = rules.get("new_high_findings")
    if limit is not None and new_high >= int(limit):
        violations.append({"rule":"new_high_findings","actual":new_high,"threshold":limit})

    if before is not None:
        old = before.get("health",{}).get("overall")
        now = current.get("health",{}).get("overall")
        allowed = rules.get("health_drop_points")
        if isinstance(old,(int,float)) and isinstance(now,(int,float)) and allowed is not None and old-now >= float(allowed):
            violations.append({"rule":"health_drop_points","actual":old-now,"threshold":allowed})

    risks = current.get("components",{}).get("intelligence",{}).get("v3",{}).get("risk_and_debt",{}).get("top_change_risk",[])
    max_risk = max([x.get("change_risk_score",0) for x in risks] or [0])
    limit = rules.get("max_change_risk")
    if limit is not None and max_risk >= float(limit):
        violations.append({"rule":"max_change_risk","actual":max_risk,"threshold":limit})

    if rules.get("drift") is True and drift and drift.get("has_drift"):
        violations.append({"rule":"drift","actual":True,"threshold":False})

    return {
        "policy": policy.get("name","default"),
        "passed": not violations,
        "violations": violations,
        "metrics": {"new_critical":new_critical,"new_high":new_high,"max_change_risk":max_risk},
    }
