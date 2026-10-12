from __future__ import annotations
from typing import Any

REQUIRED_TOP_LEVEL = {
    "product": dict, "run": dict, "org": dict, "inventory": dict,
    "components": dict, "dependencies": list, "findings": list,
    "health": dict, "audit": dict, "code_analyzer": dict,
}

def validate_assessment_payload(data: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    for key, typ in REQUIRED_TOP_LEVEL.items():
        if key not in data:
            errors.append(f"Missing required key: {key}")
        elif not isinstance(data[key], typ):
            errors.append(f"Invalid type for {key}: expected {typ.__name__}, got {type(data[key]).__name__}")
    health = data.get("health", {})
    if isinstance(health, dict):
        score = health.get("overall")
        if score is not None and (not isinstance(score, (int,float)) or score < 0 or score > 100):
            errors.append("health.overall must be between 0 and 100 or null")
    for i, edge in enumerate(data.get("dependencies", []) if isinstance(data.get("dependencies"), list) else []):
        if not isinstance(edge, dict) or not edge.get("source") or not edge.get("target") or not edge.get("relationship"):
            warnings.append(f"Dependency edge {i} is incomplete")
            if len(warnings) >= 50:
                break
    for i, finding in enumerate(data.get("findings", []) if isinstance(data.get("findings"), list) else []):
        if not isinstance(finding, dict):
            errors.append(f"Finding {i} must be an object")
            continue
        for key in ("id", "category", "severity", "title"):
            if not finding.get(key):
                errors.append(f"Finding {i} missing {key}")
        confidence = finding.get("confidence", 1.0)
        if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
            errors.append(f"Finding {i} confidence must be between 0 and 1")
        if not finding.get("evidence"):
            warnings.append(f"Finding {finding.get('id', i)} has no evidence")
    audit = data.get("audit", {})
    if isinstance(audit, dict):
        if any(audit.get(k, 0) for k in ("dml_executed", "metadata_deployments", "apex_anonymous_executions")):
            errors.append("Read-only safety invariant violated: write-capable operation counter is non-zero")
    return {"valid": not errors, "errors": errors, "warnings": warnings[:200]}
