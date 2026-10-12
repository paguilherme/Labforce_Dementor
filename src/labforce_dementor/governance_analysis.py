from __future__ import annotations

import re
import math
from datetime import datetime, timezone
from typing import Any
from .apex_lexical import code_only


_METHOD = re.compile(
    r"(?im)\b(?:(?:public|private|protected|global)\s+)?"
    r"(?:(?:static|virtual|override|abstract|testmethod)\s+)*"
    r"[A-Za-z_][A-Za-z0-9_.]*(?:\s*<[^;{}()]+>)?(?:\[\])?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"
)
_TEST_METHOD = re.compile(
    r"(?is)(?:@isTest(?:\([^)]*\))?\s+|\btestMethod\s+)"
    r"(?:(?:public|private|protected|global|static)\s+)*"
    r"[A-Za-z_][A-Za-z0-9_<>,.\[\]\s?]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\("
)


def _code(text: str) -> str:
    # Scan strings and comments together: URLs inside strings must not start comments.
    return code_only(text)


def _score(value: int, threshold: int, points: int) -> float:
    if threshold <= 0:
        return 0.0
    return min(float(points), (value / threshold) * points)


def _apex_metrics(item: dict[str, Any], class_names: set[str], object_names: set[str] | None = None) -> dict[str, Any]:
    raw = str(item.get("text", ""))
    text = _code(raw)
    nonblank_lines = sum(1 for line in text.splitlines() if line.strip())
    methods = sum(name.lower() not in {"if", "for", "while", "switch", "catch"} for name in _METHOD.findall(text))
    test_methods = len(_TEST_METHOD.findall(text))
    complexity = 1 + len(re.findall(r"\b(?:if|for|while|catch|when)\b|&&|\|\||\?", text, re.I))
    identifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text))
    dependencies = sorted((class_names & identifiers) - {item.get("api_name")})
    objects = set(re.findall(r"\bfrom\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.I))
    known_objects = (object_names or set()) | {"Account", "Contact", "Lead", "Opportunity", "Case", "Task", "Event", "User", "Order", "Contract", "Product2", "PricebookEntry", "Campaign", "Asset"}
    constructors = re.findall(r"\bnew\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.I)
    objects.update(name for name in constructors if name in known_objects or name.endswith(("__c", "__e", "__mdt")))
    objects.update(known_objects & identifiers)
    entrypoint_kinds = {
        name for name, pattern in {
            "REST": r"@RestResource\b",
            "Aura": r"@AuraEnabled\b",
            "Invocable": r"@InvocableMethod\b",
            "Batch": r"Database\.Batchable\b",
            "Queueable": r"\bQueueable\b",
            "Schedulable": r"\bSchedulable\b",
            "Callout": r"HttpRequest|\bcallout:",
        }.items() if re.search(pattern, text, re.I)
    }
    return {
        "component": f"{item.get('component_type', 'ApexClass')}:{item.get('api_name', '')}",
        "api_name": item.get("api_name", ""),
        "is_test": bool(item.get("is_test")),
        "source_file": item.get("source_file", ""),
        "lines": nonblank_lines,
        "methods": methods,
        "test_methods": test_methods,
        "complexity_proxy": complexity,
        "class_dependencies": len(dependencies),
        "referenced_classes": dependencies[:100],
        "responsibilities": len(objects) + len(entrypoint_kinds),
        "referenced_objects": sorted(objects)[:100],
        "entrypoint_kinds": sorted(entrypoint_kinds),
        "soql_statements": len(re.findall(r"\[\s*select\b|Database\.(?:query|countQuery)\s*\(", text, re.I)),
        "dml_statements": len(re.findall(r"\b(?:insert|update|upsert|delete|undelete|merge)\b\s+[A-Za-z_]", text, re.I)) + len(re.findall(r"Database\.(?:insert|update|upsert|delete|undelete)\s*\(", text, re.I)),
        "callouts": len(re.findall(r"\.send\s*\(|HttpRequest\s+[A-Za-z_]|\bcallout:", text, re.I)),
    }


def _classify(metrics: dict[str, Any], thresholds: dict[str, Any], *, test: bool) -> dict[str, Any]:
    method_key = "test_methods" if test else "methods"
    method_threshold_key = "min_test_methods" if test else "min_methods"
    signals = {
        "lines": metrics["lines"] >= int(thresholds.get("min_lines", 700 if test else 500)),
        method_key: metrics[method_key] >= int(thresholds.get(method_threshold_key, 25 if test else 20)),
        "dependencies": metrics["class_dependencies"] >= int(thresholds.get("min_dependencies", 15 if test else 12)),
        "responsibilities": metrics["responsibilities"] >= int(thresholds.get("min_responsibilities", 10 if test else 8)),
    }
    if not test:
        signals["complexity"] = metrics["complexity_proxy"] >= int(thresholds.get("min_complexity", 50))
    score = (
        _score(metrics["lines"], int(thresholds.get("min_lines", 700 if test else 500)), 25)
        + _score(metrics[method_key], int(thresholds.get(method_threshold_key, 25 if test else 20)), 20)
        + _score(metrics["class_dependencies"], int(thresholds.get("min_dependencies", 15 if test else 12)), 20)
        + _score(metrics["responsibilities"], int(thresholds.get("min_responsibilities", 10 if test else 8)), 15)
    )
    if test:
        score += _score(metrics["complexity_proxy"], 60, 20)
    else:
        score += _score(metrics["complexity_proxy"], int(thresholds.get("min_complexity", 50)), 20)
    score = round(min(100.0, score), 1)
    active_signals = [name for name, active in signals.items() if active]
    return {
        **metrics,
        "score": score,
        "signals": active_signals,
        "candidate": score >= float(thresholds.get("min_score", 65)) and len(active_signals) >= 2,
    }


def analyze_code_governance(components: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    classes = components.get("apex_classes", [])
    triggers = [{**item, "component_type": "ApexTrigger"} for item in components.get("apex_triggers", [])]
    object_names = {str(item.get("api_name")) for item in components.get("objects", []) if item.get("api_name")}
    names = {str(item.get("api_name")) for item in classes if item.get("api_name")}
    analysis = config.get("analysis", {})
    production: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []
    governor_cfg = analysis.get("governor_risk", {})
    governor_risks: list[dict[str, Any]] = []
    for item in classes + triggers:
        metrics = _apex_metrics(item, names, object_names)
        is_test = bool(metrics["is_test"])
        thresholds = analysis.get("god_test_class" if is_test else "god_class", {})
        row = _classify(metrics, thresholds, test=is_test)
        if item.get("component_type") != "ApexTrigger":
            all_rows.append(row)
            if row["candidate"]:
                (tests if is_test else production).append(row)
        exceeded = []
        for metric, default in (("soql_statements", 80), ("dml_statements", 120), ("callouts", 80)):
            threshold = int(governor_cfg.get(metric, default))
            if row[metric] >= threshold:
                exceeded.append({"metric": metric, "count": row[metric], "warning_threshold": threshold})
        if exceeded:
            governor_risks.append({"component": row["component"], "risks": exceeded})
    production.sort(key=lambda row: row["score"], reverse=True)
    tests.sort(key=lambda row: row["score"], reverse=True)
    all_rows.sort(key=lambda row: row["score"], reverse=True)
    return {
        "methodology": "Heurística determinística baseada em tamanho, métodos, complexidade aproximada, dependências e objetos/pontos de entrada; candidatos exigem revisão humana. Contagens por arquivo não medem consumo de uma transação.",
        "thresholds": {"production": analysis.get("god_class", {}), "tests": analysis.get("god_test_class", {}), "static_governor": governor_cfg},
        "triggers_analyzed": len(triggers),
        "classes_analyzed": len(all_rows),
        "god_class_candidates": production,
        "god_test_class_candidates": tests,
        "transaction_governor_risks": governor_risks,
        "largest_scores": all_rows[:100],
    }


def analyze_org_limits(limits: dict[str, Any], config: dict[str, Any], before: dict[str, Any] | None = None) -> dict[str, Any]:
    thresholds = config.get("analysis", {}).get("org_limits", {})
    warning = float(thresholds.get("warning_remaining_percent", 20))
    critical = float(thresholds.get("critical_remaining_percent", 10))
    if not 0 <= critical <= warning <= 100:
        raise ValueError("Org limit thresholds must satisfy 0 <= critical <= warning <= 100")
    rows: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for name, value in limits.items():
        if not isinstance(value, dict):
            continue
        maximum = value.get("max")
        remaining = value.get("remaining")
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (maximum, remaining)) or maximum <= 0:
            unavailable.append(name)
            continue
        margin = remaining / maximum * 100
        remaining_percent = round(margin, 2)
        used = max(0, maximum - remaining)
        used_percent = round(used / maximum * 100, 2)
        status = "critical" if margin <= critical else ("warning" if margin <= warning else "healthy")
        previous = (before or {}).get(name, {})
        previous_remaining = previous.get("remaining")
        delta = previous_remaining - remaining if previous.get("max") == maximum and isinstance(previous_remaining, (int, float)) else None
        rows.append({
            "name": name,
            "max": maximum,
            "remaining": remaining,
            "used": used,
            "used_percent": used_percent,
            "remaining_percent": remaining_percent,
            "status": status,
            "exhausted": remaining <= 0,
            "usage_change_during_assessment": delta,
        })
    rows.sort(key=lambda row: (row["remaining_percent"], row["name"]))
    return {
        "source": "sf org list limits",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "available": bool(rows),
        "unavailable_limits": unavailable,
        "note": "Margem observada na coleta; não é previsão. A variação inclui outros consumidores da org. Limites por transação não são retornados por esta API.",
        "warning_remaining_percent": warning,
        "critical_remaining_percent": critical,
        "limits": rows,
        "outside_governance": [row for row in rows if row["status"] in {"warning", "critical"}],
        "critical_count": sum(row["status"] == "critical" for row in rows),
        "warning_count": sum(row["status"] == "warning" for row in rows),
    }
