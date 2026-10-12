from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


SEV = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}


def _f(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if is_dataclass(item):
        return asdict(item)
    return {k: getattr(item, k, None) for k in ("id", "category", "severity", "title", "description", "component", "recommendation", "effort", "confidence", "evidence")}


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("result", payload)
        if isinstance(payload, dict):
            rows = payload.get("records", [])
            return rows if isinstance(rows, list) else []
    return payload if isinstance(payload, list) else []


def _text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _node(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def _flow_xml(flow: dict[str, Any]) -> ET.Element | None:
    path = Path(flow.get("source_file", ""))
    if not path.exists():
        return None
    try:
        return ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for c in list(node):
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return ""


def _all_text(node: ET.Element, name: str) -> list[str]:
    return [(x.text or "").strip() for x in node.iter() if _local(x.tag) == name and (x.text or "").strip()]


def build_order_of_execution_graph(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Builds a deterministic transaction topology per object.

    This does not claim Salesforce's internal runtime scheduler is fully observable. It
    models the stable record-save phases that matter for architectural collision and
    recursion analysis and attaches the org's metadata components to those phases.
    """
    objects: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    trigger_events: dict[str, list[str]] = defaultdict(list)

    for flow in components.get("flows", []):
        obj = flow.get("object")
        if not obj or str(flow.get("status", "")).lower() != "active":
            continue
        rtt = str(flow.get("record_trigger_type", "")).lower()
        trigger_type = str(flow.get("trigger_type", "")).lower()
        if "fastfieldupdates" in rtt or "before" in rtt:
            phase = "03_before_save_flow"
        elif "actionsandrelatedrecords" in rtt or "after" in rtt:
            phase = "08_after_save_flow"
        elif "scheduled" in trigger_type or "schedule" in str(flow.get("process_type", "")).lower():
            phase = "12_async_or_scheduled"
        else:
            phase = "08_after_save_flow"
        objects[str(obj)][phase].append(_node("Flow", str(flow.get("api_name"))))

    for trig in components.get("apex_triggers", []):
        text = trig.get("text", "") or _text(trig.get("source_file", ""))
        m = re.search(r"\btrigger\s+\w+\s+on\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", text, re.I | re.S)
        if not m:
            continue
        obj = m.group(1)
        events = [x.strip().lower().replace(" ", "_") for x in m.group(2).split(",") if x.strip()]
        trigger_events[trig.get("api_name", "")].extend(events)
        if any(x.startswith("before_") for x in events):
            objects[obj]["04_before_trigger"].append(_node("ApexTrigger", str(trig.get("api_name"))))
        if any(x.startswith("after_") for x in events):
            objects[obj]["07_after_trigger"].append(_node("ApexTrigger", str(trig.get("api_name"))))

    for obj in components.get("objects", []):
        api = obj.get("api_name")
        if not api:
            continue
        for vr in obj.get("validation_rules", []):
            if vr.get("active"):
                objects[api]["05_validation_rules"].append(_node("ValidationRule", f"{api}.{vr.get('api_name')}"))
        # Workflow/approval remain observable as legacy/post-save execution actors.
    for wf_file in components.get("workflows", []):
        obj = wf_file.get("object")
        for wf in wf_file.get("rules", []):
            if obj and wf.get("active", True):
                name = f"{obj}.{wf.get('api_name')}" if wf.get("api_name") else str(obj)
                objects[obj]["09_legacy_workflow"].append(_node("WorkflowRule", name))
    for ap in components.get("approval_processes", []):
        obj = ap.get("object") or ap.get("api_name", "").split(".", 1)[0]
        if obj and ap.get("active", True):
            objects[obj]["10_approval_process"] .append(_node("ApprovalProcess", str(ap.get("api_name"))))

    phases = [
        "01_system_validation", "02_before_save_context", "03_before_save_flow",
        "04_before_trigger", "05_validation_rules", "06_duplicate_rules",
        "07_after_trigger", "08_after_save_flow", "09_legacy_workflow",
        "10_approval_process", "11_commit_boundary", "12_async_or_scheduled",
    ]
    rows = []
    graph_edges: list[dict[str, Any]] = []
    collisions = []
    for obj, mapping in sorted(objects.items()):
        components_count = sum(len(v) for v in mapping.values())
        mutating = sum(len(mapping.get(x, [])) for x in ("03_before_save_flow", "04_before_trigger", "07_after_trigger", "08_after_save_flow", "09_legacy_workflow"))
        collision_score = min(100, max(0, mutating - 1) * 12 + len(mapping.get("05_validation_rules", [])) * 2)
        row = {"object": obj, "automation_components": components_count, "mutating_actors": mutating, "collision_score": collision_score, "phases": {p: mapping.get(p, []) for p in phases}}
        rows.append(row)
        if collision_score >= 36:
            collisions.append({"object": obj, "collision_score": collision_score, "mutating_actors": mutating, "components": [c for p in phases for c in mapping.get(p, [])]})
        prior = _node("TransactionPhase", f"{obj}.{phases[0]}")
        for phase in phases:
            phase_node = _node("TransactionPhase", f"{obj}.{phase}")
            if phase != phases[0]:
                graph_edges.append({"source": prior, "relationship": "PRECEDES", "target": phase_node, "confidence": 1.0, "evidence": "Salesforce record-save transaction model"})
            for comp in mapping.get(phase, []):
                graph_edges.append({"source": phase_node, "relationship": "EXECUTES_COMPONENT", "target": comp, "confidence": 0.95, "evidence": f"metadata mapping for {obj}"})
            prior = phase_node
    dependencies.extend(graph_edges)
    rows.sort(key=lambda x: (x["collision_score"], x["automation_components"]), reverse=True)
    return {
        "model": "record-save-phase-topology/v1",
        "objects": rows,
        "hotspots": rows[:100],
        "collision_candidates": collisions[:100],
        "trigger_events": dict(trigger_events),
        "graph_edges_added": len(graph_edges),
        "interpretation": "Phase topology is deterministic; exact intra-phase ordering between independent automations can remain platform/runtime dependent and must not be inferred from list order.",
    }


def build_flow_quality(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for flow in components.get("flows", []):
        root = _flow_xml(flow)
        if root is None:
            continue
        kinds = Counter()
        fault_connectors = 0
        targets: dict[str, set[str]] = defaultdict(set)
        element_nodes: dict[str, str] = {}
        record_ops = 0
        loops = 0
        subflows = 0
        actions = 0
        for child in list(root):
            kind = _local(child.tag)
            name = _child_text(child, "name")
            if not name:
                continue
            kinds[kind] += 1
            element_nodes[name] = kind
            refs = _all_text(child, "targetReference")
            for ref in refs:
                targets[name].add(ref)
            if _all_text(child, "faultConnector") or any(_local(x.tag) == "faultConnector" for x in child.iter()):
                fault_connectors += 1
            if kind in {"recordCreates", "recordUpdates", "recordDeletes", "recordLookups"}:
                record_ops += 1
            if kind == "loops":
                loops += 1
            if kind == "subflows":
                subflows += 1
            if kind == "actionCalls":
                actions += 1

        # Reachability from start connectors when visible.
        start_targets = set()
        for n in root.iter():
            if _local(n.tag) == "start":
                start_targets.update(_all_text(n, "targetReference"))
        reachable = set(start_targets)
        q = deque(start_targets)
        while q:
            cur = q.popleft()
            for nxt in targets.get(cur, set()):
                if nxt not in reachable:
                    reachable.add(nxt); q.append(nxt)
        named = set(element_nodes)
        unreachable = sorted(named - reachable) if start_targets else []

        # Approximate DML/query-in-loop risk by traversing outbound from loop elements.
        risky_loop_ops = []
        op_kinds = {"recordCreates", "recordUpdates", "recordDeletes", "recordLookups", "actionCalls"}
        for loop_name in [n for n, k in element_nodes.items() if k == "loops"]:
            seen = {loop_name}; qq = deque([loop_name])
            while qq and len(seen) <= 100:
                cur = qq.popleft()
                for nxt in targets.get(cur, set()):
                    if nxt in seen: continue
                    seen.add(nxt); qq.append(nxt)
            hits = sorted(n for n in seen if element_nodes.get(n) in op_kinds)
            if hits:
                risky_loop_ops.append({"loop": loop_name, "operations": hits})

        complexity = max(1, kinds.get("decisions", 0) + kinds.get("loops", 0) + 1)
        score = min(100, complexity * 4 + record_ops * 5 + actions * 3 + len(risky_loop_ops) * 20 + len(unreachable) * 2)
        source = _node("Flow", str(flow.get("api_name")))
        for sub in [n for n, k in element_nodes.items() if k == "subflows"]:
            # Existing v3 maps exact flowName; here keep element graph evidence only.
            dependencies.append({"source": source, "relationship": "CONTAINS_SUBFLOW_ELEMENT", "target": f"FlowElement:{flow.get('api_name')}.{sub}", "confidence": 1.0, "evidence": flow.get("source_file", "")})
        rows.append({
            "flow": flow.get("api_name"), "status": flow.get("status"), "object": flow.get("object"),
            "elements": sum(kinds.values()), "element_types": dict(kinds), "cyclomatic_proxy": complexity,
            "record_operations": record_ops, "loops": loops, "subflows": subflows, "actions": actions,
            "fault_connectors": fault_connectors, "unreachable_elements": unreachable[:100],
            "loop_operation_risks": risky_loop_ops[:50], "complexity_risk_score": score,
        })
    rows.sort(key=lambda x: x["complexity_risk_score"], reverse=True)
    return {
        "flows_analyzed": len(rows), "highest_complexity": rows[:100],
        "missing_fault_handling_candidates": [x for x in rows if (x["record_operations"] or x["actions"]) and x["fault_connectors"] == 0][:100],
        "loop_operation_candidates": [x for x in rows if x["loop_operation_risks"]][:100],
        "unreachable_element_candidates": [x for x in rows if x["unreachable_elements"]][:100],
    }


def _strip_apex(text: str) -> str:
    scrub = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    scrub = re.sub(r"//[^\n]*", " ", scrub)
    scrub = re.sub(r"'(?:\\.|[^'\\])*'", "''", scrub)
    return scrub


def build_apex_quality(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    classes = components.get("apex_classes", [])
    names = {x.get("api_name") for x in classes if x.get("api_name")}
    rows = []
    call_edges = []
    for item in classes + components.get("apex_triggers", []):
        name = str(item.get("api_name") or "")
        typ = "ApexTrigger" if item in components.get("apex_triggers", []) else "ApexClass"
        source = _node(typ, name)
        text = _strip_apex(item.get("text", "") or _text(item.get("source_file", "")))
        calls = []
        for target in names:
            if target != name and re.search(rf"\b{re.escape(str(target))}\s*\.", text):
                calls.append(str(target))
                e = {"source": source, "relationship": "CALLS_APEX", "target": _node("ApexClass", str(target)), "confidence": 0.96, "evidence": item.get("source_file", "")}
                dependencies.append(e); call_edges.append(e)
        loops = [(m.start(), m.group(0)) for m in re.finditer(r"\b(?:for|while)\s*\(", text, re.I)]
        soql = list(re.finditer(r"\[\s*SELECT\b", text, re.I))
        dml = list(re.finditer(r"\b(?:insert|update|upsert|delete|undelete|merge)\b", text, re.I))
        # Conservative proximity heuristic: DML/SOQL within 1000 chars after loop start.
        soql_in_loop = sum(1 for pos, _ in loops if any(pos <= s.start() <= pos + 1000 for s in soql))
        dml_in_loop = sum(1 for pos, _ in loops if any(pos <= d.start() <= pos + 1000 for d in dml))
        methods = len(re.findall(r"(?:public|private|protected|global)\s+(?:static\s+)?[A-Za-z_<>,\[\]\s]+\s+[A-Za-z_]\w*\s*\(", text))
        branches = len(re.findall(r"\b(?:if|else\s+if|for|while|catch|switch\s+on)\b", text, re.I))
        complexity = max(1, 1 + branches)
        is_test = bool(re.search(r"@isTest\b|\btestMethod\b", text, re.I))
        sharing = "inherited" if re.search(r"\binherited\s+sharing\b", text, re.I) else "with" if re.search(r"\bwith\s+sharing\b", text, re.I) else "without" if re.search(r"\bwithout\s+sharing\b", text, re.I) else "unspecified"
        risk = min(100, complexity * 2 + soql_in_loop * 25 + dml_in_loop * 25 + (8 if typ == "ApexClass" and not is_test and sharing == "unspecified" else 0))
        rows.append({"component": source, "methods": methods, "cyclomatic_proxy": complexity, "calls": sorted(calls), "soql_count": len(soql), "dml_count": len(dml), "soql_in_loop_candidates": soql_in_loop, "dml_in_loop_candidates": dml_in_loop, "sharing_mode": sharing, "is_test": is_test, "quality_risk_score": risk})

    indeg = Counter(e["target"] for e in call_edges); outdeg = Counter(e["source"] for e in call_edges)
    for row in rows:
        row["fan_in"] = indeg.get(row["component"], 0); row["fan_out"] = outdeg.get(row["component"], 0)
    rows.sort(key=lambda x: x["quality_risk_score"], reverse=True)
    tests = [x for x in rows if x["is_test"]]
    prod = [x for x in rows if not x["is_test"]]
    return {
        "components_analyzed": len(rows), "classes": prod, "tests": tests,
        "soql_in_loop_candidates": [x for x in rows if x["soql_in_loop_candidates"]][:100],
        "dml_in_loop_candidates": [x for x in rows if x["dml_in_loop_candidates"]][:100],
        "high_coupling": sorted(rows, key=lambda x: x["fan_in"] + x["fan_out"], reverse=True)[:100],
        "test_to_class_edges": [e for e in call_edges if any(t["component"] == e["source"] for t in tests)],
    }


def build_test_intelligence(components: dict[str, Any], runtime_v2: dict[str, Any], apex_quality: dict[str, Any]) -> dict[str, Any]:
    coverage_rows = _records(runtime_v2.get("apex_coverage", {}))
    cov = {}
    for row in coverage_rows:
        name = (row.get("ApexClassOrTrigger") or {}).get("Name") or row.get("ApexClassOrTriggerId")
        c = int(row.get("NumLinesCovered") or 0); u = int(row.get("NumLinesUncovered") or 0)
        cov[str(name)] = round(c / (c + u) * 100, 1) if c + u else None
    tests_by_target: dict[str, set[str]] = defaultdict(set)
    for e in apex_quality.get("test_to_class_edges", []):
        tests_by_target[e["target"].split(":", 1)[-1]].add(e["source"].split(":", 1)[-1])
    prod_names = [x.get("api_name") for x in components.get("apex_classes", []) if x.get("api_name") and not re.search(r"(?:Test|Tests)$", str(x.get("api_name")), re.I)]
    prod_names += [x.get("api_name") for x in components.get("apex_triggers", []) if x.get("api_name")]
    rows = []
    for name in sorted(set(prod_names)):
        direct_tests = sorted(tests_by_target.get(str(name), set()))
        pct = cov.get(str(name))
        rows.append({"component": name, "coverage_percent": pct, "direct_test_references": direct_tests, "test_mapping_confidence": 0.96 if direct_tests else 0.4, "gap": (pct is not None and pct < 75) or (not direct_tests and pct in (None, 0))})
    return {
        "coverage_available": bool(coverage_rows), "components": rows,
        "coverage_below_75": [x for x in rows if isinstance(x["coverage_percent"], (int, float)) and x["coverage_percent"] < 75],
        "without_direct_test_mapping": [x for x in rows if not x["direct_test_references"]],
        "note": "Direct test mapping is static call/reference evidence; Salesforce runtime coverage remains the authoritative coverage signal when available.",
    }


def build_data_health(components: dict[str, Any], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    intel = components.get("intelligence", {})
    profile = intel.get("v3", {}).get("data_quality_profile", {})
    counts = intel.get("data_profile", {}).get("largest_objects", [])
    objects = []
    prof_by_obj = {x.get("object"): x for x in profile.get("objects", []) if isinstance(x, dict)}
    for row in counts:
        api = row.get("object")
        prof = prof_by_obj.get(api, {})
        field_stats = prof.get("field_stats", [])
        nulls = [x.get("null_percent") for x in field_stats if isinstance(x.get("null_percent"), (int, float))]
        avg_null = round(sum(nulls) / len(nulls), 1) if nulls else None
        sparse = sum(1 for x in nulls if x >= 95)
        low_card = sum(1 for x in field_stats if isinstance(x.get("distinct_ratio_percent"), (int, float)) and x.get("distinct_ratio_percent") <= 2 and x.get("sampled_rows", 0) >= 20)
        skew = prof.get("owner_skew", {})
        risk = min(100, (avg_null or 0) * 0.35 + sparse * 4 + low_card * 2 + (25 if skew.get("potential_skew") else 0) + (15 if int(row.get("record_count") or 0) >= 1_000_000 else 0))
        objects.append({"object": api, "record_count": row.get("record_count"), "profile_available": bool(field_stats), "average_null_percent_sample": avg_null, "fields_95pct_null": sparse, "low_cardinality_fields_sample": low_card, "ownership_skew_candidate": bool(skew.get("potential_skew")), "data_health_risk_score": round(risk)})
    objects.sort(key=lambda x: x["data_health_risk_score"], reverse=True)
    completeness = None
    all_stats = [f for x in profile.get("objects", []) for f in x.get("field_stats", [])]
    if all_stats:
        vals = [100 - f["null_percent"] for f in all_stats if isinstance(f.get("null_percent"), (int, float))]
        completeness = round(sum(vals) / len(vals), 1) if vals else None
    return {
        "profile_enabled": bool(profile.get("enabled")), "profile_available": bool(profile.get("available")),
        "sample_completeness_percent": completeness, "objects": objects[:500],
        "highest_risk_objects": objects[:100], "raw_values_persisted": False,
        "limitations": ["Duplicate detection is not inferred from low cardinality; duplicate semantics require organization-specific keys.", "Sample statistics are evidence, not whole-table guarantees."],
    }


def build_runtime_health(components: dict[str, Any], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    intel = components.get("intelligence", {})
    events = intel.get("v3", {}).get("event_monitoring", {})
    coverage = intel.get("apex_coverage", {})
    failed = _records(runtime_v2.get("failed_async", {}))
    failure_classes = Counter()
    for x in failed:
        name = (x.get("ApexClass") or {}).get("Name") if isinstance(x.get("ApexClass"), dict) else None
        failure_classes[str(name or x.get("JobType") or "Unknown")] += 1
    cov_pct = coverage.get("overall_percent")
    signals = {
        "event_monitoring_available": bool(events.get("available")),
        "event_files_downloaded": sum(1 for x in events.get("files", []) if x.get("downloaded")),
        "active_user_evidence": events.get("active_users_evidence"),
        "failed_async_jobs_30d": len(failed),
        "apex_coverage_percent": cov_pct,
    }
    score = 0
    if failed: score += min(45, len(failed) * 4)
    if isinstance(cov_pct, (int, float)) and cov_pct < 75: score += min(35, 75 - cov_pct)
    if not events.get("available"): score += 10
    return {
        "runtime_risk_score": round(min(100, score)), "signals": signals,
        "failed_components": [{"component": k, "failures": v} for k, v in failure_classes.most_common(100)],
        "app_usage": events.get("app_usage", [])[:100], "app_user_usage": events.get("app_user_usage", [])[:500],
        "api_clients": events.get("api_clients", [])[:100],
        "coverage": coverage,
        "interpretation": "Unavailable telemetry increases uncertainty, not health. Runtime risk is conservative and evidence-aware.",
    }


def build_integration_health(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    intel = components.get("intelligence", {})
    semantic = intel.get("v3", {}).get("apex_semantic_map", {})
    callouts = semantic.get("callouts", [])
    named = {str(x.get("api_name")) for x in components.get("named_credentials", []) if x.get("api_name")}
    hardcoded = []
    mapped = []
    for c in callouts:
        endpoint = str(c.get("endpoint") or "")
        if endpoint.lower().startswith("callout:"):
            name = endpoint.split(":", 1)[1].split("/", 1)[0]
            mapped.append({**c, "named_credential": name, "credential_retrieved": name in named})
        else:
            hardcoded.append(c)
    inbound = semantic.get("endpoints", [])
    return {
        "named_credentials": sorted(named), "outbound_callouts": mapped,
        "hardcoded_endpoint_candidates": hardcoded, "inbound_endpoints": inbound,
        "single_points_of_failure": [x for x in mapped if not x.get("credential_retrieved")],
        "health_risk_score": min(100, len(hardcoded) * 20 + sum(10 for x in mapped if not x.get("credential_retrieved"))),
    }


def build_lineage_index(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in dependencies:
        s, t = e.get("source"), e.get("target")
        if s and t:
            by_source[s].append(e); by_target[t].append(e)
    fields = {}
    for node, incoming in by_target.items():
        if not str(node).startswith("Field:"):
            continue
        reads = [e for e in incoming if "READ" in str(e.get("relationship")) or "REFERENCES_FIELD" in str(e.get("relationship"))]
        writes = [e for e in incoming if "WRITE" in str(e.get("relationship"))]
        downstream = by_source.get(node, [])
        fields[node.removeprefix("Field:")] = {"readers": reads, "writers": writes, "downstream": downstream, "reader_count": len(reads), "writer_count": len(writes)}
    return {"fields": fields, "field_count": len(fields)}


def build_v7_intelligence(components: dict[str, Any], dependencies: list[dict[str, Any]], findings: list[Any], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    order = build_order_of_execution_graph(components, dependencies)
    flow = build_flow_quality(components, dependencies)
    apex = build_apex_quality(components, dependencies)
    tests = build_test_intelligence(components, runtime_v2, apex)
    data = build_data_health(components, runtime_v2)
    runtime = build_runtime_health(components, runtime_v2)
    integrations = build_integration_health(components, dependencies)
    lineage = build_lineage_index(dependencies)
    return {
        "order_of_execution_graph": order,
        "flow_quality": flow,
        "apex_quality": apex,
        "test_intelligence": tests,
        "data_health": data,
        "runtime_health": runtime,
        "integration_health": integrations,
        "lineage_index": lineage,
        "finalization": {
            "engine_layer": "enterprise-correlation/v1",
            "mutation_capability": False,
            "raw_business_values_persisted": False,
        },
    }


def analyze_v7_intelligence(components: dict[str, Any], findings: list[Any]) -> None:
    from .models import Evidence, Finding
    v7 = components.get("intelligence", {}).get("v7", {})
    seq = 1
    collisions = [x for x in v7.get("order_of_execution_graph", {}).get("collision_candidates", []) if x.get("collision_score", 0) >= 60]
    if collisions:
        findings.append(Finding(id=f"V7AUTO-{seq:04d}", category="automation", severity="high", title="High transaction automation collision potential", description=f"{len(collisions)} object(s) have multiple mutating automation actors across record-save phases.", component="Automation Architecture", recommendation="Review order-of-execution interactions, recursion guards, conflicting writes and regression tests on these objects.", effort="High", confidence=0.9, evidence=[Evidence("ORDER_OF_EXECUTION", "metadata topology", ", ".join(f"{x['object']}={x['collision_score']}" for x in collisions[:20]), 0.9)])); seq += 1
    loop_risks = v7.get("flow_quality", {}).get("loop_operation_candidates", [])
    if loop_risks:
        findings.append(Finding(id=f"V7FLOW-{seq:04d}", category="automation", severity="high", title="Flow operations reachable from loop paths", description=f"{len(loop_risks)} flow(s) contain record/action operations reachable from loop elements.", component="Flows", recommendation="Inspect loop paths and move record/query/callout operations outside loops when semantics allow; add bulk-volume tests.", effort="Medium", confidence=0.82, evidence=[Evidence("FLOW_XML_GRAPH", "loop traversal", ", ".join(str(x.get('flow')) for x in loop_risks[:30]), 0.82)])); seq += 1
    missing_fault = v7.get("flow_quality", {}).get("missing_fault_handling_candidates", [])
    if missing_fault:
        findings.append(Finding(id=f"V7FLOW-{seq:04d}", category="automation", severity="medium", title="Flow operations without visible fault connectors", description=f"{len(missing_fault)} flow(s) execute records/actions without a detected fault connector.", component="Flows", recommendation="Review fault paths and implement explicit error handling/telemetry for business-critical automations.", effort="Medium", confidence=0.78, evidence=[Evidence("FLOW_XML", "faultConnector", ", ".join(str(x.get('flow')) for x in missing_fault[:30]), 0.78)])); seq += 1
    apex_loops = v7.get("apex_quality", {}).get("soql_in_loop_candidates", []) + v7.get("apex_quality", {}).get("dml_in_loop_candidates", [])
    if apex_loops:
        findings.append(Finding(id=f"V7APEX-{seq:04d}", category="performance", severity="high", title="Potential SOQL/DML inside Apex loop scope", description=f"{len({x.get('component') for x in apex_loops})} Apex component(s) matched the conservative loop-proximity heuristic.", component="Apex", recommendation="Validate each candidate with Code Analyzer/AST review and bulkify confirmed query/DML-in-loop logic.", effort="Medium", confidence=0.72, evidence=[Evidence("APEX_STATIC_HEURISTIC", "loop proximity", ", ".join(sorted({str(x.get('component')) for x in apex_loops})[:30]), 0.72)])); seq += 1
    test_gaps = v7.get("test_intelligence", {}).get("coverage_below_75", [])
    if test_gaps:
        findings.append(Finding(id=f"V7TEST-{seq:04d}", category="testing", severity="high", title="Apex runtime coverage below deployment baseline", description=f"{len(test_gaps)} covered Apex component(s) are below 75% aggregate coverage.", component="Apex Tests", recommendation="Raise targeted coverage with behavior-focused tests; prioritize structurally critical components first.", effort="Medium", confidence=0.99, evidence=[Evidence("APEX_CODE_COVERAGE_AGGREGATE", "runtime coverage", ", ".join(f"{x['component']}={x['coverage_percent']}%" for x in test_gaps[:30]), 0.99)])); seq += 1
    runtime = v7.get("runtime_health", {})
    if runtime.get("signals", {}).get("failed_async_jobs_30d", 0) > 0:
        findings.append(Finding(id=f"V7OBS-{seq:04d}", category="observability", severity="medium", title="Recent failed asynchronous Apex jobs detected", description=f"{runtime['signals']['failed_async_jobs_30d']} failed/error async job(s) were observed in the last 30 days.", component="Async Apex", recommendation="Correlate recurring failures with owning classes/integrations, establish alerting and verify retry/idempotency behavior.", effort="Medium", confidence=0.99, evidence=[Evidence("ASYNC_APEX_JOB", "read-only runtime query", json.dumps(runtime.get('failed_components', [])[:20], ensure_ascii=False), 0.99)])); seq += 1


def simulate_change(snapshot: dict[str, Any], component: str, operation: str = "change", depth: int = 4) -> dict[str, Any]:
    """Purely offline change simulation. Never mutates Salesforce or local source."""
    deps = snapshot.get("dependencies", [])
    candidates = {component}
    nodes = {str(e.get("source")) for e in deps} | {str(e.get("target")) for e in deps}
    if ":" not in component:
        candidates |= {n for n in nodes if n.endswith(":" + component) or n.endswith("." + component)}
    out = defaultdict(list); inc = defaultdict(list)
    for e in deps:
        if e.get("source") and e.get("target"):
            out[e["source"]].append(e); inc[e["target"]].append(e)
    visited = set(candidates); q = deque((n, 0) for n in candidates); paths = []
    while q:
        n, d = q.popleft()
        if d >= max(1, depth): continue
        # Downstream dependents are primary break-risk; include outgoing context separately.
        for e in inc.get(n, []):
            dep = e["source"]
            paths.append({"depth": d + 1, "dependent": dep, "relationship": e.get("relationship"), "target": n, "confidence": e.get("confidence")})
            if dep not in visited:
                visited.add(dep); q.append((dep, d + 1))
    affected = visited - candidates
    by_type = Counter(x.split(":", 1)[0] if ":" in x else "Other" for x in affected)
    related = []
    for raw in snapshot.get("findings", []):
        f = _f(raw); c = str(f.get("component") or "")
        if c in affected or c in candidates or any(n.endswith(":" + c) for n in visited if c):
            related.append(f)
    severity = sum(SEV.get(str(x.get("severity", "")).lower(), 0) for x in related)
    base = len(affected) * (4 if operation in {"remove", "deprecate"} else 2) + severity
    risky_rels = sum(1 for x in paths if any(k in str(x.get("relationship", "")) for k in ("WRITE", "CALL", "EXECUTE", "VALID", "DISPLAYS", "READS_FIELD")))
    score = min(100, round(base + risky_rels * 2))
    risk = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"
    plan = ["Run targeted regression tests for affected dependency neighborhood", "Validate runtime telemetry after the change", "Keep a rollback path and compare a post-change snapshot"]
    if operation in {"remove", "deprecate"}:
        plan = ["Introduce/confirm replacement capability", "Migrate direct writers/readers and integrations", "Run dual-path observation where feasible", "Remove references only after dependency and runtime evidence is clean", *plan]
    return {
        "mode": "OFFLINE_READ_ONLY_SIMULATION", "operation": operation, "component": component,
        "resolved_nodes": sorted(candidates), "depth": max(1, depth), "affected_components": sorted(affected),
        "blast_radius": len(affected), "affected_by_type": dict(sorted(by_type.items())),
        "breaking_paths": sorted(paths, key=lambda x: (x["depth"], x["dependent"]))[:2000],
        "related_findings": related[:500], "change_risk_score": score, "risk": risk,
        "recommendation": "DO NOT REMOVE WITHOUT MIGRATION" if operation in {"remove", "deprecate"} and risk in {"HIGH", "CRITICAL"} else "PROCEED WITH CONTROLLED VALIDATION",
        "migration_plan": plan, "mutation_executed": False,
    }


def continuous_intelligence(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def edges(s: dict[str, Any]) -> set[tuple[str, str, str]]:
        return {(str(e.get("source")), str(e.get("relationship")), str(e.get("target"))) for e in s.get("dependencies", [])}
    a, b = edges(before), edges(after)
    fa = {str(_f(x).get("id")): _f(x) for x in before.get("findings", [])}
    fb = {str(_f(x).get("id")): _f(x) for x in after.get("findings", [])}
    ha = before.get("health", {}).get("overall"); hb = after.get("health", {}).get("overall")
    cats_a = before.get("health", {}).get("categories", {}); cats_b = after.get("health", {}).get("categories", {})
    trends = []
    for key in sorted(set(cats_a) | set(cats_b)):
        x, y = cats_a.get(key), cats_b.get(key)
        delta = round(y - x, 1) if isinstance(x, (int, float)) and isinstance(y, (int, float)) else None
        trends.append({"category": key, "before": x, "after": y, "delta": delta, "trend": "UP" if delta is not None and delta > 0 else "DOWN" if delta is not None and delta < 0 else "FLAT_OR_NA"})
    new = [fb[k] for k in sorted(set(fb) - set(fa))]
    resolved = [fa[k] for k in sorted(set(fa) - set(fb))]
    new_critical = [x for x in new if str(x.get("severity", "")).lower() == "critical"]
    changed_edges = len(b - a) + len(a - b)
    drift = "HIGH" if changed_edges >= 100 or new_critical else "MEDIUM" if changed_edges >= 20 or new else "LOW"
    return {
        "schema": "labforce-dementor-continuous-intelligence/v1",
        "health": {"before": ha, "after": hb, "delta": round(hb - ha, 1) if isinstance(ha, (int, float)) and isinstance(hb, (int, float)) else None, "category_trends": trends},
        "findings": {"new": new, "resolved": resolved, "new_critical": new_critical, "new_count": len(new), "resolved_count": len(resolved)},
        "architecture_drift": {"added_edges": len(b - a), "removed_edges": len(a - b), "changed_edges": changed_edges, "level": drift},
        "improved": bool(isinstance(ha, (int, float)) and isinstance(hb, (int, float)) and hb > ha and not new_critical),
    }


def final_readiness(snapshot: dict[str, Any]) -> dict[str, Any]:
    intel = snapshot.get("components", {}).get("intelligence", {})
    v7 = intel.get("v7", {})
    ent = intel.get("enterprise", {})
    checks = {
        "metadata_inventory": bool(snapshot.get("inventory")),
        "digital_twin": bool(ent.get("digital_twin", {}).get("nodes")),
        "order_of_execution": bool(v7.get("order_of_execution_graph", {}).get("objects")),
        "field_lineage": bool(v7.get("lineage_index", {}).get("field_count")),
        "flow_intelligence": v7.get("flow_quality", {}).get("flows_analyzed", 0) >= 0,
        "apex_intelligence": v7.get("apex_quality", {}).get("components_analyzed", 0) >= 0,
        "test_intelligence": "test_intelligence" in v7,
        "data_intelligence": "data_health" in v7,
        "runtime_intelligence": "runtime_health" in v7,
        "integration_intelligence": "integration_health" in v7,
        "security_intelligence": bool(intel.get("effective_permissions") or intel.get("v4", {}).get("effective_access")),
        "remediation": bool(ent.get("remediation_plan")),
        "evidence_quality": bool(ent.get("evidence_quality")),
        "read_only": snapshot.get("audit", {}).get("dml_executed", 0) == 0 and snapshot.get("audit", {}).get("metadata_deployments", 0) == 0,
    }
    ready = sum(1 for v in checks.values() if v)
    return {"checks": checks, "ready_checks": ready, "total_checks": len(checks), "readiness_percent": round(ready / len(checks) * 100, 1), "engine_status": "PRODUCT_GRADE_CORE" if ready == len(checks) else "PARTIAL", "note": "Runtime/data completeness still depends on Salesforce edition, permissions, telemetry and opt-in profiling."}
