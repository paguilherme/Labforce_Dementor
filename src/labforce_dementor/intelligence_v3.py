from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .sfcli import SFCLI


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("result", payload)
        if isinstance(payload, dict):
            rows = payload.get("records", [])
            return rows if isinstance(rows, list) else []
    return payload if isinstance(payload, list) else []


def enrich_report_dashboard_dependencies(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    field_names = {f.get("full_name") for o in components.get("objects", []) for f in o.get("fields", []) if f.get("full_name")}
    object_names = {o.get("api_name") for o in components.get("objects", []) if o.get("api_name")}
    summary = {"report_field_edges": 0, "dashboard_report_edges": 0}
    for key, prefix in (("reports", "Report"), ("dashboards", "Dashboard")):
        for item in components.get(key, []):
            path = Path(item.get("source_file", ""))
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            source = f"{prefix}:{item.get('api_name')}"
            if key == "reports":
                for full in field_names:
                    if full and full in text:
                        dependencies.append({"source": source, "relationship": "READS_FIELD", "target": f"Field:{full}", "confidence": 0.98, "evidence": str(path)})
                        summary["report_field_edges"] += 1
                for obj in object_names:
                    if obj and re.search(rf"\b{re.escape(obj)}\b", text):
                        dependencies.append({"source": source, "relationship": "READS_OBJECT", "target": f"Object:{obj}", "confidence": 0.8, "evidence": str(path)})
            else:
                refs = set(re.findall(r"<report>([^<]+)</report>", text, re.I)) | set(re.findall(r"<reportName>([^<]+)</reportName>", text, re.I))
                for ref in refs:
                    dependencies.append({"source": source, "relationship": "DISPLAYS_REPORT", "target": f"Report:{ref}", "confidence": 0.98, "evidence": str(path)})
                    summary["dashboard_report_edges"] += 1
    return summary


def apex_semantic_map(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    classes = {x.get("api_name") for x in components.get("apex_classes", []) if x.get("api_name")}
    endpoints: list[dict[str, Any]] = []
    dynamic_refs: list[dict[str, Any]] = []
    callouts: list[dict[str, Any]] = []
    for item in components.get("apex_classes", []) + components.get("apex_triggers", []):
        name = item.get("api_name")
        text = item.get("text", "")
        prefix = "Trigger" if item in components.get("apex_triggers", []) else "ApexClass"
        source = f"{prefix}:{name}"
        for target in classes:
            if target != name and re.search(rf"\b{re.escape(target)}\b", text):
                dependencies.append({"source": source, "relationship": "REFERENCES_APEX", "target": f"ApexClass:{target}", "confidence": 0.86, "evidence": item.get("source_file", "")})
        rr = re.search(r"@RestResource\s*\(\s*urlMapping\s*=\s*['\"]([^'\"]+)", text, re.I)
        if rr:
            endpoints.append({"class": name, "type": "APEX_REST", "url_mapping": rr.group(1)})
        if re.search(r"\bwebservice\s+", text, re.I):
            endpoints.append({"class": name, "type": "APEX_SOAP", "url_mapping": None})
        for m in re.finditer(r"Type\.forName\s*\(\s*['\"]([^'\"]+)", text):
            dynamic_refs.append({"class": name, "target": m.group(1), "kind": "Type.forName"})
            dependencies.append({"source": source, "relationship": "DYNAMIC_APEX_REFERENCE", "target": f"ApexClass:{m.group(1)}", "confidence": 0.72, "evidence": item.get("source_file", "")})
        for m in re.finditer(r"setEndpoint\s*\(\s*['\"]([^'\"]+)", text, re.I):
            endpoint = m.group(1)
            callouts.append({"class": name, "endpoint": endpoint})
            relation = "USES_NAMED_CREDENTIAL" if endpoint.lower().startswith("callout:") else "USES_ENDPOINT"
            dependencies.append({"source": source, "relationship": relation, "target": endpoint, "confidence": 0.98, "evidence": item.get("source_file", "")})
    return {"endpoints": endpoints, "dynamic_references": dynamic_refs, "callouts": callouts}


def flow_path_map(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    flows: dict[str, Any] = {}
    for flow in components.get("flows", []):
        path = Path(flow.get("source_file", ""))
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        names = re.findall(r"<name>([^<]+)</name>", text)
        refs = re.findall(r"<targetReference>([^<]+)</targetReference>", text)
        subflows = re.findall(r"<flowName>([^<]+)</flowName>", text)
        actions = re.findall(r"<actionName>([^<]+)</actionName>", text)
        unique_names = sorted(set(names))[:1000]
        edges = []
        for ref in refs:
            edges.append({"target": ref, "kind": "connector"})
        for sub in sorted(set(subflows)):
            dependencies.append({"source": f"Flow:{flow.get('api_name')}", "relationship": "CALLS_SUBFLOW", "target": f"Flow:{sub}", "confidence": 0.98, "evidence": str(path)})
        for action in sorted(set(actions)):
            dependencies.append({"source": f"Flow:{flow.get('api_name')}", "relationship": "CALLS_ACTION", "target": action, "confidence": 0.85, "evidence": str(path)})
        flows[flow.get("api_name")] = {"element_names": unique_names, "connector_targets": sorted(set(refs)), "subflows": sorted(set(subflows)), "actions": sorted(set(actions)), "path_edge_count": len(edges)}
    return {"flows": flows, "flows_mapped": len(flows)}


def integration_map(components: dict[str, Any], apex_map: dict[str, Any]) -> dict[str, Any]:
    integrations = []
    for x in components.get("named_credentials", []):
        integrations.append({"type": "NamedCredential", "name": x.get("api_name"), "source": x.get("source_file")})
    for x in components.get("external_credentials", []):
        integrations.append({"type": "ExternalCredential", "name": x.get("api_name"), "source": x.get("source_file")})
    for x in components.get("connected_apps", []):
        integrations.append({"type": "ConnectedApp", "name": x.get("api_name"), "source": x.get("source_file")})
    return {"inventory": integrations, "apex_endpoints": apex_map.get("endpoints", []), "callouts": apex_map.get("callouts", [])}


def _safe_scalar_fields(obj: dict[str, Any], limit: int) -> list[str]:
    excluded = {"LongTextArea", "Html", "EncryptedText", "Address", "Location", "Base64"}
    out = []
    for f in obj.get("fields", []):
        if f.get("formula") or f.get("type") in excluded:
            continue
        name = f.get("api_name")
        if name and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            out.append(name)
        if len(out) >= limit:
            break
    return out


def profile_data(sf: SFCLI, components: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    cfg = config.get("analysis", {})
    if not cfg.get("data_profile_enabled", False):
        return {"enabled": False, "available": False, "note": "Opt-in only. Enable with --profile-data."}
    sample = max(1, min(int(cfg.get("data_profile_sample_size", 200)), 2000))
    max_objects = max(1, int(cfg.get("data_profile_max_objects", 10)))
    max_fields = max(1, int(cfg.get("data_profile_max_fields_per_object", 25)))
    custom_first = sorted(components.get("objects", []), key=lambda o: (not str(o.get("api_name", "")).endswith("__c"), o.get("api_name", "")))[:max_objects]
    results = []
    for obj in custom_first:
        api = obj.get("api_name")
        fields = _safe_scalar_fields(obj, max_fields)
        if not api or not fields:
            continue
        # OwnerId is sampled when available to estimate ownership skew; objects without
        # OwnerId automatically fall back to the scalar-field query.
        q = sf.query(f"SELECT OwnerId, {', '.join(fields)} FROM {api} LIMIT {sample}", tolerate_failure=True)
        owner_available = bool(q.get("ok"))
        if not q.get("ok"):
            q = sf.query(f"SELECT {', '.join(fields)} FROM {api} LIMIT {sample}", tolerate_failure=True)
        if not q.get("ok"):
            results.append({"object": api, "unavailable": True, "error": "query_failed"})
            continue
        rows = _records(q.get("payload", {}))
        field_stats = []
        for field in fields:
            vals = [r.get(field) for r in rows]
            non_null = [v for v in vals if v not in (None, "")]
            # Hash values before cardinality to avoid retaining business data in memory structures/report.
            distinct_hashes = {hashlib.sha256(repr(v).encode("utf-8", errors="ignore")).hexdigest() for v in non_null}
            field_stats.append({
                "field": f"{api}.{field}",
                "sampled_rows": len(rows),
                "null_count": len(vals) - len(non_null),
                "null_percent": round(((len(vals)-len(non_null))/len(vals))*100, 1) if vals else None,
                "distinct_count_sample": len(distinct_hashes),
                "distinct_ratio_percent": round((len(distinct_hashes)/len(non_null))*100, 1) if non_null else None,
            })
        owner_skew = {"available": False}
        if owner_available and rows:
            owner_hashes = [hashlib.sha256(str(r.get("OwnerId")).encode("utf-8", errors="ignore")).hexdigest()[:16] for r in rows if r.get("OwnerId")]
            counts = Counter(owner_hashes)
            top = counts.most_common(1)[0][1] if counts else 0
            owner_skew = {
                "available": bool(counts),
                "distinct_owners_sample": len(counts),
                "top_owner_share_percent": round(top / len(owner_hashes) * 100, 1) if owner_hashes else None,
                "potential_skew": bool(owner_hashes and top / len(owner_hashes) >= 0.5 and len(owner_hashes) >= 20),
                "owner_identifiers_hashed": True,
            }
        results.append({"object": api, "sampled_rows": len(rows), "field_stats": field_stats, "owner_skew": owner_skew})
    return {"enabled": True, "available": bool(results), "objects_profiled": len(results), "sample_size_cap": sample, "objects": results, "raw_values_persisted": False}


def collect_event_log_bodies(sf: SFCLI, runtime_v2: dict[str, Any], config: dict[str, Any], evidence_dir: Path) -> dict[str, Any]:
    cfg = config.get("analysis", {})
    if not cfg.get("event_log_download_enabled", True):
        return {"enabled": False, "available": False}
    allowed = set(cfg.get("event_log_types", []))
    max_files = max(0, int(cfg.get("event_log_max_files", 12)))
    rows = [r for r in _records(runtime_v2.get("event_logs", {})) if not allowed or r.get("EventType") in allowed][:max_files]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    dimensions: Counter[str] = Counter()
    apps: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    users: Counter[str] = Counter()
    app_users: Counter[tuple[str, str]] = Counter()
    for row in rows:
        event_id = row.get("Id")
        event_type = row.get("EventType") or "Unknown"
        if not event_id:
            continue
        dest = evidence_dir / f"{event_type}-{event_id}.csv"
        resp = sf.rest_get(f"/services/data/v66.0/sobjects/EventLogFile/{event_id}/LogFile", stream_to=dest, tolerate_failure=True)
        if not resp.get("ok") or not dest.exists():
            summaries.append({"id": event_id, "event_type": event_type, "downloaded": False})
            continue
        row_count = 0
        columns = []
        try:
            with dest.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
                reader = csv.DictReader(fh)
                columns = reader.fieldnames or []
                for rec in reader:
                    row_count += 1
                    dimensions[event_type] += 1
                    app = rec.get("APP_NAME") or rec.get("APPLICATION") or rec.get("APP_ID")
                    client = rec.get("CLIENT_NAME") or rec.get("CONNECTED_APP_ID") or rec.get("CLIENT_ID")
                    user = rec.get("USER_ID") or rec.get("USER_NAME")
                    if app: apps[str(app)] += 1
                    if client: clients[str(client)] += 1
                    if user:
                        user_hash = hashlib.sha256(str(user).encode("utf-8", errors="ignore")).hexdigest()[:16]
                        users[user_hash] += 1
                        if app:
                            app_users[(str(app), user_hash)] += 1
        except OSError:
            pass
        summaries.append({"id": event_id, "event_type": event_type, "downloaded": True, "rows": row_count, "columns": columns[:80], "file": str(dest)})
    return {
        "enabled": True,
        "available": any(x.get("downloaded") for x in summaries),
        "files": summaries,
        "events_by_type": dict(dimensions),
        "app_usage": [{"app": k, "events": v} for k, v in apps.most_common(100)],
        "api_clients": [{"client": k, "events": v} for k, v in clients.most_common(100)],
        "app_user_usage": [{"app": app, "user_hash": user_hash, "events": events} for (app, user_hash), events in app_users.most_common(500)],
        "active_users_evidence": len(users),
        "user_identifiers_hashed": True,
    }


def change_risk_and_debt(components: dict[str, Any], dependencies: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    incident_by_component = Counter()
    severity_weight = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
    for f in findings:
        comp = getattr(f, "component", "") or ""
        if comp:
            incident_by_component[comp] += severity_weight.get(getattr(f, "severity", "medium"), 7)
    neighbors: dict[str, set[str]] = defaultdict(set)
    for e in dependencies:
        a, b = e.get("source"), e.get("target")
        if a and b:
            neighbors[a].add(b); neighbors[b].add(a)
    rows = []
    for comp in set(neighbors) | set(incident_by_component):
        degree = len(neighbors.get(comp, set()))
        risk = min(100, round(degree * 7 + incident_by_component.get(comp, 0)))
        debt = min(100, round(degree * 4 + incident_by_component.get(comp, 0) * 1.2))
        rows.append({"component": comp, "dependency_degree": degree, "finding_penalty": incident_by_component.get(comp, 0), "change_risk_score": risk, "technical_debt_score": debt})
    rows.sort(key=lambda x: (x["change_risk_score"], x["technical_debt_score"]), reverse=True)
    return {"components_scored": len(rows), "top_change_risk": rows[:100], "top_technical_debt": sorted(rows, key=lambda x: x["technical_debt_score"], reverse=True)[:100]}


def build_v3_intelligence(sf: SFCLI, components: dict[str, Any], dependencies: list[dict[str, Any]], findings: list[Any], runtime_v2: dict[str, Any], config: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    reports = enrich_report_dashboard_dependencies(components, dependencies)
    apex = apex_semantic_map(components, dependencies)
    flows = flow_path_map(components, dependencies)
    integrations = integration_map(components, apex)
    data = profile_data(sf, components, config)
    events = collect_event_log_bodies(sf, runtime_v2, config, output_dir / "evidence" / "event-logs")
    scores = change_risk_and_debt(components, dependencies, findings)
    return {
        "report_dashboard_dependencies": reports,
        "apex_semantic_map": apex,
        "flow_path_map": flows,
        "integration_map": integrations,
        "data_quality_profile": data,
        "event_monitoring": events,
        "risk_and_debt": scores,
    }


def analyze_v3_intelligence(components: dict[str, Any], findings: list[Any]) -> None:
    from .models import Evidence, Finding
    v3 = components.get("intelligence", {}).get("v3", {})
    seq = 1
    dq = v3.get("data_quality_profile", {})
    if dq.get("enabled") and dq.get("available"):
        high_null = []
        for obj in dq.get("objects", []):
            for f in obj.get("field_stats", []):
                if isinstance(f.get("null_percent"), (int, float)) and f["null_percent"] >= 95 and f.get("sampled_rows", 0) >= 20:
                    high_null.append(f)
        if high_null:
            findings.append(Finding(
                id=f"V3DATA-{seq:04d}", category="data_quality", severity="medium",
                title="Fields with very high null density in sampled data",
                description=f"{len(high_null)} fields were at least 95% null in the configured sample.",
                component="Data Model", recommendation="Review whether these fields are required, obsolete, conditionally populated, or missing expected integration/user input.", effort="Medium", confidence=0.8,
                evidence=[Evidence("DATA_PROFILE_SAMPLE", "read-only sample", ", ".join(f"{x['field']}={x['null_percent']}%" for x in high_null[:30]), 0.8)]
            )); seq += 1
        skewed = [obj for obj in dq.get("objects", []) if obj.get("owner_skew", {}).get("potential_skew")]
        if skewed:
            findings.append(Finding(
                id=f"V3PERF-{seq:04d}", category="performance", severity="medium",
                title="Potential ownership skew detected in sampled data",
                description=f"{len(skewed)} profiled object(s) had one owner holding at least 50% of sampled owned records.",
                component="Data Model", recommendation="Validate ownership skew with a larger approved query and review sharing recalculation, locking and automation impact on high-volume objects.", effort="Medium", confidence=0.72,
                evidence=[Evidence("DATA_PROFILE_SAMPLE", "OwnerId hashed sample", ", ".join(f"{x['object']}={x['owner_skew'].get('top_owner_share_percent')}%" for x in skewed[:30]), 0.72)]
            )); seq += 1
    apex = v3.get("apex_semantic_map", {})
    hardcoded = [x for x in apex.get("callouts", []) if not str(x.get("endpoint", "")).lower().startswith("callout:")]
    if hardcoded:
        findings.append(Finding(
            id=f"V3INT-{seq:04d}", category="integrations", severity="high",
            title="Apex callout endpoints appear hardcoded",
            description=f"{len(hardcoded)} setEndpoint() values do not use the callout: Named Credential syntax.",
            component="Apex Callouts", recommendation="Review and migrate endpoint/authentication configuration to Named Credentials where appropriate.", effort="Medium", confidence=0.92,
            evidence=[Evidence("APEX_STATIC_ANALYSIS", "setEndpoint", ", ".join(f"{x['class']}->{x['endpoint']}" for x in hardcoded[:20]), 0.92)]
        )); seq += 1
    dynamic = apex.get("dynamic_references", [])
    if dynamic:
        findings.append(Finding(
            id=f"V3ARC-{seq:04d}", category="architecture", severity="low",
            title="Dynamic Apex references require manual dependency review",
            description=f"{len(dynamic)} Type.forName-style dynamic references were detected; static dead-code analysis can undercount these dependencies.",
            component="Apex", recommendation="Preserve these dynamic edges in removal/change reviews and validate configuration-driven class names before deleting candidates.", effort="Low", confidence=0.9,
            evidence=[Evidence("APEX_STATIC_ANALYSIS", "Type.forName", ", ".join(f"{x['class']}->{x['target']}" for x in dynamic[:20]), 0.9)]
        )); seq += 1
    high_risk = [x for x in v3.get("risk_and_debt", {}).get("top_change_risk", []) if x.get("change_risk_score", 0) >= 70]
    if high_risk:
        findings.append(Finding(
            id=f"V3ARC-{seq:04d}", category="architecture", severity="medium",
            title="High change-risk dependency hotspots detected",
            description=f"{len(high_risk)} components scored 70+ on the deterministic change-risk heuristic.", component="Dependency Graph",
            recommendation="Require impact analysis and targeted regression tests before changing the highest-risk components.", effort="Medium", confidence=0.75,
            evidence=[Evidence("DEPENDENCY_GRAPH", "change-risk", ", ".join(f"{x['component']}={x['change_risk_score']}" for x in high_risk[:20]), 0.75)]
        ))
