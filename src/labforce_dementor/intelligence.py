from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .sfcli import SFCLI


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("result", payload)
        if isinstance(payload, dict):
            return payload.get("records", []) if isinstance(payload.get("records", []), list) else []
    return payload if isinstance(payload, list) else []


def collect_v2_runtime(sf: SFCLI, config: dict[str, Any]) -> dict[str, Any]:
    """Best-effort, read-only runtime enrichment.

    Every query may be unavailable due to license/permissions/API shape. Unavailable
    sources are retained as evidence gaps rather than treated as healthy.
    """
    queries: dict[str, tuple[bool, str]] = {
        "apex_coverage": (True, "SELECT ApexClassOrTriggerId, ApexClassOrTrigger.Name, NumLinesCovered, NumLinesUncovered FROM ApexCodeCoverageAggregate"),
        "permission_assignments": (False, "SELECT Assignee.Id, Assignee.Username, Assignee.IsActive, PermissionSet.Id, PermissionSet.Name, PermissionSet.Label, PermissionSet.Profile.Name FROM PermissionSetAssignment WHERE Assignee.IsActive = true LIMIT 50000"),
        "permission_set_groups": (False, "SELECT Assignee.Id, Assignee.Username, PermissionSetGroup.Id, PermissionSetGroup.DeveloperName, PermissionSetGroup.MasterLabel FROM PermissionSetAssignment WHERE Assignee.IsActive = true AND PermissionSetGroupId != null LIMIT 50000"),
        "record_counts": (False, "SELECT QualifiedApiName, RecordCount FROM EntityDefinition WHERE IsQueryable = true AND RecordCount != null ORDER BY RecordCount DESC LIMIT 2000"),
        "event_logs": (False, "SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE LogDate = LAST_N_DAYS:7 ORDER BY LogDate DESC LIMIT 2000"),
        "failed_async": (False, "SELECT Id, JobType, Status, ApexClass.Name, CreatedDate, CompletedDate, NumberOfErrors, ExtendedStatus FROM AsyncApexJob WHERE CreatedDate = LAST_N_DAYS:30 AND (Status = 'Failed' OR NumberOfErrors > 0) ORDER BY CreatedDate DESC LIMIT 2000"),
    }
    out: dict[str, Any] = {}
    for name, (tooling, soql) in queries.items():
        q = sf.query(soql, tooling=tooling, tolerate_failure=True)
        if q.get("ok"):
            out[name] = q.get("payload", {})
        else:
            out[name] = {"unavailable": True, "error": q.get("error")}
    return out


def _apex_field_usage(components: dict[str, Any]) -> list[dict[str, Any]]:
    fields = [f for o in components.get("objects", []) for f in o.get("fields", [])]
    edges: list[dict[str, Any]] = []
    for comp_type, prefix in (("apex_classes", "ApexClass"), ("apex_triggers", "Trigger")):
        for comp in components.get(comp_type, []):
            text = comp.get("text", "")
            if not text:
                continue
            for fld in fields:
                full = fld.get("full_name", "")
                short = fld.get("api_name", "")
                obj = full.split(".", 1)[0] if "." in full else ""
                qualified = bool(full and full in text)
                member = bool(short and re.search(rf"\.{re.escape(short)}\b", text))
                if not (qualified or member):
                    continue
                # Assignment is strong write evidence; non-assignment remains a read/use edge.
                write = bool(re.search(rf"(?:\b{re.escape(obj)}\b\s*\.\s*)?{re.escape(short)}\s*=", text))
                relation = "WRITES_FIELD" if write else "READS_FIELD"
                edges.append({
                    "source": f"{prefix}:{comp.get('api_name')}",
                    "relationship": relation,
                    "target": f"Field:{full}",
                    "confidence": 0.94 if qualified else (0.86 if write else 0.76),
                    "evidence": comp.get("source_file", ""),
                })
    return edges


def _flow_lineage(components: dict[str, Any]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    known_fields = {f.get("api_name"): f.get("full_name") for o in components.get("objects", []) for f in o.get("fields", [])}
    for flow in components.get("flows", []):
        try:
            text = Path(flow.get("source_file", "")).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        obj = flow.get("object", "")
        for fname in flow.get("field_references", []):
            full = f"{obj}.{fname}" if obj and "." not in fname else known_fields.get(fname, fname)
            if not full or "." not in full:
                continue
            # recordUpdates/recordCreates with a field reference provide write evidence;
            # otherwise classify conservatively as usage/read.
            write = bool(re.search(rf"<(?:recordUpdates|recordCreates)>[\s\S]*?<field>{re.escape(fname)}</field>", text, re.I))
            edges.append({
                "source": f"Flow:{flow.get('api_name')}",
                "relationship": "WRITES_FIELD" if write else "READS_FIELD",
                "target": f"Field:{full}",
                "confidence": 0.9 if write else 0.76,
                "evidence": flow.get("source_file", ""),
            })
    return edges


def build_field_lineage(components: dict[str, Any]) -> dict[str, Any]:
    edges = _apex_field_usage(components) + _flow_lineage(components)
    by_field: dict[str, dict[str, Any]] = defaultdict(lambda: {"writers": [], "readers": []})
    for edge in edges:
        field = edge["target"].removeprefix("Field:")
        bucket = "writers" if edge["relationship"] == "WRITES_FIELD" else "readers"
        by_field[field][bucket].append({
            "component": edge["source"], "confidence": edge["confidence"], "evidence": edge["evidence"]
        })
    # UI/manual evidence is also lineage: user is a potential writer when editable + rendered.
    for obj in components.get("objects", []):
        for fld in obj.get("fields", []):
            full = fld.get("full_name", "")
            if fld.get("manual_candidate"):
                by_field[full]["writers"].append({
                    "component": "User:UI", "confidence": fld.get("manual_confidence", 0.5), "evidence": ", ".join(fld.get("layouts", []))
                })
    return {"edges": edges, "fields": dict(by_field), "field_count_with_lineage": len(by_field)}


def build_effective_permissions(components: dict[str, Any], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    metadata_by_name: dict[str, dict[str, Any]] = {}
    for ps in components.get("permission_sets", []):
        metadata_by_name[ps.get("api_name", "")] = ps
    assignments = _records(runtime_v2.get("permission_assignments", {}))
    users: dict[str, Any] = defaultdict(lambda: {"username": "", "permission_sets": [], "critical_user_permissions": [], "objects_modify_all": [], "objects_view_all": []})
    critical = {"ModifyAllData", "ViewAllData", "AuthorApex", "ManageUsers", "CustomizeApplication", "ModifyMetadata"}
    for rec in assignments:
        assignee = rec.get("Assignee") or {}
        ps = rec.get("PermissionSet") or {}
        uid = assignee.get("Id") or "unknown"
        name = ps.get("Name") or ""
        u = users[uid]
        u["username"] = assignee.get("Username") or u["username"]
        u["permission_sets"].append(name)
        meta = metadata_by_name.get(name)
        if not meta:
            continue
        for p in meta.get("user_permissions", []):
            if p.get("enabled") and p.get("name") in critical:
                u["critical_user_permissions"].append(p.get("name"))
        for op in meta.get("object_permissions", []):
            if op.get("modify_all"):
                u["objects_modify_all"].append(op.get("object"))
            if op.get("view_all"):
                u["objects_view_all"].append(op.get("object"))
    for u in users.values():
        for key in ("permission_sets", "critical_user_permissions", "objects_modify_all", "objects_view_all"):
            u[key] = sorted(set(x for x in u[key] if x))
    return {
        "available": bool(assignments),
        "active_users_analyzed": len(users),
        "users": dict(users),
        "privileged_users": [u for u in users.values() if u["critical_user_permissions"] or u["objects_modify_all"]],
    }


def build_apex_coverage(runtime_v2: dict[str, Any]) -> dict[str, Any]:
    rows = _records(runtime_v2.get("apex_coverage", {}))
    classes = []
    total_covered = total_uncovered = 0
    for r in rows:
        c = int(r.get("NumLinesCovered") or 0)
        u = int(r.get("NumLinesUncovered") or 0)
        name = (r.get("ApexClassOrTrigger") or {}).get("Name") or r.get("ApexClassOrTriggerId")
        pct = round((c / (c + u) * 100), 1) if c + u else None
        classes.append({"name": name, "covered": c, "uncovered": u, "coverage_percent": pct})
        total_covered += c; total_uncovered += u
    overall = round(total_covered / (total_covered + total_uncovered) * 100, 1) if total_covered + total_uncovered else None
    return {"available": bool(rows), "overall_percent": overall, "components": sorted(classes, key=lambda x: (x["coverage_percent"] is None, x["coverage_percent"] or 0))}


def build_data_profile(runtime_v2: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    rows = _records(runtime_v2.get("record_counts", {}))
    counts = []
    for r in rows:
        name = r.get("QualifiedApiName") or r.get("DeveloperName")
        count = r.get("RecordCount")
        if name and isinstance(count, (int, float)):
            counts.append({"object": name, "record_count": int(count)})
    counts.sort(key=lambda x: x["record_count"], reverse=True)
    threshold = int(config.get("analysis", {}).get("large_data_volume_threshold", 1_000_000))
    return {
        "available": bool(counts),
        "objects_counted": len(counts),
        "total_records_estimate": sum(x["record_count"] for x in counts),
        "largest_objects": counts[:50],
        "ldv_candidates": [x for x in counts if x["record_count"] >= threshold],
        "note": "v0.2 uses org record-count telemetry. Null-density/cardinality profiling is intentionally deferred to an opt-in profiler to control API/data exposure.",
    }


def build_order_of_execution(components: dict[str, Any]) -> dict[str, Any]:
    by_object: dict[str, Any] = defaultdict(lambda: {"before_save_flows": [], "after_save_flows": [], "other_flows": [], "triggers": [], "validation_rules": []})
    for flow in components.get("flows", []):
        obj = flow.get("object")
        if not obj or str(flow.get("status", "")).lower() != "active":
            continue
        rt = str(flow.get("record_trigger_type", "")).lower()
        if "before" in rt or "fastfieldupdates" in rt:
            bucket = "before_save_flows"
        elif "after" in rt or "actionsandrelatedrecords" in rt:
            bucket = "after_save_flows"
        else:
            bucket = "other_flows"
        by_object[obj][bucket].append(flow.get("api_name"))
    # Trigger object is inferred from declaration.
    for trig in components.get("apex_triggers", []):
        text = trig.get("text", "")
        m = re.search(r"\btrigger\s+\w+\s+on\s+([A-Za-z0-9_]+)\s*\(", text, re.I)
        if m:
            by_object[m.group(1)]["triggers"].append(trig.get("api_name"))
    for obj in components.get("objects", []):
        by_object[obj.get("api_name")]["validation_rules"] = [v.get("api_name") for v in obj.get("validation_rules", []) if v.get("active")]
    hotspots = []
    for obj, data in by_object.items():
        score = sum(len(data[k]) for k in data)
        if score:
            hotspots.append({"object": obj, "automation_components": score, **data})
    hotspots.sort(key=lambda x: x["automation_components"], reverse=True)
    return {"objects": dict(by_object), "hotspots": hotspots[:100]}


def calculate_blast_radius(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, set[str]] = defaultdict(set)
    for e in dependencies:
        outgoing[e.get("source", "")].add(e.get("target", ""))
        incoming[e.get("target", "")].add(e.get("source", ""))
    nodes = set(outgoing) | set(incoming)
    ranking = []
    for n in nodes:
        direct = len(outgoing.get(n, set()) | incoming.get(n, set()))
        second: set[str] = set()
        for x in outgoing.get(n, set()) | incoming.get(n, set()):
            second |= outgoing.get(x, set()) | incoming.get(x, set())
        second.discard(n)
        ranking.append({"component": n, "direct_dependencies": direct, "two_hop_reach": len(second), "blast_radius_score": direct + min(50, len(second))})
    ranking.sort(key=lambda x: x["blast_radius_score"], reverse=True)
    return {"top_components": ranking[:100], "components_scored": len(ranking)}


def build_runtime_usage(runtime_v2: dict[str, Any]) -> dict[str, Any]:
    logs = _records(runtime_v2.get("event_logs", {}))
    by_type = Counter(str(x.get("EventType") or "Unknown") for x in logs)
    failed = _records(runtime_v2.get("failed_async", {}))
    return {
        "event_monitoring_available": bool(logs),
        "event_log_files_by_type": dict(by_type),
        "failed_async_jobs_30d": len(failed),
        "failed_async_jobs": failed[:200],
        "app_usage_note": "Exact app/user usage requires the relevant Event Monitoring event types/licenses. Dementor reports evidence coverage instead of inferring usage from app existence.",
    }


def build_intelligence(components: dict[str, Any], dependencies: list[dict[str, Any]], runtime_v2: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    lineage = build_field_lineage(components)
    # Add v2 lineage edges to the dependency graph without mutating the legacy edge schema.
    dependencies.extend(lineage["edges"])
    return {
        "field_lineage": lineage,
        "effective_permissions": build_effective_permissions(components, runtime_v2),
        "apex_coverage": build_apex_coverage(runtime_v2),
        "data_profile": build_data_profile(runtime_v2, config),
        "order_of_execution": build_order_of_execution(components),
        "blast_radius": calculate_blast_radius(dependencies),
        "runtime_usage": build_runtime_usage(runtime_v2),
        "evidence_gaps": [k for k, v in runtime_v2.items() if isinstance(v, dict) and v.get("unavailable")],
    }
