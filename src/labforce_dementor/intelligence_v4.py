from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .parser import local, child_text, all_text, xml_root


def _node(component_type: str, name: str) -> str:
    return f"{component_type}:{name}"


def apex_ast_enrichment(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Conservative token/structure parser. Avoids counting comments/strings as references.
    It is deliberately dependency-free; if tree-sitter is added later this contract stays stable.
    """
    class_names = {x.get("api_name") for x in components.get("apex_classes", []) if x.get("api_name")}
    summaries = []
    for item in components.get("apex_classes", []) + components.get("apex_triggers", []):
        text = item.get("text", "")
        # Strip block/line comments and quoted strings before structural reference scan.
        scrub = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        scrub = re.sub(r"//[^\n]*", " ", scrub)
        scrub = re.sub(r"'(?:\\.|[^'\\])*'", "''", scrub)
        source_type = "ApexTrigger" if item in components.get("apex_triggers", []) else "ApexClass"
        source = _node(source_type, item.get("api_name", ""))
        refs = []
        for target in sorted(class_names):
            if target != item.get("api_name") and re.search(rf"\b{re.escape(target)}\b", scrub):
                refs.append(target)
                dependencies.append({"source": source, "relationship": "AST_REFERENCES_APEX", "target": _node("ApexClass", target), "confidence": 0.94, "evidence": item.get("source_file", "")})
        dml = sorted(set(re.findall(r"\b(?:insert|update|upsert|delete|undelete|merge)\s+([A-Za-z_][A-Za-z0-9_]*)", scrub, re.I)))
        soql_objects = sorted(set(re.findall(r"\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)", scrub, re.I)))
        for obj in soql_objects:
            dependencies.append({"source": source, "relationship": "AST_QUERIES_OBJECT", "target": _node("Object", obj), "confidence": 0.95, "evidence": item.get("source_file", "")})
        summaries.append({"component": source, "apex_references": refs, "soql_objects": soql_objects, "dml_variables": dml})
    return {"parser": "conservative-structural", "components": summaries, "components_mapped": len(summaries)}


def flow_structural_map(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    mapped = {}
    element_tags = {"recordCreates","recordUpdates","recordDeletes","recordLookups","loops","subflows","decisions","assignments","actionCalls","waits","screens"}
    for flow in components.get("flows", []):
        path = Path(flow.get("source_file", ""))
        root = xml_root(path)
        if root is None:
            continue
        elements = {}
        edges = []
        for node in list(root):
            kind = local(node.tag)
            if kind not in element_tags:
                continue
            name = child_text(node, "name")
            if not name:
                continue
            refs = all_text(node, "targetReference")
            elements[name] = {"kind": kind, "targets": sorted(set(refs))}
            for target in refs:
                edges.append({"source": name, "target": target})
        mapped[flow.get("api_name")] = {"elements": elements, "edges": edges, "edge_count": len(edges)}
    return {"flows": mapped, "flows_mapped": len(mapped)}


def ui_lineage(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Maps LWC/Aura/VF textual references to Apex and object/field tokens."""
    roots = set()
    for bucket in ("lwc", "aura", "pages"):
        for item in components.get(bucket, []):
            p = Path(item.get("source_file", ""))
            roots.add(p.parent if p.is_file() else p)
    classes = {x.get("api_name") for x in components.get("apex_classes", []) if x.get("api_name")}
    fields = {f.get("full_name") for o in components.get("objects", []) for f in o.get("fields", []) if f.get("full_name")}
    edges = 0
    scanned = 0
    seen_files = set()
    for base in roots:
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p in seen_files or p.suffix.lower() not in {".js",".html",".cmp",".app",".evt",".design",".auradoc",".page",".xml"}:
                continue
            seen_files.add(p); scanned += 1
            text = p.read_text(encoding="utf-8", errors="ignore")
            source = f"UI:{p.stem}"
            for cls in classes:
                if re.search(rf"\b{re.escape(cls)}\b", text):
                    dependencies.append({"source": source, "relationship": "UI_REFERENCES_APEX", "target": _node("ApexClass", cls), "confidence": 0.88, "evidence": str(p)}); edges += 1
            for full in fields:
                obj, fld = full.split(".",1)
                if full in text or re.search(rf"\b{re.escape(fld)}\b", text):
                    dependencies.append({"source": source, "relationship": "UI_REFERENCES_FIELD", "target": _node("Field", full), "confidence": 0.78, "evidence": str(p)}); edges += 1
    return {"files_scanned": scanned, "edges_added": edges}


def effective_access_v4(components: dict[str, Any], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    """Combines Profile + Permission Set assignment and surfaces PSG/muting evidence when retrievable."""
    assignments = runtime_v2.get("permission_set_assignments", {})
    rows = assignments.get("result", assignments).get("records", []) if isinstance(assignments, dict) and isinstance(assignments.get("result", assignments), dict) else []
    ps_by_name = {x.get("api_name"): x for x in components.get("permission_sets", [])}
    users = defaultdict(lambda: {"permission_sets": [], "critical_user_permissions": set(), "object_modify_all": set(), "field_edit": set()})
    critical = {"ModifyAllData","ViewAllData","AuthorApex","ManageUsers","CustomizeApplication","ModifyMetadata"}
    for row in rows:
        uid = row.get("AssigneeId") or row.get("Assignee", {}).get("Id")
        psname = row.get("PermissionSet", {}).get("Name") if isinstance(row.get("PermissionSet"), dict) else row.get("PermissionSetName")
        if not uid or not psname: continue
        users[uid]["permission_sets"].append(psname)
        ps = ps_by_name.get(psname, {})
        for p in ps.get("user_permissions", []):
            if p.get("enabled") and p.get("name") in critical: users[uid]["critical_user_permissions"].add(p["name"])
        for op in ps.get("object_permissions", []):
            if op.get("modify_all"): users[uid]["object_modify_all"].add(op.get("object"))
        for fp in ps.get("field_permissions", []):
            if fp.get("editable"): users[uid]["field_edit"].add(fp.get("field"))
    normalized=[]
    for uid, d in users.items():
        normalized.append({"user_id":uid,"permission_sets":sorted(set(d["permission_sets"])),"critical_user_permissions":sorted(d["critical_user_permissions"]),"object_modify_all":sorted(x for x in d["object_modify_all"] if x),"editable_fields_count":len(d["field_edit"])})
    return {"users": normalized, "users_analyzed": len(normalized), "note":"Profile/PSG/muting completeness depends on retrieved metadata and runtime query availability."}


def sharing_model(components: dict[str, Any]) -> dict[str, Any]:
    return {"objects":[{"object":o.get("api_name"),"internal_owd":o.get("sharing_model") or None,"external_owd":o.get("external_sharing_model") or None} for o in components.get("objects", [])]}


def package_lineage(components: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    counts=defaultdict(int)
    for bucket in ("objects","apex_classes","apex_triggers","flows"):
        for x in components.get(bucket, []):
            name=x.get("api_name","")
            ns=name.split("__",1)[0] if "__" in name and not name.endswith("__c") else None
            if ns: counts[ns]+=1
    return {"namespace_component_counts":dict(sorted(counts.items()))}


def _adjacency(dependencies: list[dict[str, Any]]) -> tuple[dict[str,list[dict]],dict[str,list[dict]]]:
    out=defaultdict(list); inc=defaultdict(list)
    for e in dependencies:
        out[e.get("source","")].append(e); inc[e.get("target","")].append(e)
    return out,inc


def impact_report(snapshot: dict[str, Any], component: str, max_depth: int = 3) -> dict[str, Any]:
    deps=snapshot.get("dependencies",[])
    # Accept exact node or friendly API name.
    candidates={component}
    if ":" not in component:
        candidates |= {n for e in deps for n in (e.get("source",""),e.get("target","")) if n.endswith(":"+component) or n.endswith("."+component)}
    out,inc=_adjacency(deps)
    visited=set(candidates); q=deque((c,0) for c in candidates); affected=[]; edge_rows=[]
    while q:
        n,d=q.popleft()
        if d>=max_depth: continue
        for e in out.get(n,[])+inc.get(n,[]):
            other=e.get("target") if e.get("source")==n else e.get("source")
            edge_rows.append(e)
            if other and other not in visited:
                visited.add(other); affected.append(other); q.append((other,d+1))
    by_type=defaultdict(int)
    for n in affected:
        by_type[n.split(":",1)[0] if ":" in n else "Other"]+=1
    findings=[f for f in snapshot.get("findings",[]) if f.get("component") in visited or f.get("component")==component]
    severity_weight={"critical":25,"high":12,"medium":5,"low":1,"info":0}
    score=min(100, len(affected)*2 + sum(severity_weight.get(str(f.get("severity","")).lower(),0) for f in findings))
    return {"component":component,"resolved_nodes":sorted(candidates),"max_depth":max_depth,"change_risk_score":score,"risk":"CRITICAL" if score>=90 else "HIGH" if score>=70 else "MEDIUM" if score>=40 else "LOW","blast_radius":len(affected),"affected_by_type":dict(sorted(by_type.items())),"affected_components":sorted(affected),"supporting_edges":edge_rows[:500],"related_findings":findings[:100]}


def build_v4_intelligence(components: dict[str, Any], dependencies: list[dict[str, Any]], runtime_v2: dict[str, Any]) -> dict[str, Any]:
    return {
        "apex_ast": apex_ast_enrichment(components, dependencies),
        "flow_structural": flow_structural_map(components, dependencies),
        "ui_lineage": ui_lineage(components, dependencies),
        "effective_access": effective_access_v4(components, runtime_v2),
        "sharing": sharing_model(components),
        "package_lineage": package_lineage(components, dependencies),
    }
