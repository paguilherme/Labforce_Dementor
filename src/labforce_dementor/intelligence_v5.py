from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


METADATA_SUFFIXES = (
    ".cls", ".trigger", ".flow-meta.xml", ".object-meta.xml", ".field-meta.xml",
    ".layout-meta.xml", ".app-meta.xml", ".flexipage-meta.xml", ".permissionset-meta.xml",
    ".profile-meta.xml", ".report-meta.xml", ".dashboard-meta.xml", ".page",
    ".js", ".html", ".cmp", ".xml",
)


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_fingerprint(source_root: Path) -> dict[str, Any]:
    files = []
    if not source_root.exists():
        return {"available": False, "root": str(source_root), "files": [], "count": 0}
    for p in sorted(source_root.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(source_root)).replace("\\", "/")
        # Exclude generated/non-source noise; retain Salesforce source and metadata.
        if p.name.startswith(".") or "__pycache__" in p.parts:
            continue
        if not any(p.name.endswith(s) for s in METADATA_SUFFIXES):
            continue
        files.append({"path": rel, "sha256": _sha(p), "bytes": p.stat().st_size})
    return {"available": True, "root": str(source_root), "files": files, "count": len(files)}


def compare_fingerprints(org_snapshot: dict[str, Any], repo_snapshot: dict[str, Any]) -> dict[str, Any]:
    org = {x["path"]: x for x in org_snapshot.get("files", [])}
    repo = {x["path"]: x for x in repo_snapshot.get("files", [])}
    only_org = sorted(set(org) - set(repo))
    only_repo = sorted(set(repo) - set(org))
    common = sorted(set(org) & set(repo))
    modified = [p for p in common if org[p].get("sha256") != repo[p].get("sha256")]
    same = [p for p in common if org[p].get("sha256") == repo[p].get("sha256")]
    return {
        "org_only": only_org,
        "repo_only": only_repo,
        "modified": modified,
        "identical": same,
        "counts": {
            "org_only": len(only_org), "repo_only": len(only_repo),
            "modified": len(modified), "identical": len(same),
        },
        "has_drift": bool(only_org or only_repo or modified),
    }


def drift_from_assessment(assessment: dict[str, Any], repo_dir: Path) -> dict[str, Any]:
    org_fp = assessment.get("components", {}).get("intelligence", {}).get("v5", {}).get("source_fingerprint", {})
    repo_fp = source_fingerprint(repo_dir)
    if not org_fp.get("available"):
        return {
            "available": False,
            "error": "Assessment does not contain a v1.5 source fingerprint. Run a new v1.5 assessment first.",
            "repo_fingerprint": repo_fp,
        }
    result = compare_fingerprints(org_fp, repo_fp)
    result.update({"available": True, "repo_root": str(repo_dir), "org_source_root_at_assessment": org_fp.get("root")})
    return result


def _graph(snapshot: dict[str, Any]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    out: dict[str, set[str]] = defaultdict(set)
    inc: dict[str, set[str]] = defaultdict(set)
    for e in snapshot.get("dependencies", []):
        a, b = e.get("source"), e.get("target")
        if a and b:
            out[a].add(b); inc[b].add(a)
    return out, inc


def select_tests(snapshot: dict[str, Any], changed_components: list[str], depth: int = 3) -> dict[str, Any]:
    out, inc = _graph(snapshot)
    nodes = set()
    for c in changed_components:
        nodes.add(c)
        if ":" not in c:
            for n in set(out) | set(inc):
                if n.endswith(":" + c) or n.endswith("." + c):
                    nodes.add(n)
    visited = set(nodes)
    q = deque((n, 0) for n in nodes)
    while q:
        n, d = q.popleft()
        if d >= depth:
            continue
        for other in out.get(n, set()) | inc.get(n, set()):
            if other not in visited:
                visited.add(other); q.append((other, d + 1))

    classes = snapshot.get("components", {}).get("apex_classes", [])
    tests = [x.get("api_name") for x in classes if x.get("is_test") and x.get("api_name")]
    selected: dict[str, dict[str, Any]] = {}
    changed_names = {c.split(":",1)[-1].split(".")[-1] for c in changed_components}
    impacted_names = {n.split(":",1)[-1] for n in visited}

    for test in tests:
        score = 0
        reasons = []
        lower = test.lower()
        for name in changed_names | impacted_names:
            core = name.replace("__c","").replace("__r","")
            if core and core.lower() in lower:
                score += 35
                reasons.append(f"name_correlates:{name}")
        test_node = f"ApexClass:{test}"
        neighbors = out.get(test_node, set()) | inc.get(test_node, set())
        overlap = neighbors & visited
        if overlap:
            score += min(55, len(overlap) * 15)
            reasons.append(f"dependency_overlap:{len(overlap)}")
        if score:
            selected[test] = {"test": test, "score": min(100, score), "reasons": sorted(set(reasons))}

    ranked = sorted(selected.values(), key=lambda x: (-x["score"], x["test"]))
    confidence = min(0.99, 0.45 + (0.08 * len(ranked))) if ranked else 0.25
    return {
        "changed_components": changed_components,
        "depth": depth,
        "recommended_tests": ranked,
        "test_names": [x["test"] for x in ranked],
        "confidence": round(confidence, 2),
        "manual_review_required": True,
        "note": "A seleção se baseia em evidências, mas não substitui a verificação de dependências e execução no Salesforce.",
    }


def build_knowledge_pack(snapshot: dict[str, Any]) -> dict[str, Any]:
    components = snapshot.get("components", {})
    intel = components.get("intelligence", {})
    return {
        "organization": {
            "product": snapshot.get("product", {}),
            "run": snapshot.get("run", {}),
            "org": snapshot.get("org", {}),
            "inventory": snapshot.get("inventory", {}),
            "health": snapshot.get("health", {}),
        },
        "architecture": {
            "applications": components.get("applications", []),
            "objects": components.get("objects", []),
            "flows": components.get("flows", []),
            "apex_classes": components.get("apex_classes", []),
            "apex_triggers": components.get("apex_triggers", []),
        },
        "dependency_graph": snapshot.get("dependencies", []),
        "field_lineage": intel.get("field_lineage", {}),
        "automation_map": {
            "order_of_execution": intel.get("order_of_execution", {}),
            "flow_structural": intel.get("v4", {}).get("flow_structural", {}),
        },
        "integration_map": {
            "inventory": components.get("named_credentials", []) + components.get("external_credentials", []) + components.get("connected_apps", []),
            "semantic": intel.get("v3", {}).get("apex_semantic_map", {}),
        },
        "security_map": {
            "effective_permissions": intel.get("effective_permissions", {}),
            "effective_access": intel.get("v4", {}).get("effective_access", {}),
            "sharing": intel.get("v4", {}).get("sharing", {}),
        },
        "findings": snapshot.get("findings", []),
        "risk": intel.get("v3", {}).get("risk_and_debt", {}),
        "evidence": {
            "audit": snapshot.get("audit", {}),
            "code_analyzer": snapshot.get("code_analyzer", {}),
            "quality": intel.get("enterprise", {}).get("evidence_quality", {}),
        },
        "digital_twin": intel.get("enterprise", {}).get("digital_twin", {}),
        "remediation": intel.get("enterprise", {}).get("remediation_plan", {}),
        "capabilities": intel.get("enterprise", {}).get("capability_matrix", {}),
        "architecture_advisor": intel.get("enterprise", {}).get("architecture_advisor", {}),
        "transaction_topology": intel.get("v7", {}).get("order_of_execution_graph", {}),
        "flow_quality": intel.get("v7", {}).get("flow_quality", {}),
        "apex_quality": intel.get("v7", {}).get("apex_quality", {}),
        "test_intelligence": intel.get("v7", {}).get("test_intelligence", {}),
        "data_health": intel.get("v7", {}).get("data_health", {}),
        "runtime_health": intel.get("v7", {}).get("runtime_health", {}),
        "integration_health": intel.get("v7", {}).get("integration_health", {}),
        "final_readiness": intel.get("v7", {}).get("final_readiness", {}),
    }


def write_knowledge_pack(snapshot: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    pack = build_knowledge_pack(snapshot)
    output_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "organization.json": pack["organization"],
        "architecture.json": pack["architecture"],
        "dependency-graph.json": pack["dependency_graph"],
        "field-lineage.json": pack["field_lineage"],
        "automation-map.json": pack["automation_map"],
        "integration-map.json": pack["integration_map"],
        "security-map.json": pack["security_map"],
        "findings.json": pack["findings"],
        "risk.json": pack["risk"],
        "evidence.json": pack["evidence"],
        "digital-twin.json": pack["digital_twin"],
        "remediation-plan.json": pack["remediation"],
        "capability-matrix.json": pack["capabilities"],
        "architecture-advisor.json": pack["architecture_advisor"],
        "transaction-topology.json": pack["transaction_topology"],
        "flow-quality.json": pack["flow_quality"],
        "apex-quality.json": pack["apex_quality"],
        "test-intelligence.json": pack["test_intelligence"],
        "data-health.json": pack["data_health"],
        "runtime-health.json": pack["runtime_health"],
        "integration-health.json": pack["integration_health"],
        "final-readiness.json": pack["final_readiness"],
    }
    for name, data in mapping.items():
        (output_dir / name).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    index = {
        "schema": "labforce-dementor-knowledge-pack/v3",
        "files": list(mapping),
        "source_assessment": snapshot.get("run", {}),
    }
    (output_dir / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return {"output_dir": str(output_dir), "files": ["index.json", *mapping.keys()], "count": len(mapping) + 1}


def build_v5_intelligence(source_root: Path) -> dict[str, Any]:
    return {"source_fingerprint": source_fingerprint(source_root)}
