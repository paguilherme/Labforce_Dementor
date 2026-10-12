from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable

import networkx as nx


SEVERITY_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 0}
EFFORT_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Unknown": 2}


def _finding_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if is_dataclass(item):
        return asdict(item)
    return {
        "id": getattr(item, "id", ""),
        "category": getattr(item, "category", ""),
        "severity": getattr(item, "severity", ""),
        "title": getattr(item, "title", ""),
        "description": getattr(item, "description", ""),
        "component": getattr(item, "component", ""),
        "recommendation": getattr(item, "recommendation", ""),
        "effort": getattr(item, "effort", "Unknown"),
        "confidence": getattr(item, "confidence", 1.0),
        "evidence": [asdict(x) if is_dataclass(x) else x for x in getattr(item, "evidence", [])],
    }


def normalize_edges(edges: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate graph evidence without discarding stronger evidence.

    Multiple analyzers can discover the same logical relationship.  The Digital Twin
    keeps one logical edge and stores all evidence locations so traversal/risk metrics
    are not artificially inflated by duplicate scanners.
    """
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in edges:
        src = str(edge.get("source") or "").strip()
        rel = str(edge.get("relationship") or "RELATED_TO").strip()
        dst = str(edge.get("target") or "").strip()
        if not src or not dst:
            continue
        key = (src, rel, dst)
        confidence = float(edge.get("confidence") or 0.0)
        evidence = str(edge.get("evidence") or "").strip()
        if key not in merged:
            merged[key] = {
                "source": src,
                "relationship": rel,
                "target": dst,
                "confidence": confidence,
                "evidence": [evidence] if evidence else [],
            }
        else:
            row = merged[key]
            row["confidence"] = max(float(row["confidence"]), confidence)
            if evidence and evidence not in row["evidence"]:
                row["evidence"].append(evidence)
    rows = list(merged.values())
    rows.sort(key=lambda x: (x["source"], x["relationship"], x["target"]))
    return rows


def _graph(edges: list[dict[str, Any]]) -> nx.DiGraph:
    g = nx.DiGraph()
    for e in edges:
        g.add_edge(e["source"], e["target"], relationship=e["relationship"], confidence=e["confidence"])
    return g


def _node_type(node: str) -> str:
    return node.split(":", 1)[0] if ":" in node else "Other"


def build_digital_twin(components: dict[str, Any], dependencies: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    edges = normalize_edges(dependencies)
    g = _graph(edges)
    findings_by_component: Counter[str] = Counter()
    finding_penalty: Counter[str] = Counter()
    for raw in findings:
        f = _finding_dict(raw)
        comp = str(f.get("component") or "")
        if comp:
            findings_by_component[comp] += 1
            finding_penalty[comp] += SEVERITY_WEIGHT.get(str(f.get("severity") or "").lower(), 0)

    type_counts = Counter(_node_type(n) for n in g.nodes)
    in_degree = dict(g.in_degree())
    out_degree = dict(g.out_degree())
    undirected = g.to_undirected()
    centrality = nx.degree_centrality(undirected) if g.number_of_nodes() > 1 else {n: 0.0 for n in g.nodes}

    hotspots = []
    for node in g.nodes:
        friendly = node.split(":", 1)[-1]
        fcount = findings_by_component.get(node, 0) + findings_by_component.get(friendly, 0)
        penalty = finding_penalty.get(node, 0) + finding_penalty.get(friendly, 0)
        degree = in_degree.get(node, 0) + out_degree.get(node, 0)
        score = min(100, round(degree * 4 + centrality.get(node, 0.0) * 30 + min(40, penalty * 0.2)))
        hotspots.append({
            "component": node,
            "node_type": _node_type(node),
            "in_degree": in_degree.get(node, 0),
            "out_degree": out_degree.get(node, 0),
            "degree": degree,
            "centrality": round(centrality.get(node, 0.0), 4),
            "related_findings": fcount,
            "structural_criticality_score": score,
        })
    hotspots.sort(key=lambda x: (x["structural_criticality_score"], x["degree"]), reverse=True)

    scc = [sorted(c) for c in nx.strongly_connected_components(g) if len(c) > 1]
    scc.sort(key=len, reverse=True)
    automation_prefixes = {"Flow", "Trigger", "ApexClass", "ValidationRule"}
    automation_cycles = [c for c in scc if sum(1 for n in c if _node_type(n) in automation_prefixes) >= 2]

    weak = list(nx.weakly_connected_components(g)) if g.number_of_nodes() else []
    isolated = list(nx.isolates(g)) if g.number_of_nodes() else []
    articulation = []
    if undirected.number_of_nodes() > 2:
        try:
            articulation = sorted(nx.articulation_points(undirected))
        except nx.NetworkXError:
            articulation = []

    return {
        "schema_version": "1.0",
        "nodes": g.number_of_nodes(),
        "edges": len(edges),
        "node_types": dict(sorted(type_counts.items())),
        "weakly_connected_components": len(weak),
        "isolated_nodes": isolated[:500],
        "strong_cycles": scc[:200],
        "automation_cycles": automation_cycles[:100],
        "articulation_points": articulation[:200],
        "hotspots": hotspots[:250],
        "normalized_edges": edges,
        "note": "A criticidade estrutural é uma aproximação determinística. A criticidade de negócio exige ajustes e evidências específicos da organização.",
    }


def component_explanation(snapshot: dict[str, Any], component: str, depth: int = 2) -> dict[str, Any]:
    edges = normalize_edges(snapshot.get("dependencies", []))
    candidates = {component}
    if ":" not in component:
        for e in edges:
            for node in (e["source"], e["target"]):
                if node.split(":", 1)[-1] == component or node.endswith("." + component):
                    candidates.add(node)
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in edges:
        outgoing[e["source"]].append(e)
        incoming[e["target"]].append(e)

    visited = set(candidates)
    q = deque((n, 0) for n in candidates)
    traversed: list[dict[str, Any]] = []
    while q:
        node, d = q.popleft()
        if d >= max(1, depth):
            continue
        for edge in outgoing.get(node, []) + incoming.get(node, []):
            traversed.append(edge)
            other = edge["target"] if edge["source"] == node else edge["source"]
            if other not in visited:
                visited.add(other)
                q.append((other, d + 1))

    findings = []
    for raw in snapshot.get("findings", []):
        f = _finding_dict(raw)
        fc = str(f.get("component") or "")
        if fc in visited or any(v.endswith(":" + fc) for v in visited if fc):
            findings.append(f)

    deps_by_rel = Counter(e["relationship"] for e in traversed)
    return {
        "requested_component": component,
        "resolved_nodes": sorted(candidates),
        "depth": max(1, depth),
        "neighborhood_size": len(visited),
        "relationship_counts": dict(deps_by_rel.most_common()),
        "neighbors": sorted(visited - candidates),
        "supporting_edges": traversed[:1000],
        "findings": findings[:200],
        "summary": {
            "risk": "HIGH" if any(str(f.get("severity", "")).lower() in {"critical", "high"} for f in findings) else "MEDIUM" if findings else "LOW",
            "has_write_lineage": any(e["relationship"] in {"WRITES_FIELD", "AST_DML_OBJECT", "FLOW_WRITES_OBJECT"} for e in traversed),
            "has_integration_lineage": any("CALLOUT" in e["relationship"] or "NAMED_CREDENTIAL" in e["relationship"] for e in traversed),
        },
    }


def build_evidence_quality(findings: list[Any], health: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    rows = [_finding_dict(x) for x in findings]
    with_evidence = 0
    high_conf = 0
    confidence_values = []
    missing = []
    for f in rows:
        evidence = f.get("evidence") or []
        confidence = float(f.get("confidence") or 0.0)
        confidence_values.append(confidence)
        if evidence:
            with_evidence += 1
        else:
            missing.append(f.get("id"))
        if confidence >= 0.9:
            high_conf += 1
    total = len(rows)
    return {
        "findings_total": total,
        "findings_with_evidence": with_evidence,
        "evidence_coverage_percent": round(with_evidence / total * 100, 1) if total else 100.0,
        "high_confidence_findings_percent": round(high_conf / total * 100, 1) if total else 100.0,
        "average_finding_confidence": round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 1.0,
        "findings_missing_evidence": [x for x in missing if x][:100],
        "health_evidence_coverage_percent": health.get("overall_coverage_percent"),
        "read_errors": len(audit.get("read_errors", [])),
        "assessment_mode": audit.get("mode"),
    }


def build_capability_matrix(components: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    intel = components.get("intelligence", {})
    v3 = intel.get("v3", {})
    v4 = intel.get("v4", {})
    v5 = intel.get("v5", {})
    v7 = intel.get("v7", {})

    def status(ready: bool, partial: bool = False, reason: str = "") -> dict[str, Any]:
        state = "READY" if ready else ("PARTIAL" if partial else "UNAVAILABLE")
        return {"status": state, "reason": reason}

    matrix = {
        "metadata_inventory": status(bool(components.get("objects") or components.get("apex_classes") or components.get("flows"))),
        "dependency_graph": status(bool(intel.get("blast_radius"))),
        "field_lineage": status(bool(intel.get("field_lineage", {}).get("field_count_with_lineage"))),
        "order_of_execution": status(bool(intel.get("order_of_execution", {}).get("objects"))),
        "apex_runtime_coverage": status(bool(intel.get("apex_coverage", {}).get("available")), bool(components.get("apex_classes")), "Tooling API evidence may be permission-dependent."),
        "effective_access": status(bool(intel.get("effective_permissions", {}).get("available")), bool(v4.get("effective_access", {}).get("users_analyzed")), "Exact record-level sharing remains context-dependent."),
        "data_quality_profiling": status(bool(v3.get("data_quality_profile", {}).get("available")), bool(v3.get("data_quality_profile", {}).get("enabled")), "Opt-in profiling; raw business values are not persisted."),
        "event_monitoring": status(bool(v3.get("event_monitoring", {}).get("available")), bool(intel.get("runtime_usage", {}).get("event_monitoring_available")), "Requires Salesforce Event Monitoring/license/permissions for full telemetry."),
        "ui_lineage": status(bool(v4.get("ui_lineage", {}).get("files_scanned"))),
        "source_fingerprint": status(bool(v5.get("source_fingerprint", {}).get("files"))),
        "snapshot_diff": status(True),
        "deployment_impact": status(True),
        "sarif": status(True),
        "policy_gate": status(True),
        "transaction_topology": status(bool(v7.get("order_of_execution_graph", {}).get("objects")), bool(components.get("flows") or components.get("apex_triggers"))),
        "flow_deep_analysis": status("flow_quality" in v7),
        "apex_call_graph": status("apex_quality" in v7),
        "test_intelligence": status("test_intelligence" in v7),
        "data_health": status("data_health" in v7, bool(v3.get("data_quality_profile", {}).get("enabled")), "Full sample-based data health requires opt-in profiling."),
        "runtime_health": status("runtime_health" in v7, True, "Telemetry depth depends on Event Monitoring and Tooling/API permissions."),
        "integration_health": status("integration_health" in v7),
        "change_simulation": status(True, False, "Offline simulation; no Salesforce mutation capability exists."),
        "continuous_intelligence": status(True),
        "read_only_safety": status(audit.get("dml_executed", 0) == 0 and audit.get("metadata_deployments", 0) == 0 and audit.get("apex_anonymous_executions", 0) == 0),
    }
    counts = Counter(v["status"] for v in matrix.values())
    return {
        "capabilities": matrix,
        "summary": dict(counts),
        "readiness_percent": round((counts.get("READY", 0) + counts.get("PARTIAL", 0) * 0.5) / len(matrix) * 100, 1),
    }


def build_remediation_plan(findings: list[Any], digital_twin: dict[str, Any]) -> dict[str, Any]:
    hotspot_score = {x["component"]: x["structural_criticality_score"] for x in digital_twin.get("hotspots", [])}
    rows = []
    for raw in findings:
        f = _finding_dict(raw)
        severity = str(f.get("severity") or "info").lower()
        confidence = float(f.get("confidence") or 0.0)
        comp = str(f.get("component") or "")
        hs = hotspot_score.get(comp, 0)
        if not hs and comp:
            hs = max((score for node, score in hotspot_score.items() if node.endswith(":" + comp)), default=0)
        score = round(SEVERITY_WEIGHT.get(severity, 0) * max(0.4, confidence) * 0.7 + hs * 0.3)
        priority = "P0" if severity == "critical" and confidence >= 0.8 else "P1" if score >= 65 else "P2" if score >= 35 else "P3"
        rows.append({
            "finding_id": f.get("id"),
            "priority": priority,
            "severity": severity,
            "confidence": confidence,
            "component": comp,
            "title": f.get("title"),
            "recommendation": f.get("recommendation"),
            "effort": f.get("effort") or "Unknown",
            "structural_criticality_score": hs,
            "remediation_priority_score": min(100, score),
            "requires_human_validation": confidence < 0.95 or severity in {"critical", "high"},
            "automatic_mutation_allowed": False,
        })
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    rows.sort(key=lambda x: (order[x["priority"]], -x["remediation_priority_score"], EFFORT_WEIGHT.get(x["effort"], 2)))
    return {
        "items": rows,
        "by_priority": dict(Counter(x["priority"] for x in rows)),
        "guardrail": "O Dementor recomenda e prioriza remediações, mas nunca altera a organização Salesforce.",
    }


def build_architecture_advisor(components: dict[str, Any], digital_twin: dict[str, Any], remediation: dict[str, Any]) -> dict[str, Any]:
    recommendations = []
    cycles = digital_twin.get("automation_cycles", [])
    if cycles:
        recommendations.append({
            "theme": "automation",
            "priority": "P1",
            "title": "Revisar ciclos de dependência entre automações",
            "rationale": f"Foram encontrados {len(cycles)} ciclo(s) de automação fortemente conectado(s) no Gêmeo Digital.",
            "actions": ["Confirmar a ordem da transação e as proteções contra recursão", "Consolidar automações sobrepostas quando justificável", "Adicionar testes de regressão nos limites do ciclo"],
        })
    top = digital_twin.get("hotspots", [])[:10]
    if top:
        recommendations.append({
            "theme": "architecture",
            "priority": "P1",
            "title": "Proteger pontos críticos estruturais com critérios de impacto",
            "rationale": "Componentes com alta conectividade possuem raio de impacto desproporcional.",
            "actions": ["Exigir análise de impacto antes da mudança", "Selecionar testes de regressão a partir das dependências próximas", "Acompanhar a pontuação do ponto crítico ao longo do tempo"],
            "components": [x["component"] for x in top],
        })
    if any(x.get("priority") == "P0" for x in remediation.get("items", [])):
        recommendations.append({
            "theme": "risk",
            "priority": "P0",
            "title": "Resolver primeiro os achados críticos sustentados por evidências",
            "rationale": "Pelo menos um achado crítico com evidências suficientes exige revisão imediata.",
            "actions": ["Definir um responsável", "Validar o achado no ambiente-alvo", "Preparar remediação considerando reversão", "Executar novamente o assessment após a remediação"],
        })
    if not components.get("intelligence", {}).get("v3", {}).get("data_quality_profile", {}).get("enabled"):
        recommendations.append({
            "theme": "data_quality",
            "priority": "P2",
            "title": "Executar perfil de dados opcional para uma linha de base completa",
            "rationale": "Somente os metadados não determinam o preenchimento, a cardinalidade nem a concentração real dos campos.",
            "actions": ["Ativar --profile-data em uma janela de assessment aprovada", "Manter limites conservadores para a amostra", "Não persistir valores brutos de negócio"],
        })
    return {"recommendations": recommendations, "generated_by": "deterministic-advisor", "llm_required": False}


def build_competitive_readiness(capability_matrix: dict[str, Any]) -> dict[str, Any]:
    caps = capability_matrix.get("capabilities", {})
    domains = {
        "metadata_and_documentation": ["metadata_inventory", "ui_lineage", "source_fingerprint"],
        "dependency_and_change_intelligence": ["dependency_graph", "field_lineage", "snapshot_diff", "deployment_impact"],
        "security_and_access": ["effective_access", "read_only_safety"],
        "runtime_and_observability": ["event_monitoring", "apex_runtime_coverage"],
        "data_intelligence": ["data_quality_profiling"],
        "devops_governance": ["sarif", "policy_gate"],
    }
    rows = []
    for name, keys in domains.items():
        points = 0.0
        for key in keys:
            state = caps.get(key, {}).get("status")
            points += 1.0 if state == "READY" else 0.5 if state == "PARTIAL" else 0.0
        score = round(points / len(keys) * 100, 1) if keys else 0.0
        rows.append({"domain": name, "readiness_percent": score, "capabilities": keys})
    return {
        "domains": rows,
        "overall_readiness_percent": round(sum(x["readiness_percent"] for x in rows) / len(rows), 1) if rows else 0.0,
        "interpretation": "Prontidão interna das capacidades; não é uma afirmação de desempenho de fornecedores. A paridade competitiva deve ser validada conforme edições e licenças atuais.",
    }


def stable_snapshot_digest(snapshot: dict[str, Any]) -> str:
    body = {
        "inventory": snapshot.get("inventory", {}),
        "dependencies": normalize_edges(snapshot.get("dependencies", [])),
        "findings": sorted((_finding_dict(x) for x in snapshot.get("findings", [])), key=lambda x: str(x.get("id"))),
        "health": snapshot.get("health", {}),
    }
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_enterprise_intelligence(components: dict[str, Any], dependencies: list[dict[str, Any]], findings: list[Any], health: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    twin = build_digital_twin(components, dependencies, findings)
    remediation = build_remediation_plan(findings, twin)
    capability = build_capability_matrix(components, audit)
    return {
        "digital_twin": twin,
        "evidence_quality": build_evidence_quality(findings, health, audit),
        "capability_matrix": capability,
        "remediation_plan": remediation,
        "architecture_advisor": build_architecture_advisor(components, twin, remediation),
        "competitive_readiness": build_competitive_readiness(capability),
    }
