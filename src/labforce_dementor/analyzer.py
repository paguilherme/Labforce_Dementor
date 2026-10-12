from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import networkx as nx

from .models import Evidence, Finding


SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
DANGEROUS_USER_PERMS = {
    "ModifyAllData": "Modify All Data",
    "ViewAllData": "View All Data",
    "AuthorApex": "Author Apex",
    "ManageUsers": "Manage Users",
    "CustomizeApplication": "Customize Application",
    "ManageProfilesPermissionsets": "Manage Profiles and Permission Sets",
}


def _finding(fid: str, category: str, severity: str, title: str, description: str, *,
             component: str = "", recommendation: str = "", effort: str = "Unknown",
             confidence: float = 1.0, evidence: list[Evidence] | None = None) -> Finding:
    return Finding(
        id=fid, category=category, severity=severity, title=title, description=description,
        component=component, recommendation=recommendation, effort=effort,
        confidence=confidence, evidence=evidence or [],
    )


def enrich_fields(components: dict[str, Any]) -> None:
    layouts_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for layout in components.get("layouts", []):
        layouts_by_object[layout.get("object", "")].append(layout)

    editable_fields: set[str] = set()
    readable_fields: set[str] = set()
    for bundle in (components.get("permission_sets", []), components.get("profiles", [])):
        for perm in bundle:
            for fp in perm.get("field_permissions", []):
                if fp.get("readable"):
                    readable_fields.add(fp.get("field", ""))
                if fp.get("editable"):
                    editable_fields.add(fp.get("field", ""))

    source_files: list[tuple[str, str, str]] = []
    for kind in ("apex_classes", "apex_triggers"):
        for item in components.get(kind, []):
            source_files.append((kind, item.get("api_name", ""), item.get("text", "")))
    for flow in components.get("flows", []):
        try:
            text = Path(flow["source_file"]).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        source_files.append(("flows", flow.get("api_name", ""), text))

    for obj in components.get("objects", []):
        obj_name = obj.get("api_name", "")
        obj_layouts = layouts_by_object.get(obj_name, [])
        for fld in obj.get("fields", []):
            fname = fld.get("api_name", "")
            full = fld.get("full_name", "")
            fld["layouts"] = [l["api_name"] for l in obj_layouts if fname in l.get("fields", [])]
            fld["readable_by_metadata"] = full in readable_fields
            fld["editable_by_metadata"] = full in editable_fields
            fld["references"] = []
            for kind, name, text in source_files:
                if not text:
                    continue
                qualified = full in text
                unqualified = bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(fname)}(?![A-Za-z0-9_])", text))
                if qualified or unqualified:
                    confidence = 1.0 if qualified else 0.72
                    fld["references"].append({"kind": kind, "component": name, "confidence": confidence})
            auto_type = fld.get("type") in {"Formula", "Summary", "AutoNumber"} or bool(fld.get("formula"))
            fld["manual_candidate"] = bool(fld["layouts"]) and not auto_type
            fld["manual_confidence"] = 0.9 if fld["manual_candidate"] and fld["editable_by_metadata"] else (0.65 if fld["manual_candidate"] else 0.1)
            fld["automation_candidate"] = bool(fld["references"])


def build_dependency_graph(components: dict[str, Any]) -> tuple[nx.DiGraph, list[dict[str, Any]]]:
    graph = nx.DiGraph()
    edges: list[dict[str, Any]] = []

    def add(src: str, rel: str, dst: str, confidence: float, evidence: str) -> None:
        if not src or not dst:
            return
        graph.add_edge(src, dst, relationship=rel, confidence=confidence, evidence=evidence)
        edges.append({"source": src, "relationship": rel, "target": dst, "confidence": confidence, "evidence": evidence})

    for app in components.get("applications", []):
        for tab in app.get("tabs", []):
            object_name = tab.replace("standard-", "")
            add(f"App:{app['api_name']}", "CONTAINS", f"Object:{object_name}", 0.85, app.get("source_file", ""))

    for obj in components.get("objects", []):
        for fld in obj.get("fields", []):
            add(f"Object:{obj['api_name']}", "HAS_FIELD", f"Field:{fld['full_name']}", 1.0, fld.get("source_file", ""))
            for target in fld.get("reference_to", []):
                add(f"Field:{fld['full_name']}", "REFERENCES", f"Object:{target}", 1.0, fld.get("source_file", ""))
            for ref in fld.get("references", []):
                prefix = "Flow" if ref["kind"] == "flows" else ("Trigger" if ref["kind"] == "apex_triggers" else "ApexClass")
                add(f"{prefix}:{ref['component']}", "USES_FIELD", f"Field:{fld['full_name']}", ref["confidence"], fld.get("source_file", ""))
        for vr in obj.get("validation_rules", []):
            add(f"ValidationRule:{obj['api_name']}.{vr['api_name']}", "VALIDATES", f"Object:{obj['api_name']}", 1.0, vr.get("source_file", ""))

    for layout in components.get("layouts", []):
        for fname in layout.get("fields", []):
            full = f"{layout.get('object')}.{fname}" if layout.get("object") else fname
            add(f"Layout:{layout['api_name']}", "DISPLAYS", f"Field:{full}", 1.0, layout.get("source_file", ""))

    for wf in components.get("workflows", []):
        obj = wf.get("object", "")
        for rule in wf.get("rules", []):
            if rule.get("active"):
                add(f"WorkflowRule:{obj}.{rule.get('api_name','')}", "AUTOMATES", f"Object:{obj}", 1.0, wf.get("source_file", ""))

    for ap in components.get("approval_processes", []):
        obj = ap.get("object", "")
        add(f"ApprovalProcess:{ap.get('api_name','')}", "GOVERNS", f"Object:{obj}", 1.0, ap.get("source_file", ""))

    for group in components.get("permission_set_groups", []):
        for ps in group.get("permission_sets", []):
            add(f"PermissionSetGroup:{group.get('api_name','')}", "INCLUDES", f"PermissionSet:{ps}", 1.0, group.get("source_file", ""))

    class_names = [c.get("api_name", "") for c in components.get("apex_classes", [])]
    all_apex = components.get("apex_classes", []) + components.get("apex_triggers", [])
    for item in all_apex:
        src_prefix = "Trigger" if item in components.get("apex_triggers", []) else "ApexClass"
        text = item.get("text", "")
        for cname in class_names:
            if cname and cname != item.get("api_name") and re.search(rf"\b{re.escape(cname)}\b", text):
                add(f"{src_prefix}:{item['api_name']}", "CALLS", f"ApexClass:{cname}", 0.95, item.get("source_file", ""))

    return graph, edges


def analyze_security(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    for kind in ("profiles", "permission_sets"):
        for perm in components.get(kind, []):
            for up in perm.get("user_permissions", []):
                if up.get("enabled") and up.get("name") in DANGEROUS_USER_PERMS:
                    name = DANGEROUS_USER_PERMS[up["name"]]
                    severity = "critical" if up["name"] == "ModifyAllData" else "high"
                    findings.append(_finding(
                        f"SEC-{seq:04d}", "security", severity,
                        f"Permissão privilegiada: {name}",
                        f"'{perm['api_name']}' concede a permissão {name}.",
                        component=perm["api_name"],
                        recommendation="Confirme a necessidade de negócio e aplique o menor privilégio com conjuntos de permissões de escopo restrito.",
                        effort="Medium",
                        evidence=[Evidence("METADATA", perm.get("source_file", ""), up["name"], 1.0)],
                    ))
                    seq += 1
            for op in perm.get("object_permissions", []):
                if op.get("modify_all"):
                    findings.append(_finding(
                        f"SEC-{seq:04d}", "security", "high",
                        f"Modificar tudo em {op.get('object')}",
                        f"'{perm['api_name']}' concede Modify All Records em {op.get('object')}.",
                        component=perm["api_name"], recommendation="Revise o acesso administrativo no objeto e reduza o escopo sempre que possível.",
                        effort="Low", evidence=[Evidence("METADATA", perm.get("source_file", ""), op.get("object", ""), 1.0)]
                    ))
                    seq += 1

    for cls in components.get("apex_classes", []):
        text = cls.get("text", "")
        externally_reachable = cls.get("is_rest") or cls.get("is_aura_enabled") or cls.get("is_invocable")
        explicit_sharing = bool(re.search(r"\b(with|inherited)\s+sharing\b", text, re.I))
        if externally_reachable and not explicit_sharing:
            findings.append(_finding(
                f"SEC-{seq:04d}", "security", "high", "Apex acessível externamente sem compartilhamento explícito",
                f"{cls['api_name']} expõe um ponto de entrada REST/Aura/Invocable sem declaração explícita 'with sharing' ou 'inherited sharing'.",
                component=cls["api_name"], recommendation="Revise o contexto de execução, o modelo de compartilhamento e a aplicação de CRUD/FLS; declare explicitamente o comportamento de compartilhamento pretendido.",
                effort="Medium", confidence=0.85,
                evidence=[Evidence("STATIC_ANALYSIS", cls.get("source_file", ""), "Entry point without explicit sharing", 0.85)]
            ))
            seq += 1


def analyze_apex(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    loop_pattern = re.compile(r"\b(for|while)\s*\([^)]*\)\s*\{(?P<body>.{0,5000}?)\}", re.I | re.S)
    for cls in components.get("apex_classes", []) + components.get("apex_triggers", []):
        text = cls.get("text", "")
        for loop in loop_pattern.finditer(text):
            body = loop.group("body")
            if re.search(r"\[[\s\S]*?SELECT\b|Database\.query\s*\(", body, re.I):
                findings.append(_finding(
                    f"APEX-{seq:04d}", "apex", "high", "Possível execução de SOQL dentro de loop",
                    f"Foi detectada uma operação SOQL dentro de um loop em {cls['api_name']}.",
                    component=cls["api_name"], recommendation="Bulkifique a consulta: reúna as chaves, consulte uma única vez e mapeie os resultados fora do loop.",
                    effort="Medium", confidence=0.82, evidence=[Evidence("REGEX", cls.get("source_file", ""), "SOQL inside loop", 0.82)]
                )); seq += 1
            if re.search(r"\b(insert|update|delete|upsert)\b\s+[A-Za-z_]", body, re.I):
                findings.append(_finding(
                    f"APEX-{seq:04d}", "performance", "high", "Possível execução de DML dentro de loop",
                    f"Foi detectada uma operação DML dentro de um loop em {cls['api_name']}.",
                    component=cls["api_name"], recommendation="Reúna os registros e execute o DML em massa fora do loop.",
                    effort="Medium", confidence=0.82, evidence=[Evidence("REGEX", cls.get("source_file", ""), "DML inside loop", 0.82)]
                )); seq += 1
        if re.search(r"setEndpoint\s*\(\s*['\"]https?://", text, re.I):
            findings.append(_finding(
                f"APEX-{seq:04d}", "integrations", "high", "Endpoint de integração fixo no código",
                f"{cls['api_name']} parece conter um endpoint HTTP diretamente no código Apex.",
                component=cls["api_name"], recommendation="Mova os endpoints e a autenticação para Named Credentials / External Credentials.",
                effort="Medium", confidence=0.95, evidence=[Evidence("REGEX", cls.get("source_file", ""), "setEndpoint(http...)", 0.95)]
            )); seq += 1
        if re.search(r"['\"][A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?['\"]", text):
            findings.append(_finding(
                f"APEX-{seq:04d}", "governance", "medium", "Possível ID Salesforce fixo no código",
                f"{cls['api_name']} contém uma string compatível com o formato de ID Salesforce de 15/18 caracteres.",
                component=cls["api_name"], recommendation="Substitua IDs fixos por metadados, configurações, consultas ou referências semânticas.",
                effort="Low", confidence=0.72, evidence=[Evidence("REGEX", cls.get("source_file", ""), "15/18 character ID-like literal", 0.72)]
            )); seq += 1


def analyze_flows(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    active_by_object: Counter[str] = Counter()
    for flow in components.get("flows", []):
        status = (flow.get("status") or "").lower()
        if status == "active" and flow.get("object"):
            active_by_object[flow["object"]] += 1
        counts = flow.get("counts", {})
        dml = counts.get("recordCreates", 0) + counts.get("recordUpdates", 0) + counts.get("recordDeletes", 0)
        if counts.get("loops", 0) and dml:
            findings.append(_finding(
                f"FLOW-{seq:04d}", "automation", "medium", "Flow contém loops e elementos DML",
                f"{flow['api_name']} contém {counts.get('loops', 0)} loop(s) e {dml} elemento(s) DML. É um possível ponto crítico e requer verificação dos caminhos.",
                component=flow["api_name"], recommendation="Revise os caminhos de execução e garanta que o DML não execute a cada iteração; confirme com o Salesforce Flow Scanner.",
                effort="Medium", confidence=0.65, evidence=[Evidence("FLOW_XML", flow.get("source_file", ""), str(counts), 0.65)]
            )); seq += 1
        if status and status != "active":
            findings.append(_finding(
                f"FLOW-{seq:04d}", "governance", "low", "Flow inativo mantido",
                f"{flow['api_name']} está com o status '{flow.get('status')}'.",
                component=flow["api_name"], recommendation="Confirme se a versão inativa deve ser mantida ou se pode ser arquivada/removida após revisar as dependências.",
                effort="Low", confidence=1.0, evidence=[Evidence("FLOW_XML", flow.get("source_file", ""), f"status={flow.get('status')}", 1.0)]
            )); seq += 1

    for obj, count in active_by_object.items():
        if count >= 8:
            findings.append(_finding(
                f"FLOW-{seq:04d}", "architecture", "high", "Ponto crítico de automação",
                f"O objeto {obj} possui {count} Flows ativos, aumentando a complexidade da ordem de execução e o risco de regressão.",
                component=obj, recommendation="Crie um mapa de automações do objeto e avalie limites de consolidação e orquestração.",
                effort="High", confidence=0.95, evidence=[Evidence("FLOW_INVENTORY", obj, f"active_flows={count}", 0.95)]
            )); seq += 1


def analyze_governance(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    missing_field_desc = []
    for obj in components.get("objects", []):
        if obj.get("api_name", "").endswith("__c") and not obj.get("description"):
            findings.append(_finding(
                f"GOV-{seq:04d}", "governance", "low", "Objeto customizado sem descrição",
                f"{obj['api_name']} não possui descrição nos metadados.", component=obj["api_name"],
                recommendation="Documente a finalidade de negócio, responsabilidade, classificação dos dados e ciclo de vida.", effort="Low",
                evidence=[Evidence("METADATA", obj.get("api_name", ""), "description empty", 1.0)]
            )); seq += 1
        for fld in obj.get("fields", []):
            if fld.get("api_name", "").endswith("__c") and not fld.get("description"):
                missing_field_desc.append(fld["full_name"])
    if missing_field_desc:
        findings.append(_finding(
            f"GOV-{seq:04d}", "governance", "medium", "Campos customizados sem descrição",
            f"{len(missing_field_desc)} campos customizados não possuem descrição nos metadados.",
            component="Vários campos", recommendation="Adicione descrições concisas de negócio e técnicas, incluindo o responsável pela integração quando aplicável.",
            effort="Medium", evidence=[Evidence("METADATA_SUMMARY", "CustomField", ", ".join(missing_field_desc[:20]), 1.0)]
        ))


def analyze_extended_governance(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    active_workflows = []
    for wf in components.get("workflows", []):
        for rule in wf.get("rules", []):
            if rule.get("active"):
                active_workflows.append(f"{wf.get('object')}.{rule.get('api_name')}")
    if active_workflows:
        findings.append(_finding(
            f"GOVX-{seq:04d}", "governance", "medium", "Regras de Workflow legadas ativas detectadas",
            f"Ainda existem {len(active_workflows)} regra(s) de Workflow ativa(s) nos metadados recuperados.",
            component="Workflow Rules",
            recommendation="Planeje uma migração controlada para Flow, preservando a ordem de execução e a cobertura de regressão.",
            effort="High", confidence=1.0,
            evidence=[Evidence("METADATA", "Workflow", ", ".join(active_workflows[:50]), 1.0)],
        )); seq += 1
    dense_approvals = []
    counts = Counter(ap.get("object") for ap in components.get("approval_processes", []) if ap.get("active") and ap.get("object"))
    for obj, count in counts.items():
        if count >= 8:
            dense_approvals.append((obj, count))
    if dense_approvals:
        findings.append(_finding(
            f"GOVX-{seq:04d}", "architecture", "medium", "Alta concentração de processos de aprovação",
            "Um ou mais objetos possuem muitos processos de aprovação ativos, aumentando a complexidade de mudanças e regressões.",
            component="Processos de aprovação", recommendation="Revise sobreposições, critérios de entrada, responsáveis e ciclo de vida dos processos de aprovação.",
            effort="Medium", confidence=0.9,
            evidence=[Evidence("METADATA", "ApprovalProcess", ", ".join(f"{o}={c}" for o,c in dense_approvals), 0.9)],
        ))


def analyze_unused(components: dict[str, Any], findings: list[Finding]) -> None:
    seq = 1
    classes = components.get("apex_classes", [])
    triggers = components.get("apex_triggers", [])
    searchable = [(x["api_name"], x.get("text", "")) for x in classes + triggers]
    for cls in classes:
        if cls.get("is_test"):
            continue
        entrypoint = any(cls.get(k) for k in ("is_rest", "is_aura_enabled", "is_invocable", "is_batch", "is_queueable", "is_schedulable"))
        refs = 0
        for name, text in searchable:
            if name == cls["api_name"]:
                continue
            refs += len(re.findall(rf"\b{re.escape(cls['api_name'])}\b", text))
        flow_refs = sum(1 for f in components.get("flows", []) if cls["api_name"] in Path(f["source_file"]).read_text(encoding="utf-8", errors="ignore"))
        if refs == 0 and flow_refs == 0 and not entrypoint:
            findings.append(_finding(
                f"UNUSED-{seq:04d}", "maintainability", "medium", "Classe Apex candidata a código não utilizado",
                f"Nenhuma referência estática Apex/Trigger/Flow ou padrão conhecido de ponto de entrada foi detectado para {cls['api_name']}.",
                component=cls["api_name"], recommendation="Revise execução e configuração antes de remover; verifique referências dinâmicas, pacotes, agendadores e consumidores externos.",
                effort="Low", confidence=0.90,
                evidence=[Evidence("REFERENCE_GRAPH", cls.get("source_file", ""), "0 static references; no known entrypoint", 0.90)]
            )); seq += 1


def analyze_testing(components: dict[str, Any], findings: list[Finding]) -> None:
    classes = components.get("apex_classes", [])
    prod = [c for c in classes if not c.get("is_test")]
    tests = [c for c in classes if c.get("is_test")]
    if prod and not tests:
        findings.append(_finding(
            "TEST-0001", "testing", "critical", "Nenhuma classe de teste Apex recuperada",
            f"Foram recuperadas {len(prod)} classes Apex de produção, mas nenhuma classe de teste foi detectada.",
            recommendation="Verifique se a recuperação foi completa e estabeleça cobertura de testes para o Apex de produção.", effort="High",
            evidence=[Evidence("SOURCE_INVENTORY", "ApexClass", f"production={len(prod)}, tests=0", 0.95)], confidence=0.95
        ))
    elif prod:
        ratio = len(tests) / max(len(prod), 1)
        if ratio < 0.15:
            findings.append(_finding(
                "TEST-0002", "testing", "medium", "Baixa proporção entre classes de teste e de produção",
                f"Foram detectadas {len(tests)} classes de teste para {len(prod)} classes de produção. Isso não representa a cobertura de código, mas indica necessidade de revisão.",
                recommendation="Colete ApexCodeCoverageAggregate e associe testes significativos às classes críticas antes de decidir a remediação.", effort="Medium",
                evidence=[Evidence("SOURCE_INVENTORY", "ApexClass", f"ratio={ratio:.2f}", 0.7)], confidence=0.7
            ))


def import_code_analyzer(path: Path, findings: list[Finding]) -> dict[str, Any]:
    if not path.exists():
        return {"available": False, "violations": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"available": False, "violations": 0, "error": str(exc)}

    candidates: list[dict[str, Any]] = []
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            keys = {str(k).lower() for k in node}
            if ("rule" in keys or "rulename" in keys) and ("severity" in keys or "message" in keys):
                candidates.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(data)

    for i, item in enumerate(candidates, 1):
        sev_raw = item.get("severity", item.get("Severity", 3))
        try:
            severity = SEVERITY_MAP.get(int(sev_raw), "medium")
        except Exception:
            severity = str(sev_raw).lower() if str(sev_raw).lower() in {"critical", "high", "medium", "low", "info"} else "medium"
        rule = item.get("rule") or item.get("ruleName") or item.get("Rule") or "Code Analyzer violation"
        msg = item.get("message") or item.get("Message") or str(item)[:500]
        engine = item.get("engine") or item.get("Engine") or "code-analyzer"
        findings.append(_finding(
            f"SFCA-{i:04d}", "apex", severity, str(rule), str(msg),
            component=str(item.get("file") or item.get("path") or ""),
            recommendation="Revise a orientação da regra do Salesforce Code Analyzer e faça a remediação após confirmar o contexto.",
            effort="Unknown", confidence=1.0,
            evidence=[Evidence("SALESFORCE_CODE_ANALYZER", str(engine), str(item)[:1000], 1.0)]
        ))
    return {"available": True, "violations": len(candidates), "raw": data}


def calculate_health(findings: list[Finding], config: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    weights = config["scoring"]["weights"]
    penalties = config["scoring"]["severity_penalty"]
    runtime = components.get("runtime", {})
    intel = components.get("intelligence", {})
    integration_inventory = sum(len(components.get(k, [])) for k in ("named_credentials", "external_credentials", "connected_apps", "remote_sites"))
    integration_inventory += sum(1 for c in components.get("apex_classes", []) if c.get("uses_callout"))

    # Coverage represents how much evidence Dementor actually collected for each score.
    coverage = {
        "security": 1.0 if (components.get("permission_sets") or components.get("profiles")) else 0.0,
        "architecture": 1.0 if components.get("objects") else 0.0,
        "performance": 0.8 if (components.get("apex_classes") or components.get("flows")) else 0.0,
        "automation": 1.0 if (components.get("flows") or components.get("apex_triggers")) else 0.0,
        "apex": 1.0 if (components.get("apex_classes") or components.get("apex_triggers")) else 0.0,
        "testing": 1.0 if intel.get("apex_coverage", {}).get("available") else (0.65 if components.get("apex_classes") else 0.0),
        "integrations": 0.75 if integration_inventory else 0.0,
        "data_quality": 0.9 if intel.get("v3", {}).get("data_quality_profile", {}).get("available") else 0.0,
        "governance": 0.9 if components.get("objects") else 0.0,
        "maintainability": 0.9 if (components.get("apex_classes") or components.get("flows")) else 0.0,
        "observability": 1.0 if intel.get("v3", {}).get("event_monitoring", {}).get("available") else (0.75 if intel.get("runtime_usage", {}).get("event_monitoring_available") else (0.35 if isinstance(runtime.get("api_total_usage_logs"), dict) and not runtime.get("api_total_usage_logs", {}).get("unavailable") else 0.0)),
    }
    raw_scores = {k: 100.0 for k in weights}
    aliases = {k: k for k in raw_scores}
    for f in findings:
        cat = aliases.get(f.category)
        if cat in raw_scores:
            raw_scores[cat] = max(0.0, raw_scores[cat] - penalties.get(f.severity, 0) * max(0.35, f.confidence))

    categories: dict[str, float | None] = {}
    for k, score in raw_scores.items():
        # Require at least 50% evidence coverage before publishing a health score.
        categories[k] = round(score, 1) if coverage.get(k, 0.0) >= 0.5 else None

    effective_weight = sum(float(weights[k]) for k, v in categories.items() if v is not None)
    if effective_weight:
        overall = sum(float(categories[k]) * float(weights[k]) for k in weights if categories[k] is not None) / effective_weight
    else:
        overall = 0.0
    weighted_coverage = sum(float(weights[k]) * coverage.get(k, 0.0) for k in weights) / sum(float(v) for v in weights.values())
    sev_counts = Counter(f.severity for f in findings)
    return {
        "overall": round(overall, 1),
        "overall_coverage_percent": round(weighted_coverage * 100, 1),
        "categories": categories,
        "coverage": {k: round(v * 100, 1) for k, v in coverage.items()},
        "findings_by_severity": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "note": "As pontuações são exibidas somente quando a cobertura de evidências da categoria é de pelo menos 50%; caso contrário, o valor é N/D.",
    }


def analyze(components: dict[str, Any], config: dict[str, Any], code_analyzer_path: Path | None = None) -> tuple[list[Finding], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    enrich_fields(components)
    _, dependencies = build_dependency_graph(components)
    findings: list[Finding] = []
    analyze_security(components, findings)
    analyze_apex(components, findings)
    analyze_flows(components, findings)
    analyze_governance(components, findings)
    analyze_extended_governance(components, findings)
    analyze_unused(components, findings)
    analyze_testing(components, findings)
    ca = import_code_analyzer(code_analyzer_path, findings) if code_analyzer_path else {"available": False, "violations": 0}
    health = calculate_health(findings, config, components)
    return findings, health, dependencies, ca


def analyze_v2_intelligence(components: dict[str, Any], findings: list[Finding]) -> None:
    """Findings that require v0.2 cross-source intelligence."""
    intel = components.get("intelligence", {})
    seq = 1
    perms = intel.get("effective_permissions", {})
    for user in perms.get("privileged_users", [])[:200]:
        critical = user.get("critical_user_permissions", [])
        modify = user.get("objects_modify_all", [])
        if "ModifyAllData" in critical:
            findings.append(_finding(
                f"V2SEC-{seq:04d}", "security", "critical", "Usuário ativo recebe efetivamente Modify All Data",
                f"{user.get('username','Usuário desconhecido')} recebe ModifyAllData por meio dos metadados de permissões atribuídas.",
                component=user.get("username", ""), recommendation="Revise a necessidade de negócio e substitua o acesso administrativo amplo por permissões de menor privilégio.",
                effort="Medium", confidence=0.95, evidence=[Evidence("PERMISSION_ASSIGNMENT", user.get("username", ""), ", ".join(user.get("permission_sets", [])), 0.95)]
            )); seq += 1
        elif modify:
            findings.append(_finding(
                f"V2SEC-{seq:04d}", "security", "high", "Usuário ativo recebe Modify All em um ou mais objetos",
                f"{user.get('username','Usuário desconhecido')} possui Modify All em {len(modify)} objeto(s) por meio dos metadados de permissões atribuídas.",
                component=user.get("username", ""), recommendation="Valide a necessidade do acesso Modify All no objeto segundo o princípio do menor privilégio.",
                effort="Medium", confidence=0.92, evidence=[Evidence("PERMISSION_ASSIGNMENT", user.get("username", ""), ", ".join(modify[:30]), 0.92)]
            )); seq += 1

    coverage = intel.get("apex_coverage", {})
    if coverage.get("available") and coverage.get("overall_percent") is not None and coverage["overall_percent"] < 75:
        findings.append(_finding(
            f"V2TEST-{seq:04d}", "testing", "critical", "Cobertura Apex da organização abaixo do limite de implantação",
            f"ApexCodeCoverageAggregate informa cobertura agregada de {coverage['overall_percent']}%.",
            component="Apex", recommendation="Aumente a cobertura com testes significativos, priorizando classes e triggers críticos antes das releases.",
            effort="High", confidence=1.0, evidence=[Evidence("TOOLING_API", "ApexCodeCoverageAggregate", f"coverage={coverage['overall_percent']}%", 1.0)]
        )); seq += 1
    if coverage.get("available"):
        low = [x for x in coverage.get("components", []) if x.get("coverage_percent") is not None and x["coverage_percent"] < 60]
        if low:
            findings.append(_finding(
                f"V2TEST-{seq:04d}", "testing", "high", "Componentes Apex com baixa cobertura",
                f"{len(low)} agregado(s) de cobertura de classe/trigger Apex estão abaixo de 60%.", component="Apex",
                recommendation="Revise os componentes de produção com menor cobertura e adicione testes orientados ao comportamento.", effort="Medium", confidence=1.0,
                evidence=[Evidence("TOOLING_API", "ApexCodeCoverageAggregate", ", ".join(f"{x['name']}={x['coverage_percent']}%" for x in low[:30]), 1.0)]
            )); seq += 1

    profile = intel.get("data_profile", {})
    if profile.get("ldv_candidates"):
        findings.append(_finding(
            f"V2PERF-{seq:04d}", "performance", "medium", "Candidatos a grande volume de dados detectados",
            f"{len(profile['ldv_candidates'])} objeto(s) consultável(is) atingem o limite configurado de grande volume de dados.", component="Modelo de dados",
            recommendation="Revise seletividade de consultas, índices, concentração de proprietários/lookups, arquivamento e custo de automação nos objetos LDV.", effort="High", confidence=0.9,
            evidence=[Evidence("ENTITY_DEFINITION", "RecordCount", ", ".join(f"{x['object']}={x['record_count']}" for x in profile['ldv_candidates'][:20]), 0.9)]
        )); seq += 1

    ooe = intel.get("order_of_execution", {})
    severe_hotspots = [x for x in ooe.get("hotspots", []) if x.get("automation_components", 0) >= 15]
    for h in severe_hotspots[:30]:
        findings.append(_finding(
            f"V2ARC-{seq:04d}", "architecture", "high", "Ponto crítico na ordem de execução",
            f"{h['object']} possui {h['automation_components']} componentes ativos de automação/validação representados no mapa de execução v0.2.",
            component=h["object"], recommendation="Revise a ordem de execução, limites de recursão, oportunidades de consolidação e o risco transacional de CPU/DML.", effort="High", confidence=0.9,
            evidence=[Evidence("AUTOMATION_MAP", h["object"], str({k:v for k,v in h.items() if k != 'object'}), 0.9)]
        )); seq += 1

    runtime_usage = intel.get("runtime_usage", {})
    failed = runtime_usage.get("failed_async_jobs_30d", 0)
    if failed:
        findings.append(_finding(
            f"V2OBS-{seq:04d}", "observability", "medium", "Falhas em trabalhos assíncronos detectadas",
            f"Foram observados {failed} trabalhos Apex assíncronos com falha/erro nos últimos 30 dias (sujeito à retenção e às permissões de consulta).",
            component="AsyncApexJob", recommendation="Classifique as falhas recorrentes, defina responsáveis e alertas e corrija as causas-raiz.", effort="Medium", confidence=0.95,
            evidence=[Evidence("SOQL", "AsyncApexJob", f"failed_or_errors={failed}", 0.95)]
        ))
