from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .branding import footer_text, logo_data_uri, logo_path, report_metadata, with_report_metadata
from .models import AssessmentResult
from .localization import category_label, inventory_label, severity_label


def _make_charts(data: dict[str, Any], output_dir: Path) -> dict[str, str]:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return {}
    chart_dir = output_dir / "charts"
    chart_dir.mkdir(parents=True, exist_ok=True)
    charts: dict[str, str] = {}

    categories = data["health"]["categories"]
    if categories:
        fig, ax = plt.subplots(figsize=(10, 6))
        category_rows = [(category_label(n), v) for n, v in categories.items() if v is not None]
        names = [name for name, _ in category_rows]
        values = [value for _, value in category_rows]
        if names:
            ax.barh(names, values)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Pontuação")
        ax.set_title("Saúde por categoria")
        ax.invert_yaxis()
        fig.tight_layout()
        p = chart_dir / "health_scores.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["health"] = str(p.relative_to(output_dir))

    severity = data["health"]["findings_by_severity"]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar([severity_label(k) for k in severity], list(severity.values()))
    ax.set_ylabel("Achados")
    ax.set_title("Achados por severidade")
    fig.tight_layout()
    p = chart_dir / "findings_by_severity.png"
    fig.savefig(p, dpi=160, bbox_inches="tight")
    plt.close(fig)
    charts["findings"] = str(p.relative_to(output_dir))

    inventory = data.get("inventory", {})
    if inventory:
        top = sorted(inventory.items(), key=lambda kv: kv[1] if isinstance(kv[1], (int, float)) else 0, reverse=True)[:12]
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([inventory_label(k) for k, _ in top], [v for _, v in top])
        ax.set_xlabel("Quantidade")
        ax.set_title("Inventário de metadados")
        ax.invert_yaxis()
        fig.tight_layout()
        p = chart_dir / "inventory.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["inventory"] = str(p.relative_to(output_dir))

    intel = data.get("components", {}).get("intelligence", {})
    cov = intel.get("apex_coverage", {})
    cov_rows = [x for x in cov.get("components", []) if x.get("coverage_percent") is not None][:20]
    if cov_rows:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["name"] for x in reversed(cov_rows)], [x["coverage_percent"] for x in reversed(cov_rows)])
        ax.set_xlim(0, 100)
        ax.set_xlabel("Cobertura %")
        ax.set_title("Componentes Apex com menor cobertura")
        fig.tight_layout()
        p = chart_dir / "apex_coverage.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["apex_coverage"] = str(p.relative_to(output_dir))

    volumes = intel.get("data_profile", {}).get("largest_objects", [])[:15]
    if volumes:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["object"] for x in reversed(volumes)], [x["record_count"] for x in reversed(volumes)])
        ax.set_xlabel("Quantidade estimada de registros")
        ax.set_title("Maiores objetos consultáveis")
        fig.tight_layout()
        p = chart_dir / "data_volume.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["data_volume"] = str(p.relative_to(output_dir))

    hotspots = intel.get("order_of_execution", {}).get("hotspots", [])[:15]
    if hotspots:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["object"] for x in reversed(hotspots)], [x["automation_components"] for x in reversed(hotspots)])
        ax.set_xlabel("Componentes de automação/validação")
        ax.set_title("Pontos críticos na ordem de execução")
        fig.tight_layout()
        p = chart_dir / "automation_hotspots.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["automation_hotspots"] = str(p.relative_to(output_dir))

    v3 = intel.get("v3", {})
    risk = v3.get("risk_and_debt", {}).get("top_change_risk", [])[:15]
    if risk:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["component"] for x in reversed(risk)], [x["change_risk_score"] for x in reversed(risk)])
        ax.set_xlim(0, 100)
        ax.set_xlabel("Pontuação de risco da mudança")
        ax.set_title("Componentes com maior risco de mudança")
        fig.tight_layout()
        p = chart_dir / "change_risk.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["change_risk"] = str(p.relative_to(output_dir))

    apps = v3.get("event_monitoring", {}).get("app_usage", [])[:12]
    if apps:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["app"] for x in reversed(apps)], [x["events"] for x in reversed(apps)])
        ax.set_xlabel("Eventos observados")
        ax.set_title("Evidências de uso das aplicações")
        fig.tight_layout()
        p = chart_dir / "app_usage.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["app_usage"] = str(p.relative_to(output_dir))
    limits = data.get("components", {}).get("org_limit_governance", {}).get("limits", [])[:12]
    if limits:
        fig, ax = plt.subplots(figsize=(9, max(3, len(limits) * .32)))
        ax.barh([row["name"] for row in reversed(limits)], [row["remaining_percent"] for row in reversed(limits)],
                color=["#e67b84" if row["status"] == "critical" else "#e0b76a" if row["status"] == "warning" else "#6c9bba" for row in reversed(limits)])
        ax.set_xlabel("Margem restante (%)")
        ax.set_title("Menores margens dos limites da organização")
        p = chart_dir / "org_limit_headroom.png"
        fig.tight_layout()
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["org_limit_headroom"] = str(p.relative_to(output_dir))
    return charts


def _markdown(data: dict[str, Any], logo_reference: str = "assets/labforce-logo.webp") -> str:
    h = data["health"]
    metadata = data["report_metadata"]
    lines = [
        f"![Labforce]({logo_reference})", "", f"# {data['product']['name']}", "",
        f"**Organização:** {data['run'].get('target_org', '')}",
        f"**Gerado em:** {metadata['generated_at_display']}", "",
        f"## Saúde geral: {h['overall']}/100", "",
        "## Saúde por categoria", "",
        "| Categoria | Pontuação |", "|---|---:|",
    ]
    for category, score in h["categories"].items():
        lines.append(f"| {category_label(category)} | {score if score is not None else 'N/D'} |")
    lines += ["", "## Achados", "", "| ID | Severidade | Categoria | Componente | Achado |", "|---|---|---|---|---|"]
    for f in data["findings"]:
        lines.append(f"| {f['id']} | {f.get('severity_label', severity_label(f['severity']))} | {f.get('category_label', category_label(f['category']))} | {f.get('component','')} | {f['title']} |")
    lines += ["", "## Inventário", "", "| Tipo | Quantidade |", "|---|---:|"]
    for key, value in data.get("inventory", {}).items():
        lines.append(f"| {inventory_label(key)} | {value} |")

    audit = data.get("audit", {})
    manifest = audit.get("metadata_manifest", {})
    coverage = audit.get("metadata_coverage", {})
    if manifest or coverage:
        lines += ["", "## Snapshot de metadados", "",
                  f"- Modo de descoberta: **{audit.get('metadata_discovery_mode', 'N/D')}**",
                  f"- Tipos no manifesto: **{manifest.get('types', 0)}**",
                  f"- Membros no manifesto: **{manifest.get('members', 0)}**",
                  f"- Arquivos recuperados: **{audit.get('metadata_snapshot_files', coverage.get('file_count', 0))}**",
                  f"- Cobertura: **{coverage.get('status', 'N/D')}**",
                  f"- SHA-256 do manifesto: `{manifest.get('sha256', 'N/D')}`",
                  "- Auditoria detalhada: `metadata-retrieve-audit.json`; manifesto: `metadata-package.xml` quando houve retrieve.",
                  "- O escopo recuperado depende da API, permissões e pacotes; não comprova cobertura integral da org."]

    governance = data.get("components", {}).get("code_governance", {})
    org_limits = data.get("components", {}).get("org_limit_governance", {})
    if governance or org_limits:
        lines += ["", "## Governança técnica", "",
                  f"- Candidatas a Classe Deus: **{len(governance.get('god_class_candidates', []))}**",
                  f"- Candidatas a Classe Deus de testes: **{len(governance.get('god_test_class_candidates', []))}**",
                  f"- Limites da org em estado crítico: **{org_limits.get('critical_count', 0)}**",
                  f"- Limites da org em alerta: **{org_limits.get('warning_count', 0)}**"]
        candidates = governance.get("god_class_candidates", []) + governance.get("god_test_class_candidates", [])
        if candidates:
            lines += ["", "### Classes com concentração de responsabilidades", "", "| Classe | Tipo | Pontuação | Linhas | Métodos | Complexidade |", "|---|---|---:|---:|---:|---:|"]
            for row in candidates[:50]:
                kind = "Teste" if row.get("is_test") else "Produção"
                methods = row.get("test_methods") if row.get("is_test") else row.get("methods")
                lines.append(f"| {row.get('api_name')} | {kind} | {row.get('score')} | {row.get('lines')} | {methods} | {row.get('complexity_proxy')} |")
        attention = org_limits.get("outside_governance", [])
        lines += ["", org_limits.get("note", ""), "", governance.get("methodology", "")]
        if not org_limits.get("available"):
            lines.append("Limites da org indisponíveis; ausência de alerta não significa margem saudável.")
        risks = governance.get("transaction_governor_risks", [])
        if risks:
            lines += ["", "### Concentração estática de operações", "", "| Componente | Indicadores estáticos |", "|---|---|"]
            for row in risks:
                detail = ", ".join(f"{risk['metric']}={risk['count']} (alerta: {risk['warning_threshold']})" for risk in row['risks'])
                lines.append(f"| {row['component']} | {detail} |")
        if attention:
            lines += ["", "### Limites com margem reduzida", "", "| Limite | Status | Utilizado | Restante |", "|---|---|---:|---:|"]
            for row in attention[:50]:
                lines.append(f"| {row.get('name')} | {row.get('status')} | {row.get('used_percent')}% | {row.get('remaining_percent')}% |")
        if org_limits.get("limits"):
            lines += ["", "### Todos os limites observados", "", "| Limite | Status | Máximo | Utilizado | Restante | Margem |", "|---|---|---:|---:|---:|---:|"]
            for row in org_limits["limits"]:
                label = {"healthy": "Saudável", "warning": "Alerta", "critical": "Crítico"}[row["status"]]
                lines.append(f"| {row['name']} | {label} | {row['max']} | {row['used']} | {row['remaining']} | {row['remaining_percent']}% |")

    ent = data.get("components", {}).get("intelligence", {}).get("enterprise", {})
    twin = ent.get("digital_twin", {})
    if twin:
        lines += ["", "## Inteligência empresarial", "",
                  f"- Gêmeo digital: **{twin.get('nodes', 0)} nós / {twin.get('edges', 0)} arestas**",
                  f"- Ciclos de automação: **{len(twin.get('automation_cycles', []))}**",
                  f"- Pontos de articulação: **{len(twin.get('articulation_points', []))}**"]
        readiness = ent.get("competitive_readiness", {}).get("overall_readiness_percent")
        if readiness is not None:
            lines.append(f"- Prontidão interna das capacidades: **{readiness}%**")
        eq = ent.get("evidence_quality", {})
        if eq:
            lines.append(f"- Achados com evidências: **{eq.get('evidence_coverage_percent')}%**")
        plan = ent.get("remediation_plan", {})
        if plan:
            lines += ["", "### Prioridades de remediação", "", "| Prioridade | Quantidade |", "|---|---:|"]
            for prio in ("P0","P1","P2","P3"):
                lines.append(f"| {prio} | {plan.get('by_priority', {}).get(prio, 0)} |")
        advisor = ent.get("architecture_advisor", {}).get("recommendations", [])
        if advisor:
            lines += ["", "### Orientador de arquitetura", ""]
            for rec in advisor[:12]:
                lines.append(f"- **{rec.get('priority','')} — {rec.get('title','')}**: {rec.get('rationale','')}")
    v7 = data.get("components", {}).get("intelligence", {}).get("v7", {})
    if v7:
        ready = v7.get("final_readiness", {})
        lines += ["", "## Camada final de inteligência", "",
                  f"- Prontidão do núcleo: **{ready.get('readiness_percent','N/D')}%** ({ready.get('engine_status_label', ready.get('engine_status','N/D'))})",
                  f"- Análise aprofundada de Flow: **{v7.get('flow_quality',{}).get('flows_analyzed',0)} Flow(s)**",
                  f"- Análise aprofundada de Apex: **{v7.get('apex_quality',{}).get('components_analyzed',0)} componente(s)**",
                  f"- Candidatos a colisão transacional: **{len(v7.get('order_of_execution_graph',{}).get('collision_candidates',[]))}**",
                  f"- Risco de execução: **{v7.get('runtime_health',{}).get('runtime_risk_score','N/D')}/100**",
                  f"- Risco de integração: **{v7.get('integration_health',{}).get('health_risk_score','N/D')}/100**"]
    lines += ["", "---", footer_text(metadata), ""]
    return "\n".join(lines) + "\n"


def generate_reports(result: AssessmentResult, output_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = report_metadata(config)
    data = with_report_metadata(
        result.to_dict(),
        config,
        generated_at=datetime.fromisoformat(metadata["generated_at"]),
    )
    assets_dir = output_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(logo_path(), assets_dir / "labforce-logo.webp")
    json_path = output_dir / "assessment.json"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    md_path = output_dir / "assessment.md"
    md_path.write_text(_markdown(data), encoding="utf-8")

    charts = _make_charts(data, output_dir)
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html", "xml"]))
    template = env.get_template("report.html.j2")
    branding = {
        **metadata,
        "logo_data_uri": logo_data_uri(),
        "footer_text": footer_text(metadata),
    }
    html = template.render(data=data, config=config, charts=charts, branding=branding)
    html_path = output_dir / "assessment.html"
    html_path.write_text(html, encoding="utf-8")

    pdf_path = output_dir / "assessment.pdf"
    pdf_result: dict[str, Any] = {"generated": False, "path": str(pdf_path)}
    try:
        from weasyprint import HTML
        HTML(filename=str(html_path), base_url=str(output_dir)).write_pdf(str(pdf_path))
        pdf_result["generated"] = True
    except Exception as exc:
        pdf_result["error"] = str(exc)

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "html": str(html_path),
        "pdf": pdf_result,
        "charts": charts,
    }
