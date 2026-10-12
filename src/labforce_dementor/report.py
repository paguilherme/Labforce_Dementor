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
        names = [n for n, v in categories.items() if v is not None]
        values = [categories[n] for n in names]
        if names:
            ax.barh(names, values)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Score")
        ax.set_title("Health score by category")
        ax.invert_yaxis()
        fig.tight_layout()
        p = chart_dir / "health_scores.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["health"] = str(p.relative_to(output_dir))

    severity = data["health"]["findings_by_severity"]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(list(severity.keys()), list(severity.values()))
    ax.set_ylabel("Findings")
    ax.set_title("Findings by severity")
    fig.tight_layout()
    p = chart_dir / "findings_by_severity.png"
    fig.savefig(p, dpi=160, bbox_inches="tight")
    plt.close(fig)
    charts["findings"] = str(p.relative_to(output_dir))

    inventory = data.get("inventory", {})
    if inventory:
        top = sorted(inventory.items(), key=lambda kv: kv[1] if isinstance(kv[1], (int, float)) else 0, reverse=True)[:12]
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([k for k, _ in top], [v for _, v in top])
        ax.set_xlabel("Count")
        ax.set_title("Metadata inventory")
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
        ax.set_xlabel("Coverage %")
        ax.set_title("Lowest Apex coverage components")
        fig.tight_layout()
        p = chart_dir / "apex_coverage.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["apex_coverage"] = str(p.relative_to(output_dir))

    volumes = intel.get("data_profile", {}).get("largest_objects", [])[:15]
    if volumes:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["object"] for x in reversed(volumes)], [x["record_count"] for x in reversed(volumes)])
        ax.set_xlabel("Estimated record count")
        ax.set_title("Largest queryable objects")
        fig.tight_layout()
        p = chart_dir / "data_volume.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["data_volume"] = str(p.relative_to(output_dir))

    hotspots = intel.get("order_of_execution", {}).get("hotspots", [])[:15]
    if hotspots:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["object"] for x in reversed(hotspots)], [x["automation_components"] for x in reversed(hotspots)])
        ax.set_xlabel("Automation / validation components")
        ax.set_title("Order-of-execution hotspots")
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
        ax.set_xlabel("Change risk score")
        ax.set_title("Highest change-risk components")
        fig.tight_layout()
        p = chart_dir / "change_risk.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["change_risk"] = str(p.relative_to(output_dir))

    apps = v3.get("event_monitoring", {}).get("app_usage", [])[:12]
    if apps:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh([x["app"] for x in reversed(apps)], [x["events"] for x in reversed(apps)])
        ax.set_xlabel("Observed events")
        ax.set_title("Application usage evidence")
        fig.tight_layout()
        p = chart_dir / "app_usage.png"
        fig.savefig(p, dpi=160, bbox_inches="tight")
        plt.close(fig)
        charts["app_usage"] = str(p.relative_to(output_dir))
    return charts


def _markdown(data: dict[str, Any], logo_reference: str = "assets/labforce-logo.webp") -> str:
    h = data["health"]
    metadata = data["report_metadata"]
    lines = [
        f"![Labforce]({logo_reference})", "", f"# {data['product']['name']}", "",
        f"**Org:** {data['run'].get('target_org', '')}",
        f"**Gerado em:** {metadata['generated_at_display']}", "",
        f"## Overall Health: {h['overall']}/100", "",
        "## Health by category", "",
        "| Category | Score |", "|---|---:|",
    ]
    for category, score in h["categories"].items():
        lines.append(f"| {category.replace('_', ' ').title()} | {score if score is not None else 'N/A'} |")
    lines += ["", "## Findings", "", "| ID | Severity | Category | Component | Finding |", "|---|---|---|---|---|"]
    for f in data["findings"]:
        lines.append(f"| {f['id']} | {f['severity'].upper()} | {f['category']} | {f.get('component','')} | {f['title']} |")
    lines += ["", "## Inventory", "", "| Type | Count |", "|---|---:|"]
    for key, value in data.get("inventory", {}).items():
        lines.append(f"| {key.replace('_',' ').title()} | {value} |")

    ent = data.get("components", {}).get("intelligence", {}).get("enterprise", {})
    twin = ent.get("digital_twin", {})
    if twin:
        lines += ["", "## Enterprise Intelligence", "",
                  f"- Digital Twin: **{twin.get('nodes', 0)} nodes / {twin.get('edges', 0)} edges**",
                  f"- Automation cycles: **{len(twin.get('automation_cycles', []))}**",
                  f"- Articulation points: **{len(twin.get('articulation_points', []))}**"]
        readiness = ent.get("competitive_readiness", {}).get("overall_readiness_percent")
        if readiness is not None:
            lines.append(f"- Internal competitive capability readiness: **{readiness}%**")
        eq = ent.get("evidence_quality", {})
        if eq:
            lines.append(f"- Findings with evidence: **{eq.get('evidence_coverage_percent')}%**")
        plan = ent.get("remediation_plan", {})
        if plan:
            lines += ["", "### Remediation priorities", "", "| Priority | Count |", "|---|---:|"]
            for prio in ("P0","P1","P2","P3"):
                lines.append(f"| {prio} | {plan.get('by_priority', {}).get(prio, 0)} |")
        advisor = ent.get("architecture_advisor", {}).get("recommendations", [])
        if advisor:
            lines += ["", "### Architecture Advisor", ""]
            for rec in advisor[:12]:
                lines.append(f"- **{rec.get('priority','')} — {rec.get('title','')}**: {rec.get('rationale','')}")
    v7 = data.get("components", {}).get("intelligence", {}).get("v7", {})
    if v7:
        ready = v7.get("final_readiness", {})
        lines += ["", "## Final Intelligence Layer", "",
                  f"- Product-grade core readiness: **{ready.get('readiness_percent','N/A')}%** ({ready.get('engine_status','N/A')})",
                  f"- Flow deep-analysis: **{v7.get('flow_quality',{}).get('flows_analyzed',0)} flow(s)**",
                  f"- Apex deep-analysis: **{v7.get('apex_quality',{}).get('components_analyzed',0)} component(s)**",
                  f"- Transaction collision candidates: **{len(v7.get('order_of_execution_graph',{}).get('collision_candidates',[]))}**",
                  f"- Runtime risk: **{v7.get('runtime_health',{}).get('runtime_risk_score','N/A')}/100**",
                  f"- Integration risk: **{v7.get('integration_health',{}).get('health_risk_score','N/A')}/100**"]
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
