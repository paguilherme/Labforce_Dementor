from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .branding import footer_text, logo_data_uri, report_metadata, with_report_metadata


def render_impact_html(
    data: dict[str, Any],
    output: Path,
    config: dict[str, Any] | None = None,
    *,
    generated_at: datetime | None = None,
) -> Path:
    if "report_metadata" not in data:
        data = with_report_metadata(data, config, generated_at=generated_at)
    metadata = data["report_metadata"]
    footer = html.escape(footer_text(metadata))
    rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
        for k, v in data.get("affected_by_type", {}).items()
    )
    affected = "".join(f"<li>{html.escape(x)}</li>" for x in data.get("affected_components", [])[:250])
    findings = "".join(
        f"<tr><td>{html.escape(str(f.get('id','')))}</td><td>{html.escape(str(f.get('severity','')).upper())}</td><td>{html.escape(str(f.get('title','')))}</td></tr>"
        for f in data.get("related_findings", [])
    )
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Change Impact - {html.escape(data.get('component',''))}</title>
<style>
@page {{ size:A4; margin:18mm 18mm 22mm; @bottom-center {{ content:"{footer} · Página " counter(page) " / " counter(pages); font-size:8pt; color:#657184; }} }}
body {{ font-family: Arial, sans-serif; color:#1d2733; font-size:11px; }}
h1 {{ font-size:24px; margin-bottom:4px; }}
.logo {{ width:310px; max-width:75%; height:auto; margin-bottom:24px; }}
h2 {{ margin-top:24px; border-bottom:1px solid #ccd4dd; padding-bottom:4px; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:18px 0; }}
.card {{ border:1px solid #d8dee6; border-radius:8px; padding:12px; }}
.big {{ font-size:24px; font-weight:700; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border-bottom:1px solid #e1e5ea; text-align:left; padding:6px; }}
.badge {{ font-weight:700; }}
code {{ font-family:monospace; }}
footer {{ margin-top:34px; border-top:1px solid #d8dee6; padding-top:10px; color:#657184; font-size:9px; }}
</style></head>
<body>
<img class="logo" src="{logo_data_uri()}" alt="Labforce">
<h1>Labforce Dementor — Change Impact Assessment</h1>
<p><code>{html.escape(data.get('component',''))}</code></p>
<div class="grid">
<div class="card"><div>Risk</div><div class="big">{html.escape(data.get('risk',''))}</div></div>
<div class="card"><div>Change Risk</div><div class="big">{data.get('change_risk_score',0)}/100</div></div>
<div class="card"><div>Blast Radius</div><div class="big">{data.get('blast_radius',0)}</div></div>
</div>
<h2>Affected component types</h2>
<table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Related findings</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{findings or '<tr><td colspan="3">No related findings.</td></tr>'}</tbody></table>
<h2>Affected components</h2><ul>{affected}</ul>
<p><small>Generated from an existing assessment snapshot. No Salesforce API calls were made by this impact command.</small></p>
<footer>{footer}</footer>
</body></html>"""
    output.write_text(doc, encoding="utf-8")
    return output


def render_impact_pdf(html_path: Path, pdf_path: Path) -> dict[str, Any]:
    try:
        from weasyprint import HTML
        HTML(filename=str(html_path), base_url=str(html_path.parent)).write_pdf(str(pdf_path))
        return {"generated": True, "path": str(pdf_path)}
    except Exception as exc:
        return {"generated": False, "path": str(pdf_path), "error": str(exc)}
