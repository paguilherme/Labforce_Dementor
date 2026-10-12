from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from . import PRODUCT_NAME, __version__
from .ai_complement import (
    AiComplementError,
    DATA_SCOPES,
    PROVIDERS,
    create_preview,
    execute_complement,
)
from .ai_credentials import resolve_ai_credential
from .branding import report_metadata, with_report_metadata
from .config import load_config
from .engine import run_assessment
from .diffing import write_diff
from .safety import UnsafeCommandError
from .intelligence_v4 import impact_report
from .impact_reporting import render_impact_html, render_impact_pdf
from .diagnostics import doctor
from .intelligence_v5 import drift_from_assessment, select_tests, write_knowledge_pack
from .policy import load_policy, evaluate_policy
from .intelligence_v6 import git_changed_files, temporal_diff, deployment_impact, sarif, business_criticality
from .enterprise import component_explanation
from .intelligence_v7 import simulate_change, continuous_intelligence
from .sfcli import SFCLIError


def _write_report_json(path: Path, result: dict[str, object]) -> dict[str, object]:
    branded = with_report_metadata(result)
    path.write_text(json.dumps(branded, indent=2, ensure_ascii=False), encoding="utf-8")
    return branded


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dementor", description=f"{PRODUCT_NAME} — read-only Salesforce org assessment")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run a read-only Salesforce org assessment")
    run.add_argument("--target-org", "-o", required=True, help="Salesforce CLI org alias or username")
    run.add_argument("--config", help="Optional YAML config overriding defaults")
    run.add_argument("--output", help="Output directory. Default: ./assessments/<org>/<timestamp>")
    run.add_argument("--work-dir", help="Working directory for retrieved metadata. Default: <output>/_work")
    run.add_argument("--wait-for-deploy", type=int, default=0, metavar="SECONDS", help="Wait this many seconds for active deploy/validate to finish before skipping metadata retrieve")
    run.add_argument("--source-dir", help="Analyze an existing Salesforce source snapshot instead of retrieving metadata. Recommended with STRICT_READ_ONLY mode.")
    run.add_argument("--profile-data", action="store_true", help="Opt-in: sample a limited number of record values for null/cardinality statistics. Raw values are not persisted.")
    run.add_argument("--resume", action="store_true", help="Resume from a compatible local checkpoint when possible.")

    diff = sub.add_parser("diff", help="Compare two assessment.json snapshots")
    diff.add_argument("--from", dest="before", required=True, help="Older assessment.json")
    diff.add_argument("--to", dest="after", required=True, help="Newer assessment.json")
    diff.add_argument("--output", default="assessment-diff.json", help="Diff JSON output path")

    impact = sub.add_parser("impact", help="Generate change-impact analysis from an existing assessment snapshot")
    impact.add_argument("--assessment", required=True, help="assessment.json snapshot")
    impact.add_argument("--component", required=True, help="Component/API name, e.g. Account.Status__c")
    impact.add_argument("--depth", type=int, default=3, help="Dependency traversal depth")
    impact.add_argument("--output", default="impact-report.json", help="Impact JSON output path")
    impact.add_argument("--html", help="Optional impact HTML output path")
    impact.add_argument("--pdf", help="Optional impact PDF output path")

    sub.add_parser("doctor", help="Validate local dependencies without connecting to an org")

    drift = sub.add_parser("drift", help="Compare org assessment fingerprint with a local Salesforce source tree")
    drift.add_argument("--assessment", required=True)
    drift.add_argument("--repo-dir", required=True)
    drift.add_argument("--output", default="drift-report.json")

    tests = sub.add_parser("tests", help="Recommend Apex tests for changed/impacted components from a snapshot")
    tests.add_argument("--assessment", required=True)
    tests.add_argument("--component", action="append", required=True, help="Changed component; repeat as needed")
    tests.add_argument("--depth", type=int, default=3)
    tests.add_argument("--output", default="recommended-tests.json")
    tests.add_argument("--tests-file", help="Optional plain-text output, one Apex test per line")

    kp = sub.add_parser("knowledge-pack", help="Export an AI/RAG-oriented knowledge pack from a snapshot")
    kp.add_argument("--assessment", required=True)
    kp.add_argument("--output-dir", required=True)

    pol = sub.add_parser("policy", help="Evaluate an assessment against a policy pack")
    pol.add_argument("--assessment", required=True)
    pol.add_argument("--before", help="Optional previous assessment snapshot")
    pol.add_argument("--drift", help="Optional drift-report.json")
    pol.add_argument("--policy", help="Optional YAML policy pack")
    pol.add_argument("--output", default="policy-result.json")

    ci = sub.add_parser("ci", help="Offline CI gate using current/before assessment, policy and optional drift")
    ci.add_argument("--assessment", required=True)
    ci.add_argument("--before")
    ci.add_argument("--drift")
    ci.add_argument("--policy")
    ci.add_argument("--output", default="ci-result.json")

    pr = sub.add_parser("pr-impact", help="Analyze a Git diff/PR against an assessment dependency graph")
    pr.add_argument("--assessment", required=True)
    pr.add_argument("--repo-dir", required=True)
    pr.add_argument("--base", required=True)
    pr.add_argument("--head", required=True)
    pr.add_argument("--depth", type=int, default=3)
    pr.add_argument("--output", default="pr-impact.json")

    temporal = sub.add_parser("timeline", help="Compare architecture graph/findings between two snapshots")
    temporal.add_argument("--from", dest="from_file", required=True)
    temporal.add_argument("--to", dest="to_file", required=True)
    temporal.add_argument("--output", default="timeline.json")

    sar = sub.add_parser("sarif", help="Export assessment findings as SARIF 2.1.0")
    sar.add_argument("--assessment", required=True)
    sar.add_argument("--output", default="dementor.sarif")

    bc = sub.add_parser("criticality", help="Calculate structural/business-criticality proxy")
    bc.add_argument("--assessment", required=True)
    bc.add_argument("--output", default="criticality.json")

    explain = sub.add_parser("explain", help="Explain a component using the Digital Twin/dependency evidence")
    explain.add_argument("--assessment", required=True)
    explain.add_argument("--component", required=True)
    explain.add_argument("--depth", type=int, default=2)
    explain.add_argument("--output", default="component-explanation.json")

    rem = sub.add_parser("remediation", help="Export the prioritized remediation plan from an assessment")
    rem.add_argument("--assessment", required=True)
    rem.add_argument("--output", default="remediation-plan.json")

    caps = sub.add_parser("capabilities", help="Export capability/evidence readiness from an assessment")
    caps.add_argument("--assessment", required=True)
    caps.add_argument("--output", default="capability-matrix.json")

    sim = sub.add_parser("simulate", help="Offline read-only change/removal simulation using the dependency graph")
    sim.add_argument("--assessment", required=True)
    sim.add_argument("--component", required=True)
    sim.add_argument("--operation", choices=["change", "remove", "deprecate"], default="change")
    sim.add_argument("--depth", type=int, default=4)
    sim.add_argument("--output", default="change-simulation.json")

    cont = sub.add_parser("continuous", help="Compare two snapshots for health trend, resolved/new risks and architecture drift")
    cont.add_argument("--from", dest="before", required=True)
    cont.add_argument("--to", dest="after", required=True)
    cont.add_argument("--output", default="continuous-intelligence.json")

    ai_preview = sub.add_parser("ai-preview", help="Prepare the exact sanitized payload for explicit AI consent; no provider call is made")
    ai_preview.add_argument("--assessment", required=True, help="Deterministic assessment.json")
    ai_preview.add_argument("--provider", required=True, choices=PROVIDERS)
    ai_preview.add_argument("--model", required=True, help="Exact provider model selected by the user")
    ai_preview.add_argument("--scope", action="append", required=True, choices=DATA_SCOPES, help="Authorized data scope; repeat to combine scopes")
    ai_preview.add_argument("--max-output-tokens", type=int, default=2000)
    ai_preview.add_argument("--expires-in-minutes", type=int, default=30)
    ai_preview.add_argument("--output", default="ai-consent-preview.json")

    ai_run = sub.add_parser("ai-complement", help="Execute a single-use AI complement after explicit user consent")
    ai_run.add_argument("--preview", required=True, help="Preview generated by ai-preview")
    ai_run.add_argument("--authorize", required=True, help="Exact authorization phrase shown in the preview")
    ai_run.add_argument("--authorized-by", required=True, help="User identifier recorded in the consent receipt")
    ai_run.add_argument("--credential-source", choices=["labforce-base", "environment"], default="labforce-base")
    ai_run.add_argument("--organization", help="Labforce organization scope used to lease the user's credential")
    ai_run.add_argument("--client", help="Optional Labforce client scope")
    ai_run.add_argument("--project", help="Optional Labforce project scope")
    ai_run.add_argument("--base-root", help="Labforce Base root; normally auto-detected")
    ai_run.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434/api/chat")
    ai_run.add_argument("--output-dir", default="ai-complement-report")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "ai-preview":
        try:
            plan = create_preview(
                Path(args.assessment),
                provider=args.provider,
                model=args.model,
                data_scopes=args.scope,
                output_path=Path(args.output),
                expires_in_minutes=args.expires_in_minutes,
                max_output_tokens=args.max_output_tokens,
            )
        except (AiComplementError, OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        print("Nenhum dado foi enviado à IA.")
        print(f"Provedor   : {plan['provider']}")
        print(f"Modelo     : {plan['model']}")
        print(f"Escopos    : {', '.join(plan['data_scopes'])}")
        print(f"Itens      : {plan['item_counts']}")
        print(f"Tokens est.: {plan['estimated_input_tokens']}")
        print(f"Expira em  : {plan['expires_at']}")
        print(f"Autorizar  : {plan['authorization_phrase']}")
        print(f"Prévia     : {args.output}")
        print(f"Conteúdo   : {plan['input_path']}")
        return
    if args.command == "ai-complement":
        try:
            preview = json.loads(Path(args.preview).read_text(encoding="utf-8"))
            provider = str(preview.get("provider", ""))

            def credential_loader() -> tuple[str | None, str]:
                credential = resolve_ai_credential(
                    provider,
                    source=args.credential_source,
                    organization=args.organization,
                    client=args.client,
                    project=args.project,
                    base_root=Path(args.base_root) if args.base_root else None,
                )
                return credential.api_key, credential.reference

            result = execute_complement(
                Path(args.preview),
                authorization_phrase=args.authorize,
                authorized_by=args.authorized_by,
                output_dir=Path(args.output_dir),
                credential_loader=credential_loader,
                endpoint=args.ollama_endpoint if provider == "ollama" else None,
            )
        except (AiComplementError, OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        print("Complemento consultivo concluído; o diagnóstico determinístico foi preservado.")
        print(f"Provedor   : {result['provider']}")
        print(f"Modelo     : {result['model']}")
        print(f"Relatórios : {Path(args.output_dir).resolve()}")
        return
    if args.command == "doctor":
        result = doctor()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if not result.get("ready_for_full_assessment"):
            raise SystemExit(1)
        return
    if args.command == "drift":
        snapshot = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result = drift_from_assessment(snapshot, Path(args.repo_dir))
        _write_report_json(Path(args.output), result)
        print(f"Drift       : {result.get('has_drift') if result.get('available') else 'N/A'}")
        print(f"Output      : {args.output}")
        if not result.get("available"):
            raise SystemExit(2)
        return
    if args.command == "tests":
        snapshot = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result = select_tests(snapshot, args.component, max(1, args.depth))
        _write_report_json(Path(args.output), result)
        if args.tests_file:
            Path(args.tests_file).write_text("\n".join(result["test_names"]) + ("\n" if result["test_names"] else ""), encoding="utf-8")
        print(f"Recommended : {len(result['test_names'])} test(s)")
        print(f"Confidence  : {result['confidence']}")
        print(f"Output      : {args.output}")
        return
    if args.command == "knowledge-pack":
        snapshot = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result = write_knowledge_pack(snapshot, Path(args.output_dir))
        print(f"Knowledge pack: {result['output_dir']} ({result['count']} files)")
        return
    if args.command in {"policy", "ci"}:
        current = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        before = json.loads(Path(args.before).read_text(encoding="utf-8")) if args.before else None
        drift = json.loads(Path(args.drift).read_text(encoding="utf-8")) if args.drift else None
        policy = load_policy(Path(args.policy) if args.policy else None)
        result = evaluate_policy(current, before=before, drift=drift, policy=policy)
        _write_report_json(Path(args.output), result)
        print(f"Policy      : {result['policy']}")
        print(f"Passed      : {result['passed']}")
        print(f"Violations  : {len(result['violations'])}")
        print(f"Output      : {args.output}")
        if args.command == "ci" and not result["passed"]:
            raise SystemExit(3)
        return
    if args.command == "pr-impact":
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        changed=git_changed_files(Path(args.repo_dir),args.base,args.head)
        if not changed.get("available"):
            print(changed.get("error","Git diff unavailable"))
            raise SystemExit(2)
        result={"git":changed,"impact":deployment_impact(snapshot,changed["components"],max(1,args.depth))}
        _write_report_json(Path(args.output), result)
        print(f"Changed     : {len(changed['components'])} component(s)")
        print(f"Blast radius: {result['impact']['blast_radius']}")
        print(f"Risk        : {result['impact']['risk']} ({result['impact']['deployment_risk_score']}/100)")
        print(f"Output      : {args.output}")
        return
    if args.command == "timeline":
        before=json.loads(Path(args.from_file).read_text(encoding="utf-8"))
        after=json.loads(Path(args.to_file).read_text(encoding="utf-8"))
        result=temporal_diff(before,after)
        _write_report_json(Path(args.output), result)
        print(f"Edges added : {result['dependency_edges']['added_count']}")
        print(f"Edges removed: {result['dependency_edges']['removed_count']}")
        print(f"Output      : {args.output}")
        return
    if args.command == "sarif":
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result=sarif(snapshot.get("findings",[]))
        result.setdefault("runs", [{}])[0].setdefault("properties", {})["report_metadata"] = report_metadata()
        Path(args.output).write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
        print(f"SARIF       : {args.output}")
        return
    if args.command == "criticality":
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result=business_criticality(snapshot)
        _write_report_json(Path(args.output), result)
        print(f"Components  : {len(result['components'])}")
        print(f"Output      : {args.output}")
        return
    if args.command == "explain":
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result=component_explanation(snapshot,args.component,max(1,args.depth))
        _write_report_json(Path(args.output), result)
        print(f"Component   : {args.component}")
        print(f"Neighborhood: {result['neighborhood_size']}")
        print(f"Risk        : {result['summary']['risk']}")
        print(f"Output      : {args.output}")
        return
    if args.command in {"remediation", "capabilities"}:
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        enterprise=snapshot.get("components",{}).get("intelligence",{}).get("enterprise",{})
        key="remediation_plan" if args.command=="remediation" else "capability_matrix"
        result=enterprise.get(key)
        if not result:
            print(f"Enterprise intelligence '{key}' is unavailable in this snapshot", file=sys.stderr)
            raise SystemExit(2)
        _write_report_json(Path(args.output), result)
        print(f"Output      : {args.output}")
        return
    if args.command == "simulate":
        snapshot=json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result=simulate_change(snapshot,args.component,args.operation,max(1,args.depth))
        _write_report_json(Path(args.output), result)
        print(f"Operation   : {args.operation}")
        print(f"Component   : {args.component}")
        print(f"Risk        : {result['risk']} ({result['change_risk_score']}/100)")
        print(f"Blast radius: {result['blast_radius']}")
        print(f"Output      : {args.output}")
        return
    if args.command == "continuous":
        before=json.loads(Path(args.before).read_text(encoding="utf-8"))
        after=json.loads(Path(args.after).read_text(encoding="utf-8"))
        result=continuous_intelligence(before,after)
        _write_report_json(Path(args.output), result)
        print(f"Health delta: {result['health'].get('delta')}")
        print(f"New findings: {result['findings']['new_count']}")
        print(f"Resolved    : {result['findings']['resolved_count']}")
        print(f"Drift       : {result['architecture_drift']['level']}")
        print(f"Output      : {args.output}")
        return
    if args.command == "diff":
        result = write_diff(Path(args.before), Path(args.after), Path(args.output))
        print(f"Health delta: {result['overall_health'].get('delta')}")
        print(f"New findings: {len(result['new_findings'])}")
        print(f"Resolved findings: {len(result['resolved_findings'])}")
        print(f"Diff JSON: {args.output}")
        return
    if args.command == "impact":
        snapshot = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
        result = impact_report(snapshot, args.component, max_depth=max(1, args.depth))
        json_out = Path(args.output)
        metadata = report_metadata()
        result = with_report_metadata(
            result,
            generated_at=datetime.fromisoformat(metadata["generated_at"]),
        )
        json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        html_out = Path(args.html) if args.html else json_out.with_suffix(".html")
        render_impact_html(result, html_out)
        pdf_out = Path(args.pdf) if args.pdf else json_out.with_suffix(".pdf")
        pdf = render_impact_pdf(html_out, pdf_out)
        print(f"Component   : {result['component']}")
        print(f"Risk        : {result['risk']} ({result['change_risk_score']}/100)")
        print(f"Blast radius: {result['blast_radius']}")
        print(f"Impact JSON : {json_out}")
        print(f"Impact HTML : {html_out}")
        print(f"Impact PDF  : {pdf_out}" + ("" if pdf.get("generated") else f" (not generated: {pdf.get('error','unknown')})"))
        return
    if args.command != "run":
        raise SystemExit(2)
    cfg = load_config(args.config)
    if args.profile_data:
        cfg.setdefault("analysis", {})["data_profile_enabled"] = True
    safe_org = "".join(c if c.isalnum() or c in "-_" else "_" for c in args.target_org)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = Path(args.output) if args.output else Path.cwd() / "assessments" / safe_org / timestamp
    work = Path(args.work_dir) if args.work_dir else output / "_work"

    print(f"{PRODUCT_NAME} v{__version__}")
    print(f"Target org : {args.target_org}")
    print(f"Mode       : {cfg['safety']['mode']}")
    print(f"Output     : {output}")
    print("Safety     : READ-ONLY command allow-list; no deploy/DML/Apex Anonymous capability")
    try:
        manifest = run_assessment(args.target_org, work, output, cfg, wait_for_deploy_seconds=args.wait_for_deploy, source_dir=Path(args.source_dir) if args.source_dir else None, resume=args.resume)
    except (UnsafeCommandError, SFCLIError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print("\nAssessment completed.")
    print(f"Health     : {manifest['health']['overall']}/100")
    print(f"JSON       : {manifest['reports']['json']}")
    print(f"Markdown   : {manifest['reports']['markdown']}")
    print(f"HTML       : {manifest['reports']['html']}")
    pdf = manifest['reports']['pdf']
    print(f"PDF        : {pdf['path']}" + ("" if pdf.get("generated") else f" (not generated: {pdf.get('error','unknown error')})"))


if __name__ == "__main__":
    main()
