from __future__ import annotations

import hashlib
import json
import shutil
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import analyze, analyze_v2_intelligence, calculate_health
from .models import AssessmentResult
from .intelligence import collect_v2_runtime, build_intelligence
from .intelligence_v3 import build_v3_intelligence, analyze_v3_intelligence
from .intelligence_v4 import build_v4_intelligence
from .parser import parse_source
from .report import generate_reports
from .sfcli import SFCLI, SFCLIError
from .resilience import CheckpointStore, integrity_manifest
from .validation import validate_assessment_payload
from .intelligence_v5 import build_v5_intelligence
from .enterprise import build_enterprise_intelligence, stable_snapshot_digest
from .intelligence_v7 import build_v7_intelligence, analyze_v7_intelligence, final_readiness


ACTIVE_DEPLOY_STATUSES = {"pending", "inprogress", "queued", "canceling"}


def _unwrap(payload: dict[str, Any]) -> Any:
    return payload.get("result", payload)


def _normalize_org(payload: dict[str, Any]) -> dict[str, Any]:
    result = _unwrap(payload)
    if not isinstance(result, dict):
        return {"raw": result}
    return {
        "id": result.get("id") or result.get("orgId"),
        "username": result.get("username"),
        "instance_url": result.get("instanceUrl"),
        "access_token_present": bool(result.get("accessToken")),
        "api_version": result.get("apiVersion"),
        "name": result.get("name"),
        "status": result.get("status"),
        "connected_status": result.get("connectedStatus"),
        "is_sandbox": result.get("isSandbox"),
        "raw_non_secret": {k: v for k, v in result.items() if k.lower() not in {"accesstoken", "refreshtoken", "password", "clientsecret"}},
    }


def _normalize_limits(payload: dict[str, Any]) -> dict[str, Any]:
    result = _unwrap(payload)
    out: dict[str, Any] = {}
    if isinstance(result, list):
        for item in result:
            name = item.get("name") or item.get("Name")
            if name:
                out[name] = {
                    "max": item.get("max") if "max" in item else item.get("Max"),
                    "remaining": item.get("remaining") if "remaining" in item else item.get("Remaining"),
                }
    elif isinstance(result, dict):
        for name, item in result.items():
            if isinstance(item, dict):
                out[name] = {
                    "max": item.get("max") if "max" in item else item.get("Max"),
                    "remaining": item.get("remaining") if "remaining" in item else item.get("Remaining"),
                }
    return out


def _api_budget(before: dict[str, Any], after: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    b = before.get("DailyApiRequests", {})
    a = after.get("DailyApiRequests", {})
    max_calls = b.get("max") or a.get("max") or 0
    rem_before = b.get("remaining")
    rem_after = a.get("remaining")
    consumed = None
    if isinstance(rem_before, (int, float)) and isinstance(rem_after, (int, float)):
        consumed = max(0, rem_before - rem_after)
    remaining_pct = None
    if max_calls and isinstance(rem_after, (int, float)):
        remaining_pct = round((rem_after / max_calls) * 100, 2)
    budget_pct = float(cfg["safety"].get("max_api_budget_percent_of_remaining", 5.0))
    allowed_calls = round((rem_before or 0) * (budget_pct / 100), 0) if isinstance(rem_before, (int, float)) else None
    return {
        "max": max_calls,
        "remaining_before": rem_before,
        "remaining_after": rem_after,
        "consumed_by_assessment_estimate": consumed,
        "remaining_percent_after": remaining_pct,
        "configured_budget_percent_of_remaining": budget_pct,
        "configured_budget_calls_at_start": allowed_calls,
    }



def _budget_exceeded(before: dict[str, Any], current: dict[str, Any], config: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    b = before.get("DailyApiRequests", {})
    c = current.get("DailyApiRequests", {})
    rem_before = b.get("remaining")
    rem_current = c.get("remaining")
    if not isinstance(rem_before, (int, float)) or not isinstance(rem_current, (int, float)):
        return False, {"known": False}
    consumed = max(0, rem_before - rem_current)
    pct = float(config["safety"].get("max_api_budget_percent_of_remaining", 5.0))
    allowed = max(1, int(rem_before * pct / 100.0))
    return consumed > allowed, {"known": True, "consumed": consumed, "allowed": allowed, "budget_percent": pct}

def _check_api_headroom(limits: dict[str, Any], config: dict[str, Any]) -> None:
    d = limits.get("DailyApiRequests")
    if not d:
        return
    maximum = d.get("max") or 0
    remaining = d.get("remaining")
    if not maximum or not isinstance(remaining, (int, float)):
        return
    pct = remaining / maximum * 100
    floor = float(config["safety"].get("stop_if_api_remaining_percent_below", 20.0))
    if pct < floor:
        raise RuntimeError(f"Assessment stopped before metadata collection: DailyApiRequests remaining is {pct:.1f}%, below configured safety floor {floor:.1f}%.")


def _deploy_status(sf: SFCLI) -> dict[str, Any]:
    q = sf.query(
        "SELECT Id, Status, CheckOnly, CreatedDate, CompletedDate FROM DeployRequest ORDER BY CreatedDate DESC LIMIT 20",
        tooling=True,
        tolerate_failure=True,
    )
    if not q.get("ok"):
        return {"known": False, "active": [], "error": q.get("error")}
    records = _unwrap(q.get("payload", {}))
    if isinstance(records, dict):
        records = records.get("records", [])
    if not isinstance(records, list):
        records = []
    active = [r for r in records if str(r.get("Status", "")).lower().replace(" ", "") in ACTIVE_DEPLOY_STATUSES]
    return {"known": True, "active": active, "recent": records[:10]}


def _wait_for_deploys(sf: SFCLI, config: dict[str, Any], audit: dict[str, Any], max_wait_seconds: int = 0) -> bool:
    status = _deploy_status(sf)
    audit["deployment_guard"] = status
    if not status.get("known"):
        if config["safety"].get("fail_if_deploy_status_unknown", False):
            raise RuntimeError("Could not determine deployment status and fail_if_deploy_status_unknown=true.")
        return True
    if not status.get("active"):
        return True
    if not config["safety"].get("pause_metadata_if_deploy_active", True):
        return True
    if max_wait_seconds <= 0:
        return False
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        time.sleep(min(30, max(1, deadline - time.time())))
        status = _deploy_status(sf)
        audit["deployment_guard"] = status
        if status.get("known") and not status.get("active"):
            return True
    return False


def _query_runtime(sf: SFCLI) -> dict[str, Any]:
    queries = {
        "organization": (False, "SELECT Id, Name, OrganizationType, InstanceName, IsSandbox FROM Organization LIMIT 1"),
        "users": (False, "SELECT IsActive, COUNT(Id) total FROM User GROUP BY IsActive"),
        "async_apex_recent": (False, "SELECT Id, JobType, Status, ApexClassId, CreatedDate, CompletedDate, NumberOfErrors FROM AsyncApexJob WHERE CreatedDate = LAST_N_DAYS:30 ORDER BY CreatedDate DESC LIMIT 2000"),
        "scheduled_jobs": (False, "SELECT Id, State, NextFireTime, PreviousFireTime, TimesTriggered, CronJobDetail.Name FROM CronTrigger ORDER BY NextFireTime ASC NULLS LAST LIMIT 1000"),
        "api_total_usage_logs": (False, "SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE EventType = 'ApiTotalUsage' AND LogDate = LAST_N_DAYS:1 ORDER BY LogDate DESC LIMIT 50"),
        "apex_classes_tooling": (True, "SELECT Id, Name, ApiVersion, Status, NamespacePrefix, LengthWithoutComments, CreatedDate, LastModifiedDate FROM ApexClass ORDER BY Name"),
        "apex_triggers_tooling": (True, "SELECT Id, Name, ApiVersion, Status, NamespacePrefix, LengthWithoutComments, CreatedDate, LastModifiedDate FROM ApexTrigger ORDER BY Name"),
    }
    result: dict[str, Any] = {}
    for name, (tooling, soql) in queries.items():
        q = sf.query(soql, tooling=tooling, tolerate_failure=True)
        if q.get("ok"):
            result[name] = _unwrap(q["payload"])
        else:
            result[name] = {"unavailable": True, "error": q.get("error")}
    return result


def _manifest_api_version(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        root = ET.parse(path).getroot()
        for n in root.iter():
            if n.tag.split("}", 1)[-1] == "version" and n.text:
                return n.text.strip()
    except Exception:
        return None
    return None


def _remove_source_bodies(components: dict[str, Any]) -> None:
    for key in ("apex_classes", "apex_triggers"):
        for item in components.get(key, []):
            text = item.pop("text", "")
            item["source_sha256"] = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest() if text else ""


def _copy_config_for_run(config_path: str | None, output_dir: Path) -> None:
    if config_path and Path(config_path).exists():
        shutil.copy2(config_path, output_dir / "assessment-config.yml")


def run_assessment(target_org: str, work_dir: Path, output_dir: Path, config: dict[str, Any], *, wait_for_deploy_seconds: int = 0, source_dir: Path | None = None, resume: bool = False) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = CheckpointStore(output_dir / "checkpoint.json")
    project_file = work_dir / "sfdx-project.json"
    if not project_file.exists():
        project_file.write_text(json.dumps({
            "packageDirectories": [{"path": "force-app", "default": True}],
            "namespace": ""
        }, indent=2), encoding="utf-8")
    (work_dir / "force-app" / "main" / "default").mkdir(parents=True, exist_ok=True)

    audit: dict[str, Any] = {
        "mode": config["safety"].get("mode", "CONTROLLED_READ_ONLY"),
        "commands": [], "read_operations": 0, "read_errors": [],
        "metadata_retrieve_executed": False,
        "dml_executed": 0, "metadata_deployments": 0, "apex_anonymous_executions": 0,
    }
    SFCLI.ensure_available()
    sf = SFCLI(target_org, work_dir, audit, config)

    checkpoint.mark("preflight", "running")
    org = _normalize_org(sf.org_display())
    limits_before = _normalize_limits(sf.limits())
    _check_api_headroom(limits_before, config)
    checkpoint.mark("preflight", "done")

    checkpoint.mark("runtime_collection", "running")
    runtime = _query_runtime(sf)
    runtime_v2 = collect_v2_runtime(sf, config)
    checkpoint.mark("runtime_collection", "done")
    limits_mid = _normalize_limits(sf.limits())
    budget_hit, budget_state = _budget_exceeded(limits_before, limits_mid, config)
    audit["api_budget_runtime_phase"] = budget_state

    can_retrieve = (not budget_hit) and _wait_for_deploys(sf, config, audit, max_wait_seconds=wait_for_deploy_seconds)
    manifest_dir = work_dir / "manifest"
    manifest_path = manifest_dir / "package.xml"
    strict_mode = str(config["safety"].get("mode", "")).upper() == "STRICT_READ_ONLY"
    if source_dir is not None:
        can_retrieve = False
        audit["metadata_source"] = "external_snapshot"
    elif strict_mode:
        can_retrieve = False
        audit["metadata_source"] = "none_strict_read_only"
        audit.setdefault("read_errors", []).append({"phase": "metadata_retrieve", "message": "STRICT_READ_ONLY mode does not invoke Metadata API retrieve. Provide --source-dir with a previously retrieved Salesforce source snapshot for full static analysis."})
    else:
        audit["metadata_source"] = "salesforce_retrieve"

    resume_source = work_dir / "force-app" / "main" / "default"
    if resume and source_dir is None and checkpoint.done("metadata_retrieve") and resume_source.exists() and any(resume_source.rglob("*")):
        can_retrieve = False
        audit["metadata_source"] = "checkpoint_resume"
        audit["resumed_from_checkpoint"] = True

    if can_retrieve:
        checkpoint.mark("metadata_retrieve", "running")
        sf.generate_manifest(config["metadata"]["types"], manifest_dir, int(config["metadata"].get("list_metadata_batch_size", 10)))
        limits_after_manifest = _normalize_limits(sf.limits())
        manifest_budget_hit, manifest_budget_state = _budget_exceeded(limits_before, limits_after_manifest, config)
        audit["api_budget_after_manifest"] = manifest_budget_state
        if not manifest_path.exists():
            # Some CLI versions can put the manifest at the project root depending on flags/plugin behavior.
            candidate = work_dir / "package.xml"
            if candidate.exists():
                manifest_path = candidate
        if not manifest_path.exists():
            raise RuntimeError("Manifest generation completed but package.xml was not found.")
        if manifest_budget_hit:
            audit.setdefault("read_errors", []).append({"phase": "metadata_retrieve", "message": "Skipped because configured API budget was exceeded during metadata discovery."})
        else:
            sf.retrieve(manifest_path)
            audit["metadata_retrieve_executed"] = True
            checkpoint.mark("metadata_retrieve", "done", manifest=str(manifest_path))
    elif source_dir is None and not strict_mode:
        reason = "configured API budget was reached" if budget_hit else "an active deploy/validate was detected and wait window was zero or expired"
        audit.setdefault("read_errors", []).append({
            "phase": "metadata_retrieve",
            "message": f"Skipped because {reason}."
        })

    source_root = source_dir.resolve() if source_dir is not None else (work_dir / "force-app" / "main" / "default")
    checkpoint.mark("static_analysis", "running", source_root=str(source_root))
    components = parse_source(source_root)
    components["runtime"] = runtime
    components["runtime_v2"] = runtime_v2
    components["manifest_api_version"] = _manifest_api_version(manifest_path)

    code_analyzer_path = output_dir / "code-analyzer.json"
    if config["analysis"].get("run_code_analyzer", True) and any(source_root.rglob("*.cls")):
        ca_exec = sf.code_analyzer(source_root, code_analyzer_path, config["analysis"].get("code_analyzer_rule_selector", "Recommended"))
        if not ca_exec.get("ok") and not code_analyzer_path.exists():
            audit.setdefault("read_errors", []).append({"phase": "code_analyzer", "message": ca_exec.get("error")})

    findings, health, dependencies, ca = analyze(components, config, code_analyzer_path if code_analyzer_path.exists() else None)
    components["intelligence"] = build_intelligence(components, dependencies, runtime_v2, config)
    analyze_v2_intelligence(components, findings)
    components["intelligence"]["v3"] = build_v3_intelligence(sf, components, dependencies, findings, runtime_v2, config, output_dir)
    components["intelligence"]["v4"] = build_v4_intelligence(components, dependencies, runtime_v2)
    components["intelligence"]["v5"] = build_v5_intelligence(source_root)
    analyze_v3_intelligence(components, findings)
    # Final enterprise correlation layer: transaction topology, deep Flow/Apex/test/data/runtime/integration intelligence.
    components["intelligence"]["v7"] = build_v7_intelligence(components, dependencies, findings, runtime_v2)
    analyze_v7_intelligence(components, findings)
    # Recalculate blast radius after all semantic and transaction edges have been added.
    from .intelligence import calculate_blast_radius
    components["intelligence"]["blast_radius"] = calculate_blast_radius(dependencies)
    health = calculate_health(findings, config, components)
    components["intelligence"]["enterprise"] = build_enterprise_intelligence(components, dependencies, findings, health, audit)
    # Replace dependency list with normalized enterprise edges so graph metrics and later
    # diffs are stable even when multiple scanners discover the same relationship.
    dependencies = components["intelligence"]["enterprise"]["digital_twin"]["normalized_edges"]
    _remove_source_bodies(components)
    checkpoint.mark("static_analysis", "done")
    limits_after = _normalize_limits(sf.limits())
    audit["api_budget"] = _api_budget(limits_before, limits_after, config)

    finished = datetime.now(timezone.utc)
    result = AssessmentResult(
        product=config["product"],
        run={
            "target_org": target_org,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round((finished - started).total_seconds(), 2),
            "work_dir": str(work_dir),
            "output_dir": str(output_dir),
        },
        org=org,
        limits_before=limits_before,
        limits_after=limits_after,
        inventory=components.pop("inventory", {}),
        components=components,
        dependencies=dependencies,
        findings=findings,
        health=health,
        audit=audit,
        code_analyzer=ca,
    )
    snapshot_payload = result.to_dict()
    snapshot_payload["components"]["intelligence"]["v7"]["final_readiness"] = final_readiness(snapshot_payload)
    # Keep result payload synchronized with the enriched snapshot used for reports.
    result.components["intelligence"]["v7"]["final_readiness"] = snapshot_payload["components"]["intelligence"]["v7"]["final_readiness"]
    audit["snapshot_digest_sha256"] = stable_snapshot_digest(snapshot_payload)
    payload_validation = validate_assessment_payload(snapshot_payload)
    audit["payload_validation"] = payload_validation
    if not payload_validation["valid"]:
        raise RuntimeError("Assessment payload validation failed: " + "; ".join(payload_validation["errors"]))

    checkpoint.mark("report_generation", "running")
    reports = generate_reports(result, output_dir, config)
    checkpoint.mark("report_generation", "done")
    integrity = integrity_manifest(output_dir, exclude_names={"integrity-manifest.json", "checkpoint.json", "run-manifest.json"})
    (output_dir / "integrity-manifest.json").write_text(json.dumps(integrity, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest = {
        "product": config["product"],
        "target_org": target_org,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "assessment_mode": audit["mode"],
        "health": health,
        "reports": reports,
        "audit": audit,
        "integrity": {"file": str(output_dir / "integrity-manifest.json"), "artifact_count": integrity.get("count", 0)},
    }
    (output_dir / "run-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    checkpoint.mark("complete", "done")
    return manifest
