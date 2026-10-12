from __future__ import annotations

import hashlib
import json
import shutil
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .analyzer import analyze, analyze_v2_intelligence, calculate_health, analyze_limit_governance
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
from .governance_analysis import analyze_org_limits
from .retrieve_audit import manifest_summary, retrieve_audit, snapshot_files, write_retrieve_audit, split_manifest, merge_profile_fragments


ACTIVE_DEPLOY_STATUSES = {"pending", "inprogress", "queued", "canceling"}
ProgressCallback = Callable[[str, str, str | None], None]


def _emit_progress(progress: ProgressCallback | None, stage: str, status: str, detail: str | None = None) -> None:
    if progress is not None:
        progress(stage, status, detail)


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


def _query_runtime(sf: SFCLI, progress: ProgressCallback | None = None) -> dict[str, Any]:
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
    labels = {
        "organization": "Organização",
        "users": "Usuários",
        "async_apex_recent": "Apex assíncrono",
        "scheduled_jobs": "Jobs agendados",
        "api_total_usage_logs": "Uso de API",
        "apex_classes_tooling": "Classes Apex",
        "apex_triggers_tooling": "Triggers Apex",
    }
    total = len(queries)
    for index, (name, (tooling, soql)) in enumerate(queries.items(), start=1):
        _emit_progress(progress, "runtime_collection", "update", f"{labels[name]} ({index}/{total})")
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


def _manifest_summary(path: Path) -> dict[str, Any]:
    return manifest_summary(path)


def _remove_source_bodies(components: dict[str, Any]) -> None:
    for key in ("apex_classes", "apex_triggers"):
        for item in components.get(key, []):
            text = item.pop("text", "")
            item["source_sha256"] = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest() if text else ""


def _copy_config_for_run(config_path: str | None, output_dir: Path) -> None:
    if config_path and Path(config_path).exists():
        shutil.copy2(config_path, output_dir / "assessment-config.yml")


def run_assessment(
    target_org: str,
    work_dir: Path,
    output_dir: Path,
    config: dict[str, Any],
    *,
    wait_for_deploy_seconds: int = 0,
    source_dir: Path | None = None,
    resume: bool = False,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = CheckpointStore(output_dir / "checkpoint.json")
    existing_source = work_dir / "force-app" / "main" / "default"
    if source_dir is None and not resume and any(path.is_file() for path in existing_source.rglob("*")):
        raise RuntimeError("Use an empty --work-dir for a new retrieve or --resume for a verified checkpoint. Existing source files were preserved.")
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

    _emit_progress(progress, "preflight", "start", "Conferindo Salesforce CLI e autenticação")
    checkpoint.mark("preflight", "running")
    org = _normalize_org(sf.org_display())
    limits_before = _normalize_limits(sf.limits())
    _check_api_headroom(limits_before, config)
    checkpoint.mark("preflight", "done")
    org_label = str(org.get("name") or org.get("username") or target_org)
    _emit_progress(progress, "preflight", "done", org_label)

    _emit_progress(progress, "runtime_collection", "start", "Consultando sinais da organização")
    checkpoint.mark("runtime_collection", "running")
    runtime = _query_runtime(sf, progress)
    _emit_progress(progress, "runtime_collection", "update", "Inteligência operacional expandida")
    runtime_v2 = collect_v2_runtime(sf, config)
    checkpoint.mark("runtime_collection", "done")
    _emit_progress(progress, "runtime_collection", "done", f"{len(runtime)} grupos básicos coletados")
    limits_mid = _normalize_limits(sf.limits())
    budget_hit, budget_state = _budget_exceeded(limits_before, limits_mid, config)
    audit["api_budget_runtime_phase"] = budget_state

    _emit_progress(progress, "deployment_guard", "start", "Consultando atividades de deploy/validate")
    if budget_hit:
        can_retrieve = False
        _emit_progress(progress, "deployment_guard", "skipped", "Limite seguro de API já atingido")
    else:
        can_retrieve = _wait_for_deploys(sf, config, audit, max_wait_seconds=wait_for_deploy_seconds)
        active_deploys = len(audit.get("deployment_guard", {}).get("active", []))
        deploy_detail = "Nenhum deploy ativo" if not active_deploys else f"{active_deploys} atividade(s) ativa(s)"
        _emit_progress(progress, "deployment_guard", "done", deploy_detail)
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
        stage = checkpoint.data["stages"]["metadata_retrieve"]
        ledger_path = output_dir / "metadata-retrieve-audit.json"
        if stage.get("org_id") != org.get("id") or not ledger_path.exists():
            raise RuntimeError("Resume stopped: checkpoint org identity or retrieve audit is unavailable. Start with an empty work directory.")
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        if ledger.get("files") != snapshot_files(resume_source):
            raise RuntimeError("Resume stopped: metadata snapshot differs from its audited hashes.")
        can_retrieve = False
        audit["metadata_source"] = "checkpoint_resume"
        audit["metadata_coverage"] = {key: value for key, value in ledger.items() if key not in {"files", "returned_members"}}
        audit["resumed_from_checkpoint"] = True

    _emit_progress(progress, "metadata_retrieve", "start", "Definindo origem dos metadados")
    if can_retrieve:
        checkpoint.mark("metadata_retrieve", "running")
        if manifest_path.exists() or (work_dir / "package.xml").exists():
            raise RuntimeError("A fresh retrieve requires a work directory without an existing package.xml. Existing files were preserved.")
        metadata_cfg = config.get("metadata", {})
        full_org = bool(metadata_cfg.get("full_org", True))
        _emit_progress(progress, "metadata_retrieve", "update", "Descobrindo todo metadado recuperável da org" if full_org else "Gerando manifesto package.xml")
        try:
            sf.generate_manifest(
                None if full_org else list(metadata_cfg.get("types", [])),
                manifest_dir,
                int(metadata_cfg.get("list_metadata_batch_size", 10)),
                include_packages=list(metadata_cfg.get("include_packages", [])),
            )
            audit["metadata_discovery_mode"] = "full_org" if full_org else "configured_types"
        except SFCLIError as exc:
            if not full_org or not metadata_cfg.get("fallback_to_configured_types", True) or metadata_cfg.get("require_complete_snapshot", True):
                raise
            audit.setdefault("read_errors", []).append({
                "phase": "full_org_manifest",
                "message": f"Full metadata discovery failed; configured-type fallback used: {exc}",
            })
            _emit_progress(progress, "metadata_retrieve", "update", "Descoberta ampla falhou; usando lista de tipos configurada")
            sf.generate_manifest(
                list(metadata_cfg.get("types", [])),
                manifest_dir,
                int(metadata_cfg.get("list_metadata_batch_size", 10)),
                include_packages=list(metadata_cfg.get("include_packages", [])),
            )
            audit["metadata_discovery_mode"] = "configured_types_fallback"
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
        audit["metadata_manifest"] = _manifest_summary(manifest_path)
        if audit["metadata_manifest"].get("error") or not audit["metadata_manifest"].get("members"):
            raise RuntimeError("Manifest is malformed or empty; static analysis was not started.")
        shutil.copy2(manifest_path, output_dir / "metadata-package.xml")
        write_retrieve_audit({"status": "discovered", "manifest": audit["metadata_manifest"], "files": []}, output_dir / "metadata-retrieve-audit.json")
        if manifest_budget_hit:
            message = "Configured API budget was exceeded during complete metadata discovery."
            audit.setdefault("read_errors", []).append({"phase": "metadata_retrieve", "message": message})
            if metadata_cfg.get("require_complete_snapshot", True):
                raise RuntimeError("Assessment stopped: the safe API budget was reached before the complete metadata snapshot could be retrieved.")
            _emit_progress(progress, "metadata_retrieve", "skipped", "Limite seguro de API atingido após o manifesto")
        else:
            _check_api_headroom(limits_after_manifest, config)
            if not _wait_for_deploys(sf, config, audit, max_wait_seconds=wait_for_deploy_seconds):
                raise RuntimeError("Retrieve stopped: a deploy/validate became active during metadata discovery.")
            manifest_summary = audit["metadata_manifest"]
            _emit_progress(progress, "metadata_retrieve", "update", f"Baixando snapshot read-only: {manifest_summary.get('types', 0)} tipos e {manifest_summary.get('members', 0)} membros")
            batches = split_manifest(manifest_path, output_dir / "metadata-manifests", int(metadata_cfg.get("retrieve_batch_members", 500)))
            merged: dict[str, Any] = {"status": "Succeeded", "done": True, "files": [], "messages": []}
            warnings: list[Any] = []
            audit["metadata_retrieve_batches"] = []
            try:
                for index, batch in enumerate(batches, 1):
                    if index > 1:
                        current_limits = _normalize_limits(sf.limits())
                        hit, state = _budget_exceeded(limits_before, current_limits, config)
                        if hit:
                            raise RuntimeError("Retrieve stopped between batches: configured API budget was reached.")
                        _check_api_headroom(current_limits, config)
                        if not _wait_for_deploys(sf, config, audit, max_wait_seconds=wait_for_deploy_seconds):
                            raise RuntimeError("Retrieve stopped between batches: deploy/validate is active.")
                    _emit_progress(progress, "metadata_retrieve", "update", f"Recuperando lote {index}/{len(batches)}")
                    previous_profiles = {path.name: path.read_bytes() for path in (existing_source / "profiles").glob("*.profile-meta.xml")}
                    reply = sf.retrieve(batch)
                    batch_result = _unwrap(reply)
                    batch_result = batch_result if isinstance(batch_result, dict) else {}
                    audit["metadata_retrieve_batches"].append({"index": index, "manifest": _manifest_summary(batch), "status": batch_result.get("status"), "id": batch_result.get("id")})
                    for key in ("files", "messages"):
                        values = batch_result.get(key, batch_result.get("fileProperties", []) if key == "files" else []) or []
                        merged[key].extend(values if isinstance(values, list) else [values])
                    if reply.get("warnings"):
                        warnings.extend(reply["warnings"] if isinstance(reply["warnings"], list) else [reply["warnings"]])
                    if reply.get("status", 0) not in (0, None) or batch_result.get("success") is False or batch_result.get("done") is False or str(batch_result.get("status", "")).lower() in {"failed", "error", "pending", "inprogress", "canceled"}:
                        raise RuntimeError("Salesforce returned an unsuccessful retrieve batch.")
                    audit["metadata_retrieve_batches"][-1]["profile_grants_merged"] = merge_profile_fragments(previous_profiles, existing_source)
                retrieve_result = {"status": 0, "result": merged, "warnings": warnings}
            except (SFCLIError, RuntimeError) as exc:
                write_retrieve_audit({"status": "failed", "manifest": audit["metadata_manifest"], "error": str(exc), "batches": audit["metadata_retrieve_batches"], "files": snapshot_files(existing_source)}, output_dir / "metadata-retrieve-audit.json")
                raise
            audit["metadata_retrieve_executed"] = True
            audit["metadata_retrieve_result"] = {
                "status": _unwrap(retrieve_result).get("status"),
                "done": _unwrap(retrieve_result).get("done"),
            }
            retrieved_root = work_dir / "force-app" / "main" / "default"
            retrieved_files = sum(1 for path in retrieved_root.rglob("*") if path.is_file())
            audit["metadata_snapshot_files"] = retrieved_files
            ledger = retrieve_audit(manifest_path, retrieved_root, retrieve_result,
                                    mode=audit["metadata_discovery_mode"], include_packages=list(metadata_cfg.get("include_packages", [])))
            ledger["batches"] = audit["metadata_retrieve_batches"]
            # Tooling inventory provides independent coverage evidence for visible unmanaged Apex.
            for key, directory, suffix in (("apex_classes_tooling", "classes", ".cls"), ("apex_triggers_tooling", "triggers", ".trigger")):
                records = runtime.get(key, {}).get("records", [])
                missing = [row["Name"] for row in records if not row.get("NamespacePrefix") and row.get("Status") != "Deleted" and row.get("Name") and not (retrieved_root / directory / f"{row['Name']}{suffix}").exists()]
                if missing:
                    ledger.setdefault("missing_apex_from_tooling", {})[key] = missing
                    ledger["status"] = "partial"
            write_retrieve_audit(ledger, output_dir / "metadata-retrieve-audit.json")
            audit["metadata_coverage"] = {key: value for key, value in ledger.items() if key not in {"files", "returned_members"}}
            if ledger["retrieve_failed"] or (metadata_cfg.get("require_complete_snapshot", True) and (ledger["status"] == "partial" or ledger["unverified_members"])):
                raise RuntimeError("Assessment stopped: snapshot coverage is partial or unverified. Review metadata-retrieve-audit.json before retrying.")
            checkpoint.mark("metadata_retrieve", "done", manifest=str(manifest_path), org_id=org.get("id"))
            _emit_progress(progress, "metadata_retrieve", "done", f"Snapshot Salesforce recuperado: {retrieved_files} arquivos")
    elif audit.get("metadata_source") == "checkpoint_resume":
        _emit_progress(progress, "metadata_retrieve", "done", "Snapshot reutilizado do checkpoint")
    elif source_dir is None and not strict_mode:
        reason = "configured API budget was reached" if budget_hit else "an active deploy/validate was detected and wait window was zero or expired"
        audit.setdefault("read_errors", []).append({
            "phase": "metadata_retrieve",
            "message": f"Skipped because {reason}."
        })
        safe_reason = "Limite seguro de API atingido" if budget_hit else "Deploy ativo; recuperação evitada"
        if config.get("metadata", {}).get("require_complete_snapshot", True):
            raise RuntimeError(f"Assessment stopped before static analysis: {safe_reason}. A complete metadata snapshot is required.")
        _emit_progress(progress, "metadata_retrieve", "skipped", safe_reason)
    elif source_dir is not None:
        if not source_dir.exists() or not any(path.is_file() for path in source_dir.rglob("*")):
            raise RuntimeError(f"Assessment stopped: the local metadata snapshot is empty or unavailable: {source_dir}")
        _emit_progress(progress, "metadata_retrieve", "done", "Usando snapshot local informado")
        ledger = {"schema": "dementor-retrieve-audit-v1", "status": "external_snapshot_unverified", "org_completeness_proven": False, "files": snapshot_files(source_dir), "boundary": "Snapshot supplied by the user; org coverage was not independently verified."}
        write_retrieve_audit(ledger, output_dir / "metadata-retrieve-audit.json")
        audit["metadata_coverage"] = {key: value for key, value in ledger.items() if key != "files"}
    elif strict_mode:
        if config.get("metadata", {}).get("require_complete_snapshot", True):
            raise RuntimeError("Assessment stopped: STRICT_READ_ONLY requires --source-dir with a previously retrieved complete snapshot.")
        _emit_progress(progress, "metadata_retrieve", "skipped", "STRICT_READ_ONLY sem snapshot local")

    source_root = source_dir.resolve() if source_dir is not None else (work_dir / "force-app" / "main" / "default")
    _emit_progress(progress, "static_analysis", "start", "Lendo componentes do snapshot")
    checkpoint.mark("static_analysis", "running", source_root=str(source_root))
    components = parse_source(source_root)
    audit["metadata_parser_boundary"] = "Retrieved files are all hashed; semantic rules cover the component families implemented by the parser. Retrieval does not imply semantic analysis of every metadata type."
    components["org_limit_governance"] = analyze_org_limits(limits_before, config)
    components["runtime"] = runtime
    components["runtime_v2"] = runtime_v2
    components["manifest_api_version"] = _manifest_api_version(manifest_path)

    code_analyzer_path = output_dir / "code-analyzer.json"
    if config["analysis"].get("run_code_analyzer", True) and any(source_root.rglob("*.cls")):
        _emit_progress(progress, "static_analysis", "update", "Executando Salesforce Code Analyzer")
        ca_exec = sf.code_analyzer(source_root, code_analyzer_path, config["analysis"].get("code_analyzer_rule_selector", "Recommended"))
        if not ca_exec.get("ok") and not code_analyzer_path.exists():
            audit.setdefault("read_errors", []).append({"phase": "code_analyzer", "message": ca_exec.get("error")})

    _emit_progress(progress, "static_analysis", "update", "Correlacionando arquitetura, riscos e dependências")
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
    limits_after = _normalize_limits(sf.limits())
    components["org_limit_governance"] = analyze_org_limits(limits_after, config, limits_before)
    findings[:] = [finding for finding in findings if not finding.id.startswith("ORGLIMIT-")]
    analyze_limit_governance(components, findings)
    audit["api_budget"] = _api_budget(limits_before, limits_after, config)
    exceeded, budget_final = _budget_exceeded(limits_before, limits_after, config)
    audit["api_budget_final"] = {**budget_final, "exceeded": exceeded, "note": "Checkpoints estimate org-wide usage; individual CLI operations can exceed the remaining budget before the next measurement."}
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
    _emit_progress(progress, "static_analysis", "done", f"{len(findings)} achado(s); health score {health.get('overall', 0)}/100")

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

    _emit_progress(progress, "report_generation", "start", "Renderizando JSON, Markdown, HTML e PDF")
    checkpoint.mark("report_generation", "running")
    reports = generate_reports(result, output_dir, config)
    checkpoint.mark("report_generation", "done")
    _emit_progress(progress, "report_generation", "done", "Relatórios gerados")
    _emit_progress(progress, "integrity", "start", "Calculando hashes SHA-256")
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
    _emit_progress(progress, "integrity", "done", f"{integrity.get('count', 0)} artefato(s) verificado(s)")
    return manifest
