from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import yaml


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | None = None) -> dict[str, Any]:
    project_default = Path(__file__).resolve().parents[2] / "config" / "default.yml"
    # When installed as a wheel, config/default.yml is outside package data. Fall back to embedded defaults.
    embedded = {
        "product": {"name": "Labforce Dementor for Salesforce", "version": "4.3.0"},
        "safety": {
            "mode": "CONTROLLED_READ_ONLY",
            "pause_metadata_if_deploy_active": True,
            "fail_if_deploy_status_unknown": False,
            "max_api_budget_percent_of_remaining": 5.0,
            "stop_if_api_remaining_percent_below": 20.0,
            "max_retries": 3,
            "retry_base_seconds": 1.5,
            "min_seconds_between_cli_calls": 0.15,
        },
        "metadata": {
            "full_org": True,
            "require_complete_snapshot": True,
            "fallback_to_configured_types": True,
            "include_packages": [],
            "list_metadata_batch_size": 10,
            "retrieve_batch_members": 500,
            "types": [
            "ApexClass", "ApexTrigger", "ApexPage", "AuraDefinitionBundle",
            "LightningComponentBundle", "CustomApplication", "CustomObject", "Layout",
            "FlexiPage", "Flow", "Workflow", "ApprovalProcess", "PermissionSet",
            "PermissionSetGroup", "Profile", "SharingRules", "CustomPermission",
            "ConnectedApp", "NamedCredential", "ExternalCredential", "AuthProvider",
            "RemoteSiteSetting", "CorsWhitelistOrigin", "CSPTrustedSite", "CustomMetadata",
            "CustomLabels", "ReportType", "Report", "Dashboard"
        ]},
        "analysis": {
            "run_code_analyzer": True,
            "code_analyzer_rule_selector": "Recommended",
            "unused_reference_confidence_threshold": 0.9,
            "old_api_version_gap": 5,
            "god_class": {"min_lines": 500, "min_methods": 20, "min_complexity": 50, "min_dependencies": 12, "min_responsibilities": 8, "min_score": 65},
            "god_test_class": {"min_lines": 700, "min_test_methods": 25, "min_dependencies": 15, "min_responsibilities": 10, "min_score": 65},
            "org_limits": {"warning_remaining_percent": 20, "critical_remaining_percent": 10},
            "governor_risk": {"soql_statements": 80, "dml_statements": 120, "callouts": 80},
        },
        "scoring": {
            "weights": {"security": .20, "architecture": .12, "performance": .12, "automation": .10, "apex": .10, "testing": .08, "integrations": .08, "data_quality": .06, "governance": .06, "maintainability": .05, "observability": .03},
            "severity_penalty": {"critical": 12, "high": 6, "medium": 2, "low": .5, "info": 0},
        },
        "report": {"title": "Assessment da organização Salesforce", "confidentiality": "Confidencial", "company_name": "", "timezone": "America/Maceio"},
    }
    base = embedded
    if project_default.exists():
        base = _merge(base, yaml.safe_load(project_default.read_text(encoding="utf-8")) or {})
    if path:
        custom = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        base = _merge(base, custom)
    for group in ("god_class", "god_test_class", "governor_risk"):
        for name, value in base["analysis"][group].items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise RuntimeError(f"analysis.{group}.{name} must be a positive number")
    thresholds = base["analysis"]["org_limits"]
    if not 0 <= thresholds["critical_remaining_percent"] <= thresholds["warning_remaining_percent"] <= 100:
        raise RuntimeError("Org limits require 0 <= critical_remaining_percent <= warning_remaining_percent <= 100")
    if set(base["metadata"].get("include_packages", [])) - {"managed", "unlocked"}:
        raise RuntimeError("metadata.include_packages supports only managed and unlocked")
    return base
