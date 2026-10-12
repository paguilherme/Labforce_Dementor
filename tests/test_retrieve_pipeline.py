from __future__ import annotations

import json
import pytest
from pathlib import Path

from labforce_dementor.config import load_config
from labforce_dementor.engine import run_assessment
from labforce_dementor.sfcli import SFCLIError
from labforce_dementor.retrieve_audit import retrieve_audit, split_manifest, manifest_summary, merge_profile_fragments


class FakeSF:
    error = None
    org_id = "00DTEST"
    deploy_on_second = False
    deploy_threshold = 2
    discovery_failure = False

    def __init__(self, target_org, cwd, audit, config):
        self.target_org, self.cwd, self.audit = target_org, cwd, audit
        self.limit_reads = self.deploy_reads = 0
        self.metadata_retrieved = False

    @staticmethod
    def ensure_available():
        pass

    def org_display(self):
        return {"result": {"id": self.org_id, "username": "fixture", "accessToken": "must-not-persist"}}

    def limits(self):
        self.limit_reads += 1
        return {"result": [{"name": "DailyApiRequests", "max": 1000, "remaining": 900},
                           {"name": "DataStorageMB", "max": 100, "remaining": 5 if self.metadata_retrieved else 90}]}

    def query(self, soql, **kwargs):
        rows = []
        if "FROM DeployRequest" in soql:
            self.deploy_reads += 1
            if self.deploy_on_second and self.deploy_reads >= self.deploy_threshold:
                rows = [{"Status": "InProgress"}]
        if "FROM ApexClass ORDER" in soql:
            rows = [{"Name": "Sample", "NamespacePrefix": None, "Status": "Active"}]
        return {"ok": True, "payload": {"result": {"records": rows, "totalSize": len(rows)}}}

    def rest_get(self, *args, **kwargs):
        return {"ok": False, "error": "telemetry unavailable in fixture"}

    def generate_manifest(self, metadata_types, manifest_dir, *args, **kwargs):
        if self.discovery_failure and metadata_types is None:
            raise SFCLIError("fixture discovery failure")
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "package.xml").write_text('<Package xmlns="http://soap.sforce.com/2006/04/metadata"><types><members>Sample</members><name>ApexClass</name></types><version>66.0</version></Package>')
        return {"status": 0}

    def retrieve(self, path):
        self.metadata_retrieved = True
        directory = self.cwd / "force-app/main/default/classes"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "Sample.cls").write_text("public with sharing class Sample { public static void run() { List<Account> a = [SELECT Id FROM Account]; } }")
        (directory / "Sample.cls-meta.xml").write_text('<ApexClass xmlns="http://soap.sforce.com/2006/04/metadata"><apiVersion>66.0</apiVersion><status>Active</status></ApexClass>')
        return {"status": 0, "result": {"status": "Succeeded", "done": True, "files": [{"type": "ApexClass", "fullName": "Sample"}], "messages": [self.error] if self.error else []}}


def setup(monkeypatch):
    import labforce_dementor.engine as engine
    monkeypatch.setattr(engine, "SFCLI", FakeSF)
    monkeypatch.setattr(FakeSF, "error", None)
    monkeypatch.setattr(FakeSF, "org_id", "00DTEST")
    monkeypatch.setattr(FakeSF, "deploy_on_second", False)
    monkeypatch.setattr(FakeSF, "deploy_threshold", 2)
    monkeypatch.setattr(FakeSF, "discovery_failure", False)
    config = load_config()
    config["analysis"]["run_code_analyzer"] = False
    return config


def test_retrieve_to_reports_uses_final_limits_and_persists_audit(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    output = tmp_path / "reports"
    result = run_assessment("fixture", tmp_path / "work", output, config)
    snapshot = json.loads((output / "assessment.json").read_text())
    ledger = json.loads((output / "metadata-retrieve-audit.json").read_text())
    assert ledger["status"] == "verified_requested_members"
    assert ledger["file_count"] == 2
    assert len(ledger["manifest"]["sha256"]) == 64
    assert all(len(row["sha256"]) == 64 for row in ledger["files"])
    assert snapshot["components"]["org_limit_governance"]["critical_count"] == 1
    assert any(row["id"].startswith("ORGLIMIT-") for row in snapshot["findings"])
    assert snapshot["health"]["categories"]["governance"] < 100
    assert "must-not-persist" not in (output / "assessment.json").read_text()
    assert "text" not in snapshot["components"]["apex_classes"][0]
    assert (output / "metadata-package.xml").exists()
    for name in ("assessment.md", "assessment.html"):
        text = (output / name).read_text()
        assert "Todos os limites observados" in text
        assert "metadata-retrieve-audit.json" in text
    assert result["reports"]["pdf"]["generated"]
    assert (output / "charts/org_limit_headroom.png").exists()


def test_partial_retrieve_stops_before_analysis_with_reviewable_evidence(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    monkeypatch.setattr(FakeSF, "error", "component omitted by Salesforce")
    with pytest.raises(RuntimeError, match="partial"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)
    assert json.loads((tmp_path / "reports/metadata-retrieve-audit.json").read_text())["status"] == "partial"
    assert not (tmp_path / "reports/assessment.json").exists()


def test_deploy_guard_is_rechecked_after_discovery(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    monkeypatch.setattr(FakeSF, "deploy_on_second", True)
    with pytest.raises(RuntimeError, match="became active"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)
    assert not (tmp_path / "work/force-app/main/default/classes/Sample.cls").exists()


def test_complete_mode_never_silently_falls_back_to_narrow_types(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    monkeypatch.setattr(FakeSF, "discovery_failure", True)
    with pytest.raises(SFCLIError, match="discovery"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)


def test_existing_work_directory_cannot_masquerade_as_fresh_retrieve(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    path = tmp_path / "work/force-app/main/default/classes/Stale.cls"
    path.parent.mkdir(parents=True)
    path.write_text("stale")
    with pytest.raises(RuntimeError, match="empty --work-dir"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)
    assert path.read_text() == "stale"


@pytest.mark.parametrize("changed_org", [False, True])
def test_resume_checks_hashes_and_org_identity(tmp_path, monkeypatch, changed_org):
    config = setup(monkeypatch)
    run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)
    if changed_org:
        monkeypatch.setattr(FakeSF, "org_id", "00DOTHER")
    else:
        (tmp_path / "work/force-app/main/default/classes/Sample.cls").write_text("altered")
    with pytest.raises(RuntimeError, match="Resume stopped"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config, resume=True)


def test_ledger_detects_missing_explicit_members_and_unresolved_wildcards(tmp_path):
    manifest = tmp_path / "package.xml"
    manifest.write_text('<Package><types><members>Missing</members><name>ApexClass</name></types><types><members>*</members><name>Report</name></types></Package>')
    ledger = retrieve_audit(manifest, tmp_path / "source", {"result": {"status": "Succeeded"}}, mode="full_org", include_packages=[])
    assert ledger["missing_members"] == [{"type": "ApexClass", "member": "Missing"}]
    assert ledger["unverified_members"][0]["type"] == "Report"
    assert ledger["org_completeness_proven"] is False


def test_manifest_batches_preserve_all_members_and_api_version(tmp_path):
    manifest = tmp_path / "package.xml"
    manifest.write_text('<Package><types><members>A</members><members>B</members><name>ApexClass</name></types><types><members>C</members><name>Flow</name></types><version>66.0</version></Package>')
    batches = split_manifest(manifest, tmp_path / "batches", 2)
    assert len(batches) == 2
    assert [manifest_summary(path)["members"] for path in batches] == [2, 1]
    assert all(manifest_summary(path)["api_version"] == "66.0" for path in batches)
    pairs = [(entry["type"], member) for path in batches for entry in manifest_summary(path)["entries"] for member in entry["members"]]
    assert pairs == [("ApexClass", "A"), ("ApexClass", "B"), ("Flow", "C")]


def test_deploy_between_batches_preserves_completed_batch_audit(tmp_path, monkeypatch):
    config = setup(monkeypatch)
    config["metadata"]["retrieve_batch_members"] = 1
    monkeypatch.setattr(FakeSF, "deploy_on_second", True)
    monkeypatch.setattr(FakeSF, "deploy_threshold", 3)
    def two_members(self, metadata_types, manifest_dir, *args, **kwargs):
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "package.xml").write_text('<Package><types><members>Sample</members><members>Another</members><name>ApexClass</name></types><version>66.0</version></Package>')
    monkeypatch.setattr(FakeSF, "generate_manifest", two_members)
    with pytest.raises(RuntimeError, match="between batches"):
        run_assessment("fixture", tmp_path / "work", tmp_path / "reports", config)
    ledger = json.loads((tmp_path / "reports/metadata-retrieve-audit.json").read_text())
    assert ledger["status"] == "failed"
    assert len(ledger["batches"]) == 1
    assert len(ledger["files"]) == 2


def test_profiles_are_included_in_every_contextual_retrieve_batch(tmp_path):
    manifest = tmp_path / "package.xml"
    manifest.write_text('<Package><types><members>A</members><members>B</members><name>ApexClass</name></types><types><members>Admin</members><name>Profile</name></types><version>66.0</version></Package>')
    batches = split_manifest(manifest, tmp_path / "batches", 2)
    assert len(batches) == 2
    assert all({"type": "Profile", "members": ["Admin"], "wildcard": False} in manifest_summary(path)["entries"] for path in batches)
    directory = tmp_path / "source/profiles"
    directory.mkdir(parents=True)
    profile = directory / "Admin.profile-meta.xml"
    previous = {profile.name: b'<Profile><classAccesses><apexClass>A</apexClass><enabled>true</enabled></classAccesses></Profile>'}
    profile.write_text('<Profile><classAccesses><apexClass>B</apexClass><enabled>true</enabled></classAccesses></Profile>')
    assert merge_profile_fragments(previous, tmp_path / "source") == 1
    assert "<apexClass>A</apexClass>" in profile.read_text()
    assert "<apexClass>B</apexClass>" in profile.read_text()
