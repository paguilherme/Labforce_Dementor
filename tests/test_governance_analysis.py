from __future__ import annotations

from labforce_dementor.analyzer import analyze
from labforce_dementor.governance_analysis import analyze_code_governance, analyze_org_limits
import pytest


def _class(name: str, body: str, *, is_test: bool = False) -> dict[str, object]:
    return {"api_name": name, "text": body, "is_test": is_test, "source_file": f"{name}.cls"}


def test_detects_god_class_and_god_test_class_with_configurable_thresholds() -> None:
    dependencies = "\n".join(f"Class{i}.run();" for i in range(6))
    methods = "\n".join(f"public void method{i}() {{ if (true) {{ Account a = new Account(); }} }}" for i in range(8))
    test_methods = "\n".join(f"@isTest static void test{i}() {{ Class{i % 6}.run(); Contact c = new Contact(); }}" for i in range(8))
    components = {"apex_classes": [
        _class("GodService", f"public class GodService {{ {dependencies} {methods} }}"),
        _class("GodServiceTest", f"@isTest private class GodServiceTest {{ {dependencies} {test_methods} }}", is_test=True),
        *[_class(f"Class{i}", f"public class Class{i} {{ public static void run() {{}} }}") for i in range(6)],
    ]}
    config = {"analysis": {
        "god_class": {"min_lines": 1, "min_methods": 3, "min_complexity": 3, "min_dependencies": 3, "min_responsibilities": 1, "min_score": 50},
        "god_test_class": {"min_lines": 1, "min_test_methods": 3, "min_dependencies": 3, "min_responsibilities": 1, "min_score": 50},
        "governor_risk": {"soql_statements": 80, "dml_statements": 120, "callouts": 80},
    }}
    result = analyze_code_governance(components, config)
    assert [row["api_name"] for row in result["god_class_candidates"]] == ["GodService"]
    assert [row["api_name"] for row in result["god_test_class_candidates"]] == ["GodServiceTest"]


def test_org_limit_governance_uses_real_remaining_margin() -> None:
    result = analyze_org_limits({
        "DailyApiRequests": {"max": 1000, "remaining": 80},
        "DataStorageMB": {"max": 1000, "remaining": 180},
        "Healthy": {"max": 1000, "remaining": 800},
    }, {"analysis": {"org_limits": {"warning_remaining_percent": 20, "critical_remaining_percent": 10}}})
    assert result["critical_count"] == 1
    assert result["warning_count"] == 1
    assert [row["name"] for row in result["outside_governance"]] == ["DailyApiRequests", "DataStorageMB"]


def test_governance_candidates_become_portuguese_findings() -> None:
    components = {
        "apex_classes": [_class("LargeService", "public class LargeService { public void a(){if(true){}} public void b(){if(true){}} }")],
        "apex_triggers": [], "objects": [], "layouts": [], "permission_sets": [], "profiles": [], "flows": [],
        "workflows": [], "approval_processes": [],
        "org_limit_governance": analyze_org_limits({"DailyApiRequests": {"max": 100, "remaining": 5}}, {"analysis": {}}),
    }
    config = {
        "analysis": {"god_class": {"min_lines": 1, "min_methods": 1, "min_complexity": 1, "min_dependencies": 99, "min_responsibilities": 99, "min_score": 20}},
        "scoring": {"weights": {"architecture": 1, "governance": 1}, "severity_penalty": {"critical": 12, "high": 6, "medium": 2, "low": .5, "info": 0}},
    }
    findings, _, _, _ = analyze(components, config)
    assert any(row.id.startswith("GOD-") and "Classe Deus" in row.title for row in findings)
    assert any(row.id.startswith("ORGLIMIT-") for row in findings)


def test_metrics_ignore_strings_comments_and_dml_variable_names():
    body = """public class Small {
 public void a() { String url = 'https://example.test/if/Other'; Other.run(); }
 public void b() { Account acc = new Account(); insert acc; update acc; }
 // Other.run(); if (true) { insert variable; }
 /* public void fake() {} */
}"""
    result = analyze_code_governance({"apex_classes": [_class("Small", body), _class("Other", "public class Other {}")], "apex_triggers": []}, {})
    row = next(row for row in result["largest_scores"] if row["api_name"] == "Small")
    assert row["methods"] == 2
    assert row["complexity_proxy"] == 1
    assert row["referenced_classes"] == ["Other"]
    assert row["referenced_objects"] == ["Account"]
    assert row["dml_statements"] == 2
    assert not row["candidate"]


def test_legacy_test_methods_and_trigger_operations_are_analyzed():
    config = {"analysis": {"governor_risk": {"soql_statements": 1}}}
    result = analyze_code_governance({"apex_classes": [_class("OldTest", "@isTest class OldTest { static testMethod void x() {} }", is_test=True)], "apex_triggers": [{"api_name": "T", "text": "trigger T on Account(before insert) { List<Account> rows = [SELECT Id FROM Account]; }"}]}, config)
    assert result["largest_scores"][0]["test_methods"] == 1
    assert result["transaction_governor_risks"][0]["component"] == "ApexTrigger:T"
    assert result["classes_analyzed"] == 1


def test_limit_thresholds_use_unrounded_margin_and_expose_unavailable_values():
    result = analyze_org_limits({"Near": {"max": 100000, "remaining": 20001}, "Exhausted": {"max": 100, "remaining": -1}, "Invalid": {"max": 0, "remaining": 0}}, {})
    rows = {row["name"]: row for row in result["limits"]}
    assert rows["Near"]["status"] == "healthy"
    assert rows["Exhausted"]["exhausted"]
    assert result["unavailable_limits"] == ["Invalid"]
    assert analyze_org_limits({}, {})["available"] is False
    with pytest.raises(ValueError):
        analyze_org_limits({}, {"analysis": {"org_limits": {"warning_remaining_percent": 5, "critical_remaining_percent": 10}}})


def test_parser_does_not_classify_production_as_test_due_to_comments_or_strings(tmp_path):
    from labforce_dementor.parser import parse_source
    directory = tmp_path / "classes"
    directory.mkdir()
    (directory / "Service.cls").write_text("public class Service { // @isTest\n String value = 'testMethod'; }")
    (directory / "LegacyTest.cls").write_text("private class LegacyTest { static testMethod void run() {} }")
    rows = {row["api_name"]: row for row in parse_source(tmp_path)["apex_classes"]}
    assert rows["Service"]["is_test"] is False
    assert rows["LegacyTest"]["is_test"] is True
