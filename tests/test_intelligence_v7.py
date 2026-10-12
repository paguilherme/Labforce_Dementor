from pathlib import Path

from labforce_dementor.intelligence_v7 import (
    build_order_of_execution_graph,
    build_apex_quality,
    build_test_intelligence,
    build_data_health,
    simulate_change,
    continuous_intelligence,
    final_readiness,
)


def test_order_of_execution_builds_transaction_phases(tmp_path: Path):
    trigger = tmp_path / "AccountTrigger.trigger"
    trigger.write_text("trigger AccountTrigger on Account (before insert, after update) {}", encoding="utf-8")
    components = {
        "flows": [{"api_name": "AccountBefore", "object": "Account", "status": "Active", "record_trigger_type": "FastFieldUpdates"}],
        "apex_triggers": [{"api_name": "AccountTrigger", "source_file": str(trigger), "text": trigger.read_text()}],
        "objects": [{"api_name": "Account", "validation_rules": [{"api_name": "Require_Name", "active": True}]}],
    }
    deps = []
    result = build_order_of_execution_graph(components, deps)
    row = result["objects"][0]
    assert row["object"] == "Account"
    assert "Flow:AccountBefore" in row["phases"]["03_before_save_flow"]
    assert "ApexTrigger:AccountTrigger" in row["phases"]["04_before_trigger"]
    assert "ApexTrigger:AccountTrigger" in row["phases"]["07_after_trigger"]
    assert result["graph_edges_added"] > 0


def test_apex_quality_and_static_test_mapping(tmp_path: Path):
    svc = "public with sharing class AccountService { public static void run(){ for(Account a: [SELECT Id FROM Account]) { update a; } } }"
    tst = "@isTest private class AccountServiceTest { @isTest static void t(){ AccountService.run(); } }"
    components = {"apex_classes": [
        {"api_name": "AccountService", "text": svc, "source_file": str(tmp_path / "AccountService.cls")},
        {"api_name": "AccountServiceTest", "text": tst, "source_file": str(tmp_path / "AccountServiceTest.cls")},
    ], "apex_triggers": []}
    deps = []
    quality = build_apex_quality(components, deps)
    assert any(x["component"] == "ApexClass:AccountServiceTest" for x in quality["tests"])
    tests = build_test_intelligence(components, {}, quality)
    target = next(x for x in tests["components"] if x["component"] == "AccountService")
    assert "AccountServiceTest" in target["direct_test_references"]


def test_data_health_uses_profile_without_raw_values():
    components = {"intelligence": {
        "data_profile": {"largest_objects": [{"object": "Account", "record_count": 1200000}]},
        "v3": {"data_quality_profile": {"enabled": True, "available": True, "objects": [{
            "object": "Account", "field_stats": [
                {"field": "Account.Foo__c", "sampled_rows": 100, "null_percent": 98.0, "distinct_ratio_percent": 1.0}
            ], "owner_skew": {"potential_skew": True}
        }]}}
    }}
    result = build_data_health(components, {})
    assert result["raw_values_persisted"] is False
    assert result["objects"][0]["data_health_risk_score"] > 0


def test_simulate_change_traverses_dependents_only():
    snapshot = {"dependencies": [
        {"source": "Flow:A", "relationship": "READS_FIELD", "target": "Field:Account.CNPJ__c", "confidence": .9},
        {"source": "ApexClass:B", "relationship": "CALLS_SUBFLOW", "target": "Flow:A", "confidence": .9},
    ], "findings": []}
    result = simulate_change(snapshot, "Account.CNPJ__c", "remove", 4)
    assert "Flow:A" in result["affected_components"]
    assert "ApexClass:B" in result["affected_components"]
    assert result["mutation_executed"] is False


def test_continuous_intelligence_tracks_health_and_drift():
    before = {"health": {"overall": 70, "categories": {"security": 60}}, "dependencies": [], "findings": [{"id": "A", "severity": "high"}]}
    after = {"health": {"overall": 80, "categories": {"security": 75}}, "dependencies": [{"source": "A", "relationship": "R", "target": "B"}], "findings": [{"id": "B", "severity": "low"}]}
    result = continuous_intelligence(before, after)
    assert result["health"]["delta"] == 10
    assert result["findings"]["new_count"] == 1
    assert result["findings"]["resolved_count"] == 1


def test_final_readiness_contract():
    snapshot = {"inventory": {"apex_classes": 1}, "audit": {"dml_executed": 0, "metadata_deployments": 0}, "components": {"intelligence": {
        "v7": {"order_of_execution_graph": {"objects": [{"object": "Account"}]}, "lineage_index": {"field_count": 1}, "flow_quality": {"flows_analyzed": 0}, "apex_quality": {"components_analyzed": 0}, "test_intelligence": {}, "data_health": {}, "runtime_health": {}, "integration_health": {}},
        "enterprise": {"digital_twin": {"nodes": 1}, "remediation_plan": {"items": []}, "evidence_quality": {"findings_total": 0}},
        "effective_permissions": {"available": True}
    }}}
    result = final_readiness(snapshot)
    assert result["engine_status"] == "PRODUCT_GRADE_CORE"
    assert result["readiness_percent"] == 100.0
