from labforce_dementor.intelligence import build_field_lineage, calculate_blast_radius, build_apex_coverage


def test_field_lineage_apex_write_and_manual():
    components = {
        "objects": [{"api_name": "Account", "fields": [{
            "api_name": "Status__c", "full_name": "Account.Status__c",
            "manual_candidate": True, "manual_confidence": 0.9, "layouts": ["Account Layout"]
        }]}],
        "apex_classes": [{"api_name": "AccountService", "text": "acc.Status__c = 'Active';", "source_file": "AccountService.cls"}],
        "apex_triggers": [], "flows": []
    }
    result = build_field_lineage(components)
    field = result["fields"]["Account.Status__c"]
    assert any(x["component"] == "User:UI" for x in field["writers"])
    assert any(x["component"] == "ApexClass:AccountService" for x in field["writers"])


def test_blast_radius_ranking():
    deps = [
        {"source": "A", "target": "B", "relationship": "CALLS", "confidence": 1.0, "evidence": ""},
        {"source": "A", "target": "C", "relationship": "CALLS", "confidence": 1.0, "evidence": ""},
        {"source": "B", "target": "D", "relationship": "CALLS", "confidence": 1.0, "evidence": ""},
    ]
    result = calculate_blast_radius(deps)
    assert result["top_components"][0]["component"] in {"A", "B"}
    assert result["components_scored"] == 4


def test_apex_coverage_normalization():
    runtime = {"apex_coverage": {"result": {"records": [
        {"ApexClassOrTriggerId": "01p", "ApexClassOrTrigger": {"Name": "X"}, "NumLinesCovered": 75, "NumLinesUncovered": 25}
    ]}}}
    result = build_apex_coverage(runtime)
    assert result["available"] is True
    assert result["overall_percent"] == 75.0
