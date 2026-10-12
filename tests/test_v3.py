import json
from pathlib import Path

import pytest

from labforce_dementor.diffing import diff_assessments
from labforce_dementor.intelligence_v3 import change_risk_and_debt, apex_semantic_map
from labforce_dementor.safety import ReadOnlyCommandGuard, UnsafeCommandError


def test_rest_guard_allows_only_get():
    ReadOnlyCommandGuard.validate(["sf", "api", "request", "rest", "/services/data/v66.0/limits", "--method", "GET"])
    with pytest.raises(UnsafeCommandError):
        ReadOnlyCommandGuard.validate(["sf", "api", "request", "rest", "/services/data/v66.0/sobjects/Account/001", "--method", "PATCH"])
    with pytest.raises(UnsafeCommandError):
        ReadOnlyCommandGuard.validate(["sf", "api", "request", "rest", "/services/data/v66.0/limits", "--method", "GET", "--body", "{}"])


def test_apex_semantic_map_detects_rest_dynamic_and_named_credential():
    comps = {"apex_classes": [{
        "api_name": "ApiX", "source_file": "ApiX.cls",
        "text": "@RestResource(urlMapping='/x/*') global class ApiX { void x(){ Type.forName('ImplX'); HttpRequest r=new HttpRequest(); r.setEndpoint('callout:ERP/orders'); } }"
    }, {"api_name": "ImplX", "source_file": "ImplX.cls", "text": "public class ImplX {}"}], "apex_triggers": []}
    deps = []
    result = apex_semantic_map(comps, deps)
    assert result["endpoints"][0]["url_mapping"] == "/x/*"
    assert result["dynamic_references"][0]["target"] == "ImplX"
    assert result["callouts"][0]["endpoint"].startswith("callout:")
    assert any(x["relationship"] == "USES_NAMED_CREDENTIAL" for x in deps)


def test_change_risk_scores_dependency_hotspot():
    deps = [
        {"source": "A", "target": "B"}, {"source": "A", "target": "C"},
        {"source": "A", "target": "D"}, {"source": "A", "target": "E"},
    ]
    result = change_risk_and_debt({}, deps, [])
    assert result["top_change_risk"][0]["component"] == "A"
    assert result["top_change_risk"][0]["change_risk_score"] > 0


def test_snapshot_diff(tmp_path: Path):
    before = tmp_path / "before.json"; after = tmp_path / "after.json"
    before.write_text(json.dumps({"inventory":{"flows":2},"health":{"overall":70,"categories":{"security":80}},"findings":[{"id":"X"}]}))
    after.write_text(json.dumps({"inventory":{"flows":4},"health":{"overall":78,"categories":{"security":90}},"findings":[{"id":"Y"}]}))
    d = diff_assessments(before, after)
    assert d["overall_health"]["delta"] == 8
    assert d["inventory_delta"]["flows"] == 2
    assert d["new_findings"][0]["id"] == "Y"
    assert d["resolved_findings"][0]["id"] == "X"
