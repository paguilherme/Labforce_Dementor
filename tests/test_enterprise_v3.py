from pathlib import Path

from labforce_dementor.enterprise import (
    normalize_edges, build_digital_twin, build_remediation_plan,
    build_capability_matrix, component_explanation, stable_snapshot_digest,
)
from labforce_dementor.models import Evidence, Finding
from labforce_dementor.parser import parse_extended_metadata


def test_normalize_edges_deduplicates_and_keeps_strongest_confidence():
    edges = [
        {"source":"Flow:A","relationship":"CALLS","target":"ApexClass:B","confidence":0.7,"evidence":"one"},
        {"source":"Flow:A","relationship":"CALLS","target":"ApexClass:B","confidence":0.95,"evidence":"two"},
    ]
    out = normalize_edges(edges)
    assert len(out) == 1
    assert out[0]["confidence"] == 0.95
    assert out[0]["evidence"] == ["one", "two"]


def test_digital_twin_detects_automation_cycle_and_hotspots():
    deps = [
        {"source":"Flow:A","relationship":"CALLS","target":"ApexClass:B","confidence":1,"evidence":"a"},
        {"source":"ApexClass:B","relationship":"CALLS","target":"Flow:A","confidence":1,"evidence":"b"},
        {"source":"ApexClass:B","relationship":"USES_FIELD","target":"Field:Account.X__c","confidence":1,"evidence":"b"},
    ]
    twin = build_digital_twin({}, deps, [])
    assert twin["nodes"] == 3
    assert twin["automation_cycles"]
    assert twin["hotspots"][0]["structural_criticality_score"] > 0


def test_remediation_plan_promotes_supported_critical_to_p0():
    f = Finding("SEC-1","security","critical","Danger","desc",component="A",recommendation="fix",confidence=.95,evidence=[Evidence("META","x")])
    plan = build_remediation_plan([f], {"hotspots": [{"component":"A","structural_criticality_score":50}]})
    assert plan["items"][0]["priority"] == "P0"
    assert plan["items"][0]["automatic_mutation_allowed"] is False


def test_component_explanation_walks_both_directions():
    snapshot={"dependencies":[
        {"source":"Flow:F","relationship":"USES_FIELD","target":"Field:Account.X__c","confidence":1,"evidence":"x"},
        {"source":"ApexClass:C","relationship":"CALLS","target":"Flow:F","confidence":1,"evidence":"y"},
    ],"findings":[]}
    out=component_explanation(snapshot,"Account.X__c",2)
    assert "Flow:F" in out["neighbors"]
    assert "ApexClass:C" in out["neighbors"]


def test_capability_matrix_never_claims_missing_telemetry_ready():
    out=build_capability_matrix({"objects":[{"api_name":"Account"}],"intelligence":{}},{"dml_executed":0,"metadata_deployments":0,"apex_anonymous_executions":0})
    assert out["capabilities"]["metadata_inventory"]["status"] == "READY"
    assert out["capabilities"]["event_monitoring"]["status"] == "UNAVAILABLE"
    assert out["capabilities"]["read_only_safety"]["status"] == "READY"


def test_stable_snapshot_digest_is_order_stable_for_edges():
    a={"inventory":{},"dependencies":[{"source":"B","relationship":"R","target":"C","confidence":1},{"source":"A","relationship":"R","target":"B","confidence":1}],"findings":[],"health":{}}
    b={**a,"dependencies":list(reversed(a["dependencies"]))}
    assert stable_snapshot_digest(a)==stable_snapshot_digest(b)


def test_parse_extended_metadata_workflow_and_psg(tmp_path: Path):
    wf=tmp_path/'workflows'; wf.mkdir()
    (wf/'Account.workflow-meta.xml').write_text('''<Workflow xmlns="http://soap.sforce.com/2006/04/metadata"><rules><fullName>Legacy</fullName><active>true</active><triggerType>onCreateOrTriggeringUpdate</triggerType></rules></Workflow>''')
    psg=tmp_path/'permissionsetgroups'; psg.mkdir()
    (psg/'Sales.permissionsetgroup-meta.xml').write_text('''<PermissionSetGroup xmlns="http://soap.sforce.com/2006/04/metadata"><label>Sales</label><permissionSets>A</permissionSets><permissionSets>B</permissionSets><status>Updated</status></PermissionSetGroup>''')
    out=parse_extended_metadata(tmp_path)
    assert out['workflows'][0]['object']=='Account'
    assert out['workflows'][0]['rules'][0]['active'] is True
    assert out['permission_set_groups'][0]['permission_sets']==['A','B']
