from labforce_dementor.intelligence_v6 import component_from_path, temporal_diff, deployment_impact, sarif, business_criticality

def test_component_from_path():
    assert component_from_path("force-app/main/default/classes/A.cls")=="ApexClass:A"
    assert component_from_path("force-app/main/default/objects/Account/fields/X__c.field-meta.xml")=="Field:Account.X__c"

def test_temporal_diff():
    a={"dependencies":[{"source":"A","relationship":"USES","target":"B"}],"findings":[],"health":{"overall":90}}
    b={"dependencies":[{"source":"A","relationship":"USES","target":"C"}],"findings":[{"id":"X"}],"health":{"overall":85}}
    r=temporal_diff(a,b)
    assert r["dependency_edges"]["added_count"]==1
    assert r["dependency_edges"]["removed_count"]==1
    assert r["health"]["delta"]==-5

def test_deployment_impact():
    s={"dependencies":[{"source":"ApexClass:A","relationship":"USES","target":"Object:Account"},
                       {"source":"Object:Account","relationship":"HAS","target":"Field:Account.X__c"}],"findings":[]}
    r=deployment_impact(s,["ApexClass:A"],3)
    assert r["blast_radius"]==2
    assert r["deployment_risk_score"]>0

def test_sarif():
    s=sarif([{"id":"SEC-1","severity":"high","title":"Risk","description":"Bad","recommendation":"Fix","evidence":[]}])
    assert s["version"]=="2.1.0"
    assert s["runs"][0]["results"][0]["level"]=="error"

def test_criticality():
    s={"dependencies":[{"source":"A","target":"B"},{"source":"A","target":"C"}],"findings":[]}
    r=business_criticality(s)
    assert r["components"][0]["component"]=="A"
