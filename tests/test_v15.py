from pathlib import Path
from labforce_dementor.intelligence_v5 import compare_fingerprints, select_tests, build_knowledge_pack
from labforce_dementor.policy import evaluate_policy

def test_drift_compare():
    a={"files":[{"path":"classes/A.cls","sha256":"1"}]}
    b={"files":[{"path":"classes/A.cls","sha256":"2"},{"path":"classes/B.cls","sha256":"3"}]}
    r=compare_fingerprints(a,b)
    assert r["has_drift"]
    assert r["counts"]["modified"] == 1
    assert r["counts"]["repo_only"] == 1

def test_test_selection():
    snap={"dependencies":[
        {"source":"ApexClass:AccountServiceTest","target":"ApexClass:AccountService","relationship":"REFERENCES"},
        {"source":"ApexClass:AccountService","target":"Object:Account","relationship":"USES"},
    ],"components":{"apex_classes":[
        {"api_name":"AccountServiceTest","is_test":True},
        {"api_name":"OtherTest","is_test":True}
    ]}}
    r=select_tests(snap,["AccountService"],3)
    assert "AccountServiceTest" in r["test_names"]

def test_policy_fails_critical():
    cur={"findings":[{"id":"X","severity":"critical"}],"health":{"overall":80},"components":{"intelligence":{"v3":{"risk_and_debt":{"top_change_risk":[]}}}}}
    r=evaluate_policy(cur)
    assert not r["passed"]

def test_knowledge_pack_shape():
    snap={"product":{},"run":{},"org":{},"inventory":{},"health":{},"components":{"intelligence":{}},"dependencies":[],"findings":[],"audit":{},"code_analyzer":{}}
    p=build_knowledge_pack(snap)
    assert "organization" in p and "dependency_graph" in p and "security_map" in p
