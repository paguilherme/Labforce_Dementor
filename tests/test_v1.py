from pathlib import Path
from labforce_dementor.resilience import CheckpointStore, integrity_manifest, is_transient_error
from labforce_dementor.impact_reporting import render_impact_html

def test_checkpoint_roundtrip(tmp_path):
    p=tmp_path/"checkpoint.json"
    c=CheckpointStore(p)
    assert not c.done("x")
    c.mark("x","done", answer=42)
    c2=CheckpointStore(p)
    assert c2.done("x")
    assert c2.data["stages"]["x"]["answer"] == 42

def test_integrity_manifest_hashes(tmp_path):
    (tmp_path/"a.txt").write_text("abc")
    m=integrity_manifest(tmp_path)
    assert m["count"] == 1
    assert m["files"][0]["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_transient_detection():
    assert is_transient_error("503 Service Unavailable")
    assert is_transient_error("REQUEST_LIMIT_EXCEEDED")
    assert not is_transient_error("INVALID_FIELD")

def test_impact_html(tmp_path):
    data={"component":"Account.Status__c","risk":"HIGH","change_risk_score":80,"blast_radius":3,
          "affected_by_type":{"Flow":2},"affected_components":["Flow:A"],"related_findings":[]}
    out=render_impact_html(data,tmp_path/"impact.html")
    text=out.read_text()
    assert "Account.Status__c" in text
    assert "80/100" in text

from labforce_dementor.validation import validate_assessment_payload

def test_payload_validation():
    data={"product":{},"run":{},"org":{},"inventory":{},"components":{},"dependencies":[],"findings":[],"health":{"overall":80},"audit":{},"code_analyzer":{}}
    assert validate_assessment_payload(data)["valid"]
    data["health"]["overall"]=200
    assert not validate_assessment_payload(data)["valid"]
