from labforce_dementor.intelligence_v4 import impact_report, apex_ast_enrichment

def test_impact_traverses_graph():
    snap={"dependencies":[
        {"source":"Field:Account.Status__c","relationship":"USED_BY","target":"Flow:F1"},
        {"source":"Flow:F1","relationship":"CALLS","target":"ApexClass:C1"},
    ],"findings":[]}
    r=impact_report(snap,"Account.Status__c",3)
    assert r["blast_radius"] >= 2
    assert r["affected_by_type"]["Flow"] == 1

def test_apex_structural_ignores_comment_reference():
    components={"apex_classes":[
        {"api_name":"A","text":"""public class A {
 // B
 public void x(){ List<Account> a=[SELECT Id FROM Account]; }
}""","source_file":"A.cls"},
        {"api_name":"B","text":"public class B {}","source_file":"B.cls"},
    ],"apex_triggers":[]}
    deps=[]
    apex_ast_enrichment(components,deps)
    assert not any(e["target"]=="ApexClass:B" and e["source"]=="ApexClass:A" for e in deps)
    assert any(e["target"]=="Object:Account" for e in deps)
