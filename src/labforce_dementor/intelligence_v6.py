from __future__ import annotations
import hashlib, json, subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

def git_changed_files(repo: Path, base: str, head: str) -> dict[str, Any]:
    try:
        p=subprocess.run(["git","diff","--name-status",f"{base}...{head}"],cwd=repo,text=True,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        if p.returncode:
            return {"available":False,"error":p.stderr.strip()}
        rows=[]
        for line in p.stdout.splitlines():
            parts=line.split("\t")
            if not parts: continue
            status=parts[0]; path=parts[-1]
            rows.append({"status":status,"path":path,"component":component_from_path(path)})
        return {"available":True,"base":base,"head":head,"files":rows,"components":sorted({x["component"] for x in rows if x["component"]})}
    except Exception as exc:
        return {"available":False,"error":str(exc)}

def component_from_path(path: str) -> str|None:
    p=Path(path); name=p.name
    pairs=[(".cls","ApexClass"),(".trigger","ApexTrigger"),(".flow-meta.xml","Flow"),
           (".object-meta.xml","Object"),(".field-meta.xml","Field"),(".layout-meta.xml","Layout"),
           (".flexipage-meta.xml","FlexiPage"),(".permissionset-meta.xml","PermissionSet"),
           (".profile-meta.xml","Profile"),(".app-meta.xml","Application"),
           (".report-meta.xml","Report"),(".dashboard-meta.xml","Dashboard")]
    for suffix,typ in pairs:
        if name.endswith(suffix):
            api=name[:-len(suffix)]
            if typ=="Field":
                # fields/<Field>.field-meta.xml under objects/<Object>/
                try:
                    obj=p.parts[p.parts.index("objects")+1]
                    api=f"{obj}.{api}"
                except Exception: pass
            return f"{typ}:{api}"
    if "lwc" in p.parts:
        try: return f"LWC:{p.parts[p.parts.index('lwc')+1]}"
        except Exception: return f"LWC:{p.stem}"
    if "aura" in p.parts:
        try: return f"Aura:{p.parts[p.parts.index('aura')+1]}"
        except Exception: return f"Aura:{p.stem}"
    return None

def temporal_diff(before: dict[str,Any], after: dict[str,Any]) -> dict[str,Any]:
    def edge_key(e): return (e.get("source"),e.get("relationship"),e.get("target"))
    a={edge_key(e):e for e in before.get("dependencies",[])}
    b={edge_key(e):e for e in after.get("dependencies",[])}
    added=sorted(set(b)-set(a)); removed=sorted(set(a)-set(b))
    fa={f.get("id"):f for f in before.get("findings",[])}
    fb={f.get("id"):f for f in after.get("findings",[])}
    health_a=before.get("health",{}).get("overall")
    health_b=after.get("health",{}).get("overall")
    return {
      "dependency_edges":{"added":[b[x] for x in added],"removed":[a[x] for x in removed],"added_count":len(added),"removed_count":len(removed)},
      "findings":{"new":[fb[x] for x in sorted(set(fb)-set(fa))],"resolved":[fa[x] for x in sorted(set(fa)-set(fb))]},
      "health":{"before":health_a,"after":health_b,"delta":(health_b-health_a) if isinstance(health_a,(int,float)) and isinstance(health_b,(int,float)) else None},
    }

def business_criticality(snapshot: dict[str,Any]) -> dict[str,Any]:
    deps=snapshot.get("dependencies",[])
    degree=defaultdict(int)
    for e in deps:
        if e.get("source"): degree[e["source"]]+=1
        if e.get("target"): degree[e["target"]]+=1
    findings=defaultdict(int)
    sev={"critical":25,"high":12,"medium":5,"low":1}
    for f in snapshot.get("findings",[]):
        c=f.get("component")
        if c: findings[c]+=sev.get(str(f.get("severity","")).lower(),0)
    rows=[]
    for node,d in degree.items():
        score=min(100,d*2+findings.get(node,0))
        rows.append({"component":node,"structural_degree":d,"risk_weight":findings.get(node,0),
                     "criticality_score":score,"criticality":"CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=30 else "LOW"})
    return {"components":sorted(rows,key=lambda x:(-x["criticality_score"],x["component"]))[:500],
            "method":"structural proxy; business owner override recommended"}

def deployment_impact(snapshot: dict[str,Any], changed: list[str], depth:int=3) -> dict[str,Any]:
    out=defaultdict(set); inc=defaultdict(set)
    for e in snapshot.get("dependencies",[]):
        a,b=e.get("source"),e.get("target")
        if a and b: out[a].add(b); inc[b].add(a)
    resolved=set(changed)
    for c in changed:
        if ":" not in c:
            resolved |= {n for n in set(out)|set(inc) if n.endswith(":"+c) or n.endswith("."+c)}
    visited=set(resolved); q=deque((n,0) for n in resolved)
    while q:
        n,d=q.popleft()
        if d>=depth: continue
        for x in out[n]|inc[n]:
            if x not in visited: visited.add(x); q.append((x,d+1))
    affected=visited-resolved
    crit=business_criticality(snapshot)
    cmap={x["component"]:x for x in crit["components"]}
    maxcrit=max([cmap.get(x,{}).get("criticality_score",0) for x in visited] or [0])
    risk=min(100,len(affected)*2+maxcrit)
    return {"changed_components":sorted(resolved),"affected_components":sorted(affected),
            "blast_radius":len(affected),"max_structural_criticality":maxcrit,
            "deployment_risk_score":risk,"risk":"CRITICAL" if risk>=90 else "HIGH" if risk>=70 else "MEDIUM" if risk>=40 else "LOW"}

def sarif(findings:list[dict[str,Any]]) -> dict[str,Any]:
    rules={}; results=[]
    level={"critical":"error","high":"error","medium":"warning","low":"note","info":"note"}
    for f in findings:
        rid=f.get("id","DEMENTOR")
        rules[rid]={"id":rid,"name":f.get("title",rid),"shortDescription":{"text":f.get("title",rid)},
                    "help":{"text":f.get("recommendation","")}}
        ev=(f.get("evidence") or [{}])[0]
        result={"ruleId":rid,"level":level.get(str(f.get("severity","")).lower(),"warning"),
                "message":{"text":f.get("description") or f.get("title","")}}
        source=ev.get("source") if isinstance(ev,dict) else None
        if source:
            result["locations"]=[{"physicalLocation":{"artifactLocation":{"uri":str(source)}}}]
        results.append(result)
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
            "runs":[{"tool":{"driver":{"name":"Labforce Dementor for Salesforce","rules":list(rules.values())}},"results":results}]}

def incremental_plan(before:dict[str,Any], current_fingerprint:dict[str,Any]) -> dict[str,Any]:
    prev=before.get("components",{}).get("intelligence",{}).get("v5",{}).get("source_fingerprint",{})
    a={x["path"]:x.get("sha256") for x in prev.get("files",[])}
    b={x["path"]:x.get("sha256") for x in current_fingerprint.get("files",[])}
    changed=sorted({p for p in set(a)|set(b) if a.get(p)!=b.get(p)})
    comps=sorted({c for p in changed if (c:=component_from_path(p))})
    return {"changed_files":changed,"changed_components":comps,"full_reassessment_required":not bool(prev.get("available")),
            "incremental_candidate":bool(prev.get("available"))}
