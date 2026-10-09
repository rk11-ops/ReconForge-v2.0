from __future__ import annotations
import re
from typing import Any
from .normalize import normalize_endpoint

SEVERITY_BASE={"critical":95,"high":80,"medium":55,"low":30,"info":10,"unknown":10}
ORDER={"critical":5,"high":4,"medium":3,"low":2,"info":1,"unknown":0}
EVIDENCE_ORDER={"CONFIRMED_OBSERVED":5,"CONFIRMED_DERIVED":4,"SCANNER_REPORTED":3,"NEEDS_VALIDATION":2,"FALSE_POSITIVE":0}

def highest_severity(a:str,b:str)->str: return a if ORDER.get(a,0)>=ORDER.get(b,0) else b

def strongest_evidence(a:str,b:str)->str: return a if EVIDENCE_ORDER.get(a,0)>=EVIDENCE_ORDER.get(b,0) else b

def dedupe_edges(edges:list[dict[str,str]])->list[dict[str,str]]:
    seen=set(); out=[]
    for e in edges:
        key=(e.get("from",""),e.get("to",""),e.get("relation",""))
        if key not in seen: seen.add(key); out.append(e)
    return out

def correlate_findings(raw:list[dict[str,Any]], public_target:bool, endpoints:list[str])->list[dict[str,Any]]:
    grouped={}
    for item in raw:
        key=item["fingerprint"]
        cur=grouped.setdefault(key,{
            "fingerprint":key,"issue_key":item["issue_key"],"name":item["name"],"severity":item["severity"],
            "sources":[],"endpoints":[],"evidence_count":0,"instances":[],"identifiers":[],
            "evidence_states":[],"evidence_state":item.get("evidence_state","SCANNER_REPORTED"),"source_commands":{},
            "rule_ids":[],"cwe":item.get("cwe"),"owasp_category":item.get("owasp_category",""),
            "description":item.get("description",""),"impact":item.get("impact",""),"why_reported":item.get("why_reported",""),"manual_validation":item.get("manual_validation",""),"remediation":item.get("remediation",""),
            "guidance_sources":[],
        })
        cur["severity"]=highest_severity(cur["severity"],item["severity"])
        if item["source"] not in cur["sources"]: cur["sources"].append(item["source"])
        ep=item.get("endpoint")
        if ep and ep not in cur["endpoints"]: cur["endpoints"].append(ep)
        ident=item.get("identifier")
        if ident and ident not in cur["identifiers"]: cur["identifiers"].append(ident)
        if item.get("rule_id") and item.get("rule_id") not in cur["rule_ids"]: cur["rule_ids"].append(item.get("rule_id"))
        if item.get("cwe") and not cur.get("cwe"): cur["cwe"]=item.get("cwe")
        for field in ("description","impact","why_reported","manual_validation","remediation","owasp_category"):
            if item.get(field) and not cur.get(field): cur[field]=item.get(field)
        state=item.get("evidence_state","SCANNER_REPORTED")
        cur["evidence_states"].append(state)
        cur["evidence_state"]=strongest_evidence(cur["evidence_state"],state)
        cur["evidence_count"]+=1; cur["instances"].append(item.get("raw",{}))
        source_cmd=item.get("source_command")
        if source_cmd:
            cur.setdefault("source_commands", {})[item["source"]]=source_cmd
    out=[]
    for f in grouped.values():
        base=SEVERITY_BASE.get(f["severity"],10)
        corroboration=min(max(len(f["sources"])-1,0)*7,14)
        sensitive=5 if any(re.search(r"/(admin|login|auth|api|graphql|swagger|openapi)(/|$)",normalize_endpoint(ep),re.I) for ep in f["endpoints"]) else 0
        external=5 if public_target else 0
        f["contextual_risk_score"]=min(100,base+corroboration+sensitive+external)
        f["risk_score_explanation"]={"base_severity":base,"corroboration_bonus":corroboration,"sensitive_endpoint_bonus":sensitive,"public_target_bonus":external,"model":"ReconForge heuristic; not CVSS"}
        f["confidence"]="high" if f["evidence_state"] in {"CONFIRMED_OBSERVED","CONFIRMED_DERIVED"} or len(f["sources"])>=2 else ("medium" if f["evidence_state"]=="SCANNER_REPORTED" else "low")
        out.append(f)
    out.sort(key=lambda x:(-x["contextual_risk_score"],x["name"].lower()))
    return out
