"""Deterministic risk scoring. LLMs may enrich signals, but never decide the final action."""
from dataclasses import dataclass, asdict
from typing import Dict, List

@dataclass
class RiskAssessment:
    score: int
    level: str
    signals: List[Dict]
    reason: str

def assess(*, injection=False, semantic_injection=False, credential_count=0,
           sensitive_resource=False, out_of_scope_tool=False, external_recipient=False,
           tainted_data=False, dangerous_mutation=False, privilege_escalation=False,
           lakera_flagged=False, lakera_categories=None):
    signals=[]
    def add(name, points, active):
        if active: signals.append({"name":name,"points":points})
    add("prompt_injection",25,injection)
    add("semantic_injection",25,semantic_injection)
    add("credential_exposure",25,credential_count>0)
    add("sensitive_resource",20,sensitive_resource)
    add("out_of_scope_tool",25,out_of_scope_tool)
    add("external_recipient",20,external_recipient)
    add("tainted_data_flow",25,tainted_data)
    add("dangerous_mutation",20,dangerous_mutation)
    add("privilege_escalation",30,privilege_escalation)
    if lakera_flagged:
        if lakera_categories and isinstance(lakera_categories, list):
            for cat in lakera_categories[:2]:
                add(f"lakera_{cat}", 25, True)
        else:
            add("lakera_security_intel", 25, True)
    score=min(100,sum(x["points"] for x in signals))
    level="LOW" if score<40 else ("MEDIUM" if score<70 else "HIGH")
    reason="; ".join(x["name"].replace("_"," ") for x in signals) or "No elevated security signals."
    return RiskAssessment(score,level,signals,reason)
