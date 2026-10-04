import re
import os
from typing import Tuple, List, Dict, Any
from normalization import normalize, analysis_variants
from secret_scanner import scan as scan_secrets, redact as redact_secrets
try:
    from security_llm import classify_injection
except Exception:
    classify_injection=None

PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "rule_ignore_instructions"),
    (r"(?i)ignore\s+(all\s+)?(the\s+)?(above|prior|earlier|preceding)(\s+instructions)?", "rule_ignore_instructions"),
    (r"(?i)(system:/?\[?system\]?|<system>|<\|system\|>)", "rule_fake_system_header"),
    (r"(?i)do\s+not\s+tell\s+the\s+user|do\s+not\s+disclose", "rule_concealment"),
    (r"(?i)(email|send|forward)\s+(it\s+to\s+)?[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "rule_imperative_exfil"),
    (r"(?i)\b(email|send|forward|mail)\s+((the|all|its|this|that|those|these|both|my|our|user'?s?|account'?s?)\s+)*(contents?|data|files?|secrets?|it|them|both|everything|information|credentials?|passwords?|records?)\b(\s+\w+){0,3}?\s+to\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "rule_imperative_exfil"),
    (r"(?i)\b(?:reveal|print|dump|exfiltrate|upload|send|email|mail|forward|share|transmit)\b.{0,80}\b(?:secret|credential|token|password|passwd|pwd|private\s*key|confidential|auth\s*token)\b", "rule_sensitive_exfil"),
]

def decode_passes(text, depth=0):
    return normalize(text,max_depth=2).canonical

def _redact_spans(original, spans):
    out=original
    for start,end,marker in sorted(spans,key=lambda x:x[0],reverse=True):
        out=out[:start] + marker + out[end:]
    return out

def scan(text: str, source: str, semantic: bool=True) -> Tuple[str,List[Dict[str,Any]],float]:
    original=str(text or "")
    n=normalize(original)
    variants=[n.canonical]+[x["text"] for x in n.decoded_candidates]
    findings=[]
    for variant_idx, variant in enumerate(variants):
        for pattern, rule in PATTERNS:
            for m in re.finditer(pattern,variant):
                findings.append({"rule":rule,"span":m.span(),"evidence":m.group(0)[:160],
                                 "severity":"HIGH","variant":variant_idx})
    # Semantic classifier receives only normalized text and can be disabled for fast/offline mode.
    semantic_result={}
    if semantic and os.getenv("SECURITY_SEMANTIC","1")=="1" and os.getenv("USE_MOCK_LLM","0")!="1" and classify_injection:
        # Don't send credential-looking substrings to the model.
        safe_for_llm=redact_secrets(n.canonical, scan_secrets(n.canonical)[0])
        semantic_result=classify_injection(safe_for_llm,source)
        if semantic_result.get("injection") and float(semantic_result.get("confidence",0))>=0.70:
            findings.append({"rule":"llm_semantic_injection","span":[0,0],
                             "evidence":semantic_result.get("reason","semantic injection")[:160],
                             "severity":"HIGH","categories":semantic_result.get("categories",[])})

    # Credential scan is a parallel security signal; redact secrets without deleting unrelated text.
    secret_findings, secret_engine=scan_secrets(original)
    for f in secret_findings:
        findings.append({"rule":"secret_"+f["type"],"span":[f["start"],f["end"]],
                         "evidence":"[REDACTED]","severity":"CRITICAL","engine":secret_engine})

    sanitized=original
    # First redact credentials using exact offsets.
    sanitized=redact_secrets(sanitized,secret_findings)
    # For literal injection spans, preserve surrounding legitimate content.
    literal_spans=[]
    obfuscated_attack=False
    for f in findings:
        if f["rule"].startswith("secret_") or f["rule"]=="llm_semantic_injection": continue
        s,e=f["span"]
        if e>s and e<=len(original) and f.get("variant",0)==0 and n.canonical==original and not any(x.get("encoding")!="rot13" for x in n.decoded_candidates) and not any(t!="rot13_candidate" for t in n.transformations):
            literal_spans.append((s,e,"[REDACTED_INJECTION]"))
        elif f.get("variant",0)>0:
            obfuscated_attack=True
    sanitized=_redact_spans(sanitized,literal_spans)
    if obfuscated_attack:
        # Remove only the encoded carrier(s), not the surrounding legitimate text.
        import codecs
        carrier_patterns=[
            (r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])","[REDACTED_BASE64_PAYLOAD]"),
            (r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])","[REDACTED_HEX_PAYLOAD]"),
            (r"(?:%[0-9A-Fa-f]{2}){4,}","[REDACTED_URL_PAYLOAD]"),
            (r"<!--.*?-->","[REDACTED_HTML_COMMENT]"),
        ]
        for rx,marker in carrier_patterns:
            sanitized=re.sub(rx,marker,sanitized,flags=re.S)
        # ROT13: if the detected evidence is a ROT13 form, redact that exact carrier.
        for f in findings:
            if f.get("variant") and f.get("evidence"):
                try:
                    rot=codecs.encode(f["evidence"],"rot_13")
                    sanitized=sanitized.replace(rot,"[REDACTED_ROT13_PAYLOAD]")
                except Exception: pass
    if findings and not literal_spans and semantic_result.get("injection"):
        sanitized += "\n[REDACTED_INJECTION: semantic classifier flagged untrusted instructions]"
    # unique findings
    uniq=[]; seen=set()
    for f in findings:
        k=(f["rule"],str(f["span"]),f.get("evidence",""))
        if k not in seen: seen.add(k); uniq.append(f)
    risk=min(1.0,0.15*len(uniq)+0.35*sum(1 for x in uniq if x["rule"]=="llm_semantic_injection")+0.35*len(secret_findings))
    return sanitized,uniq,risk
