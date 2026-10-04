"""Scope extraction.

Architecture (LLM is ADVISORY ONLY, never the final authority):

    User request
      -> deterministic scope parser          (ground truth, always runs)
      -> optional LLM scope proposal          (security_llm.extract_scope)
      -> deterministic validator              (validate_llm_scope)
      -> final scope  (deterministic scope, optionally NARROWED by the LLM)

The validator guarantees the LLM can never WIDEN authority:
  * tools      -> only known tools, and only tools the deterministic parser
                  grounded in the user's own words; the LLM may narrow
                  mutating tools but cannot add any.
  * recipients -> must be syntactically valid AND appear literally in the
                  user message; the LLM cannot add recipients.
  * paths      -> no fake_confidential, no traversal, no absolute paths,
                  must live under documents/ and be mentioned by the user.
  * any rejected proposal is recorded in scope.validation for the trace/audit.
If the LLM fails, times out, or returns garbage, the deterministic scope is
used unchanged.
"""
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

@dataclass
class Scope:
    allowed_tools: Set[str]=field(default_factory=set)
    allowed_paths: List[str]=field(default_factory=lambda:["documents"])
    allowed_recipients: Set[str]=field(default_factory=set)
    intent: str=""
    source: str="deterministic"
    validation: Dict[str, Any]=field(default_factory=dict)

ALLOWED_TOOLS={"read_file","search_web","send_email","write_record"}
READ_ONLY_TOOLS={"read_file","search_web"}
MUTATING_TOOLS={"send_email","write_record"}
EMAIL_RE=re.compile(r'[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+')
_STRICT_EMAIL_RE=re.compile(r'^[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$')


def _path_is_safe(p: str) -> bool:
    norm = str(p).replace("\\", "/").strip()
    if not norm or len(norm) > 300:
        return False
    if "fake_confidential" in norm.lower() or ".." in norm:
        return False
    if norm.startswith("/") or re.match(r'^[A-Za-z]:', norm) or "\x00" in norm:
        return False
    return True


def _deterministic(msg: str) -> Scope:
    lower = msg.lower()
    scope = Scope(allowed_tools=set(READ_ONLY_TOOLS), allowed_paths=["documents"], intent=msg)
    if re.search(r'\b(email|send|drop a line|forward|mail|notify|share with)\b', lower):
        scope.allowed_tools.add("send_email")
    if re.search(r'\b(log|save|store|record|write|update|insert)\b', lower):
        scope.allowed_tools.add("write_record")
    scope.allowed_recipients.update(EMAIL_RE.findall(msg))
    for p in re.findall(r'[\w./\\-]+\.txt', msg):
        if p not in scope.allowed_paths:
            scope.allowed_paths.append(p)
    return scope


def validate_llm_scope(proposal: Any, user_msg: str, base: Scope) -> Scope:
    """Deterministically validate an LLM scope proposal against the user's request.

    Returns a NEW Scope that is always a subset of `base` (least privilege)."""
    msg = str(user_msg or "")
    msg_lower = msg.lower()
    rejected: List[Dict[str, str]] = []
    accepted: Dict[str, Any] = {"allowed_tools": [], "allowed_paths": [], "allowed_recipients": []}

    if not isinstance(proposal, dict) or not proposal:
        out = Scope(set(base.allowed_tools), list(base.allowed_paths), set(base.allowed_recipients),
                    base.intent, "deterministic",
                    {"llm_used": False, "fallback": "llm_unavailable_or_invalid", "rejected": []})
        return out

    def _as_list(v):
        if isinstance(v, (list, tuple, set)):
            return list(v)
        return [v] if isinstance(v, str) and v else []

    # --- tools: known + grounded in deterministic parse; LLM may only narrow ---
    llm_tools: Set[str] = set()
    for t in _as_list(proposal.get("allowed_tools")):
        t = str(t).strip()
        if t not in ALLOWED_TOOLS:
            rejected.append({"field": "allowed_tools", "value": t[:60], "reason": "unknown_tool"})
        elif t not in base.allowed_tools:
            rejected.append({"field": "allowed_tools", "value": t, "reason": "not_grounded_in_user_request"})
        else:
            llm_tools.add(t)
    accepted["allowed_tools"] = sorted(llm_tools)
    final_tools = set(READ_ONLY_TOOLS) | (base.allowed_tools & MUTATING_TOOLS & llm_tools) if llm_tools else set(base.allowed_tools)

    # --- recipients: must be valid and literally present in the user message ---
    for r in _as_list(proposal.get("allowed_recipients")):
        r = str(r).strip()
        if not _STRICT_EMAIL_RE.match(r):
            rejected.append({"field": "allowed_recipients", "value": r[:60], "reason": "invalid_email"})
        elif r.lower() not in msg_lower or r not in base.allowed_recipients:
            rejected.append({"field": "allowed_recipients", "value": r, "reason": "recipient_not_in_user_request"})
        else:
            accepted["allowed_recipients"].append(r)
    final_recips = set(base.allowed_recipients)

    # --- paths: safe, under documents/, and mentioned by the user ---
    for p in _as_list(proposal.get("allowed_paths")):
        p = str(p)
        norm = p.replace("\\", "/").strip()
        if not _path_is_safe(norm):
            reason = "confidential_path" if "fake_confidential" in norm.lower() else "path_traversal_or_absolute"
            rejected.append({"field": "allowed_paths", "value": norm[:80], "reason": reason})
        elif norm not in ("documents", "documents/") and (not norm.startswith("documents/") or norm not in msg.replace("\\", "/")):
            rejected.append({"field": "allowed_paths", "value": norm[:80], "reason": "path_not_in_user_request"})
        else:
            accepted["allowed_paths"].append(norm)
    final_paths = list(base.allowed_paths)

    # --- requested actions vs deterministic grounding (mismatch detection) ---
    action_map = {"email": "send_email", "send_email": "send_email", "write": "write_record",
                  "write_record": "write_record", "log": "write_record", "record": "write_record",
                  "read": "read_file", "read_file": "read_file", "search": "search_web", "search_web": "search_web"}
    mismatches = []
    for a in _as_list(proposal.get("requested_actions")):
        tool = action_map.get(str(a).strip().lower())
        if tool and tool not in base.allowed_tools:
            mismatches.append(tool)
            rejected.append({"field": "requested_actions", "value": str(a)[:60], "reason": "action_not_in_user_request"})

    intent = base.intent
    if isinstance(proposal.get("intent"), str) and proposal["intent"].strip():
        intent = proposal["intent"].strip()[:500]

    return Scope(final_tools, final_paths, final_recips, intent, "qwen3_advisory+deterministic_validator",
                 {"llm_used": True, "accepted": accepted, "rejected": rejected,
                  "scope_mismatch": sorted(set(mismatches)),
                  "narrowed_tools": sorted(base.allowed_tools - final_tools)})


def _sanitize(scope: Scope) -> Scope:
    clean_paths = [p for p in scope.allowed_paths if _path_is_safe(p) or p == "documents"]
    scope.allowed_paths = clean_paths if clean_paths else ["documents"]
    scope.allowed_tools = {t for t in scope.allowed_tools if t in ALLOWED_TOOLS}
    scope.allowed_recipients = {r for r in scope.allowed_recipients if _STRICT_EMAIL_RE.match(r)}
    return scope


def extract(user_msg: str, use_llm: bool = True) -> Scope:
    msg = str(user_msg or "")
    base = _sanitize(_deterministic(msg))
    base.validation = {"llm_used": False, "fallback": None, "rejected": []}

    if use_llm and os.getenv("SECURITY_SCOPE_LLM", "1") == "1" and os.getenv("USE_MOCK_LLM", "0") != "1":
        try:
            import security_llm
            proposal = security_llm.extract_scope(msg)
        except Exception as e:  # model down / timeout / import error -> deterministic fallback
            base.validation = {"llm_used": False, "fallback": f"llm_error: {type(e).__name__}", "rejected": []}
            return base
        return _sanitize(validate_llm_scope(proposal, msg, base))
    return base
