import re
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class Decision:
    decision: str  # ALLOW, BLOCK, ASK
    rule: str
    reason: str
    evidence: str

def check(call: Dict[str, Any], scope, ctx: Dict[str, Any], user_msg: str, session_taint: bool = False) -> Decision:
    if not isinstance(call, dict):
        return Decision("BLOCK", "0_invalid_call", "Tool call must be a dictionary.", "")

    name = call.get("name")
    if not name or not isinstance(name, str):
        return Decision("BLOCK", "0_invalid_tool_name", "Invalid or missing tool name.", "")

    raw_args = call.get("args")
    args = raw_args if isinstance(raw_args, dict) else {}

    # Normalize user message string for taint comparison
    user_msg_str = str(user_msg or "")

    def is_tainted(val: str) -> bool:
        if not val or not isinstance(val, str):
            return False
        return val not in user_msg_str

    # Taint & Provenance Tracking (Session Taint)
    session_tainted = bool(
        session_taint 
        or (ctx and ctx.get("session_taint", False)) 
        or (ctx and len(ctx.get("confidential_reads", [])) > 0)
    )
    if session_tainted:
        if name in ["send_email", "write_record"]:
            rule = "7_session_taint_email" if name == "send_email" else "7_session_taint_record"
            return Decision("BLOCK", rule, "Data-Flow Violation: Tainted context", name)
        elif name == "search_web":
            q = str(args.get("query", ""))
            if is_tainted(q) and (len(q) > 60 or len(set(q)) > 25):
                return Decision("BLOCK", "7_session_taint_search", "Data-Flow Violation: Tainted context", q[:20])

    # Rule 2: Path restrictions & Hard Confidential Directory Isolation
    if name == "read_file":
        import os
        from pathlib import Path
        path = str(args.get("path", ""))
        normalized_path = path.replace("\\", "/")

        # Unconditional check: fake_confidential is never accessible
        if "fake_confidential" in normalized_path:
            return Decision("BLOCK", "2_path_confidential", "Access to fake_confidential is forbidden.", path)

        base_dir = Path(__file__).parent.resolve()
        resolved_path = os.path.realpath(os.path.join(base_dir, path))
        fake_conf_dir = os.path.realpath(os.path.join(base_dir, "fake_confidential"))

        if resolved_path.startswith(fake_conf_dir) or resolved_path == fake_conf_dir:
            return Decision("BLOCK", "2_path_confidential", "Access to fake_confidential is forbidden.", path)

        allowed_paths = getattr(scope, "allowed_paths", ["documents"]) or ["documents"]
        allowed_resolved = [os.path.realpath(os.path.join(base_dir, p)) for p in allowed_paths]

        if resolved_path not in allowed_resolved and not any(resolved_path.startswith(p) for p in allowed_resolved):
            return Decision("BLOCK", "2_path_outside_scope", "Path not in allowed_paths.", path)

    # Rule 1: Tool must be explicitly in scope
    if scope is None or name not in scope.allowed_tools:
        return Decision("BLOCK", "1_out_of_scope_tool", f"Tool {name} not allowed by scope.", name)

    # Rule 3: send_email recipient validation and credential protection
    if name == "send_email":
        to = str(args.get("to", "")).strip()
        body = str(args.get("body", ""))
        subject = str(args.get("subject", ""))
        combined_text = f"{user_msg} {subject} {body}".lower()

        # Hard Block: Password / credential transmission via email
        if (
            re.search(r'\b(?:send|email|forward|share|mail|leak|transmit|exfiltrat)\b.{0,80}\b(?:password|passwd|pwd|credential|secret|private[_\s-]?key|api[_\s-]?key|auth[_\s-]?token)\b', combined_text)
            or re.search(r'\b(?:my|the|account|user)\s+passwords?\b', combined_text)
            or re.search(r'\b(?:password|passwd)\s*(?:is|:|=)\b', combined_text)
        ):
            return Decision("BLOCK", "5_credential_exfiltration", "Security Policy: Transmission of passwords or account credentials via email is strictly forbidden.", "credential_exfiltration")

        allowed_recips = getattr(scope, "allowed_recipients", set()) or set()
        if to not in allowed_recips:
            if not to:
                return Decision("ASK_HUMAN", "3_missing_recipient", "No recipient specified, ask user.", "")
            elif is_tainted(to):
                return Decision("BLOCK", "3_tainted_recipient", "Recipient not in user message, potentially from untrusted data.", to)
            else:
                return Decision("ASK_HUMAN", "3_unknown_recipient", "Recipient not explicitly allowed.", to)

    # Rule 8: Mutating action approval (ASK_HUMAN when session is clean)
    if name == "write_record":
        return Decision("ASK_HUMAN", "8_mutating_action_approval", "Database mutation requires human confirmation.", name)

    # Rule 4: Tainted / generated arg + external effect in clean session -> ASK_HUMAN
    external_tools = {"send_email", "write_record"}
    if name in external_tools:
        for k, v in args.items():
            if isinstance(v, str) and is_tainted(v):
                if k in ["body", "data"]:
                    return Decision("ASK_HUMAN", "4_generated_content_approval", f"External tool {name} with generated {k} requires human confirmation.", v[:20])

    if name == "search_web":
        q = str(args.get("query", ""))
        if len(q) > 50 and is_tainted(q):
            return Decision("BLOCK", "4_tainted_query", "Suspiciously long tainted search query.", q[:20])

    # Rule 5 & 6: Data flow & Confidential Overlap Exfiltration
    def check_overlap(val: str):
        if not ctx or not ctx.get("confidential_reads"):
            return False
        for secret in ctx["confidential_reads"]:
            if not secret:
                continue
            if len(secret) < 8:
                if secret in val:
                    return True
            else:
                for i in range(len(secret) - 8):
                    if secret[i:i+8] in val:
                        return True
        return False

    if name in ["send_email", "write_record", "search_web"]:
        for k, v in args.items():
            if isinstance(v, str) and check_overlap(v):
                return Decision("BLOCK", "5_data_exfiltration", f"Argument {k} contains confidential data.", v[:20])

        if name == "search_web":
            q = str(args.get("query", ""))
            if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}', q):  # looks like base64
                return Decision("BLOCK", "6_search_exfil", "Search query contains encoded blob.", q[:20])

    return Decision("ALLOW", "0_allow", "Action allowed.", "")
