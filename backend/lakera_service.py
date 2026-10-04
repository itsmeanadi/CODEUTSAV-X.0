"""Lakera Guard Security Intelligence Adapter for SentinelGate PS3.

Integrates Lakera Guard (v2 API) as an advisory external threat intelligence layer.
INVARIANT: Lakera signals enrich the Risk Engine and Security Trace, but Lakera
NEVER authorizes actions. Action Guard remains the final authority.
"""
import os
import re
import json
import time
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

import secret_scanner

LAKERA_DEFAULT_ENDPOINT = "https://api.lakera.ai/v2/guard"

@dataclass
class LakeraResult:
    available: bool
    flagged: bool
    categories: List[str] = field(default_factory=list)
    severity: Optional[str] = None      # "high", "medium", "low", or None
    confidence: Optional[float] = None  # Float or None if unprovided
    source: str = "lakera"              # "lakera", "lakera_mock", "disabled", "unavailable"
    latency_ms: float = 0.0
    error: Optional[str] = None
    breakdown: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "SKIPPED"             # "PASSED", "WARNING", "BLOCKED", "SKIPPED", "FAILED"
    detector_rule: str = "none"

# Performance telemetry tracking
_METRICS = {
    "lakera_calls": 0,
    "lakera_latencies_ms": [],
    "lakera_errors": 0,
    "lakera_timeouts": 0,
}

# In-memory content hash cache to avoid duplicate remote scans on identical immutable text
_SCAN_CACHE: Dict[str, LakeraResult] = {}
_MAX_CACHE_SIZE = 500

_MOCK_OVERRIDE: Optional[str] = None

def set_mock_mode(mode: Optional[str]):
    """Set deterministic mock mode for testing ('safe', 'prompt_injection', 'indirect_injection',
    'dangerous_tool_behavior', 'unavailable', 'timeout', 'api_error', or None)."""
    global _MOCK_OVERRIDE
    _MOCK_OVERRIDE = mode

def reset_telemetry():
    """Reset latency and call counters for benchmarking."""
    global _METRICS, _SCAN_CACHE
    _METRICS = {
        "lakera_calls": 0,
        "lakera_latencies_ms": [],
        "lakera_errors": 0,
        "lakera_timeouts": 0,
    }
    _SCAN_CACHE.clear()

def get_metrics() -> Dict[str, Any]:
    """Return performance and error metrics for Lakera Guard."""
    lats = _METRICS["lakera_latencies_ms"]
    mean_ms = round(sum(lats) / len(lats), 2) if lats else 0.0
    # 95th percentile
    if lats:
        sorted_lats = sorted(lats)
        p95_idx = int(0.95 * len(sorted_lats))
        p95_ms = round(sorted_lats[min(p95_idx, len(sorted_lats) - 1)], 2)
    else:
        p95_ms = 0.0
    return {
        "lakera_calls": _METRICS["lakera_calls"],
        "lakera_mean_ms": mean_ms,
        "lakera_p95_ms": p95_ms,
        "lakera_errors": _METRICS["lakera_errors"],
        "lakera_timeouts": _METRICS["lakera_timeouts"],
    }

def _redact_secrets_before_scan(text: str) -> str:
    """Ensure secrets/credentials are redacted before sending to any external API."""
    if not text:
        return ""
    findings = secret_scanner._fallback(text)
    redacted = secret_scanner.redact(text, findings) if findings else text
    
    # Also strip any live environment keys if they appear in text
    for env_k in ["LAKERA_API_KEY", "GROQ_API_KEY", "BREVO_API_KEY"]:
        v = os.getenv(env_k)
        if v and len(v) > 8 and v in redacted:
            redacted = redacted.replace(v, "[REDACTED_PROJECT_SECRET]")
    return redacted

def _cache_key(text: str, context_type: str) -> str:
    h = hashlib.sha256((context_type + ":" + text).encode("utf-8")).hexdigest()
    return h

def _simulate_mock(mode: str, latency: float = 1.0) -> LakeraResult:
    """Generate deterministic mock responses for offline testing."""
    if mode == "safe":
        return LakeraResult(
            available=True,
            flagged=False,
            categories=[],
            severity=None,
            confidence=0.0,
            source="lakera_mock",
            latency_ms=latency,
            status="PASSED",
            detector_rule="none"
        )
    elif mode in ["prompt_injection", "injection"]:
        return LakeraResult(
            available=True,
            flagged=True,
            categories=["prompt_injection"],
            severity="high",
            confidence=0.96,
            source="lakera_mock",
            latency_ms=latency,
            status="WARNING",
            detector_rule="lakera_prompt_injection",
            breakdown=[{"detector_type": "prompt_injection", "detected": True, "confidence": "L1"}]
        )
    elif mode == "indirect_injection":
        return LakeraResult(
            available=True,
            flagged=True,
            categories=["indirect_prompt_injection", "prompt_injection"],
            severity="high",
            confidence=0.93,
            source="lakera_mock",
            latency_ms=latency,
            status="WARNING",
            detector_rule="lakera_indirect_injection",
            breakdown=[{"detector_type": "indirect_prompt_injection", "detected": True, "confidence": "L1"}]
        )
    elif mode == "dangerous_tool_behavior":
        return LakeraResult(
            available=True,
            flagged=True,
            categories=["tool_manipulation", "data_exfiltration"],
            severity="high",
            confidence=0.89,
            source="lakera_mock",
            latency_ms=latency,
            status="WARNING",
            detector_rule="lakera_dangerous_tool_behavior",
            breakdown=[{"detector_type": "tool_manipulation", "detected": True, "confidence": "L2"}]
        )
    elif mode == "unavailable":
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=latency,
            error="Lakera service unreachable (simulated unavailable)",
            status="FAILED",
            detector_rule="lakera_unavailable"
        )
    elif mode == "timeout":
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=latency,
            error="Lakera request timed out (simulated timeout)",
            status="FAILED",
            detector_rule="lakera_timeout"
        )
    elif mode == "api_error":
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=latency,
            error="HTTP 500: Lakera upstream error",
            status="FAILED",
            detector_rule="lakera_api_error"
        )
    else:
        # Default mock fallback is safe
        return LakeraResult(
            available=True,
            flagged=False,
            categories=[],
            source="lakera_mock",
            latency_ms=latency,
            status="PASSED"
        )

def scan_text(text: str, context_type: str = "user_input") -> LakeraResult:
    """Core screening method. Scans text against Lakera Guard (or active mock mode).
    Always returns a structured LakeraResult without raising unhandled network exceptions."""
    t0 = time.time()
    
    # 1. Check Mock Mode override or environment
    mock_mode = _MOCK_OVERRIDE or os.getenv("LAKERA_MOCK_MODE")
    if mock_mode:
        res = _simulate_mock(mock_mode, latency=1.5)
        _METRICS["lakera_calls"] += 1
        _METRICS["lakera_latencies_ms"].append(res.latency_ms)
        return res

    # 2. Check if Lakera is enabled in environment
    enabled = os.getenv("LAKERA_ENABLED", "false").lower() in ("1", "true", "yes")
    api_key = os.getenv("LAKERA_API_KEY", "").strip()

    if not enabled:
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="disabled",
            latency_ms=0.0,
            status="SKIPPED",
            detector_rule="none"
        )

    if not api_key:
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            error="LAKERA_API_KEY not configured in environment",
            latency_ms=0.0,
            status="SKIPPED",
            detector_rule="none"
        )

    # 3. Check in-memory content cache for duplicate scans
    clean_text = _redact_secrets_before_scan(text)
    ck = _cache_key(clean_text, context_type)
    if ck in _SCAN_CACHE:
        cached = _SCAN_CACHE[ck]
        # Return a copy with fresh timestamp
        return LakeraResult(
            available=cached.available,
            flagged=cached.flagged,
            categories=list(cached.categories),
            severity=cached.severity,
            confidence=cached.confidence,
            source=cached.source,
            latency_ms=0.1,
            error=cached.error,
            breakdown=list(cached.breakdown),
            status=cached.status,
            detector_rule=cached.detector_rule
        )

    # 4. Perform live request to official Lakera Guard endpoint
    endpoint = os.getenv("LAKERA_ENDPOINT", LAKERA_DEFAULT_ENDPOINT)
    timeout_ms = float(os.getenv("LAKERA_TIMEOUT_MS", "1500"))
    timeout_sec = max(0.2, timeout_ms / 1000.0)

    payload = {
        "messages": [
            {"role": "user", "content": clean_text[:12000]}
        ],
        "breakdown": True
    }
    project_id = os.getenv("LAKERA_PROJECT_ID")
    if project_id:
        payload["project_id"] = project_id

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SentinelGate-PS3/1.0"
        },
        method="POST"
    )

    _METRICS["lakera_calls"] += 1
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            elapsed_ms = (time.time() - t0) * 1000
            _METRICS["lakera_latencies_ms"].append(elapsed_ms)
            body = resp.read().decode("utf-8")
            data = json.loads(body)

            flagged = bool(data.get("flagged", False))
            breakdown = data.get("breakdown", [])
            categories = []
            
            # Extract flagged detector categories
            if isinstance(breakdown, list):
                for b in breakdown:
                    if isinstance(b, dict) and b.get("detected"):
                        categories.append(str(b.get("detector_type", "unknown")))
            
            cat_obj = data.get("categories", {})
            if isinstance(cat_obj, dict):
                for k, v in cat_obj.items():
                    if v and k not in categories:
                        categories.append(k)
            elif isinstance(cat_obj, list):
                for k in cat_obj:
                    if k not in categories:
                        categories.append(str(k))

            severity = "high" if flagged else None
            status = "WARNING" if flagged else "PASSED"
            detector_rule = "lakera_" + (categories[0] if categories else "flagged") if flagged else "none"

            res = LakeraResult(
                available=True,
                flagged=flagged,
                categories=categories,
                severity=severity,
                confidence=0.9 if flagged else 0.0,
                source="lakera",
                latency_ms=round(elapsed_ms, 2),
                breakdown=breakdown if isinstance(breakdown, list) else [],
                status=status,
                detector_rule=detector_rule
            )
            
            # Save in cache
            if len(_SCAN_CACHE) < _MAX_CACHE_SIZE:
                _SCAN_CACHE[ck] = res
            return res

    except urllib.error.HTTPError as e:
        elapsed_ms = (time.time() - t0) * 1000
        _METRICS["lakera_latencies_ms"].append(elapsed_ms)
        _METRICS["lakera_errors"] += 1
        err_msg = f"HTTP {e.code}: {e.reason}"
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=round(elapsed_ms, 2),
            error=err_msg,
            status="FAILED",
            detector_rule="lakera_http_error"
        )
    except (urllib.error.URLError, TimeoutError) as e:
        elapsed_ms = (time.time() - t0) * 1000
        _METRICS["lakera_latencies_ms"].append(elapsed_ms)
        if "timed out" in str(e).lower() or isinstance(e, TimeoutError):
            _METRICS["lakera_timeouts"] += 1
            err_msg = f"Lakera request timed out ({int(timeout_ms)}ms)"
        else:
            _METRICS["lakera_errors"] += 1
            err_msg = f"Lakera connection error: {e}"
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=round(elapsed_ms, 2),
            error=err_msg,
            status="FAILED",
            detector_rule="lakera_timeout_or_connection"
        )
    except Exception as e:
        elapsed_ms = (time.time() - t0) * 1000
        _METRICS["lakera_latencies_ms"].append(elapsed_ms)
        _METRICS["lakera_errors"] += 1
        return LakeraResult(
            available=False,
            flagged=False,
            categories=[],
            source="unavailable",
            latency_ms=round(elapsed_ms, 2),
            error=f"Unexpected Lakera adapter error: {str(e)}",
            status="FAILED",
            detector_rule="lakera_internal_error"
        )

# Internal helper interface for SentinelGate stages
def scan_input(user_msg: str) -> LakeraResult:
    """Hook #1: Scan user prompt after normalization."""
    return scan_text(user_msg, context_type="user_input")

def scan_untrusted_content(text: str, source: str = "untrusted_data") -> LakeraResult:
    """Hook #2: Scan untrusted external content (RAG docs, search_web results, tool output)."""
    return scan_text(text, context_type=f"untrusted:{source}")

def scan_tool_proposal(tool_name: str, args: dict, context: Optional[dict] = None) -> LakeraResult:
    """Hook #3: Screen proposed tool calls before Action Guard evaluation.
    Scans the serialized invocation to detect exfiltration or suspicious payloads."""
    summary = f"Tool proposal: {tool_name}({json.dumps(args or {}, default=str)})"
    return scan_text(summary, context_type="tool_proposal")
