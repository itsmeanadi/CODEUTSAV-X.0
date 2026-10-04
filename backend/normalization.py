"""Input canonicalization used before security analysis.

The canonical form is analysis-only: the original user/tool text is retained for
audit/provenance, while decoded/normalized variants are used for detection.
"""
import base64, binascii, codecs, html, re, urllib.parse, unicodedata
from dataclasses import dataclass, field
from typing import List, Dict

ZERO_BIDI = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u2064]")
B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])")

@dataclass
class NormalizedText:
    original: str
    canonical: str
    transformations: List[str] = field(default_factory=list)
    decoded_candidates: List[str] = field(default_factory=list)

def _safe_b64(s):
    try:
        raw=base64.b64decode(s, validate=True)
        out=raw.decode("utf-8")
        return out if out.strip() else None
    except Exception:
        return None

def _safe_hex(s):
    try:
        return bytes.fromhex(s).decode("utf-8")
    except Exception:
        return None

def normalize(text: str, max_depth: int=2) -> NormalizedText:
    original = text if isinstance(text,str) else str(text)
    cur = unicodedata.normalize("NFKC", original)
    transformations=[]
    if cur != original: transformations.append("unicode_nfkc")
    stripped=ZERO_BIDI.sub("",cur)
    if stripped != cur: transformations.append("zero_width_bidi_removed")
    cur=stripped
    decoded=[]

    for depth in range(max_depth+1):
        changed=False
        for rx, decoder, label in ((B64,_safe_b64,"base64"),(HEX,_safe_hex,"hex")):
            def repl(m):
                nonlocal changed
                out=decoder(m.group(0))
                if out and out != m.group(0):
                    changed=True
                    decoded.append({"encoding":label,"depth":depth,"text":out})
                    return f" {out} "
                return m.group(0)
            cur=rx.sub(repl,cur)
        unquoted=urllib.parse.unquote(cur)
        if unquoted != cur:
            cur=unquoted; transformations.append("url_decode"); changed=True
        unhtml=html.unescape(cur)
        if unhtml != cur:
            cur=unhtml; transformations.append("html_entity_decode"); changed=True
        comments=re.sub(r"<!--(.*?)-->",r" \1 ",cur,flags=re.S)
        if comments != cur:
            cur=comments; transformations.append("html_comment_unwrap"); changed=True
        if not changed: break

    # ROT13 is kept as a separate candidate so normal text is not doubled.
    rot=codecs.decode(cur,"rot_13")
    if rot != cur:
        decoded.append({"encoding":"rot13","depth":0,"text":rot})
        transformations.append("rot13_candidate")
    return NormalizedText(original, cur, transformations, decoded)

def analysis_variants(text: str):
    n=normalize(text)
    return [n.canonical] + [x["text"] for x in n.decoded_candidates]
