#!/usr/bin/env python3
from __future__ import annotations
import re
from typing import List
from .config import CONFIG, logger

DEFAULT_ENABLER_KEYWORDS = [
    "ai",
    "artificial intelligence",
    "machine learning",
    "third-party",
    "outsourcing",
    "zero-day",
    "unpatched",
    "cryptocurrency",
    "quantum",
    "geopolitical",
    "open-source",
]


def _get_excerpt(text: str, pos: int, radius: int = 120) -> str:
    if not text:
        return ""
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    excerpt = text[start:end]
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    return excerpt


def _build_texts(text_or_record) -> tuple[str, str]:
    agg_parts = []
    prov_parts = []
    if isinstance(text_or_record, dict):
        rec = text_or_record
        for f in (
            "title",
            "summary_text",
            "summary",
            "text",
            "full_text",
            "description",
        ):
            v = rec.get(f)
            if v:
                try:
                    agg_parts.append(str(v))
                except Exception:
                    continue

        for p in rec.get("provenance") or []:
            try:
                if isinstance(p, dict):
                    # prefer an explicit excerpt if present
                    ex = p.get("excerpt") or p.get("source_name") or p.get("source_url")
                    if ex:
                        prov_parts.append(str(ex))
                else:
                    prov_parts.append(str(p))
            except Exception:
                continue
    else:
        agg_parts.append(str(text_or_record or ""))

    primary = "\n".join([p for p in agg_parts if p and not isinstance(p, dict)])
    prov_text = "\n".join([p for p in prov_parts if p])
    return primary, prov_text


def extract_enablers(
    text_or_record, detailed: bool = False, radius: int | None = None
) -> List:
    """
    Unified enabler extraction.
    - If detailed=False: returns list[str] of matched enabler keywords.
    - If detailed=True: returns list[dict] with keys: enabler, excerpt, confidence.
    """
    try:
        keywords = CONFIG.get("ENABLER_KEYWORDS") or DEFAULT_ENABLER_KEYWORDS
    except Exception:
        keywords = DEFAULT_ENABLER_KEYWORDS

    primary, prov_text = _build_texts(text_or_record)
    primary_lower = (primary or "").lower()
    prov_lower = (prov_text or "").lower()

    if radius is None:
        try:
            radius = int(CONFIG.get("EXCERPT_RADIUS", 120))
        except Exception:
            radius = 120

    results = []
    seen = set()
    for kw in keywords:
        if not kw:
            continue
        try:
            pat = re.compile(r"\b" + re.escape(kw.lower()) + r"\b", re.I)
            mobj = pat.search(primary)
            source_text = primary
            source_lower = primary_lower
            if not mobj:
                mobj = pat.search(prov_text)
                source_text = prov_text
                source_lower = prov_lower

            if not mobj:
                continue

            kn = kw.strip()
            if kn in seen:
                continue
            seen.add(kn)
            start = mobj.start()
            excerpt = _get_excerpt(source_text, start, radius=radius)

            conf = 0.6
            if len(kw) > 6:
                conf += 0.08
            if re.search(r"observed|confirmed|reported|seen|exploited", excerpt, re.I):
                conf += 0.18
            try:
                if len(list(pat.finditer(primary_lower))) > 1 or len(list(pat.finditer(prov_lower))) > 1:
                    conf += 0.08
            except Exception:
                pass

            conf = min(0.99, conf)

            if detailed:
                results.append({
                    "enabler": kn,
                    "excerpt": excerpt.strip(),
                    "confidence": round(conf, 2),
                })
            else:
                results.append(kn)
        except Exception:
            try:
                if kw.lower() in primary_lower or kw.lower() in prov_lower:
                    kn = kw.strip()
                    if detailed:
                        results.append({"enabler": kn, "excerpt": "", "confidence": 0.6})
                    else:
                        results.append(kn)
            except Exception:
                continue
    return results

def extract_enablers_detailed(text_or_record, radius: int = 120) -> List[dict]:
    return extract_enablers(text_or_record, detailed=True, radius=radius)


def extract_enablers_simple(text_or_record) -> List[str]:
    return extract_enablers(text_or_record, detailed=False)
