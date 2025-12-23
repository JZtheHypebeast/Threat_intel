from __future__ import annotations

import warnings
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except Exception:
    pass
warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*SWIG.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fitz.*")

import argparse
import datetime as dt
import hashlib
import html
import json
import logging
import os
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .progress import start_live_progress, stop_live_progress
try:
    from .reporting import _render_pdf
except Exception:
    try:
        from reporting import _render_pdf  # type: ignore
    except Exception:
        _render_pdf = None  # type: ignore

RESULTS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
ENV_GEOFEED_RSS_FEEDS = [
    s.strip()
    for s in os.getenv("GEOFEED_RSS_FEEDS", "").split(",")
    if s.strip()
]
CFG: Optional[Dict[str, Any]] = None
CONFIG_IMPORT_ERROR: Optional[Exception] = None
logger = logging.getLogger(__name__)

try:
    from .config import CONFIG as CFG
    from .config import RESULTS_ROOT as _RESULTS_ROOT

    RESULTS_ROOT = _RESULTS_ROOT
except Exception as exc:
    CONFIG_IMPORT_ERROR = exc
    CFG = None

warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*SWIG.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fitz.*")


# =========================
# ====== Config ===========
# =========================


def _require_config() -> Dict[str, Any]:
    if CFG is None:
        raise RuntimeError(
            "GeoFeed requires CONFIG from collector.config; import failed"
        ) from CONFIG_IMPORT_ERROR
    return CFG


# =========================
# ====== Models ===========
# =========================


@dataclass
class FeedItem:
    title: str
    url: str
    published: str
    summary: str


# =========================
# ===== Fetch/Parse =======
# =========================


def _http_get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; geofeed/1.0)",
            "Accept": "application/xml, text/xml, application/rss+xml, text/html, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        try:
            return raw.decode("utf-8-sig", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")


DEFAULT_GEOFEED_BOILERPLATE = [
    "cookie",
    "privacy",
    "terms",
    "subscribe",
    "newsletter",
    "sign up",
    "register",
    "all rights reserved",
    "advert",
    "promo",
    "accept cookies",
]


def _strip_html(s: str) -> str:
    s = re.sub(r"(?i)</(p|div|li|br|h[1-6])\s*>", "\n", s)
    s = re.sub(r"<script[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<style[\s\S]*?</style>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+\n", "\n", s)
    return s


def _dehyphenate(text: str) -> str:
    return re.sub(r"(\w)-\s+(\w)", r"\1\2", text)


def _sanitize_text(
    html_text: str, boilerplate_keywords: List[str], min_paragraph_words: int
) -> str:
    raw = _strip_html(html_text)
    raw = _dehyphenate(raw)
    lines = [ln.strip() for ln in raw.split("\n")]
    cleaned: List[str] = []
    for ln in lines:
        if not ln:
            continue
        low = ln.lower()
        if any(k in low for k in boilerplate_keywords):
            continue
        if len(ln.split()) < min_paragraph_words:
            continue
        cleaned.append(ln)
    return "\n\n".join(cleaned)


def _parse_rss(xml_text: str) -> List[FeedItem]:
    items: List[FeedItem] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items

    channel = root.find("channel")
    if channel is None:
        feed = root.find("{http://www.w3.org/2005/Atom}feed")
        if feed is None:
            return items
        ns = "{http://www.w3.org/2005/Atom}"
        for entry in feed.findall(f"{ns}entry"):
            title = (entry.findtext(f"{ns}title") or "").strip()
            link = ""
            for lnk in entry.findall(f"{ns}link"):
                href = lnk.attrib.get("href")
                if href:
                    link = href
                    break
            published = (entry.findtext(f"{ns}updated") or entry.findtext(f"{ns}published") or "").strip()
            summary = (entry.findtext(f"{ns}summary") or entry.findtext(f"{ns}content") or "").strip()
            items.append(FeedItem(title=title, url=link, published=published, summary=summary))
        return items

    for it in channel.findall("item"):
        title = (it.findtext("title") or "").strip()
        url = (it.findtext("link") or "").strip()
        published = (it.findtext("pubDate") or "").strip()
        summary = (it.findtext("description") or "").strip()
        items.append(FeedItem(title=title, url=url, published=published, summary=summary))

    return items


def _parse_published(s: str) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc)
    except Exception:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d.astimezone(dt.timezone.utc)
        except Exception:
            return None


# =========================
# ====== Scoring ==========
# =========================


def _stable_id(title: str, url: str) -> str:
    h = hashlib.sha1(f"{title}|{url}".encode("utf-8", errors="ignore")).hexdigest()
    return h[:24]


def find_watchlist_hits(text: str, locations: List[str], assets: List[str]) -> Tuple[List[str], List[str]]:
    t = text.lower()
    loc_hits = []
    asset_hits = []
    for x in locations:
        if x and x.lower() in t:
            loc_hits.append(x)
    for x in assets:
        if x and x.lower() in t:
            asset_hits.append(x)
    return loc_hits[:12], asset_hits[:12]


def classify_domain(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["sanction", "embargo", "ultimatum", "border", "airspace", "intercept", "navy", "military"]):
        return "geopolitics"
    if any(k in t for k in ["oil", "gas", "pipeline", "refinery", "offshore", "rig", "fpso"]):
        return "energy"
    return "unknown"


def infer_event_type(text: str) -> str:
    t = text.lower()
    if "sanction" in t:
        return "sanctions"
    if any(k in t for k in ["border", "dispute", "essequibo", "esequibo"]):
        return "territorial_dispute"
    if any(k in t for k in ["navy", "military", "intercept", "drone", "airspace"]):
        return "military_activity"
    return "unspecified"


def escalation_score(
    text: str,
    weights: Dict[str, float],
    amplifiers: Dict[str, float],
    dampeners: Dict[str, float],
) -> Tuple[float, List[str]]:
    t = text.lower()
    score = 0.0
    reasons: List[str] = []
    for k, w in weights.items():
        if k.lower() in t:
            score += float(w)
            reasons.append(k)
    for k, w in amplifiers.items():
        if k.lower() in t:
            score += float(w)
            reasons.append(k)
    for k, w in dampeners.items():
        if k.lower() in t:
            score -= float(w)
            reasons.append(f"-{k}")

    reasons = list(dict.fromkeys(reasons))[:8]
    return score, reasons


# =========================
# ===== Summaries =========
# =========================


def _ollama_situation_summary(
    host: str,
    model: str,
    title: str,
    text: str,
    timeout: int,
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    try:
        prompt = (
            "SYSTEM:\n"
            "You are a strict information extraction engine for a central bank in Aruba.\n"
            "You MUST use ONLY the provided TEXT as your source. Do NOT use outside knowledge.\n"
            "For ALL fields EXCEPT 'risk', 'change', and 'impact', do NOT infer, assume, speculate, or add context.\n"
            "If a detail is not explicitly stated in TEXT, write exactly: Not specified.\n\n"

            "TASK:\n"
            "Read the article TEXT and return JSON ONLY (a single object) with EXACTLY these keys and no others:\n"
            "title, llm_summary, domain, event_type, state, change, countries_involved, "
            "primary_actors, key_indicators, osint_indicators, drivers, impact, risk, "
            "what_happened, domain_category.\n\n"

            "OUTPUT RULES (STRICT):\n"
            "- Output must be valid JSON and NOTHING ELSE.\n"
            "- Use EXACTLY the keys above. Do not add/remove/rename keys.\n"
            "- Each value must be a SHORT STRING. No arrays, no nested objects.\n"
            "- Use comma-separated values for multiple items inside a single string.\n"
            "- Keep wording close to TEXT; avoid generic filler.\n\n"

            "HALLUCINATION CONTROL:\n"
            "- For every field except 'risk' and 'change': ONLY extract what is explicitly stated in TEXT.\n"
            "- Do NOT add impacts, motivations, or implications unless TEXT explicitly says them.\n"
            "- Do NOT add countries/actors not named in TEXT.\n\n"

            "ALLOWED WIGGLE ROOM (ONLY FOR risk, change, and impact):\n"
            "A) risk (Aruba FI impact):\n"
            "- You may assess risk to Aruba's financial institutions based on facts stated in TEXT.\n"
            "- risk MUST be exactly one of: Low, Moderate, Elevated, High.\n"
            "- You may consider ONLY these channels IF supported by TEXT facts:\n"
            "  1) Sanctions/compliance exposure (shipping, oil trading, designated entities)\n"
            "  2) Correspondent banking / payment disruption risk\n"
            "  3) Market risk: oil price shock / volatility explicitly mentioned\n"
            "  4) Shipping/insurance/freight disruption explicitly mentioned\n"
            "- If TEXT contains no facts that connect to any channel above, set risk to Low.\n"
            "- Do NOT include any explanation or reasoning in the JSON.\n\n"

            "B) change (Trend for Markdown):\n"
            "- change MUST be exactly one of: New, Stable, ↗ Escalating, ↘ De-escalating.\n"
            "- Infer change ONLY from progression explicitly described in TEXT\n"
            "  (e.g., 'more', 'additional', 'expanded', 'first time', 'slowed', 'easing', 'resumed').\n"
            "- If TEXT describes a new action/measure with no comparison, use New.\n"
            "- If TEXT indicates intensification/expansion, use ↗ Escalating.\n"
            "- If TEXT indicates easing/rollback/normalization, use ↘ De-escalating.\n"
            "- If TEXT indicates no meaningful change, use Stable.\n\n"

            "FIELD RULES (STRICT EXTRACTION FOR ALL EXCEPT risk/change):\n"
            "1) title:\n"
            "- A concise, corrected headline describing the event, based only on TEXT.\n\n"

            "2) llm_summary:\n"
            "- 2-3 sentences MAX.\n"
            "- Factual extraction only. No implications unless explicitly stated.\n\n"

            "3) what_happened:\n"
            "- 3-4 sentences MAX, factual only, past tense.\n\n"

            "4) primary_actors:\n"
            "- Only actors explicitly named in TEXT who take action or are directly involved.\n"
            "- Comma-separated if multiple.\n\n"

            "5) countries_involved:\n"
            "- Only countries explicitly named in TEXT.\n"
            "- Comma-separated if multiple.\n\n"

            "6) key_indicators (Key Signals):\n"
            "- 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <indicator>\n"
            "  - <indicator>\n"
            "- Each indicator MUST be explicitly described in TEXT.\n"
            "- If none, Not specified.\n\n"

            "7) drivers (Why it started):\n"
            "- ONLY if TEXT explicitly states drivers/causes/motivation.\n"
            "- Write 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <impact>\n"
            "  - <impact>\n"
            "- If no explicit impacts are stated, Not specified.\n\n"

            "8) impact (Why it matters to Aruba FI):\n"
            "- You MAY infer plausible Aruba FI relevance using ONLY facts in TEXT.\n"
            "- Limit to these channels: sanctions/compliance exposure, payment disruption, market/oil shock, shipping/insurance disruption.\n"
            "- Keep it factual and grounded in TEXT; no speculation beyond these channels.\n"
            "- Write 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <impact>\n"
            "  - <impact>\n"
            "- If no explicit impacts are stated, Not specified.\n\n"

            "9) osint_indicators:\n"
            "- Only sources/methods explicitly mentioned in TEXT (e.g., AIS/ship-tracking, satellite imagery, official statement).\n"
            "- If none, Not specified.\n\n"

            "10) state:\n"
            "- Use one of: active, ongoing, planned, resolved, neutral, unknown.\n"
            "- Choose only if TEXT indicates status; otherwise unknown.\n\n"

            "11) domain_category and domain:\n"
            "- domain_category MUST be exactly one of: air, maritime, land, multi, unknown.\n"
            "- domain MUST match domain_category.\n"
            "- Choose based ONLY on what TEXT describes.\n"
            "- Use these cues:\n"
            "  air: air force, aircraft, fighter, drone, airspace, intercept, NOTAM\n"
            "  maritime: navy, warship, vessel, tanker, shipping, port, maritime, coast guard\n"
            "  land: army, ground forces, border, incursion, mobilization, troops\n"
            "  multi: two or more domains explicitly present\n"
            "  unknown: none of the above\n\n"

            "12) event_type:\n"
            "- Short concrete label based ONLY on TEXT (e.g., sanctions, blockade, naval interdiction, border clash).\n"
            "- If unclear, Not specified.\n\n"

            "FINAL REMINDER:\n"
            "- Return JSON only.\n\n"

            f"TITLE: {title}\n\n"
            f"TEXT:\n{text[:6000]}"
        )
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            }
        ).encode("utf-8")
        url = host.rstrip("/") + "/api/generate"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "geofeed/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        s = (data.get("response") or "").strip()
        if not s:
            return None, raw, "empty_response"
        def _cleanup_json(candidate: str) -> str:
            cleaned = candidate.replace("\r\n", "\n").replace("\r", "\n").strip()
            cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
            return cleaned

        try:
            parsed = json.loads(_cleanup_json(s))
        except Exception:
            start = s.find("{")
            if start >= 0:
                try:
                    parsed, _ = json.JSONDecoder().raw_decode(_cleanup_json(s[start:]))
                except Exception:
                    parsed = None
            else:
                parsed = None
        if not isinstance(parsed, dict):
            return None, raw, "invalid_json"
        if "What_happened" in parsed and "what_happened" not in parsed:
            parsed["what_happened"] = parsed.pop("What_happened")
        return parsed, raw, None
    except Exception:
        return None, None, "request_failed"


# =========================
# == LLM Output Validation =
# =========================

_EXPECTED_SITUATION_KEYS = {
    "title",
    "llm_summary",
    "domain",
    "event_type",
    "state",
    "change",
    "countries_involved",
    "primary_actors",
    "key_indicators",
    "osint_indicators",
    "drivers",
    "impact",
    "risk",
    "what_happened",
    "domain_category",
}

_ALLOWED_RISK = {"Low", "Moderate", "Elevated", "High", "Not specified"}
_ALLOWED_CHANGE = {"New", "Stable", "↗ Escalating", "↘ De-escalating", "Not specified"}
_ALLOWED_DOMAIN = {"air", "maritime", "land", "multi", "unknown"}


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


def _split_csv(s: str) -> List[str]:
    return [p.strip() for p in (s or "").split(",") if p.strip()]


def _validate_situation(
    situation: Dict[str, Any],
    article_text: str,
) -> Optional[Dict[str, Any]]:
    """Normalize/validate LLM output and log issues."""
    try:
        if not isinstance(situation, dict):
            logger.warning("GeoFeed LLM validation failed: situation is not a dict")
            return None
        missing = sorted(_EXPECTED_SITUATION_KEYS - set(situation.keys()))
        extra = sorted(set(situation.keys()) - _EXPECTED_SITUATION_KEYS)
        if missing or extra:
            logger.warning(
                "GeoFeed LLM validation: key mismatch missing=%s extra=%s",
                missing,
                extra,
            )

        normalized: Dict[str, str] = {}
        for k in _EXPECTED_SITUATION_KEYS:
            v = situation.get(k, "Not specified")
            normalized[k] = str(v).strip() if v is not None else "Not specified"

        if not normalized.get("what_happened") or normalized.get("what_happened") == "Not specified":
            if normalized.get("llm_summary") and normalized.get("llm_summary") != "Not specified":
                normalized["what_happened"] = normalized["llm_summary"]
                logger.warning("GeoFeed LLM validation: filled what_happened from llm_summary")

        if normalized.get("risk") not in _ALLOWED_RISK:
            logger.warning("GeoFeed LLM validation: invalid risk=%s", normalized.get("risk"))
            normalized["risk"] = "Not specified"
        if normalized.get("change") not in _ALLOWED_CHANGE:
            logger.warning("GeoFeed LLM validation: invalid change=%s", normalized.get("change"))
            normalized["change"] = "Not specified"

        domain_cat = (normalized.get("domain_category") or "").lower()
        domain = (normalized.get("domain") or "").lower()
        if domain_cat not in _ALLOWED_DOMAIN:
            logger.warning("GeoFeed LLM validation: invalid domain_category=%s", domain_cat)
            domain_cat = "unknown"
        normalized["domain_category"] = domain_cat
        normalized["domain"] = domain_cat
        if domain and domain != domain_cat:
            logger.warning(
                "GeoFeed LLM validation: domain mismatch domain=%s domain_category=%s",
                domain,
                domain_cat,
            )

        for k in ("key_indicators", "drivers", "impact"):
            val = (normalized.get(k) or "").strip()
            if val and val != "Not specified" and not val.lstrip().startswith("- "):
                normalized[k] = f"- {val}"
                logger.warning("GeoFeed LLM validation: normalized bullets for %s", k)

        return normalized
    except Exception:
        logger.exception("GeoFeed LLM validation failed: unexpected error")
        return None

# =========================
# ====== Output ===========
# =========================

def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")


def _strip_markdown_inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"_([^_]+)_", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def _prepare_pdf_text(markdown_text: str) -> str:
    lines = markdown_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cleaned = [_strip_markdown_inline(line) for line in lines]
    return "\n".join(cleaned)


def _make_summary_json(rows: List[Dict[str, Any]], hours: int, min_score: float) -> Dict[str, Any]:
    def _published_key(row: Dict[str, Any]) -> dt.datetime:
        parsed = _parse_published((row.get("published") or "").strip())
        if parsed is None:
            return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        return parsed

    def _fmt_date(val: str) -> str:
        parsed = _parse_published(val)
        if parsed is None:
            return "-"
        return parsed.strftime("%d %b %Y")

    def _trend_label(change: str) -> str:
        c = (change or "").strip().lower()
        if not c:
            return "New"
        if "escalat" in c or "increase" in c or "rising" in c:
            return "↗ Escalating"
        if "de-escalat" in c or "deescalat" in c or "decrease" in c or "easing" in c:
            return "↘ De-escalating"
        if "stable" in c or "steady" in c or "unchanged" in c:
            return "Stable"
        return "New"

    above = [r for r in rows if float(r.get("score", 0.0)) >= float(min_score)]
    top = sorted(above, key=_published_key, reverse=True)[:25]
    entries: List[Dict[str, Any]] = []
    for r in top:
        situation = r.get("situation") or {}
        title = (situation.get("title") or r.get("title") or "Untitled").strip()
        entry = {
            "title": title,
            "risk": (situation.get("risk") or "Low").title(),
            "trend": _trend_label(situation.get("change") or ""),
            "date": _fmt_date((r.get("published") or "").strip()),
            "primary_actors": situation.get("primary_actors") or "-",
            "countries_involved": situation.get("countries_involved") or "-",
            "summary": situation.get("llm_summary") or situation.get("what_happened") or "-",
            "why_it_matters": [
                f"Drivers: {situation.get('drivers') or '-'}",
                f"Impact: {situation.get('impact') or '-'}",
                f"Risk Level: {situation.get('risk') or '-'}",
            ],
            "key_signals": [
                situation.get("key_indicators") or "-",
                situation.get("osint_indicators") or "-",
            ],
            "source": r.get("url") or "",
        }
        if (
            entry.get("summary") == "-"
            and entry.get("primary_actors") == "-"
            and entry.get("countries_involved") == "-"
        ):
            continue
        entries.append(entry)

    return {
        "window_hours": hours,
        "generated_at": f"{dt.datetime.utcnow().isoformat()}Z",
        "min_score": min_score,
        "entries": entries,
    }


def _make_summary(rows: List[Dict[str, Any]], hours: int, min_score: float) -> str:
    lines = ["# GeoFeed Summary", ""]
    lines.append(f"Window: last {hours} hours")
    lines.append(f"Generated: {dt.datetime.utcnow().isoformat()}Z")
    lines.append(f"Collected: {len(rows)} items (showing score >= {min_score})")
    lines.append("")

    if not rows:
        lines.append("No items collected.")
        lines.append("")
        return "\n".join(lines)

    above = [r for r in rows if float(r.get("score", 0.0)) >= float(min_score)]
    if not above:
        lines.append(f"No items met min_score={min_score}. (Collected {len(rows)} total.)")
        lines.append("")
        return "\n".join(lines)

    def _published_key(row: Dict[str, Any]) -> dt.datetime:
        parsed = _parse_published((row.get("published") or "").strip())
        if parsed is None:
            return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        return parsed

    def _fmt_date(val: str) -> str:
        parsed = _parse_published(val)
        if parsed is None:
            return "-"
        return parsed.strftime("%d %b %Y")

    def _trend_label(change: str) -> str:
        c = (change or "").strip().lower()
        if not c:
            return "New"
        if "escalat" in c or "increase" in c or "rising" in c:
            return "↗ Escalating"
        if "de-escalat" in c or "deescalat" in c or "decrease" in c or "easing" in c:
            return "↘ De-escalating"
        if "stable" in c or "steady" in c or "unchanged" in c:
            return "Stable"
        return "New"

    top = sorted(above, key=_published_key, reverse=True)[:25]
    groups = {"maritime": [], "land": [], "air": [], "multi": [], "unknown": []}
    for r in top:
        situation = r.get("situation") or {}
        category = str(situation.get("domain_category") or "unknown").lower()
        if category not in groups:
            category = "unknown"
        groups[category].append(r)

    order = ["maritime", "land", "air", "multi", "unknown"]
    first_entry = True
    entry_num = 1
    for label in order:
        group = groups[label]
        if not group:
            continue
        lines.append(f"## {label.capitalize()}")
        lines.append("")
        for r in group:
            if not first_entry:
                lines.append("[[PAGE_BREAK]]")
                lines.append("")
            first_entry = False
            situation = r.get("situation") or {}
            title = (situation.get("title") or r.get("title") or "Untitled").strip()
            risk = (situation.get("risk") or "Low").title()
            trend = _trend_label(situation.get("change") or "")
            date = _fmt_date((r.get("published") or "").strip())
            actors = situation.get("primary_actors") or "-"
            countries_involved = situation.get("countries_involved") or "-"
            summary = situation.get("llm_summary") or situation.get("what_happened") or "-"
            if summary == "-" and actors == "-" and countries_involved == "-":
                continue
            drivers = situation.get("drivers") or "-"
            impact = situation.get("impact") or "-"
            key_signals = situation.get("key_indicators") or situation.get("osint_indicators") or "-"

            url = (r.get("url") or "").strip()
            if url:
                lines.append(f"### {entry_num}. [{title}]({url})")
            else:
                lines.append(f"### {entry_num}. {title}")
            lines.append(
                f"**Risk:** {risk} | **Trend:** {trend} | **Date:** {date}"
            )
            lines.append("")
            lines.append(f"**Primary Actors:** {actors}  ")
            lines.append(f"**Countries Involved:** {countries_involved}")
            lines.append("")
            lines.append("**Summary**")
            lines.append(summary)
            lines.append("")
            lines.append("**Why It Matters**")
            lines.append(f"Drivers: {drivers}")
            lines.append(f"Impact: {impact}")
            lines.append(f"Risk Level: {situation.get('risk') or '-'}")
            lines.append("")
            lines.append("**Key Signals**")
            lines.append(f"Key Indicators: {situation.get('key_indicators') or '-'}")
            lines.append(f"OSINT Indicators: {situation.get('osint_indicators') or '-'}")
            lines.append("")
            entry_num += 1

    return "\n".join(lines)


# =========================
# ===== CLI/Runner ========
# =========================


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "ETA 00s"
    mins, secs = divmod(int(seconds), 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"ETA {hours}h{mins:02d}m"
    if mins:
        return f"ETA {mins:02d}m{secs:02d}s"
    return f"ETA {secs:02d}s"


def _shorten_title(title: str, max_len: int = 60) -> str:
    if not title:
        return "-"
    title = str(title).strip()
    if len(title) <= max_len:
        return title
    return title[: max_len - 3].rstrip() + "..."


def _update_progress(
    progress_state: Dict[str, Any],
    processed: int,
    total_expected: int,
    started_at: float,
    item_title: Optional[str] = None,
) -> None:
    progress_state["current"] = processed
    if total_expected <= 0:
        return
    elapsed = time.time() - started_at
    remaining = max(total_expected - processed, 0) * (elapsed / max(processed, 1))
    status = f"{processed}/{total_expected} {_format_eta(remaining)}"
    if item_title:
        status = f"{status} | {_shorten_title(item_title)}"
    progress_state["status"] = status

def build_argparser() -> argparse.ArgumentParser:
    cfg = _require_config()
    p = argparse.ArgumentParser(description="GeoFeed collector (markdown summary only).")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--outdir", type=str, default="")
    p.add_argument(
        "--results-root",
        type=str,
        default=os.getenv("TI_RESULTS_ROOT", RESULTS_ROOT),
        help="Root output directory (defaults to collector RESULTS_ROOT)",
    )
    p.add_argument("--timeout", type=int, default=int(cfg["GEOFEED_REQUEST_TIMEOUT"]))
    p.add_argument("--max-items", type=int, default=int(cfg["GEOFEED_MAX_ITEMS_PER_FEED"]))
    p.add_argument("--min-score", type=float, default=None)
    p.add_argument("--pdf", action="store_true", help="Also render the markdown summary as PDF")
    return p


def _default_outdir(results_root: str) -> str:
    now = dt.datetime.now()
    return os.path.join(results_root, "geofeed", now.strftime("%Y%m%d"), now.strftime("%H%M%S"))


def run_geofeed(
    hours: int,
    outdir: str,
    results_root: str,
    timeout: int,
    max_items: int,
    min_score: Optional[float],
    render_pdf: bool = False,
) -> int:
    cfg = _require_config()

    feeds = cfg.get("GEOFEED_RSS_FEEDS") or ENV_GEOFEED_RSS_FEEDS
    if not feeds:
        print("No GEOFEED_RSS_FEEDS configured.")
        return 0

    if not results_root:
        results_root = RESULTS_ROOT

    if not outdir:
        outdir = _default_outdir(results_root)

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=int(hours))

    wl_locations = cfg.get("GEOFEED_WATCHLIST_LOCATIONS") or []
    wl_assets = cfg.get("GEOFEED_WATCHLIST_ASSETS") or []
    boilerplate_keywords = cfg.get("GEOFEED_BOILERPLATE_KEYWORDS") or DEFAULT_GEOFEED_BOILERPLATE
    min_paragraph_words = int(cfg.get("GEOFEED_MIN_PARAGRAPH_WORDS", 20))
    min_total_words = int(cfg.get("GEOFEED_MIN_TOTAL_WORDS", 80))

    weights = cfg.get("GEOFEED_SIGNAL_WEIGHTS") or {}
    amplifiers = cfg.get("GEOFEED_AMPLIFIERS") or {}
    dampeners = cfg.get("GEOFEED_DAMPENERS") or {}

    use_ollama = bool(cfg.get("GEOFEED_USE_OLLAMA", False))
    ollama_model = str(cfg.get("GEOFEED_OLLAMA_MODEL", cfg.get("LLM_MODEL")))
    ollama_host = str(cfg.get("OLLAMA_HOST", "http://localhost:11434"))
    add_llm_summary = bool(cfg.get("GEOFEED_ADD_LLM_SUMMARY", False))
    skip_validation = os.getenv("GEOFEED_SKIP_VALIDATE", "").lower() in ("1", "true", "yes")
    validate_llm = bool(cfg.get("GEOFEED_VALIDATE_LLM", True)) and not skip_validation

    min_score_val = float(min_score if min_score is not None else cfg["GEOFEED_MIN_SCORE"])

    rows: List[Dict[str, Any]] = []
    rawtext_rows: List[Dict[str, Any]] = []
    llm_failures: List[Dict[str, Any]] = []
    seen_ids = set()
    feed_items: List[Tuple[str, List[FeedItem]]] = []
    for feed_url in feeds:
        try:
            xml_text = _http_get(feed_url, timeout=timeout)
            items = _parse_rss(xml_text)[:max_items]
        except Exception:
            items = []
        feed_items.append((feed_url, items))

    total_expected = sum(len(items) for _, items in feed_items)
    progress_state = {"current": 0, "status": ""}
    stop_evt, thread = start_live_progress(
        "GeoFeed", total_expected if total_expected > 0 else 1, progress_state
    )
    started_at = time.time()
    processed = 0

    try:
        for feed_url, items in feed_items:
            for it in items:
                pub_dt = _parse_published(it.published)
                if pub_dt is not None and pub_dt < cutoff:
                    processed += 1
                    _update_progress(
                        progress_state, processed, total_expected, started_at, it.title
                    )
                    continue

                sid = _stable_id(it.title, it.url)
                if sid in seen_ids:
                    processed += 1
                    _update_progress(
                        progress_state, processed, total_expected, started_at, it.title
                    )
                    continue
                seen_ids.add(sid)

                url = it.url.strip()

                page_text = ""
                try:
                    page_html = _http_get(url, timeout=timeout)
                    page_text = _sanitize_text(
                        page_html,
                        boilerplate_keywords=boilerplate_keywords,
                        min_paragraph_words=min_paragraph_words,
                    )
                except Exception:
                    page_text = _sanitize_text(
                        it.summary or "",
                        boilerplate_keywords=boilerplate_keywords,
                        min_paragraph_words=min_paragraph_words,
                    )
                if len(page_text.split()) < min_total_words:
                    page_text = _strip_html(it.summary or "")

                rawtext_rows.append(
                    {
                        "id": sid,
                        "title": it.title,
                        "url": url,
                        "published": it.published,
                        "source_feed": feed_url,
                        "word_count": len(page_text.split()),
                        "raw_text": page_text,
                    }
                )

                blob = f"{it.title}\n\n{page_text}"
                domain = classify_domain(blob)
                event_type = infer_event_type(blob)
                score, reasons = escalation_score(blob, weights=weights, amplifiers=amplifiers, dampeners=dampeners)
                loc_hits, asset_hits = find_watchlist_hits(blob, wl_locations, wl_assets)
                below_threshold = score < min_score_val

                situation: Optional[Dict[str, Any]] = None
                if add_llm_summary and use_ollama:
                    situation, raw_resp, err = _ollama_situation_summary(
                        host=ollama_host,
                        model=ollama_model,
                        title=it.title,
                        text=page_text,
                        timeout=max(timeout, 45),
                    )
                    if situation is None:
                        logger.warning(
                            "GeoFeed LLM returned empty/invalid response for title=%s error=%s raw=%s",
                            it.title,
                            err,
                            (raw_resp or "")[:1200],
                        )
                        llm_failures.append(
                            {
                                "title": it.title,
                                "url": url,
                                "published": it.published,
                                "source_feed": feed_url,
                                "error": err or "unknown",
                                "raw_response": raw_resp or "",
                            }
                        )
                    elif not validate_llm:
                        logger.warning(
                            "GeoFeed LLM validation bypassed for title=%s",
                            it.title,
                        )
                    else:
                        situation = _validate_situation(situation, page_text) or None

                now = dt.datetime.now(dt.timezone.utc)
                rows.append(
                    {
                        "id": sid,
                        "ts": now.isoformat(),
                        "title": it.title,
                        "url": url,
                        "published": it.published,
                        "domain": domain,
                        "event_type": event_type,
                        "score": round(float(score), 2),
                        "below_threshold": bool(below_threshold),
                        "reasons": reasons,
                        "watchlist": {"locations": loc_hits, "assets": asset_hits},
                        "source_feed": feed_url,
                        "situation": situation,
                    }
                )

                processed += 1
                _update_progress(
                    progress_state, processed, total_expected, started_at, it.title
                )
    finally:
        progress_state["current"] = total_expected if total_expected > 0 else processed
        progress_state["status"] = f"{processed}/{total_expected} {_format_eta(0)}"
        stop_live_progress(stop_evt, thread, wait=True)

    rows = sorted(rows, key=lambda r: float(r.get("score", 0.0)), reverse=True)

    run_date = dt.datetime.now().strftime("%Y%m%d")
    md_path = os.path.join(outdir, f"geofeed_summary_{run_date}.md")
    pdf_path = os.path.join(outdir, f"geofeed_summary_{run_date}.pdf")
    rawtext_path = os.path.join(outdir, f"rawtext4geofeed_{run_date}.jsonl")
    llm_fail_path = os.path.join(outdir, f"geofeed_llm_failures_{run_date}.jsonl")
    json_path = os.path.join(outdir, f"geofeed_summary_{run_date}.json")

    summary_text = _make_summary(rows, hours=hours, min_score=min_score_val)
    summary_json = _make_summary_json(rows, hours=hours, min_score=min_score_val)
    _write_jsonl(rawtext_path, rawtext_rows)
    if llm_failures:
        _write_jsonl(llm_fail_path, llm_failures)
        print(f"Wrote LLM failures -> {llm_fail_path}")
    _write_text(json_path, json.dumps(summary_json, ensure_ascii=True, indent=2))
    _write_text(md_path, summary_text)
    if render_pdf and _render_pdf is not None:
        _render_pdf(summary_text, Path(pdf_path))
        print(f"Wrote PDF -> {pdf_path}")

    print(f"Wrote rawtext -> {rawtext_path}")
    print(f"Wrote summary -> {md_path}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    return run_geofeed(
        hours=args.hours,
        outdir=args.outdir,
        results_root=args.results_root,
        timeout=args.timeout,
        max_items=args.max_items,
        min_score=args.min_score,
        render_pdf=args.pdf,
    )


if __name__ == "__main__":
    raise SystemExit(main())
