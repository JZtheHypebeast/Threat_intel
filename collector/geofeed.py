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
import shutil
import subprocess
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


def _decision_label(risk: str, score: float, thresholds: Dict[str, Any]) -> str:
    r = (risk or "").strip().title()
    try:
        s = float(score or 0.0)
    except Exception:
        s = 0.0

    action_risk = set([x.title() for x in (thresholds.get("action_required_risk") or [])])
    prepare_risk = set([x.title() for x in (thresholds.get("prepare_risk") or [])])
    prepare_score = float(thresholds.get("prepare_score") or 6.0)
    action_score = float(thresholds.get("action_required_score") or 8.0)

    if r in action_risk or s >= action_score:
        return "Action Required"
    if r in prepare_risk or s >= prepare_score:
        return "Prepare"
    return "Monitor"


def classify_domain(text: str) -> str:
    t = text.lower()
    air = any(
        k in t
        for k in [
            "air force",
            "airspace",
            "airbase",
            "aviation",
            "fighter",
            "jet",
            "drone",
            "uav",
            "notam",
            "intercept",
        ]
    )
    maritime = any(
        k in t
        for k in [
            "navy",
            "warship",
            "tanker",
            "shipping",
            "port",
            "maritime",
            "coast guard",
            "fleet",
            "submarine",
            "vessel",
        ]
    )
    land = any(
        k in t
        for k in [
            "army",
            "troops",
            "ground forces",
            "border",
            "incursion",
            "mobilization",
            "battalion",
        ]
    )
    if sum([air, maritime, land]) >= 2:
        return "multi"
    if air:
        return "air"
    if maritime:
        return "maritime"
    if land:
        return "land"
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
            "You are a geopolitical risk analyst generating an executive-friendly structured summary.\n"
            "You MUST follow these rules:\n"
            "- Use ONLY information explicitly present in TEXT.\n"
            "- Do NOT introduce assumptions, invented actors, invented locations, or speculative impacts.\n"
            "- If information is not explicitly stated in TEXT, output exactly: Not specified\n"
            "- Return a single valid JSON object and nothing else.\n"
            "- Do not wrap JSON in markdown.\n\n"

            "OUTPUT JSON SCHEMA (exact keys):\n"
            "{\n"
            "  \"risk_level\": \"Low|Moderate|Elevated|High|Not specified\",\n"
            "  \"trend\": \"New|Stable|Escalating|De-escalating|Not specified\",\n"
            "  \"decision\": \"Monitor|Prepare|Action Required|Not specified\",\n"
            "  \"primary_actors\": \"<string or Not specified>\",\n"
            "  \"countries_involved\": \"<comma-separated list or Not specified>\",\n"
            "  \"summary\": \"<2-3 sentences or Not specified>\",\n"
            "  \"aruba_relevance_summary\": \"<2-3 sentences or Not specified>\",\n"
            "  \"situation\": {\n"
            "    \"key_indicators\": \"<bullet lines as one string or Not specified>\",\n"
            "    \"drivers\": \"<bullet lines as one string or Not specified>\",\n"
            "    \"impact\": \"<bullet lines as one string or Not specified>\",\n"
            "    \"osint_indicators\": \"<string or Not specified>\",\n"
            "    \"state\": \"active|ongoing|planned|resolved|neutral|unknown\",\n"
            "    \"domain_category\": \"air|maritime|land|multi|unknown\",\n"
            "    \"domain\": \"air|maritime|land|multi|unknown\",\n"
            "    \"event_type\": \"<short label or Not specified>\",\n"
            "  }\n"
            "}\n\n"

            "INSTRUCTIONS (follow in order):\n"
            "1) risk_level:\n"
            "- Low: minor event, limited escalation signals.\n"
            "- Moderate: meaningful event but limited spillover.\n"
            "- Elevated: credible escalation signal or regional spillover risk.\n"
            "- High: imminent/active conflict or severe disruption.\n"
            "- Choose based ONLY on TEXT.\n\n"

            "2) trend:\n"
            "- New: first report or new development in TEXT.\n"
            "- Stable: continuing without clear change.\n"
            "- Escalating: TEXT explicitly indicates escalation (e.g., 'escalated', 'expanded', 'strikes', 'blockade widened').\n"
            "- De-escalating: TEXT explicitly indicates reduction/ceasefire/rollback.\n"
            "- Otherwise Not specified.\n\n"

            "3) decision:\n"
            "- Monitor: routine awareness.\n"
            "- Prepare: plausible impact path requiring readiness.\n"
            "- Action Required: immediate operational/compliance action is explicitly suggested by TEXT.\n"
            "- If TEXT does not justify an action posture, use Monitor.\n\n"

            "4) primary_actors:\n"
            "- 1-3 main actors as a comma-separated string.\n"
            "- Must be explicitly named in TEXT.\n"
            "- If unclear, Not specified.\n\n"

            "5) countries_involved:\n"
            "- Comma-separated list of countries explicitly named in TEXT.\n"
            "- DO NOT infer. DO NOT add countries not explicitly named.\n"
            "- If none, Not specified.\n\n"

            "6) summary:\n"
            "- 5-6 sentences, factual.\n"
            "- No speculation.\n"
            "- Must reflect the core event described in TEXT.\n\n"

            "6b) aruba_relevance_summary:\n"
            "- 2-3 sentences on whether and how this matters to Aruba's financial institutions.\n"
            "- You MAY infer relevance, but ground it in facts explicitly stated in TEXT.\n"
            "- If there is no credible relevance supported by TEXT, output: Not specified.\n\n"

            "7) key_indicators (Key Signals):\n"
            "- 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <indicator>\n"
            "  - <indicator>\n"
            "- Each indicator MUST be explicitly described in TEXT.\n"
            "- If none, Not specified.\n\n"

            "8) drivers (Why it started):\n"
            "- ONLY if TEXT explicitly states drivers/causes/motivation.\n"
            "- Write 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <driver>\n"
            "  - <driver>\n"
            "- If none, Not specified.\n\n"

            "9) impact (Why it matters — evidence required):\n"
            "- VERY IMPORTANT: Do NOT add finance-related impact unless TEXT explicitly supports it.\n"
            "- Allowed channels (use these exact labels ONLY when supported by TEXT):\n"
            "  - Sanctions/compliance exposure\n"
            "  - Payment disruption\n"
            "  - Market/oil shock\n"
            "  - Shipping/insurance disruption\n"
            "- If TEXT does NOT explicitly mention sanctions/OFAC/Treasury/sanctions enforcement/asset freezes/banking/payments/SWIFT,\n"
            "  then you MUST NOT write 'Sanctions/compliance exposure' or 'Payment disruption'.\n"
            "- If TEXT does NOT explicitly mention prices/production/output/supply/oil/gas/energy markets,\n"
            "  then you MUST NOT write 'Market/oil shock'.\n"
            "- If TEXT does NOT explicitly mention shipping/ports/blocks/interdiction/insurance/routing,\n"
            "  then you MUST NOT write 'Shipping/insurance disruption'.\n"
            "- Every bullet MUST include an evidence phrase copied from TEXT in parentheses.\n"
            "  Example format:\n"
            "  - Shipping/insurance disruption: higher routing risk (evidence: \"naval blockade\")\n"
            "- Write 1-3 bullet lines as ONE string.\n"
            "- If you cannot cite evidence from TEXT for any channel, output exactly: Not specified.\n\n"

            "10) osint_indicators:\n"
            "- Only sources/methods explicitly mentioned in TEXT (e.g., AIS/ship-tracking, satellite imagery, official statement).\n"
            "- If none, Not specified.\n\n"

            "11) state:\n"
            "- Use one of: active, ongoing, planned, resolved, neutral, unknown.\n"
            "- Choose only if TEXT indicates status; otherwise unknown.\n\n"

            "12) domain_category and domain:\n"
            "- domain_category MUST be exactly one of: air, maritime, land, multi, unknown.\n"
            "- domain MUST match domain_category.\n"
            "- Choose based ONLY on what TEXT describes.\n"
            "- Use these cues:\n"
            "  air: air force, aircraft, fighter, drone, airspace, intercept, NOTAM\n"
            "  maritime: navy, warship, vessel, tanker, shipping, port, maritime, coast guard\n"
            "  land: army, ground forces, border, incursion, mobilization, troops\n"
            "  multi: two or more domains explicitly present\n"
            "  unknown: none of the above\n\n"

            "13) event_type:\n"
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

        def _cleanup_json(candidate: str) -> str:
            cleaned = candidate.replace("\r\n", "\n").replace("\r", "\n").strip()
            cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
            return cleaned

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
    except Exception as exc:
        return None, None, f"request_failed:{type(exc).__name__}"


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
    "aruba_relevance_summary",
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


def _map_trend(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "Not specified"
    low = v.lower()
    if "escalat" in low and "de-" not in low:
        return "↗ Escalating"
    if "de-escalat" in low or "deescalat" in low or "de-escal" in low:
        return "↘ De-escalating"
    if "stable" in low or "steady" in low or "unchanged" in low:
        return "Stable"
    if low == "new":
        return "New"
    if v in _ALLOWED_CHANGE:
        return v
    return "Not specified"


def _flatten_llm_output(raw: Dict[str, Any], title_fallback: str) -> Dict[str, Any]:
    """Normalize nested LLM output into the flat schema expected by validators."""
    if not isinstance(raw, dict):
        return {}

    if "situation" not in raw and "risk_level" not in raw and "trend" not in raw:
        return raw

    situation = raw.get("situation") or {}
    if not isinstance(situation, dict):
        situation = {}

    flat: Dict[str, Any] = {}
    flat["title"] = raw.get("title") or title_fallback or "Not specified"
    flat["llm_summary"] = raw.get("summary") or raw.get("llm_summary") or "Not specified"
    flat["primary_actors"] = raw.get("primary_actors") or "Not specified"
    flat["countries_involved"] = raw.get("countries_involved") or "Not specified"
    flat["risk"] = raw.get("risk_level") or raw.get("risk") or "Not specified"
    flat["change"] = _map_trend(raw.get("trend") or raw.get("change") or "")
    flat["aruba_relevance_summary"] = raw.get("aruba_relevance_summary") or "Not specified"
    flat["what_happened"] = raw.get("what_happened") or flat["llm_summary"] or "Not specified"
    flat["key_indicators"] = situation.get("key_indicators") or "Not specified"
    flat["drivers"] = situation.get("drivers") or "Not specified"
    flat["impact"] = situation.get("impact") or "Not specified"
    flat["osint_indicators"] = situation.get("osint_indicators") or "Not specified"
    flat["state"] = situation.get("state") or "unknown"
    flat["domain_category"] = situation.get("domain_category") or "unknown"
    flat["domain"] = situation.get("domain") or flat["domain_category"]
    flat["event_type"] = situation.get("event_type") or "Not specified"
    return flat


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
            inferred = classify_domain(article_text)
            logger.warning(
                "GeoFeed LLM validation: invalid domain_category=%s inferred=%s",
                domain_cat,
                inferred,
            )
            domain_cat = inferred
        if domain not in _ALLOWED_DOMAIN and domain:
            inferred = classify_domain(domain)
            if inferred != "unknown":
                domain_cat = inferred
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
            "decision": situation.get("decision") or r.get("decision") or "-",
            "aruba_relevance_summary": situation.get("aruba_relevance_summary") or "-",
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
    blocks: List[str] = []
    entry_num = 1
    for r in top:
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
        decision = situation.get("decision") or r.get("decision") or "-"
        aruba_relevance_summary = situation.get("aruba_relevance_summary") or "Not specified"

        entry_lines: List[str] = []
        url = (r.get("url") or "").strip()
        if url:
            entry_lines.append(f"### {entry_num}. [{title}]({url})")
        else:
            entry_lines.append(f"### {entry_num}. {title}")
        entry_lines.append(
            f"**Risk:** {risk} | **Trend:** {trend} | **Date:** {date}"
        )
        entry_lines.append(f"**Decision:** {decision}")
        entry_lines.append("**Aruba Relevance**")
        entry_lines.append(aruba_relevance_summary)
        entry_lines.append("")
        entry_lines.append(f"**Primary Actors:** {actors}  ")
        entry_lines.append(f"**Countries Involved:** {countries_involved}")
        entry_lines.append("")
        entry_lines.append("**Summary**")
        entry_lines.append(summary)
        entry_lines.append("")
        entry_lines.append("**Why It Matters**")
        entry_lines.append(f"Drivers: {drivers}")
        entry_lines.append(f"Impact: {impact}")
        entry_lines.append(f"Risk Level: {situation.get('risk') or '-'}")
        entry_lines.append("")
        entry_lines.append("**Key Signals**")
        entry_lines.append(f"Key Indicators: {situation.get('key_indicators') or '-'}")
        entry_lines.append(f"OSINT Indicators: {situation.get('osint_indicators') or '-'}")

        blocks.append("\n".join(entry_lines))
        entry_num += 1

    if blocks:
        lines.extend(("\n\n[[PAGE_BREAK]]\n\n").join(blocks).splitlines())

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


def _send_geofeed_email(md_path: str, recipients: List[str], run_date: str) -> None:
    if not recipients:
        logger.info("GeoFeed email skipped: no recipients configured")
        return
    try:
        with open(md_path, "r", encoding="utf-8") as f:
            body = f.read()
    except Exception as exc:
        logger.warning("GeoFeed email skipped: failed to read report %s (%s)", md_path, exc)
        return

    subject = f"TIC - GeoFeed Summary {run_date}"
    mail_bin = shutil.which("mail")
    if mail_bin:
        logger.info("GeoFeed email attempt via mail to %s", ", ".join(recipients))
        try:
            subprocess.run(
                [mail_bin, "-s", subject, *recipients],
                input=body,
                text=True,
                check=True,
            )
            logger.info("GeoFeed email sent via mail to %s", ", ".join(recipients))
        except Exception as exc:
            logger.warning("GeoFeed email failed via mail: %s", exc)
        return

    sendmail_bin = shutil.which("sendmail")
    if sendmail_bin:
        logger.info("GeoFeed email attempt via sendmail to %s", ", ".join(recipients))
        try:
            to_line = ", ".join(recipients)
            headers = [f"To: {to_line}", f"Subject: {subject}"]
            message = "\n".join(headers) + "\n\n" + body
            subprocess.run([sendmail_bin, "-t"], input=message, text=True, check=True)
            logger.info("GeoFeed email sent via sendmail to %s", to_line)
        except Exception as exc:
            logger.warning("GeoFeed email failed via sendmail: %s", exc)
        return

    logger.warning("GeoFeed email skipped: no mail/sendmail binary found")


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

                exclude_keywords = cfg.get("GEOFEED_EXCLUDE_KEYWORDS") or []
                if exclude_keywords:
                    haystack = f"{it.title}\n{it.summary}\n{page_text}".lower()
                    if any(k.lower() in haystack for k in exclude_keywords):
                        processed += 1
                        _update_progress(
                            progress_state, processed, total_expected, started_at, it.title
                        )
                        continue

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

                below_threshold = score < min_score_val

                situation: Optional[Dict[str, Any]] = None
                if add_llm_summary and use_ollama:
                    situation, raw_resp, err = _ollama_situation_summary(
                        host=ollama_host,
                        model=ollama_model,
                        title=it.title,
                        text=page_text,
                        timeout=45,
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
                    else:
                        situation = _flatten_llm_output(situation, it.title)
                        if not validate_llm:
                            logger.warning(
                                "GeoFeed LLM validation bypassed for title=%s",
                                it.title,
                            )
                        else:
                            situation = _validate_situation(situation, page_text) or None

                thresholds = cfg.get("GEOFEED_DECISION_THRESHOLDS") or {}
                risk_val = (situation or {}).get("risk") if isinstance(situation, dict) else "Low"
                decision = _decision_label(risk_val, score, thresholds)

                now = dt.datetime.now(dt.timezone.utc)
                if isinstance(situation, dict):
                    situation["decision"] = decision

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
                        "decision": decision,
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
    _send_geofeed_email(md_path, cfg.get("GEOFEED_EMAIL_RECIPIENTS") or [], run_date)
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
