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
import textwrap
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
        from reporting import _render_pdf
    except Exception:
        _render_pdf = None

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







def _require_config() -> Dict[str, Any]:
    if CFG is None:
        raise RuntimeError(
            "GeoFeed requires CONFIG from collector.config; import failed"
        ) from CONFIG_IMPORT_ERROR
    return CFG







@dataclass
class FeedItem:
    title: str
    url: str
    published: str
    summary: str







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
            "  \"situation\": {\n"
            "    \"key_indicators\": \"<bullet lines as one string or Not specified>\",\n"
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

            "7) key_indicators (Key Signals):\n"
            "- 1-3 bullet lines as ONE string using this exact format:\n"
            "  - <indicator>\n"
            "  - <indicator>\n"
            "- Each indicator MUST be explicitly described in TEXT.\n"
            "- If none, Not specified.\n\n"

            "8) impact (Why it matters — evidence required):\n"
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


def _robust_json_extract(candidate: str) -> Optional[dict]:
    if not isinstance(candidate, str):
        return None
    s = candidate.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not s:
        return None
    s = re.sub(r",\s*([}\]])", r"\1", s)
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    start = s.find("{")
    if start < 0:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(s[start:])
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _llm_repair_to_strict_json(
    host: str,
    model: str,
    bad_text: str,
    label: str,
    timeout: int,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    repair_prompt = (
        f"You are GeoFeed.\n"
        f"Convert the following MODEL OUTPUT into STRICT JSON for the comparison versus {label}.\n\n"
        "STRICT OUTPUT RULES:\n"
        "- Output JSON only, with exactly one key: comparison_markdown\n"
        "- comparison_markdown must be a single string\n"
        "- Use \\n for newlines inside the JSON string\n"
        "- Do not include any other keys, commentary, or surrounding text\n\n"
        "CONTENT RULES:\n"
        "- Keep meaning as close as possible to the input\n"
        "- Remove any tables/| characters and any headings that start with '#'\n"
        "- No numbered lists\n\n"
        "MODEL OUTPUT TO CONVERT:\n"
        + textwrap.shorten((bad_text or "").strip(), width=12000, placeholder="...")
    )
    payload = json.dumps(
        {
            "model": model,
            "prompt": repair_prompt,
            "stream": False,
            "format": {
                "type": "object",
                "properties": {"comparison_markdown": {"type": "string"}},
                "required": ["comparison_markdown"],
                "additionalProperties": False,
            },
            "options": {"temperature": 0, "num_predict": 420},
        }
    ).encode("utf-8")
    url = host.rstrip("/") + "/api/generate"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "geofeed/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        s = (data.get("response") or "").strip()
        if not s:
            return None, raw, "empty_response"
        parsed = _robust_json_extract(s)
        if not isinstance(parsed, dict):
            inner = _robust_json_extract(raw)
            parsed = inner if isinstance(inner, dict) else None
        if isinstance(parsed, dict) and isinstance(parsed.get("response"), dict):
            parsed = parsed["response"]
        cm = (parsed or {}).get("comparison_markdown")
        if not isinstance(cm, str) or not cm.strip():
            return None, raw, "missing_comparison_markdown"
        return cm.strip(), raw, None
    except Exception as exc:
        return None, None, f"request_failed:{type(exc).__name__}"


def _ollama_geofeed_comparison(
    host: str,
    model: str,
    current_entries: List[Dict[str, Any]],
    baseline_entries: List[Dict[str, Any]],
    label: str,
    timeout: int,
    strict: bool = False,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        strict_block = ""
        if strict:
            strict_block = (
                "STRICT OUTPUT MODE:\n"
                "- Output MUST be a single JSON object with exactly one key: comparison_markdown.\n"
                "- If you output any other key or any list/array, the result will be rejected.\n"
                "- Do NOT include explanations, preambles, or extra text.\n\n"
            )

        cur_sig = _extract_exec_signals(current_entries or [])
        base_sig = _extract_exec_signals(baseline_entries or [])

        anchors: List[str] = []
        if cur_sig["counts"]["maritime_seizure"] > 0:
            anchors.append(
                "Current entries include multiple maritime seizure/intercept/boarding signals in the Caribbean basin "
                f"(count={cur_sig['counts']['maritime_seizure']}, baseline={base_sig['counts']['maritime_seizure']})."
            )
        if cur_sig["counts"]["war_powers_politics"] > 0:
            anchors.append(
                "Current entries include war-powers/authorization political signaling "
                f"(count={cur_sig['counts']['war_powers_politics']}, baseline={base_sig['counts']['war_powers_politics']})."
            )
        if cur_sig["counts"]["kinetic_attack"] > 0:
            anchors.append(
                "Current entries include kinetic/strike language "
                f"(count={cur_sig['counts']['kinetic_attack']}, baseline={base_sig['counts']['kinetic_attack']})."
            )
        if cur_sig["counts"]["sanctions_tariffs"] > 0:
            anchors.append(
                "Current entries include sanctions/tariff/compliance pressure signals "
                f"(count={cur_sig['counts']['sanctions_tariffs']}, baseline={base_sig['counts']['sanctions_tariffs']})."
            )
        if not anchors:
            anchors.append(
                "No dominant escalation themes are strongly signaled in the current entries; describe stability vs baseline if applicable."
            )








        prompt = (
            f"You are GeoFeed. Write an executive COMPARISON bullet brief versus {label}.\n"
            "This must be scannable for company executives.\n\n"
            "DATA RULES:\n"
            "- Use ONLY CURRENT_ENTRIES and BASELINE_ENTRIES. Do NOT invent facts.\n"
            "- You may treat title/summary/why_it_matters/key_signals as evidence even when conflict_indicators are missing.\n"
            "- If something is not present, say 'not indicated in the entries'.\n\n"
            f"CURRENT STATS: items={cur_sig['n_items']}, risk_mix={cur_sig['risk_counts']}, decisions={cur_sig['decision_counts']}\n"
            f"BASELINE STATS: items={base_sig['n_items']}, risk_mix={base_sig['risk_counts']}, decisions={base_sig['decision_counts']}\n\n"
            "ANCHOR FACTS (MUST BE REFLECTED IN THE BRIEF):\n"
            + "\n".join([f"ANCHOR: {a}" for a in anchors])
            + "\n\n"
            "OUTPUT RULES (STRICT):\n"
            "- Output JSON only (no surrounding text).\n"
            "- JSON must have exactly one key: comparison_markdown\n"
            "- comparison_markdown must be a single string.\n"
            "- Encode newlines as \\n inside the JSON string.\n\n"
            "STYLE (MATCH THIS EXACTLY):\n"
            "- NO tables; never output '|'. The '|' character is forbidden anywhere.\n"
            "- NO markdown headings; do NOT output lines starting with '#'.\n"
            "- NO numbered lists; do NOT output '1.' style lines.\n"
            "- Output must be SCANNABLE for executives:\n"
            "  * Line 1: thematic headline ending with ':'\n"
            "  * Blank line\n"
            "  * Then 4–7 bullet points using '-' (markdown bullets)\n"
            f"  * Bullet 1 MUST start with: 'Compared with {label},'\n"
            "  * Each bullet is 1–2 sentences (wrap is allowed, but keep it concise)\n"
            "  * Final bullet MUST explicitly state Aruba/Caribbean relevance\n"
            "- Do NOT use section-label lines like 'Maritime/conflict signals:' anywhere.\n"
            "- Mention concrete signals (seizures/intercepts/war powers/sanctions) only if supported by the entries.\n\n"
            "EXAMPLE (format only; do not reuse facts):\n"
            "Example thematic shift headline:\n\n"
            "- Compared with LAST 7 DAYS, enforcement and compliance signals rise while kinetic escalation is not indicated.\n"
            "- Maritime exposure concentrates around routing friction and interdiction language, increasing screening needs.\n"
            "- Policy posture emphasizes sanctions/tools and legislative constraints rather than new commitments.\n"
            "- Commercial impact is framed through cost/availability pressure and compliance risk.\n"
            "- Aruba/Caribbean relevance: second-order spillover via shipping, compliance checks, and routing decisions.\n\n"
            "FINAL OUTPUT REMINDER (MUST FOLLOW):\n"
            "- Output JSON only with exactly one key: comparison_markdown\n"
            "- Bullet 1 must start with '- Compared with {label},'\n"
            "- Use 4–7 bullets only; final bullet must mention Aruba/Caribbean relevance\n"
            "- Never output '|'\n\n"
            f"{strict_block}\n\n"
            "CURRENT_ENTRIES:\n"
            f"{json.dumps(current_entries, ensure_ascii=True)}\n\n"
            "BASELINE_ENTRIES:\n"
            f"{json.dumps(baseline_entries, ensure_ascii=True)}\n"
        )

        def _cleanup_json(candidate: str) -> str:
            cleaned = candidate.replace("\r\n", "\n").replace("\r", "\n").strip()
            cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
            return cleaned

        def _escape_newlines_in_json_strings(txt: str) -> str:
            out: List[str] = []
            in_str = False
            esc = False
            for ch in txt:
                if esc:
                    out.append(ch)
                    esc = False
                    continue
                if ch == "\\":
                    out.append(ch)
                    esc = True
                    continue
                if ch == '"':
                    out.append(ch)
                    in_str = not in_str
                    continue
                if ch == "\n" and in_str:
                    out.append("\\n")
                else:
                    out.append(ch)
            return "".join(out)

        def _request_llm(prompt_text: str, options: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
            payload = json.dumps(
                {
                    "model": model,
                    "prompt": prompt_text,
                    "stream": False,
                    "format": {
                        "type": "object",
                        "properties": {"comparison_markdown": {"type": "string"}},
                        "required": ["comparison_markdown"],
                        "additionalProperties": False,
                    },
                    "options": options,
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
            parsed: Optional[Dict[str, Any]] = None
            try:
                parsed = json.loads(_cleanup_json(s))
            except Exception:
                start = s.find("{")
                if start >= 0:
                    candidate = _escape_newlines_in_json_strings(_cleanup_json(s[start:]))
                    try:
                        parsed, _ = json.JSONDecoder().raw_decode(candidate)
                    except Exception:
                        parsed = None
            if not isinstance(parsed, dict):
                return None, raw, "invalid_json"
            inner = parsed.get("response")
            if isinstance(inner, dict) and "comparison_markdown" in inner:
                parsed = inner
            if "comparison_markdown" not in parsed:
                for k in (
                    "comparison",
                    "comparison_md",
                    "comparisonMarkdown",
                    "comparison_markdown_text",
                ):
                    v = parsed.get(k)
                    if isinstance(v, str) and v.strip():
                        parsed["comparison_markdown"] = v
                        break
            comparison = parsed.get("comparison_markdown")
            if not isinstance(comparison, str) or not comparison.strip():
                return None, raw, "missing_comparison_markdown"
            return comparison.strip(), raw, None

        def _validate_exec(md: str) -> Tuple[bool, Optional[str]]:
            if "|" in (md or "") or _looks_like_markdown_table(md):
                return False, "contains_markdown_table"
            first_line = (md.splitlines()[0] if (md or "").splitlines() else "").strip()
            bad_country_header = bool(
                re.match(r"^\s*[^/]{2,40}\s*/\s*[^/]{2,40}\s*$", first_line)
            )
            bad_start = (md or "").lower().startswith("not specified") or bad_country_header
            has_anchor_requirement = cur_sig["counts"]["maritime_seizure"] > 0
            anchor_missing = has_anchor_requirement and (
                "seiz" not in md.lower()
                and "intercept" not in md.lower()
                and "tanker" not in md.lower()
            )
            if bad_start or anchor_missing:
                return False, "format_or_content"
            if not _looks_like_exec_bullet_brief(md, label):
                return False, "format_or_content"
            return True, None

        def _rewrite_exec_brief(bad_text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
            rewrite_prompt = (
                f"You are GeoFeed. Rewrite the following draft into an executive COMPARISON bullet brief versus {label}.\n"
                "Do NOT add or invent facts. Keep content grounded in the draft and the ANCHOR FACTS.\n\n"
                "OUTPUT RULES (STRICT):\n"
                "- Output JSON only with exactly one key: comparison_markdown\n"
                "- comparison_markdown must be a single string with \\n for newlines\n"
                "- NO tables; the '|' character is forbidden anywhere\n"
                "- NO markdown headings; do NOT output lines starting with '#'\n"
                "- NO numbered lists; do NOT output '1.' style lines\n\n"
                "FORMAT (MUST MATCH EXACTLY):\n"
                "- Line 1: thematic headline ending with ':'\n"
                "- Blank line\n"
                "- Then 4–7 bullet points using '-' (markdown bullets)\n"
                f"- Bullet 1 MUST start exactly with: '- Compared with {label},'\n"
                "- Each bullet is 1–2 sentences. No sub-bullets.\n"
                "- Final bullet MUST explicitly state Aruba/Caribbean relevance\n"
                "- Do NOT use section-label lines like 'Maritime/conflict signals:' or any 'Label:' lines\n\n"
                "ANCHOR FACTS (MUST BE REFLECTED):\n"
                + "\n".join([f"ANCHOR: {a}" for a in anchors])
                + "\n\n"
                "DRAFT TO REWRITE:\n"
                + (bad_text or "")
            )
            return _request_llm(rewrite_prompt, {"temperature": 0, "num_predict": 360})

        comparison, raw, err = _request_llm(prompt, {"temperature": 0, "num_predict": 420})
        if comparison:
            ok, reason = _validate_exec(comparison)
            if ok:
                return comparison, raw, None
            if reason == "format_or_content":
                rewritten, raw2, err2 = _rewrite_exec_brief(comparison)
                if rewritten and _validate_exec(rewritten)[0]:
                    return rewritten.strip(), raw2 or raw, "rewritten_from_format_or_content"
            if reason == "contains_markdown_table":
                converted = _table_md_to_summary(comparison, label, cur_sig, base_sig)
                if isinstance(converted, str) and converted.strip():
                    return converted.strip(), raw, "fallback_from_table"
            if reason == "contains_markdown_table" or "\n-" in comparison or "\n*" in comparison or "\n#" in comparison:
                rewritten, raw2, err2 = _rewrite_exec_brief(comparison)
                if rewritten and _validate_exec(rewritten)[0]:
                    return rewritten.strip(), raw2 or raw, "rewritten_from_bad_format"
            sanitized = _sanitize_exec_brief(comparison, label, cur_sig, base_sig)
            if sanitized and _validate_exec(sanitized)[0]:
                return sanitized, raw, "sanitized_from_format"

        retry_prompt = (
            f"You are GeoFeed. Write an executive COMPARISON bullet brief versus {label}.\n"
            "Use ONLY CURRENT_ENTRIES and BASELINE_ENTRIES. Do NOT invent facts.\n\n"
            "OUTPUT RULES (STRICT):\n"
            "- Output JSON only with exactly one key: comparison_markdown\n"
            "- comparison_markdown must be a single string with \\n for newlines\n"
            "- Forbidden anywhere: '|', markdown tables, '#', numbered lists\n\n"
            "FORMAT (MUST MATCH EXACTLY):\n"
            "- Line 1: thematic headline ending with ':'\n"
            "- Blank line\n"
            "- Then 4–7 bullet points using '-' (markdown bullets)\n"
            f"- Bullet 1 MUST start exactly with: '- Compared with {label},'\n"
            "- Each bullet is 1–2 sentences. No sub-bullets.\n"
            "- Final bullet MUST explicitly state Aruba/Caribbean relevance\n"
            "- Do NOT use section labels like 'Maritime/conflict signals:'\n\n"
            "FINAL OUTPUT REMINDER (MUST FOLLOW):\n"
            "- Output JSON only with exactly one key: comparison_markdown\n"
            "- Bullet 1 must start with '- Compared with {label},'\n"
            "- Use 4–7 bullets only; final bullet must mention Aruba/Caribbean relevance\n"
            "- Never output '|'\n\n"
            "CURRENT_ENTRIES:\n"
            f"{json.dumps(current_entries, ensure_ascii=True)}\n\n"
            "BASELINE_ENTRIES:\n"
            f"{json.dumps(baseline_entries, ensure_ascii=True)}\n"
        )
        comparison, raw, err = _request_llm(retry_prompt, {"temperature": 0, "num_predict": 360})
        if comparison:
            ok, reason = _validate_exec(comparison)
            if ok:
                return comparison, raw, None
            if reason == "format_or_content":
                rewritten, raw2, err2 = _rewrite_exec_brief(comparison)
                if rewritten and _validate_exec(rewritten)[0]:
                    return rewritten.strip(), raw2 or raw, "rewritten_from_format_or_content"
            if reason == "contains_markdown_table":
                converted = _table_md_to_summary(comparison, label, cur_sig, base_sig)
                if isinstance(converted, str) and converted.strip():
                    return converted.strip(), raw, "fallback_from_table"
            if reason == "contains_markdown_table" or "\n-" in comparison or "\n*" in comparison or "\n#" in comparison:
                rewritten, raw2, err2 = _rewrite_exec_brief(comparison)
                if rewritten and _validate_exec(rewritten)[0]:
                    return rewritten.strip(), raw2 or raw, "rewritten_from_bad_format"
            sanitized = _sanitize_exec_brief(comparison, label, cur_sig, base_sig)
            if sanitized and _validate_exec(sanitized)[0]:
                return sanitized, raw, "sanitized_from_format"

        return None, raw, err or "invalid_or_unusable_llm_output"
    except Exception as exc:
        return None, None, f"comparison_exception:{type(exc).__name__}"






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
    flat["what_happened"] = raw.get("what_happened") or flat["llm_summary"] or "Not specified"
    flat["key_indicators"] = situation.get("key_indicators") or "Not specified"
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

        for k in ("key_indicators", "impact"):
            val = (normalized.get(k) or "").strip()
            if val and val != "Not specified" and not val.lstrip().startswith("- "):
                normalized[k] = f"- {val}"
                logger.warning("GeoFeed LLM validation: normalized bullets for %s", k)

        return normalized
    except Exception:
        logger.exception("GeoFeed LLM validation failed: unexpected error")
        return None





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


def _make_summary_json(
    rows: List[Dict[str, Any]], hours: int, summary_limit: int
) -> Dict[str, Any]:
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

    def _row_sort_key(r: Dict[str, Any]) -> Tuple[dt.datetime, str, str]:
        situation = r.get("situation") or {}
        title = (situation.get("title") or r.get("title") or "Untitled").strip().lower()
        url = (r.get("url") or "").strip().lower()
        return (_published_key(r), title, url)

    top = sorted(rows, key=_row_sort_key, reverse=True)[:summary_limit]
    entries: List[Dict[str, Any]] = []
    for r in top:
        situation = r.get("situation") or {}
        title = (situation.get("title") or r.get("title") or "Untitled").strip()
        entry = {
            "title": title,
            "risk": (situation.get("risk") or "Low").title(),
            "trend": _trend_label(situation.get("change") or ""),
            "date": _fmt_date((r.get("published") or "").strip()),
            "primary_actors": situation.get("primary_actors") or [],
            "countries_involved": situation.get("countries_involved") or [],
            "summary": situation.get("llm_summary") or situation.get("what_happened") or "-",
            "decision": situation.get("decision") or r.get("decision") or "-",
            "why_it_matters": [
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
            and not entry.get("primary_actors")
            and not entry.get("countries_involved")
        ):
            continue
        entries.append(_canonicalize_entry(entry))

    entries.sort(key=lambda x: x.get("id", "") or "")

    return {
        "window_hours": hours,
        "generated_at": f"{dt.datetime.utcnow().isoformat()}Z",
        "run_signature": _entries_signature(entries),
        "entries": entries,
    }


def _make_summary(
    rows: List[Dict[str, Any]],
    hours: int,
    summary_limit: int,
    comparison_section: Optional[str] = None,
) -> str:
    lines = ["# GeoFeed Summary", ""]
    lines.append(f"Window: last {hours} hours")
    lines.append(f"Generated: {dt.datetime.utcnow().isoformat()}Z")
    lines.append(f"Collected: {len(rows)} items")
    lines.append("")
    if comparison_section:
        lines.append(comparison_section.strip())
        lines.append("")
        lines.append("[[PAGE_BREAK]]")
        lines.append("")

    if not rows:
        lines.append("No items collected.")
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

    top = sorted(rows, key=_published_key, reverse=True)[:summary_limit]
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
        impact = situation.get("impact") or "-"
        decision = situation.get("decision") or r.get("decision") or "-"

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
        entry_lines.append(f"**Primary Actors:** {actors}  ")
        entry_lines.append(f"**Countries Involved:** {countries_involved}")
        entry_lines.append("")
        entry_lines.append("**Summary**")
        entry_lines.append(summary)
        entry_lines.append("")
        entry_lines.append("**Why It Matters**")
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


def _norm_ws(s: str) -> str:
    if not isinstance(s, str):
        return "-"
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _norm_enum(s: str) -> str:
    if not isinstance(s, str):
        return "-"
    s = _norm_ws(s)
    s = re.sub(r"\s*\((up|down)\)\s*$", "", s, flags=re.IGNORECASE)
    return s


def _as_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        out: List[str] = []
        for x in val:
            if isinstance(x, str):
                x = _norm_ws(x)
                if x and x != "-":
                    out.append(x)
        return out
    if isinstance(val, str):
        s = _norm_ws(val)
        if not s or s == "-":
            return []
        parts = re.split(r"\s*[,;]\s*", s)
        parts = [p for p in (_norm_ws(p) for p in parts) if p and p != "-"]
        return parts if len(parts) > 1 else [s]
    return []


def _entry_id(title: str, source: str, date: str) -> str:
    base = f"{_norm_ws(title).lower()}|{_norm_ws(source).lower()}|{_norm_ws(date).lower()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def _canonicalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    title = _norm_ws(entry.get("title") or "-")
    url = _norm_ws(entry.get("url") or entry.get("source") or "")
    date = _norm_ws(entry.get("date") or "-")
    risk = _norm_enum(entry.get("risk") or "-")
    trend = _norm_enum(entry.get("trend") or "-")
    decision = _norm_enum(entry.get("decision") or "-")

    primary_actors = sorted(set(_as_list(entry.get("primary_actors"))))
    countries = sorted(set(_as_list(entry.get("countries_involved"))))

    why = entry.get("why_it_matters") if isinstance(entry.get("why_it_matters"), list) else []
    why = [x for x in (_norm_ws(x) for x in why if isinstance(x, str)) if x and x != "-"]

    ks = entry.get("key_signals") if isinstance(entry.get("key_signals"), list) else []
    ks = [x for x in (_norm_ws(x) for x in ks if isinstance(x, str)) if x and x != "-"]

    summary = _norm_ws(entry.get("summary") or "-")

    return {
        "id": _entry_id(title, url, date),
        "title": title,
        "url": url,
        "date": date,
        "risk": risk,
        "trend": trend,
        "decision": decision,
        "primary_actors": primary_actors,
        "countries_involved": countries,
        "summary": summary,
        "why_it_matters": why,
        "key_signals": ks,
    }


def _entries_signature(entries: List[Dict[str, Any]]) -> str:
    canon = [_canonicalize_entry(e) for e in (entries or []) if isinstance(e, dict)]
    canon.sort(key=lambda x: x.get("id", "") or "")
    payload = json.dumps(canon, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_summary_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    why = entry.get("why_it_matters") or []
    key_signals = entry.get("key_signals") or []
    impact = "-"
    risk_level = "-"
    if isinstance(why, list):
        for line in why:
            if isinstance(line, str) and line.startswith("Impact:"):
                impact = line.replace("Impact:", "", 1).strip() or "-"
            if isinstance(line, str) and line.startswith("Risk Level:"):
                risk_level = line.replace("Risk Level:", "", 1).strip() or "-"
    key_indicators = key_signals[0] if len(key_signals) > 0 else "-"
    osint_indicators = key_signals[1] if len(key_signals) > 1 else "-"

    normalized = {
        "title": entry.get("title") or "-",
        "url": entry.get("url") or entry.get("source") or "",
        "date": entry.get("date") or "-",
        "risk": entry.get("risk") or "-",
        "trend": entry.get("trend") or "-",
        "decision": entry.get("decision") or "-",
        "primary_actors": entry.get("primary_actors") or "-",
        "countries_involved": entry.get("countries_involved") or "-",
        "summary": entry.get("summary") or "-",
        "why_it_matters": why if isinstance(why, list) else [],
        "key_signals": key_signals if isinstance(key_signals, list) else [],
        "impact": impact,
        "risk_level": risk_level,
        "key_indicators": key_indicators or "-",
        "osint_indicators": osint_indicators or "-",
    }
    return _canonicalize_entry(normalized)


def _compact_for_comparison(entry: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    out = {
        "title": entry.get("title"),
        "url": entry.get("url"),
        "date": entry.get("date"),
        "summary": entry.get("summary"),
        "why_it_matters": entry.get("why_it_matters"),
        "key_signals": entry.get("key_signals"),
        "risk": entry.get("risk"),
        "trend": entry.get("trend"),
        "decision": entry.get("decision"),
        "countries_involved": entry.get("countries_involved"),
        "primary_actors": entry.get("primary_actors"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}






def _looks_like_markdown_table(md: str) -> bool:

    if not isinstance(md, str) or not md.strip():
        return False
    lines = [ln.strip() for ln in md.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False

    for i in range(len(lines) - 1):
        a, b = lines[i], lines[i + 1]
        if ("|" in a) and ("|" in b) and ("---" in b or ":---" in b or "---:" in b):
            return True

    for i in range(len(lines) - 1):
        a, b = lines[i], lines[i + 1]
        if (a.count("|") >= 2 or " | " in a) and (b.count("|") >= 2 and "---" in b):
            return True

    return False


def _table_md_to_summary(
    md: str, label: str, cur_sig: Dict[str, Any], base_sig: Dict[str, Any]
) -> str:

    lines = [ln.strip() for ln in (md or "").splitlines() if ln.strip()]
    rows: List[str] = []
    for ln in lines:
        if ("---" in ln) and ("|" in ln):
            continue
        if "|" in ln:
            rows.append(ln)

    if len(rows) < 2:
        return (
            f"Situation change brief (vs {label}):\n\n"
            f"Compared with {label}, changes were detected but the model returned a table, so the output was converted to a narrative summary.\n\n"
            "Maritime/conflict signals: review the source entries for any interdictions, seizures, or confirmed kinetic activity.\n\n"
            "Risk/decision posture: see the updated risk/decision labels in the entries for specific shifts.\n\n"
            "Aruba/Caribbean relevance: prioritize any routing, compliance, or enforcement developments tied to the Caribbean basin."
        )

    def split_row(r: str) -> List[str]:
        r = r.strip().strip("|")
        return [c.strip() for c in r.split("|")]

    data_rows = [split_row(r) for r in rows[1:] if len(split_row(r)) >= 2]
    sentences: List[str] = []
    for r in data_rows[:6]:
        a = r[0] if len(r) > 0 else ""
        b = r[1] if len(r) > 1 else ""
        c = r[2] if len(r) > 2 else ""
        parts = [p for p in (a, b, c) if p]
        if parts:
            sentences.append("; ".join(parts))

    key = sentences[0] if sentences else "Notable changes detected."
    stats_line = (
        f"Compared with {label}, the current set has {cur_sig.get('n_items', 0)} items "
        f"vs {base_sig.get('n_items', 0)}."
    )
    example = sentences[0] if len(sentences) > 0 else "Notable changes detected."
    maritime = sentences[1] if len(sentences) > 1 else "no additional maritime/conflict deltas extracted from table output."
    posture = sentences[2] if len(sentences) > 2 else "risk/decision changes present; see entries for details."
    return (
        f"{key} (vs {label}):\n\n"
        f"{stats_line} Examples include {example}.\n\n"
        f"Maritime/conflict signals: {maritime}\n\n"
        f"Risk/decision posture: {posture}\n\n"
        "Aruba/Caribbean relevance: assess indirect exposure via maritime routes and enforcement actions."
    )


def _looks_like_exec_bullet_brief(md: str, label: str) -> bool:
    if not isinstance(md, str) or not md.strip():
        return False
    if "|" in md:
        return False
    lines_raw = md.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    if any(ln.lstrip().startswith("#") for ln in lines_raw):
        return False
    if any(re.match(r"^\s*\d+\.\s+", ln) for ln in lines_raw):
        return False

    nonempty = [ln.rstrip() for ln in lines_raw if ln.strip()]
    if not nonempty:
        return False
    if not nonempty[0].strip().endswith(":"):
        return False
    for ln in nonempty[1:]:
        if ln.strip().endswith(":"):
            return False
        if re.match(r"^[A-Za-z][A-Za-z /&-]{2,40}:\s+", ln.strip()):
            return False

    bullet_lines = [ln for ln in lines_raw if re.match(r"^\s*-\s+\S+", ln)]
    if not (4 <= len(bullet_lines) <= 7):
        return False
    first_bullet = bullet_lines[0].lstrip()
    if not first_bullet.startswith(f"- Compared with {label},"):
        return False
    last_bullet = bullet_lines[-1].lower()
    if ("aruba" not in last_bullet) and ("caribbean" not in last_bullet):
        return False
    return True


def _sanitize_exec_brief(
    md: str, label: str, cur_sig: Dict[str, Any], base_sig: Dict[str, Any]
) -> str:

    if not isinstance(md, str):
        return ""

    def _delabel_line(s: str) -> str:
        m = re.match(r"^([A-Za-z][A-Za-z /&-]{2,40}):\s+(.+)$", s.strip())
        if not m:
            return s
        label_txt, body = m.group(1), m.group(2)
        label_txt = label_txt.replace("/", " and ")
        body = body.rstrip()
        if not body.endswith((".", "!", "?")):
            body += "."
        return f"{label_txt} in the entries {body}"

    lines = md.splitlines()
    cleaned: List[str] = []
    for ln in lines:

        ln = re.sub(r"^\s*#+\s*", "", ln)
        ln = re.sub(r"^\s*[-*•]+\s*", "", ln)
        cleaned.append(_delabel_line(ln.rstrip()))
    text = "\n".join(cleaned).strip()
    if "|" in text:
        text = text.replace("|", " ")
        text = re.sub(r"\s{2,}", " ", text)

    if text and not text.splitlines()[0].strip().endswith(":"):
        first = text.splitlines()[0].strip()
        text = first.rstrip(":") + ":\n" + "\n".join(text.splitlines()[1:]).strip()

    if f"Compared with {label}," not in text:
        compare_line = (
            f"- Compared with {label}, the current set has {cur_sig.get('n_items', 0)} items "
            f"vs {base_sig.get('n_items', 0)}."
        )
        parts = text.splitlines()
        if parts:
            text = parts[0].strip() + "\n\n" + compare_line + "\n" + "\n".join(parts[1:]).strip()
        else:
            text = compare_line

    return text.strip()






def _normtxt(x: Any) -> str:
    try:
        return str(x or "").strip()
    except Exception:
        return ""


def _entry_text_for_compare(e: Dict[str, Any]) -> str:
    parts: List[str] = []
    parts.append(_normtxt(e.get("title")))
    parts.append(_normtxt(e.get("summary")))
    wi = e.get("why_it_matters")
    if isinstance(wi, list):
        parts.extend(_normtxt(x) for x in wi[:4])
    ks = e.get("key_signals")
    if isinstance(ks, list):
        parts.extend(_normtxt(x) for x in ks[:4])
    return " | ".join([p for p in parts if p])


def _count_hits(entries: List[Dict[str, Any]], needles: List[str]) -> int:
    n = 0
    for e in (entries or []):
        t = _entry_text_for_compare(e).lower()
        if any(k in t for k in needles):
            n += 1
    return n


def _sample_titles(
    entries: List[Dict[str, Any]], needles: List[str], limit: int = 2
) -> List[str]:
    out: List[str] = []
    for e in (entries or []):
        t = _entry_text_for_compare(e).lower()
        if any(k in t for k in needles):
            title = _normtxt(e.get("title"))
            if title and title not in out:
                out.append(title)
        if len(out) >= limit:
            break
    return out


def _extract_exec_signals(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    buckets = {
        "maritime_seizure": [
            "seiz",
            "seized",
            "intercept",
            "board",
            "boarding",
            "tanker",
            "coast guard",
            "marines",
        ],
        "kinetic_attack": [
            "attack",
            "strike",
            "bomb",
            "missile",
            "drone",
            "second wave",
            "airstrike",
        ],
        "war_powers_politics": [
            "war powers",
            "resolution",
            "senate",
            "congress",
            "authorize",
            "rein in",
        ],
        "sanctions_tariffs": [
            "sanction",
            "tariff",
            "secondary",
            "export control",
            "compliance",
            "pressure campaign",
        ],
        "shipping_trade": [
            "shipping rates",
            "container",
            "imports",
            "port",
            "terminal",
            "trade uncertainty",
        ],
    }

    counts: Dict[str, int] = {}
    examples: Dict[str, List[str]] = {}
    for k, needles in buckets.items():
        counts[k] = _count_hits(entries, needles)
        examples[k] = _sample_titles(entries, needles, limit=2)

    risk_counts = {"Elevated": 0, "Moderate": 0, "Low": 0}
    decision_counts: Dict[str, int] = {}
    for e in (entries or []):
        r = _normtxt(e.get("risk"))
        if r in risk_counts:
            risk_counts[r] += 1
        d = _normtxt(e.get("decision"))
        if d:
            decision_counts[d] = decision_counts.get(d, 0) + 1

    return {
        "n_items": len(entries or []),
        "counts": counts,
        "examples": examples,
        "risk_counts": risk_counts,
        "decision_counts": decision_counts,
    }


def _build_exec_compare_bullet_brief(
    label: str,
    cur_sig: Dict[str, Any],
    base_sig: Dict[str, Any],
    current_entries: List[Dict[str, Any]],
    baseline_entries: List[Dict[str, Any]],
) -> str:

    cur = cur_sig.get("counts", {}) or {}
    base = base_sig.get("counts", {}) or {}

    def d(key: str) -> int:
        return int(cur.get(key, 0) or 0) - int(base.get(key, 0) or 0)

    dm = d("maritime_seizure")
    ds = d("sanctions_tariffs")
    dk = d("kinetic_attack")
    dp = d("war_powers_politics")
    dt = d("shipping_trade")

    headline = "Risk signals broadly stable"
    if dm > 0 and ds >= 0:
        headline = "Maritime enforcement and sanctions pressure rise"
    elif ds > 0 and dm >= 0:
        headline = "Sanctions and compliance pressure increase"
    elif dm > 0:
        headline = "Maritime interdiction activity increases"
    elif dk > 0:
        headline = "Kinetic escalation language increases"
    elif dk < 0:
        headline = "Kinetic escalation language eases"
    elif ds < 0 and dm <= 0:
        headline = "Compliance pressure eases while maritime signals hold"

    def _trend_phrase(name: str, cur_n: int, base_n: int) -> str:
        if cur_n > base_n:
            return f"increase in {name} (count={cur_n}, baseline={base_n})"
        if cur_n < base_n:
            return f"decrease in {name} (count={cur_n}, baseline={base_n})"
        return f"no change in {name} (count={cur_n}, baseline={base_n})"

    bullets: List[str] = []
    bullets.append(
        f"Compared with {label}, there is an "
        + _trend_phrase(
            "maritime seizure/intercept/boarding signals",
            int(cur.get("maritime_seizure", 0) or 0),
            int(base.get("maritime_seizure", 0) or 0),
        )
        + "; "
        + _trend_phrase(
            "sanctions/tariff/compliance pressure signals",
            int(cur.get("sanctions_tariffs", 0) or 0),
            int(base.get("sanctions_tariffs", 0) or 0),
        )
        + "; and "
        + _trend_phrase(
            "kinetic/strike language",
            int(cur.get("kinetic_attack", 0) or 0),
            int(base.get("kinetic_attack", 0) or 0),
        )
        + "."
    )

    ex = (cur_sig.get("examples", {}) or {})
    maritime_ex = (ex.get("maritime_seizure") or [])[:1]
    sanctions_ex = (ex.get("sanctions_tariffs") or [])[:1]
    kinetic_ex = (ex.get("kinetic_attack") or [])[:1]

    example_bits: List[str] = []
    if maritime_ex:
        example_bits.append(f"maritime enforcement (e.g., {maritime_ex[0]})")
    if sanctions_ex:
        example_bits.append(f"sanctions/compliance posture (e.g., {sanctions_ex[0]})")
    if kinetic_ex:
        example_bits.append(f"kinetic language (e.g., {kinetic_ex[0]})")

    if example_bits:
        bullets.append(
            "The mix of coverage concentrates around "
            + ", ".join(example_bits[:2])
            + ", with implications for routing, screening, and compliance posture."
        )

    def _count_title_mentions(entries: List[Dict[str, Any]], needle: str) -> int:
        n = 0
        for e in entries or []:
            t = str(e.get("title") or "").lower()
            if needle in t:
                n += 1
        return n

    ven = _count_title_mentions(current_entries, "venezuela")
    guy = _count_title_mentions(current_entries, "guyana")

    if ven >= 3:
        bullets.append(
            "Venezuela remains a primary driver of the feed, dominated by sanctions/market-access framing and second-order impacts on shipping and insurance."
        )
    elif ven > 0 or guy > 0:
        bullets.append(
            "Regional energy and policy coverage (Venezuela/Guyana) remains present, with commercial and sanctions-adjacent implications rather than purely operational updates."
        )

    if int(cur.get("war_powers_politics", 0) or 0) > 0:
        bullets.append(
            "Political signaling (war-powers/authorization language) appears in the current entries, which can raise uncertainty even when sustained kinetic escalation is not confirmed."
        )

    if int(cur.get("shipping_trade", 0) or 0) > 0:
        bullets.append(
            "Commercial and maritime-operational risks are also visible (fraud, routing friction, or trade disruption language), supporting a posture of tighter controls and verification."
        )

    bullets.append(
        "Aruba/Caribbean relevance: maritime enforcement and compliance spillover can affect routing decisions, detention risk, documentation scrutiny, and downstream screening requirements."
    )

    neutral = (
        "Overall risk posture is best characterized as monitoring and preparedness over the next 7–14 days, based on the entries in this window."
    )
    while len(bullets) < 4:
        bullets.insert(-1, neutral)
    bullets = bullets[:7]

    out_lines = [f"{headline}:", ""]
    for b in bullets:
        b = re.sub(r"\s+", " ", (b or "").strip())
        out_lines.append(f"- {b}")
    return "\n".join(out_lines).strip()


def _build_exec_compare_fallback(
    label: str, cur_sig: Dict[str, Any], base_sig: Dict[str, Any]
) -> str:
    cur = cur_sig["counts"]
    base = base_sig["counts"]

    theme_order = [
        "maritime_seizure",
        "sanctions_tariffs",
        "war_powers_politics",
        "kinetic_attack",
        "shipping_trade",
    ]
    theme_names = {
        "maritime_seizure": "Caribbean tanker interdictions and seizure pressure",
        "sanctions_tariffs": "Sanctions and tariff enforcement pressure",
        "war_powers_politics": "U.S. political constraints and war powers signaling",
        "kinetic_attack": "Kinetic activity and strike signaling",
        "shipping_trade": "Trade and shipping market spillover",
    }
    dominant = max(theme_order, key=lambda k: int(cur.get(k, 0)))
    headline = f"{theme_names.get(dominant, 'Geopolitical risk update')}:"

    def _delta(k: str) -> str:
        return f"{int(cur.get(k, 0))} vs {int(base.get(k, 0))}"

    parts: List[str] = [headline]
    parts.append(
        f"Compared with {label}, the current set shows a higher concentration of operational maritime enforcement signals "
        f"({_delta('maritime_seizure')}) alongside sanctions/tariff language ({_delta('sanctions_tariffs')}). "
        f"Overall item volume is {cur_sig.get('n_items', 0)} vs {base_sig.get('n_items', 0)}."
    )
    if cur.get("maritime_seizure", 0) > 0:
        parts.append(
            "Maritime/conflict signals: multiple items reference tanker seizures/intercepts/boardings, suggesting elevated routing and insurance sensitivity in the Caribbean basin. "
            "This is operational pressure rather than confirmed blockade language unless explicitly stated in the entries."
        )
    else:
        parts.append(
            "Maritime/conflict signals: no confirmed tanker seizures/intercepts or naval boardings are indicated in the current entries."
        )
    if cur.get("war_powers_politics", 0) > 0 or cur.get("kinetic_attack", 0) > 0:
        parts.append(
            "Political/kinetic posture: the entries include war-powers/authorization signaling and/or strike language, indicating a contested decision environment even if a sustained attack campaign is not confirmed."
        )
    else:
        parts.append(
            "Political/kinetic posture: no explicit war-powers constraints or confirmed kinetic activity are emphasized in the current entries."
        )
    parts.append(
        "Aruba/Caribbean relevance: enforcement activity in Caribbean waters increases the odds of short-notice routing disruptions, detention risk, and knock-on compliance checks. "
        "Primary watchpoints are additional interdictions, changes in legal/sanctions posture, and any verified escalation at sea."
    )
    return "\n\n".join(parts)







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
    p.add_argument("--pdf", action="store_true", help="Also render the markdown summary as PDF")
    p.add_argument(
        "--compare",
        type=str,
        choices=["latest", "2d", "7d"],
        default=None,
        help="Add LLM comparison vs latest, last 2 days, or last 7 days",
    )
    return p


def _default_outdir(results_root: str) -> str:
    now = dt.datetime.now()
    return os.path.join(results_root, "geofeed", now.strftime("%Y%m%d"), now.strftime("%H%M%S"))


def _collect_geofeed_baseline_entries(
    results_root: str,
    current_outdir: str,
    mode: str,
    max_entries: int = 120,
) -> Tuple[List[Dict[str, Any]], str]:
    label = "most recent report" if mode == "latest" else f"last {mode.replace('d', '')} days"
    root = Path(results_root) / "geofeed"
    if not root.exists():
        return [], label

    now = dt.datetime.now(dt.timezone.utc)
    cutoff = None
    if mode in ("2d", "7d"):
        cutoff = now - dt.timedelta(days=int(mode.replace("d", "")))

    candidates: List[Tuple[dt.datetime, Path]] = []
    for path in root.glob("**/geofeed_summary_*.json"):
        if current_outdir and Path(current_outdir) in path.parents:
            continue
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
        except Exception:
            continue
        if cutoff and mtime < cutoff:
            continue
        candidates.append((mtime, path))

    candidates.sort(key=lambda x: x[0], reverse=True)
    if mode == "latest":
        candidates = candidates[:1]

    entries: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for _, path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = data.get("entries") or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            norm = _normalize_summary_entry(item)
            key = (norm.get("id") or (norm.get("url") or norm.get("title") or "")).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            entries.append(norm)
            if len(entries) >= max_entries:
                return entries, label

    entries.sort(key=lambda x: x.get("id", "") or "")
    return entries, label


def run_geofeed(
    hours: int,
    outdir: str,
    results_root: str,
    timeout: int,
    max_items: int,
    render_pdf: bool = False,
    compare_mode: Optional[str] = None,
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

                below_threshold = False

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
                            "GeoFeed LLM returned empty/invalid response for title=%s url=%s error=%s raw=%s",
                            it.title,
                            url,
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
    comparison_fail_path = os.path.join(outdir, f"geofeed_comparison_failures_{run_date}.jsonl")
    json_path = os.path.join(outdir, f"geofeed_summary_{run_date}.json")

    summary_limit = int(cfg.get("GEOFEED_SUMMARY_LIMIT", 35))
    summary_text = _make_summary(rows, hours=hours, summary_limit=summary_limit)
    summary_json = _make_summary_json(rows, hours=hours, summary_limit=summary_limit)

    comparison_section = None
    comparison_failures: List[Dict[str, Any]] = []
    if compare_mode:
        if not use_ollama:
            logger.warning("GeoFeed comparison skipped: LLM disabled")
        else:
            baseline_entries, label = _collect_geofeed_baseline_entries(
                results_root, outdir, compare_mode
            )
            if not baseline_entries:
                logger.warning(
                    "GeoFeed comparison skipped: no baseline reports found for %s",
                    compare_mode,
                )
            else:
                max_items = int(cfg.get("GEOFEED_COMPARISON_MAX_ITEMS", 18))
                current_entries = summary_json.get("entries") or []
                if isinstance(current_entries, list):
                    current_entries = current_entries[:max_items]
                else:
                    current_entries = []
                baseline_entries = baseline_entries[:max_items]

                try:
                    cur_sig = _entries_signature(current_entries if isinstance(current_entries, list) else [])
                    base_sig = _entries_signature(baseline_entries)
                    if cur_sig == base_sig:
                        comparison_section = (
                            f"Compared with {label}, there is no material structural change "
                            f"(canonical signatures match)."
                        )
                    else:
                        current_entries = [
                            _canonicalize_entry(e) for e in current_entries if isinstance(e, dict)
                        ]
                        baseline_entries = [
                            _canonicalize_entry(e) for e in baseline_entries if isinstance(e, dict)
                        ]
                        current_entries.sort(key=lambda x: x.get("id", "") or "")
                        baseline_entries.sort(key=lambda x: x.get("id", "") or "")
                except Exception:
                    pass

                if not comparison_section:
                    current_entries = [
                        _compact_for_comparison(e) for e in (current_entries or [])
                    ]
                    baseline_entries = [
                        _compact_for_comparison(e) for e in (baseline_entries or [])
                    ]
                    compare_timeout = max(int(timeout), 120)
                    comparison_section, comp_raw, comp_err = _ollama_geofeed_comparison(
                        host=ollama_host,
                        model=ollama_model,
                        current_entries=current_entries,
                        baseline_entries=baseline_entries,
                        label=label,
                        timeout=compare_timeout,
                    )
                    if not comparison_section:
                        comparison_section, comp_raw2, comp_err2 = _ollama_geofeed_comparison(
                            host=ollama_host,
                            model=ollama_model,
                            current_entries=current_entries,
                            baseline_entries=baseline_entries,
                            label=label,
                            timeout=compare_timeout,
                            strict=True,
                        )
                        if comp_raw2:
                            comp_raw = comp_raw2
                        if comp_err2:
                            comp_err = comp_err2
                    if comp_err:
                        comparison_failures.append(
                            {
                                "mode": compare_mode,
                                "label": label,
                                "current_entries": len(current_entries),
                                "baseline_entries": len(baseline_entries),
                                "error": comp_err,
                                "raw_response": comp_raw or "",
                            }
                        )
                        logger.warning("GeoFeed comparison used fallback/sanitizer: %s", comp_err)
                    if not comparison_section and not comp_err:
                        comparison_failures.append(
                            {
                                "mode": compare_mode,
                                "label": label,
                                "current_entries": len(current_entries),
                                "baseline_entries": len(baseline_entries),
                                "error": comp_err or "unknown",
                                "raw_response": comp_raw or "",
                            }
                        )
                        logger.warning("GeoFeed comparison skipped: LLM returned no content")

    if comparison_section:
        summary_text = _make_summary(
            rows,
            hours=hours,
            summary_limit=summary_limit,
            comparison_section=comparison_section,
        )
        summary_json["comparison_markdown"] = comparison_section
    _write_jsonl(rawtext_path, rawtext_rows)
    if llm_failures:
        _write_jsonl(llm_fail_path, llm_failures)
        print(f"Wrote LLM failures -> {llm_fail_path}")
    if comparison_failures:
        _write_jsonl(comparison_fail_path, comparison_failures)
        print(f"Wrote comparison failures -> {comparison_fail_path}")
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
        render_pdf=args.pdf,
        compare_mode=args.compare,
    )






def _looks_like_exec_storyboard(md: str) -> bool:

    if not isinstance(md, str) or not md.strip():
        return False
    s = md.strip()
    if "|" in s:
        return False
    for bad in ("\n#", "\n##", "\n###", "\n####"):
        if bad in ("\n" + s):
            return False
    for line in s.splitlines():
        ln = line.strip()
        if not ln:
            continue
        if ln[:2].isdigit() and ln[1:3] in (". ", ".)"):
            return False
        if ln.startswith("1. ") or ln.startswith("2. "):
            return False
    lines = [ln.rstrip() for ln in s.splitlines()]
    first = next((ln.strip() for ln in lines if ln.strip()), "")
    if not first.endswith(":"):
        return False
    heading_count = 0
    bullet_count = 0
    for ln in lines:
        t = ln.strip()
        if not t:
            continue
        if t.startswith(("-", "•", "*")):
            bullet_count += 1
            continue
        heading_count += 1
    return heading_count >= 4 and bullet_count >= 4


def _build_exec_compare_storyboard_good_pdf(
    label: str,
    cur_sig: Dict[str, Any],
    base_sig: Dict[str, Any],
    current_entries: List[Dict[str, Any]],
    baseline_entries: List[Dict[str, Any]],
) -> str:

    cur = (cur_sig.get("counts") or {})
    base = (base_sig.get("counts") or {})

    def d(key: str) -> int:
        return int(cur.get(key, 0) or 0) - int(base.get(key, 0) or 0)

    dm = d("maritime_seizure")
    ds = d("sanctions_tariffs")
    dk = d("kinetic_attack")
    dp = d("war_powers_politics")
    dt = d("shipping_trade")

    theme = "Risk signal mix broadly stable:"
    if (ds > 0 and dm >= 0) or (dm > 0 and ds >= 0):
        theme = "Sanctions and maritime enforcement pressure increases:"
    elif ds > 0:
        theme = "Sanctions and compliance pressure increases:"
    elif dm > 0:
        theme = "Maritime interdiction and enforcement activity increases:"
    elif dk > 0:
        theme = "Kinetic escalation language increases:"
    elif (ds < 0 and dm <= 0 and dk <= 0):
        theme = "Compliance and escalation pressure eases:"

    ex = (cur_sig.get("examples") or {})
    ex_m = ex.get("maritime_seizure") or []
    ex_s = ex.get("sanctions_tariffs") or []
    ex_k = ex.get("kinetic_attack") or []
    ex_p = ex.get("war_powers_politics") or []
    ex_t = ex.get("shipping_trade") or []

    def _fmt_examples(lst: List[str]) -> str:
        if not lst:
            return ""
        if len(lst) == 1:
            return f" Example: {lst[0]}."
        return f" Examples: {lst[0]}; {lst[1]}."

    sections: List[str] = []
    sections.append(
        "\n".join(
            [
                f"Compared with {label}, overall volume and dominant themes shift as follows",
                f"- Net item volume is {cur_sig.get('n_items', 0)} vs {base_sig.get('n_items', 0)} in {label}.",
                "- The points below highlight the most decision-relevant changes rather than listing every article.",
            ]
        )
    )
    sections.append(
        "\n".join(
            [
                "Sanctions and compliance posture",
                f"- Sanctions/tariff/compliance signals show {'an increase' if ds>0 else 'a decrease' if ds<0 else 'no material change'} ({cur.get('sanctions_tariffs',0)} vs {base.get('sanctions_tariffs',0)})."
                + _fmt_examples(ex_s),
                "- Operational impact is most likely via financing, counterparties, and insurance scrutiny rather than immediate physical disruption.",
            ]
        )
    )
    sections.append(
        "\n".join(
            [
                "Maritime enforcement and routing sensitivity",
                f"- Maritime interdiction/seizure/boarding indicators show {'an increase' if dm>0 else 'a decrease' if dm<0 else 'no material change'} ({cur.get('maritime_seizure',0)} vs {base.get('maritime_seizure',0)})."
                + _fmt_examples(ex_m),
                "- This is best interpreted as enforcement pressure (detention/inspection risk) unless an explicit blockade is stated in-source.",
            ]
        )
    )
    sections.append(
        "\n".join(
            [
                "Political and escalation indicators",
                f"- War-powers/authorization/political constraint signaling is {'higher' if dp>0 else 'lower' if dp<0 else 'similar'} ({cur.get('war_powers_politics',0)} vs {base.get('war_powers_politics',0)})."
                + _fmt_examples(ex_p),
                f"- Strike/attack/kinetic language is {'higher' if dk>0 else 'lower' if dk<0 else 'similar'} ({cur.get('kinetic_attack',0)} vs {base.get('kinetic_attack',0)})."
                + _fmt_examples(ex_k),
            ]
        )
    )
    if int(cur.get("shipping_trade", 0) or 0) > 0 or int(base.get("shipping_trade", 0) or 0) > 0:
        sections.append(
            "\n".join(
                [
                    "Shipping and commercial conditions",
                    f"- Shipping/trade indicators are {'higher' if dt>0 else 'lower' if dt<0 else 'similar'} ({cur.get('shipping_trade',0)} vs {base.get('shipping_trade',0)})."
                    + _fmt_examples(ex_t),
                    "- Watch for knock-on changes in transit times, surcharges, and carrier capacity decisions if enforcement or sanctions expand.",
                ]
            )
        )
    sections.append(
        "\n".join(
            [
                "Aruba/Caribbean relevance",
                "- Any rise in interdictions/boardings elevates short-notice routing disruption risk and increases the chance of documentation/compliance checks for vessels transiting the basin.",
                "- Primary watchpoints: additional interdictions, verified legal/sanctions changes affecting Venezuela-linked trade, and any confirmed escalation at sea.",
            ]
        )
    )

    out_lines: List[str] = [theme, ""]
    for sec in sections:
        sec_lines = [ln.rstrip() for ln in sec.splitlines()]
        if not sec_lines:
            continue
        heading = sec_lines[0].strip()
        bullets = sec_lines[1:]
        out_lines.append(heading)
        for b in bullets:
            t = b.strip()
            if not t:
                continue
            if t.startswith(("-", "•", "*")):
                t = "- " + t.lstrip("-•* ").strip()
            else:
                t = "- " + t
            out_lines.append(t)
        out_lines.append("")

    return "\n".join(out_lines).strip() + "\n"


def _ollama_geofeed_comparison(
    host: str,
    model: str,
    current_entries: List[Dict[str, Any]],
    baseline_entries: List[Dict[str, Any]],
    label: str,
    timeout: int,
    strict: bool = False,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        cur_sig = _extract_exec_signals(current_entries or [])
        base_sig = _extract_exec_signals(baseline_entries or [])

        strict_block = ""
        if strict:
            strict_block = (
                "STRICT OUTPUT MODE:\n"
                "- Output MUST be a single JSON object with exactly one key: comparison_markdown.\n"
                "- Do NOT output any other keys.\n"
                "- Do NOT include any preamble text.\n\n"
            )

        anchors: List[str] = []
        c = cur_sig.get("counts", {}) or {}
        b = base_sig.get("counts", {}) or {}
        anchors.append(
            f"Counts (current vs {label}): sanctions_tariffs={c.get('sanctions_tariffs',0)} vs {b.get('sanctions_tariffs',0)}."
        )
        anchors.append(
            f"Counts (current vs {label}): maritime_seizure={c.get('maritime_seizure',0)} vs {b.get('maritime_seizure',0)}."
        )
        anchors.append(
            f"Counts (current vs {label}): war_powers_politics={c.get('war_powers_politics',0)} vs {b.get('war_powers_politics',0)}."
        )
        anchors.append(
            f"Counts (current vs {label}): kinetic_attack={c.get('kinetic_attack',0)} vs {b.get('kinetic_attack',0)}."
        )
        anchors.append(
            f"Counts (current vs {label}): shipping_trade={c.get('shipping_trade',0)} vs {b.get('shipping_trade',0)}."
        )

        prompt = (
            "You are GeoFeed. Write an executive COMPARISON in the SAME visual style as an executive one-page brief.\n"
            f"You are comparing CURRENT_ENTRIES versus {label} (BASELINE_ENTRIES).\n\n"
            "NON-NEGOTIABLE RULES:\n"
            "- Use ONLY the provided entries. Do NOT invent facts.\n"
            "- No tables. The '|' character is forbidden anywhere.\n"
            "- No markdown headings (#). No numbered lists.\n"
            "- Output must be a storyboard with short headings and bullets (like a slide).\n\n"
            "REQUIRED STORYBOARD FORMAT (MUST MATCH):\n"
            "Line 1: Theme headline ending with ':'\n"
            "Blank line\n"
            "Then repeat 4–6 times:\n"
            "  Heading line (no bullet)\n"
            "  - bullet\n"
            "  - bullet\n"
            "  Blank line\n"
            "Hard requirements:\n"
            f"- The FIRST section heading must begin with: 'Compared with {label},'\n"
            "- The FINAL section heading must be exactly: 'Aruba/Caribbean relevance'\n"
            "- Each heading should be concise (<= 14 words).\n"
            "- Each bullet is 1 sentence; keep it scannable.\n\n"
            "ANCHOR FACTS (MUST BE CONSISTENT WITH THESE COUNTS):\n"
            + "\n".join([f"- {a}" for a in anchors])
            + "\n\n"
            f"{strict_block}"
            "CURRENT_ENTRIES:\n"
            f"{json.dumps(current_entries or [], ensure_ascii=True)}\n\n"
            "BASELINE_ENTRIES:\n"
            f"{json.dumps(baseline_entries or [], ensure_ascii=True)}\n"
        )

        def _request_llm(prompt_text: str, options: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
            payload = json.dumps(
                {
                    "model": model,
                    "prompt": prompt_text,
                    "stream": False,
                    "format": {
                        "type": "object",
                        "properties": {"comparison_markdown": {"type": "string"}},
                        "required": ["comparison_markdown"],
                        "additionalProperties": False,
                    },
                    "options": options,
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
            parsed = _robust_json_extract(s)
            if not isinstance(parsed, dict):
                parsed = _robust_json_extract(raw)
            if isinstance(parsed, dict) and isinstance(parsed.get("response"), dict):
                parsed = parsed["response"]
            if not isinstance(parsed, dict):
                return None, raw, "invalid_json"
            comparison = parsed.get("comparison_markdown")
            if not isinstance(comparison, str) or not comparison.strip():
                return None, raw, "missing_comparison_markdown"
            return comparison.strip(), raw, None

        comparison, raw, err = _request_llm(prompt, {"temperature": 0, "num_predict": 480})
        if not comparison or err:
            repaired, raw2, err2 = _llm_repair_to_strict_json(
                host=host, model=model, bad_text=(raw or ""), label=label, timeout=timeout
            )
            if repaired and _looks_like_exec_storyboard(repaired):
                return repaired.strip() + "\n", raw2 or raw, "repaired_from_bad_json"
            return None, raw2 or raw, f"llm_failed_{err2 or err or 'invalid_or_unusable_llm_output'}"

        if not _looks_like_exec_storyboard(comparison):
            repaired, raw2, err2 = _llm_repair_to_strict_json(
                host=host, model=model, bad_text=comparison, label=label, timeout=timeout
            )
            if repaired and _looks_like_exec_storyboard(repaired):
                return repaired.strip() + "\n", raw2 or raw, "repaired_from_bad_format"
            return None, raw2 or raw, f"invalid_or_unusable_llm_output_{err2 or 'unknown'}"

        return comparison.strip() + "\n", raw, None

    except Exception as exc:
        return None, None, f"comparison_exception:{type(exc).__name__}"

if __name__ == "__main__":
    raise SystemExit(main())
