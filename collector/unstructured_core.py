from __future__ import annotations
from typing import TYPE_CHECKING

# =========================
# === Standard Library ====
# =========================
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from typing import Dict, List
from urllib.parse import urlparse

# =========================
# ===== Third-Party =======
# =========================
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# =========================
# ====== Local App ========
# =========================
from .config import CONFIG, load_enabler_keywords

logger = logging.getLogger(__name__)

try:
    import fitz

    HAS_PYMUPDF = True
except Exception:
    fitz = None
    HAS_PYMUPDF = False

if TYPE_CHECKING:
    import fitz

# =========================
# ===== Module Config =====
# =========================
CVE_RX = re.compile(CONFIG.get("CVE_REGEX", r"\bCVE-\d{4}-\d{4,7}\b"), re.I)
BULLET_FINDING_RE = re.compile(
    CONFIG.get(
        "BULLET_FINDING_REGEX",
        r"^[-*•]\s+|^\d+[.)]\s+|^(?:finding|finding\s+\d+)\s*[:\-]\s*",
    ),
    re.IGNORECASE,
)
SHORT_SOCIAL_RE = re.compile(
    CONFIG.get(
        "SHORT_SOCIAL_REGEX", r"\b(follow|subscribe|share|like|google news|gbhackers)\b"
    ),
    re.I,
)
PROMO_PATTERNS = [re.compile(p, re.I) for p in (CONFIG.get("PROMO_PATTERNS") or [])]
PROVENANCE_STRIP_PATTERNS = [
    re.compile(p, re.MULTILINE)
    for p in (CONFIG.get("PROVENANCE_STRIP_PATTERNS") or [])
]
RELATED_ARTICLES_MARKER = "related articles"
CORE_FOCUS_LIMIT = 1000
NPM_TRIGGER_PHRASES = (
    "npm package",
    "malicious npm",
    "malicious package",
    "typosquatting",
    "postinstall",
    "post install",
    "supply chain",
    "eslint plugin",
    "eslint-plugin",
)
TEXT_RELEVANCE_BOOSTS = {
    k.lower(): v for k, v in (CONFIG.get("TEXT_RELEVANCE_BOOSTS") or {}).items()
}
SECTOR_RELEVANCE_BOOSTS = {
    k.lower(): v for k, v in (CONFIG.get("SECTOR_RELEVANCE_BOOSTS") or {}).items()
}
ACTIONABILITY_KEYWORD_WEIGHTS = {
    k.lower(): v
    for k, v in (CONFIG.get("ACTIONABILITY_KEYWORD_WEIGHTS") or {}).items()
}

# =========================
# ===== Pattern Loading ===
# =========================
def load_patterns() -> Dict[str, List[dict]]:
    patterns_path = CONFIG.get("PATTERNS_FILE") or os.path.join(
        os.path.dirname(__file__), "..", "data", "patterns.json"
    )
    if not os.path.exists(patterns_path):
        patterns_path = CONFIG.get("PATTERNS_FILE") or os.path.join(
            os.path.dirname(__file__), "patterns.json"
        )
    try:
        with open(patterns_path, "r", encoding="utf-8") as f:
            patterns = json.load(f)
        return patterns
    except Exception:
        return {}


@lru_cache(maxsize=CONFIG.get("COMPILED_PATTERNS_CACHE_MAXSIZE", 1))
def load_compiled_patterns() -> Dict[str, List[dict]]:
    patterns = load_patterns()
    compiled: Dict[str, List[dict]] = {}
    for key, items in patterns.items():
        compiled[key] = []
        for item in items:
            pat_str = None
            new_item = None
            if isinstance(item, str):
                pat_str = item
                new_item = {"pattern": pat_str}
            elif isinstance(item, dict):
                pat_str = item.get("pattern")
                new_item = dict(item)
            if not pat_str:
                continue
            flags = re.IGNORECASE | re.MULTILINE
            try:
                comp = re.compile(pat_str, flags)
            except re.error:
                logger.warning("Invalid regex for key %s: %s", key, pat_str)
                continue
            new_item["regex"] = comp
            compiled[key].append(new_item)
    return compiled


def load_mitre_map() -> Dict[str, dict]:

    mitre_path = CONFIG.get("MITRE_MAP_FILE") or os.path.join(
        os.path.dirname(__file__), "..", "data", "mitre_mapping.json"
    )
    if not os.path.exists(mitre_path):
        mitre_path = CONFIG.get("MITRE_MAP_FILE") or os.path.join(
            os.path.dirname(__file__), "mitre_map.json"
        )
    try:
        with open(mitre_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    mapping: Dict[str, dict] = {}

    if isinstance(data, dict):

        for _, entries in data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                tid = entry.get("id") or entry.get("technique_id") or ""
                if not tid:
                    continue
                mapping[tid.upper()] = entry
    elif isinstance(data, list):
        for entry in data:
            tid = entry.get("id") or entry.get("technique_id") or ""
            if not tid:
                continue
            mapping[tid.upper()] = entry
    return mapping


def load_mitre_mitigations() -> Dict[str, dict]:

    mitig_path = CONFIG.get("MITRE_MITIGATIONS_FILE") or os.path.join(
        os.path.dirname(__file__), "..", "data", "mitre_mitigations.json"
    )
    if not os.path.exists(mitig_path):
        mitig_path = CONFIG.get("MITRE_MITIGATIONS_FILE") or os.path.join(
            os.path.dirname(__file__), "mitre_mitigations.json"
        )
    try:
        with open(mitig_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    mapping: Dict[str, dict] = {}

    if isinstance(data, dict):
        for mid, meta in data.items():
            if not mid:
                continue
            mapping[str(mid).upper()] = (
                meta if isinstance(meta, dict) else {"description": meta}
            )
    elif isinstance(data, list):
        for entry in data:
            mid = entry.get("id") or entry.get("mitigation_id") or ""
            if not mid:
                continue
            mapping[mid.upper()] = entry
    return mapping


def load_mitre_phrase_map() -> Dict[str, List[dict]]:
    mitig_path = CONFIG.get("MITRE_MAP_FILE") or os.path.join(
        os.path.dirname(__file__), "..", "data", "mitre_mapping.json"
    )
    if not os.path.exists(mitig_path):
        mitig_path = CONFIG.get("MITRE_MAP_FILE") or os.path.join(
            os.path.dirname(__file__), "mitre_mapping.json"
        )
    try:
        with open(mitig_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    phrase_map: Dict[str, List[dict]] = {}

    if isinstance(data, dict):
        for phrase, entries in data.items():
            if not phrase or not isinstance(entries, list):
                continue
            phrase_map[str(phrase).lower()] = entries

    try:
        for phrase, entries in data.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                try:
                    ename = (e.get("name") or "").strip().lower()
                    if not ename:
                        continue
                    if ename not in phrase_map:
                        phrase_map[ename] = [e]
                    else:

                        if e not in phrase_map[ename]:
                            phrase_map[ename].append(e)
                except Exception:
                    continue
    except Exception:
        pass

    try:
        if "cross-site scripting" in phrase_map and "xss" not in phrase_map:
            phrase_map["xss"] = phrase_map.get("cross-site scripting")
        if "remote code execution" in phrase_map and "rce" not in phrase_map:
            phrase_map["rce"] = phrase_map.get("remote code execution")
    except Exception:
        pass

    return phrase_map


def _norm_key(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]+", "-", s.strip().lower())


def attach_mitre_to_intel(intel: dict) -> dict:
    techniques = intel.get("threat", {}).get("technique", [])
    if not isinstance(techniques, list):
        return intel

    mitre_map = load_mitre_map()
    for t in techniques:
        tid = t.get("id") or t.get("technique_id") or ""
        if not tid:
            continue
        mt = mitre_map.get(str(tid).upper())
        if mt:
            t["name"] = t.get("name") or mt.get("name")
            t["reference"] = mt.get("reference") or mt.get("url")
            t["tactic"] = mt.get("tactic") or mt.get("kill_chain_phase")
    return intel


def compute_mitre_relevance(intel: dict) -> dict:
    try:
        th = intel.setdefault("threat", {})
        techs = th.get("technique") or []
        if isinstance(techs, dict):
            techs = techs.get("name") or []
        if not techs:
            return intel

        mitre_map = load_mitre_map() or {}
        boosts = CONFIG.get("TECHNIQUE_SCORE_BOOST") or {}
        ioc_count = len(intel.get("iocs", []) or [])
        actor_count = len((th.get("actor") or []) or [])

        details = []
        for t in techs:

            tid = None
            name = None
            if isinstance(t, dict):
                tid = t.get("id") or t.get("technique_id") or None
                name = t.get("name") or None
            elif isinstance(t, str):
                name = t

            score = 0
            if tid:
                score = 50
            else:
                score = 30

            if ioc_count:
                score += 10
            score += min(20, actor_count * 10)

            if tid:
                try:
                    extra = int(boosts.get(str(tid).upper()) or 0)
                    score += extra
                except Exception:
                    pass

            try:
                multiplier = float(
                    CONFIG.get("INFERRED_TECHNIQUE_SCORE_MULTIPLIER", 0.8)
                )
            except Exception:
                multiplier = 0.8

            is_inferred = False
            if isinstance(t, dict):
                if t.get("inferred") or t.get("source") == "inferred":
                    is_inferred = True

            if is_inferred:
                score = int(max(0, min(100, round(score * multiplier))))

            score = int(min(100, max(0, score)))
            label = _score_to_label(score)

            entry: dict = {"score": score, "label": label}
            if tid:
                entry["id"] = tid.upper()
            if name:
                entry["name"] = name

            if tid and mitre_map:
                mm = mitre_map.get(str(tid).upper())
                if mm:
                    entry.setdefault("reference", mm.get("url") or mm.get("reference"))
                    entry.setdefault(
                        "tactic", mm.get("tactic") or mm.get("kill_chain_phase")
                    )
                    entry.setdefault("mitre_name", mm.get("name"))

            if is_inferred:
                entry["inferred"] = True

            details.append(entry)

            try:
                if isinstance(t, dict):
                    t["mitre_score"] = score
                    t["mitre_label"] = label
                    if is_inferred:
                        t["mitre_inferred"] = True

                        t.setdefault("source", "inferred")

            except Exception:
                pass

        th["mitre_details"] = details
        intel["threat"] = th
    except Exception:
        pass
    return intel


def compute_mitre_priority(intel: dict) -> dict:
    try:
        th = intel.setdefault("threat", {})
        details = th.get("mitre_details") or []
        if not details:
            return intel

        mitre_map = load_mitre_map() or {}

        base_w = float(CONFIG.get("MITRE_PRIORITY_BASE_WEIGHT", 0.6))
        evid_w = float(CONFIG.get("MITRE_PRIORITY_EVIDENCE_WEIGHT", 0.4))
        mult = float(CONFIG.get("INFERRED_TECHNIQUE_SCORE_MULTIPLIER", 0.8))

        sig_mention = int(CONFIG.get("MITRE_SIGNAL_MENTION", 30))
        sig_cve = int(CONFIG.get("MITRE_SIGNAL_CVE", 20))
        sig_ioc = int(CONFIG.get("MITRE_SIGNAL_IOC", 15))
        sig_action = int(CONFIG.get("MITRE_SIGNAL_ACTIONABILITY", 25))

        txt = " ".join(
            str(intel.get(k) or "")
            for k in ("title", "summary_text", "summary", "raw_text", "text")
        ).lower()

        scores = []
        for d in details:
            try:
                tid = (d.get("id") or d.get("technique_id") or "").upper()
                name = d.get("name") or ""
                mm = mitre_map.get(tid) if tid else None
                try:
                    base = (
                        int(
                            mm.get("priority")
                            or mm.get("score")
                            or mm.get("risk")
                            or 50
                        )
                        if mm
                        else 50
                    )
                except Exception:
                    base = 50

                evidence = 0

                try:
                    if name:
                        n = (
                            " ".join(name).lower()
                            if isinstance(name, list)
                            else str(name).lower()
                        )
                        if n and re.search(r"\b" + re.escape(n) + r"\b", txt):
                            evidence += sig_mention
                except Exception:
                    pass

                if intel.get("related_cves"):
                    evidence += sig_cve

                if intel.get("iocs"):
                    evidence += sig_ioc

                try:
                    act = (th.get("actionability") or {}).get("score")
                    if act:
                        evidence += int(
                            min(sig_action, max(0, (float(act) / 100.0) * sig_action))
                        )
                except Exception:
                    pass

                inferred = bool(d.get("inferred") or d.get("source") == "inferred")
                if inferred:
                    evidence = int(round(evidence * mult))

                raw = (base * base_w) + (evidence * evid_w)
                score = int(max(0, min(100, round(raw))))
                label = _score_to_label(score)

                d["priority_score"] = score
                d["priority_label"] = label

                try:
                    techs = th.get("technique") or []
                    if isinstance(techs, list):
                        for t in techs:
                            if isinstance(t, dict):
                                matched = False
                                if (
                                    tid
                                    and t.get("id")
                                    and str(t.get("id")).upper() == tid
                                ):
                                    matched = True
                                else:
                                    tn = t.get("name")
                                    tn_s = ""
                                    if isinstance(tn, list):
                                        tn_s = " ".join([str(x) for x in tn]).lower()
                                    elif isinstance(tn, str):
                                        tn_s = tn.lower()
                                    if name and name.lower() in tn_s:
                                        matched = True
                                if matched:
                                    t["mitre_priority"] = score
                                    t["mitre_priority_label"] = label
                                    if inferred:
                                        t["mitre_inferred"] = True
                except Exception:
                    pass

                scores.append(score)
            except Exception:
                continue

        if scores:
            max_score = max(scores)
            th["mitre_priority"] = {
                "score": max_score,
                "label": _score_to_label(max_score),
            }
            intel["threat"] = th
    except Exception:
        pass
    return intel


def correlate_unstructured_with_cves(
    unstructured_items: list[dict], cves: list[dict]
) -> list[dict]:
    return unstructured_items


def html_to_main_text(
    html: str, *, strip_boilerplate: bool = True, max_len: int | None = None
) -> str:
    if not html:
        return ""
    parser = CONFIG.get("HTML_PARSER", "html.parser")
    soup = BeautifulSoup(html, parser)

    strip_elems = CONFIG.get(
        "HTML_STRIP_ELEMENTS",
        ["script", "style", "noscript", "header", "footer", "nav"],
    ) or ["script", "style", "noscript", "header", "footer", "nav"]
    try:
        for elem in soup(tuple(strip_elems)):
            elem.decompose()
    except Exception:
        for elem in soup(["script", "style", "noscript", "header", "footer", "nav"]):
            try:
                elem.decompose()
            except Exception:
                continue

    text = soup.get_text(separator="\n")
    lines = [ln.strip() for ln in text.splitlines()]
    if strip_boilerplate:
        cleaned = []
        bp_keywords = [
            k.lower()
            for k in CONFIG.get(
                "BOILERPLATE_KEYWORDS",
                [
                    "cookies",
                    "privacy",
                    "terms",
                    "all rights reserved",
                    "subscribe",
                    "advert",
                    "promo",
                ],
            )
            or []
        ]
        for ln in lines:
            if not ln:
                continue
            low = ln.lower()
            if any(k in low for k in bp_keywords):
                continue
            cleaned.append(ln)
        lines = cleaned
    text = "\n".join(lines)
    max_len = max_len if max_len is not None else CONFIG.get("HTML_MAX_LEN", 50000)
    if len(text) > max_len:
        text = text[:max_len]
    return text


def get_requests_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=CONFIG.get("HTTP_RETRIES_TOTAL", 3),
        backoff_factor=CONFIG.get("HTTP_BACKOFF_FACTOR", 0.5),
        status_forcelist=tuple(
            CONFIG.get("HTTP_STATUS_FORCELIST", (500, 502, 503, 504))
        ),
        allowed_methods=frozenset(CONFIG.get("HTTP_ALLOWED_METHODS", ["GET", "HEAD"])),
    )
    adapter = HTTPAdapter(
        max_retries=retries,
        pool_connections=CONFIG.get("HTTP_POOL_CONNECTIONS", 100),
        pool_maxsize=CONFIG.get("HTTP_POOL_MAXSIZE", 100),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(
        {"User-Agent": CONFIG.get("USER_AGENT", "ThreatIntelCollector/5.0")}
    )
    return s


# =========================
# ===== Fetch & Parse =====
# =========================
def fetch_article_text(url: str, timeout: int | None = None) -> str:
    try:
        session = get_requests_session()
        timeout = int(timeout or CONFIG.get("REQUEST_TIMEOUT", 10))
        headers = {
            "User-Agent": CONFIG.get("USER_AGENT", session.headers.get("User-Agent"))
        }
        resp = session.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Error fetching url %s: %s", url, exc)
        return ""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype or "<html" in resp.text.lower():
        try:
            main_text = html_to_main_text(resp.text)
        except Exception:
            main_text = ""
        extras = []
        try:
            raw_iocs = extract_iocs(resp.text) or []
            for i in raw_iocs:
                t = (i.get("type") or "").lower()
                if t in {"ip", "cve"}:
                    val = i.get("indicator") or i.get("value")
                    if val:
                        extras.append(val)
        except Exception:
            pass
        extra_text = "\n".join(extras)
        return f"{main_text}\n{extra_text}".strip()
    return resp.text


# =========================
# == Threat Extraction ====
# =========================
def extract_threat_indicators(
    parsed_record: dict | str, source: str | None = None, title: str | None = None
) -> dict:
    parsed_record, aggregate_text = _normalize_record_input(
        parsed_record, source, title
    )
    if _is_nav_placeholder(aggregate_text, parsed_record.get("title")):
        th = parsed_record.setdefault("threat", {})
        th["technique"] = {"name": []}
        return parsed_record
    if not aggregate_text:
        return parsed_record

    found = _collect_pattern_hits(aggregate_text)
    _apply_pattern_hits(found, parsed_record)

    has_techniques = bool(
        (parsed_record.get("threat") or {}).get("technique")
        or found.get("technique")
    )
    if not has_techniques:
        _maybe_classify_from_text(aggregate_text, parsed_record)

    _apply_phrase_map_to_record(aggregate_text, parsed_record)

    try:
        _expand_mitre_by_name(parsed_record)
    except Exception:
        pass

    try:
        th = parsed_record.setdefault("threat", {})
        _ensure_technique_list(th)
    except Exception:
        pass

    try:
        parsed_record = enrich_campaign_heuristics(parsed_record, aggregate_text)
    except Exception:
        pass

    try:
        th = parsed_record.setdefault("threat", {})
        _prune_placeholder_techniques(th)
    except Exception:
        pass

    parsed_record = attach_mitre_to_intel(parsed_record)
    parsed_record = compute_mitre_relevance(parsed_record)

    try:
        parsed_record = compute_mitre_priority(parsed_record)
    except Exception:
        pass
    try:
        th = parsed_record.setdefault("threat", {})
        _ensure_technique_list(th)
        _prune_placeholder_techniques(th)
        _normalize_mitre_techniques(th)
    except Exception:
        pass

    try:
        _coerce_technique_output(parsed_record)
    except Exception:
        pass

    return parsed_record


def _coerce_technique_output(rec: dict) -> None:
    th = rec.get("threat") or {}
    labels = th.get("labels") or []
    tech = th.get("technique")
    if isinstance(tech, list):
        names: list[str] = []
        for t in tech:
            if isinstance(t, dict):
                n = t.get("name")
                if isinstance(n, list):
                    names.extend(n)
                elif isinstance(n, str):
                    names.append(n)
                elif t.get("id"):
                    names.append(t.get("id"))
            elif isinstance(t, str):
                names.append(t)
        # ensure labels are included as names
        for lbl in labels:
            cap = str(lbl).capitalize()
            if cap not in names:
                names.append(cap)
        th["technique"] = {"name": names, "mitre": tech}
        rec["threat"] = th
    elif isinstance(tech, dict):
        if "name" not in tech:
            tech["name"] = []
        if "mitre" not in tech:
            tech["mitre"] = []
        for lbl in labels:
            cap = str(lbl).capitalize()
            if cap not in tech["name"]:
                tech["name"].append(cap)
        rec["threat"] = th


def extract_iocs(
    text_or_intel, source: str | None = None, title: str | None = None
) -> list[dict]:
    if isinstance(text_or_intel, dict):
        results = []
        for ioc in text_or_intel.get("iocs", []):
            if not isinstance(ioc, dict):
                continue
            itype = ioc.get("type") or ""
            val = ioc.get("indicator") or ioc.get("value")
            if not val:
                continue
            results.append({"type": itype, "indicator": val})
        return results

    text = str(text_or_intel or "")
    defanged_text = (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )
    texts_to_scan = [text, defanged_text]
    iocs = []
    seen = set()
    package_pattern = re.compile(
        r"@?[a-z0-9][\w.-]*(?:/[a-z0-9][\w.-]*)?@[0-9]+(?:\.[0-9]+){2,}", re.I
    )

    ipv4_pattern = re.compile(r"(?<!\d)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d)")
    ipv6_pattern = re.compile(
        r"(?<![A-F0-9])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9:]{1,4}(?![A-F0-9])", re.I
    )
    cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

    patterns = {
        "ip": ipv4_pattern,
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "url": re.compile(r"\bhttps?://[\w\-./?&=%#]+", re.I),
        "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
        "domain": re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I
        ),
    }
    file_ext_block = {
        "exe",
        "dll",
        "lnk",
        "pdf",
        "zip",
        "png",
        "rar",
        "7z",
        "iso",
        "scr",
        "json",
        "php",
        "asp",
        "aspx",
        "jsp",
        "cgi",
        "html",
        "htm",
    }

    image_ext = {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "webp",
        "bmp",
        "ico",
    }

    def _add(t, v):
        key = (t, v.lower())
        if v.startswith("block_domain:") or v.startswith("block_url:"):
            return
        if key in seen:
            return
        seen.add(key)
        typ = "hash" if t in ("sha256", "sha1", "md5") else t
        val = v.lower()
        if typ == "ip":
            blocked_ips = CONFIG.get("IOC_IP_BLOCKLIST") or set()
            if val in blocked_ips:
                return
        if typ == "ip":
            if ":" in val and "." not in val:
                try:
                    parts = val.split(":")
                    if len(parts) <= 3 and all(p.isdigit() for p in parts if p):
                        return
                except Exception:
                    pass
        if typ == "filename":
            try:
                ext = val.rsplit(".", 1)[1]
                if ext in image_ext:
                    return
            except Exception:
                pass
        iocs.append({"type": typ, "indicator": val, "value": val})

    for scan_text in texts_to_scan:
        for m in package_pattern.finditer(scan_text):
            val = m.group(0)
            _add("software_package", val)

        for m in ipv6_pattern.finditer(scan_text):
            _add("ip", m.group(0))

        for m in cve_pattern.finditer(scan_text):
            _add("cve", m.group(0).upper())

        for t, p in patterns.items():
            for m in p.finditer(scan_text):
                val = m.group(0)
                if t == "domain" and val.startswith("www."):
                    val = val[4:]
                if t == "domain":
                    try:
                        suffix = val.rsplit(".", 1)[1].lower()
                        if suffix in file_ext_block:
                            _add("filename", val)
                            continue
                    except Exception:
                        pass
                if t == "email":
                    try:
                        local, _, dom = val.partition("@")
                        if "/" in local or "\\" in local:
                            continue
                        if dom and dom.replace(".", "").isdigit():
                            continue
                    except Exception:
                        pass
                _add(t, val)

    return iocs


def generate_actionable_items(intel: dict) -> list[dict]:
    mitre_mitig = load_mitre_mitigations()
    out_items: list[dict] = []

    techs = (intel.get("threat") or {}).get("technique") or []
    tech_list: list = []
    if isinstance(techs, dict):
        names = techs.get("name")
        if isinstance(names, list):
            for n in names:
                tech_list.append({"name": [n]})
        else:
            tech_list.append(techs)
    elif isinstance(techs, list):
        for item in techs:
            if isinstance(item, str):
                tech_list.append({"name": [item]})
            else:
                tech_list.append(item)
    else:
        tech_list = [techs]

    for t in tech_list:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or "").upper()
        if not tid:
            continue
        for mid, meta in mitre_mitig.items():
            if tid in (meta.get("related_techniques") or []):
                out_items.append(
                    {
                        "type": "mitigation",
                        "id": mid,
                        "technique": tid,
                        "description": meta.get("description"),
                        "reference": meta.get("url"),
                    }
                )

    rec_actions: list[str] = []
    for i in intel.get("iocs", []) or []:
        typ = (i.get("type") or "").lower()
        val = i.get("value") or i.get("indicator") or ""
        if not val:
            continue
        if typ == "ip":
            rec_actions.append(f"block_ip:{val}")
        elif typ == "domain":
            rec_actions.append(f"block_domain:{val}")
        elif typ == "url":
            rec_actions.append(f"block_url:{val}")

    mitigation_snippets = {
        "firewall": ["deny ip <ip>", "deny domain <domain>"],
        "proxy": ["block_url <url>", "block_domain <domain>"],
        "suricata": ['alert http any any -> any any (msg:"IOCs seen"; sid:1000001;)'],
    }

    if rec_actions:
        out_items.append(
            {
                "type": "operational",
                "description": "Review and deploy updated detection content for extracted IOCs.",
            }
        )

    return {
        "recommended_actions": rec_actions,
        "mitigation_snippets": mitigation_snippets,
        "mitigations": out_items,
    }


def generate_actionable_summary(intel: dict) -> str:
    items = generate_actionable_items(intel)
    if not items:
        return ""
    items_list: list = []
    if isinstance(items, dict):
        items_list = items.get("mitigations") or []
        if not items_list and items.get("recommended_actions"):
            items_list = [
                {"type": "operational", "description": a}
                for a in items.get("recommended_actions")
            ]
    elif isinstance(items, list):
        items_list = items

    parts = []
    for it in items_list:
        try:
            if isinstance(it, dict) and it.get("type") == "mitigation":
                parts.append(
                    f"Mitigation {it.get('id')} for technique {it.get('technique')}: {it.get('description')}"
                )
            elif isinstance(it, dict) and it.get("type") == "operational":
                parts.append(str(it.get("description")))
            elif isinstance(it, str):
                parts.append(it)
        except Exception:
            continue
    return " ".join(parts)


# =========================
# == Scoring & Priority ===
# =========================
def compute_relevance_score(intel: dict) -> dict:
    tcount = len((intel.get("threat") or {}).get("technique", []) or [])
    acount = len((intel.get("threat") or {}).get("actor", []) or [])
    ioc_count = len(intel.get("iocs", []))
    score = int(min(100, (tcount * 25) + (acount * 20) + min(ioc_count, 10) * 2))
    try:
        boost = 0
        fin_boost = CONFIG.get("FIN_ORG_RELEVANCE_BOOST", 20)
        high_domains = CONFIG.get("HIGH_RELEVANCE_DOMAINS", []) or []
        sectors = (intel.get("threat") or {}).get("target", {}).get("sector", []) or []
        for s in sectors:
            sl = s.lower()
            for key, val in SECTOR_RELEVANCE_BOOSTS.items():
                if key in sl:
                    boost += val
        src = intel.get("source") or ""
        try:
            parsed = urlparse(src)
            host = (parsed.netloc or "").lower()
        except Exception:
            host = ""
        if host:
            for hd in high_domains:
                if hd.lower() in host:
                    boost += 10
        if intel.get("related_cves"):
            boost += 10
        title = (intel.get("title") or "").lower()
        desc = " ".join(
            str(intel.get(f) or "") for f in ("summary_text", "summary", "description")
        ).lower()
        txt = f"{title} {desc}"
        for key, val in TEXT_RELEVANCE_BOOSTS.items():
            if key in txt:
                boost += val
        score = int(min(100, score + boost))
    except Exception:
        pass
    label = _score_to_label(score)
    intel.setdefault("threat", {})
    intel["threat"]["relevance"] = {"score": score, "label": label}
    return intel


def _ensure_technique_list(threat: dict) -> list:
    tech = threat.get("technique")
    if tech is None:
        threat["technique"] = []
    elif isinstance(tech, list):
        pass
    elif isinstance(tech, dict):
        threat["technique"] = [tech]
    else:
        threat["technique"] = [{"name": [tech]}]
    return threat.get("technique", [])


def _add_technique_if_missing(
    threat: dict,
    *,
    tid: str,
    name: str | None = None,
    tactic: str | None = None,
    confidence: float | None = None,
    reason: str | None = None,
    source: str | None = None,
):
    tech_list = _ensure_technique_list(threat)
    tid_up = (tid or "").upper()
    for t in tech_list:
        if isinstance(t, dict) and (t.get("id") or t.get("technique_id")):
            if str(t.get("id") or t.get("technique_id")).upper() == tid_up:
                return
    entry = {"id": tid_up}
    if name:
        entry["name"] = name
    if tactic:
        entry["tactic"] = tactic
    if confidence is not None:
        entry["confidence"] = confidence
    if reason:
        entry["reason"] = reason
    if source:
        entry["source"] = source
    tech_list.append(entry)
    threat["technique"] = tech_list


def build_campaign_summary(text: str) -> str:
    if not text:
        return ""
    txt_low = text.lower()
    parts = []
    if "zip" in txt_low or "archive" in txt_low:
        parts.append("Spear-phishing delivers a malicious ZIP archive.")
    if "lnk" in txt_low or ".lnk" in txt_low:
        parts.append("Embedded LNK triggers execution of a pseudo-polyglot loader.")
    if "dll" in txt_low or "sideload" in txt_low:
        parts.append("Loader sideloads a DLL payload (e.g., LOTUSHARVEST).")
    if "browser" in txt_low and ("credential" in txt_low or "history" in txt_low):
        parts.append("Payload targets browser credentials and history.")
    if (
        "exfiltrat" in txt_low
        or "attacker controlled" in txt_low
        or "pipedream.net" in txt_low
    ):
        parts.append(
            "Stolen data is exfiltrated to attacker-controlled infrastructure."
        )
    return " ".join(parts)


def _normalize_record_input(
    parsed_record: dict | str, source: str | None, title: str | None
) -> tuple[dict, str]:
    if isinstance(parsed_record, str):
        parsed_record = {"text": parsed_record}
        if source:
            parsed_record["source"] = source
        if title:
            parsed_record["title"] = title
    text_parts = []
    for f in ("title", "summary_text", "summary", "text", "full_text", "description"):
        v = parsed_record.get(f)
        if v:
            text_parts.append(str(v))
    aggregate_text = "\n".join(text_parts) if text_parts else ""
    return parsed_record, aggregate_text


def _is_nav_placeholder(text: str, title: str | None) -> bool:
    if title and str(title).strip():
        return False
    lower = (text or "").strip().lower()
    if not lower:
        return False
    nav_prefixes = ("nav", "menu", "navigation")
    if not lower.startswith(nav_prefixes):
        return False
    tokens = [t for t in re.findall(r"[a-z0-9]+", lower)]
    tokens = [t for t in tokens if t not in {"nav", "menu", "navigation", "item", "link"}]
    return len(tokens) == 1 and tokens[0] == "phishing"


def _collect_pattern_hits(aggregate_text: str) -> Dict[str, set]:
    found: Dict[str, set] = defaultdict(set)
    compiled = load_compiled_patterns()
    for key, patterns in compiled.items():
        for pat in patterns:
            regex = pat.get("regex")
            if not regex:
                continue
            try:
                for m in regex.finditer(aggregate_text):
                    val = m.group(0).strip()
                    if not val:
                        continue
                    if key == "cve":
                        found["cve"].add(val.upper())
                    elif key == "ip":
                        found["ip"].add(val)
                    elif key == "domain":
                        found["domain"].add(val.lower())
                    elif key == "hash":
                        found["hash"].add(val.lower())
                    elif key == "email":
                        found["email"].add(val.lower())
                    elif key == "technique":
                        found["technique"].add(val.upper())
                    elif key in ("threats", "threat"):
                        found.setdefault("threat_label", set()).add(val)
                    elif key == "actor":
                        found["actor"].add(val)
            except re.error:
                continue
    return found


def _apply_pattern_hits(found: Dict[str, set], parsed_record: dict) -> None:
    iocs = []
    for k in ("ip", "domain", "hash", "email"):
        for v in sorted(found.get(k, [])):
            iocs.append({"type": k, "indicator": v})
    if iocs:
        parsed_record["iocs"] = iocs

    techniques = [{"id": tid} for tid in sorted(found.get("technique", []))]
    actors = [{"name": a} for a in sorted(found.get("actor", []))]

    if found.get("threat_label"):
        th = parsed_record.setdefault("threat", {})
        th.setdefault("labels", [])
        for lbl in sorted(found.get("threat_label", [])):
            if lbl not in th["labels"]:
                th["labels"].append(lbl)

    if techniques or actors:
        th = parsed_record.setdefault("threat", {})
        if techniques:
            th.setdefault("technique", [])
            th["technique"].extend(techniques)
        if actors:
            th.setdefault("actor", [])
            th["actor"].extend(actors)


def _maybe_classify_from_text(aggregate_text: str, parsed_record: dict) -> None:
    if not aggregate_text:
        return
    if _is_nav_placeholder(aggregate_text, parsed_record.get("title")):
        return
    words = [w.lower() for w in re.findall(r"\w+", aggregate_text)]
    min_repeat = int(CONFIG.get("MIN_REPEAT_FOR_SHORT_MATCH", 2))
    repeated_label = None
    try:
        from collections import Counter

        counts = Counter(words)
        for w, c in counts.items():
            if c >= min_repeat and len(w) > 3:
                if any(w.startswith(prefix) for prefix in ("nav", "menu", "link", "item")):
                    continue
                repeated_label = w
                break
    except Exception:
        repeated_label = None

    th = parsed_record.setdefault("threat", {})
    tech = th.setdefault("technique", {})

    def _attach_label(lbl: str) -> None:
        if isinstance(tech, dict):
            names = tech.get("name") or []
            if isinstance(names, list):
                if lbl not in names:
                    names.append(lbl)
                tech["name"] = names
            elif isinstance(names, str):
                tech["name"] = [names] if names == lbl else [names, lbl]
        elif isinstance(tech, list):
            if lbl not in tech:
                tech.append(lbl)
        else:
            th["technique"] = {"name": [lbl]}

    if repeated_label:
        label = classify_threat(repeated_label)
        if label and label != "Unknown":
            _attach_label(label)
            return

    min_words = CONFIG.get("MIN_WORDS_FOR_CLASSIFY", 6)
    if len(words) >= min_words:
        label = classify_threat(aggregate_text)
        if label and label != "Unknown":
            _attach_label(label)


def _apply_phrase_map_to_record(aggregate_text: str, parsed_record: dict) -> None:
    try:
        phrase_map = load_mitre_phrase_map() or {}
    except Exception:
        phrase_map = {}
    if not (phrase_map and aggregate_text):
        return
    skip_terms = CONFIG.get("MITRE_PHRASE_SKIP_TERMS") or set()
    min_len = CONFIG.get("MIN_MITRE_PHRASE_LEN", 4)
    txt = aggregate_text
    th = parsed_record.setdefault("threat", {})
    tech = th.get("technique")
    if isinstance(tech, list):
        pass
    elif isinstance(tech, dict):
        th["technique"] = [tech]
    else:
        th["technique"] = []
    for phrase, entries in phrase_map.items():
        try:
            if not entries:
                continue
            cleaned = str(phrase).strip().lower()
            if cleaned in skip_terms:
                continue
            if len(cleaned) < max(1, int(min_len)):
                continue
            if not re.search(r"(?i)\b" + re.escape(phrase) + r"\b", txt):
                continue
        except re.error:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("id") or entry.get("technique_id")
            name = entry.get("name")
            add = True
            tech_list = th.get("technique") or []
            for ex in tech_list:
                if isinstance(ex, dict):
                    if tid and str(ex.get("id", "")).upper() == str(tid).upper():
                        add = False
                        break
                    en = ex.get("name")
                    if isinstance(en, list) and name in en:
                        add = False
                        break
                    if isinstance(en, str) and name and en == name:
                        add = False
                        break
                elif isinstance(ex, str) and name and ex == name:
                    add = False
                    break
            if not add:
                continue
            item: dict = {}
            if tid:
                item["id"] = str(tid).upper()
            if name:
                item["name"] = name
            tech_list.append(item)
            th["technique"] = tech_list


def _expand_mitre_by_name(parsed_record: dict) -> None:
    th = parsed_record.setdefault("threat", {})
    techs = th.get("technique") or []
    if isinstance(techs, list):
        tech_list = techs
    elif isinstance(techs, dict):
        tech_list = [techs]
    else:
        tech_list = []

    try:
        mitre_map = load_mitre_map() or {}
    except Exception:
        mitre_map = {}
    name_index = {}
    entries_iter = mitre_map.items() if isinstance(mitre_map, dict) else []
    for mid, entry in entries_iter:
        try:
            name = (entry.get("name") or "").strip()
            if not name:
                continue
            key = name.lower()
            name_index.setdefault(key, []).append(entry)
        except Exception:
            continue

    keyword_index = {}
    heuristics = [
        "phish",
        "ransom",
        "xss",
        "cross-site",
        "sql",
        "injection",
        "privilege",
        "exfil",
        "ddos",
        "botnet",
        "remote code",
        "rce",
        "malware",
        "credential",
    ]
    try:
        for mid, entry in entries_iter:
            ename = (entry.get("name") or "").lower()
            for k in heuristics:
                if k in ename:
                    keyword_index.setdefault(k, []).append(entry)
    except Exception:
        pass

    heuristic_label_map = {"phishing": "T1566", "ransomware": "T1486"}

    for t in tech_list:
        try:
            if isinstance(t, dict):
                if t.get("id"):
                    continue
                names = t.get("name") or []
                if isinstance(names, str):
                    names = [names]
            elif isinstance(t, str):
                names = [t]
            else:
                names = []

            for nm in names:
                if not nm:
                    continue
                key = str(nm).strip().lower()
                entries = name_index.get(key) or []

                try:
                    if not entries:
                        pm = load_mitre_phrase_map() or {}
                        entries = pm.get(key) or []
                except Exception:
                    pass

                if not entries:
                    for hk in keyword_index:
                        if hk in key or hk in str(nm).lower():
                            entries = keyword_index.get(hk) or []
                            if entries:
                                break
                for e in entries:
                    tid = e.get("id") or e.get("technique_id") or None
                    if not tid:
                        continue
                    exists = False
                    for ex in tech_list:
                        if (
                            isinstance(ex, dict)
                            and ex.get("id")
                            and ex.get("id").upper() == str(tid).upper()
                        ):
                            exists = True
                            break
                    if exists:
                        continue
                    tech_list.append(
                        {
                            "id": str(tid).upper(),
                            "name": e.get("name"),
                            "inferred": True,
                            "source": "inferred_by_name",
                        }
                    )

            if not entries:
                try:
                    lname = str(nm).strip().lower()
                    hid = heuristic_label_map.get(lname)
                    if hid:
                        exists = any(
                            isinstance(ex, dict)
                            and ex.get("id")
                            and ex.get("id").upper() == hid
                            for ex in tech_list
                        )
                        if not exists:
                            mm = (
                                mitre_map.get(hid.upper())
                                if isinstance(mitre_map, dict)
                                else None
                            )
                            tech_list.append(
                                {
                                    "id": hid.upper(),
                                    "name": mm.get("name") if mm else nm,
                                    "inferred": True,
                                    "source": "heuristic_label",
                                }
                            )
                except Exception:
                    pass
        except Exception:
            continue

    if isinstance(techs, list):
        th["technique"] = tech_list


def _ensure_technique_names(th: dict) -> None:
    tech = th.get("technique")
    if tech is None:
        th["technique"] = {"name": []}
    elif isinstance(tech, list):
        names: list[str] = []
        for t in tech:
            if isinstance(t, dict):
                if isinstance(t.get("name"), list):
                    names.extend(t.get("name") or [])
                elif t.get("id"):
                    names.append(t.get("id"))
            elif isinstance(t, str):
                names.append(t)
        th["technique"] = {"name": names}
    elif isinstance(tech, dict):
        if "name" not in tech:
            tech["name"] = []


def build_keyword_summary(
    text: str, keywords: list[str], max_sentences: int = 3
) -> str:
    if not text or not keywords:
        return ""
    txt = re.sub(r"\s+", " ", text).strip()
    sents = re.split(r"(?<=[\.!?])\s+", txt)
    sents = [s.strip() for s in sents if s.strip()]
    kw = [k.lower() for k in keywords]
    chosen = []
    for s in sents:
        low = s.lower()
        if any(k in low for k in kw):
            chosen.append(s)
        if len(chosen) >= max_sentences:
            break
    return " ".join(chosen)


def _prune_placeholder_techniques(threat: dict) -> dict:
    """
    Drop placeholder entries like {'name': ['Other']} when there are real technique IDs present.
    """
    tech_list = _ensure_technique_list(threat)
    has_ids = any(
        isinstance(t, dict) and (t.get("id") or t.get("technique_id"))
        for t in tech_list
    )
    if not has_ids:
        return threat
    filtered = []
    for t in tech_list:
        if isinstance(t, dict):
            names = t.get("name")
            if (
                names
                and isinstance(names, list)
                and len(names) == 1
                and names[0].lower() == "other"
            ):
                continue
            if names and isinstance(names, str) and names.lower() == "other":
                continue
        filtered.append(t)
    threat["technique"] = filtered
    return threat


def _normalize_mitre_techniques(threat: dict) -> dict:
    tech_list = _ensure_technique_list(threat)
    mitre_map = load_mitre_map() or {}
    valid_ids = {k.upper(): v for k, v in mitre_map.items() if k}
    name_index = {}
    for tid, entry in mitre_map.items():
        try:
            nm = (entry.get("name") or "").strip().lower()
            if nm and tid:
                name_index[nm] = tid
        except Exception:
            continue
    normalized = []
    seen_ids = set()
    for t in tech_list:
        if isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id")
            names = t.get("name")
            name_val = None
            if isinstance(names, list) and names:
                name_val = str(names[0])
            elif isinstance(names, str):
                name_val = names
            if tid:
                tid_up = str(tid).upper()
                if tid_up not in valid_ids or tid_up in seen_ids:
                    continue
                seen_ids.add(tid_up)
                base = {"id": tid_up}
                if not name_val:
                    name_val = (valid_ids.get(tid_up) or {}).get("name")
                if name_val:
                    base["name"] = name_val
                merged = dict(t)
                merged.update(base)
                normalized.append(merged)
            elif name_val:
                nm_l = name_val.strip().lower()
                guessed_id = name_index.get(nm_l)
                if not guessed_id:
                    continue
                gid = guessed_id.upper()
                if gid in seen_ids:
                    continue
                seen_ids.add(gid)
                base = {
                    "id": gid,
                    "name": mitre_map.get(gid, {}).get("name") or name_val,
                }
                merged = dict(t)
                merged.update(base)
                normalized.append(merged)
        elif isinstance(t, str):
            nm = t.strip().lower()
            guessed_id = name_index.get(nm)
            if not guessed_id:
                continue
            gid = guessed_id.upper()
            if gid in seen_ids:
                continue
            seen_ids.add(gid)
            normalized.append(
                {"id": gid, "name": mitre_map.get(gid, {}).get("name") or t}
            )
    threat["technique"] = normalized
    return threat


# =========================
# === Campaign Heuristics =
# =========================
def enrich_campaign_heuristics(intel: dict, text: str) -> dict:
    """
    Add lightweight, rule-based enrichment (MITRE techniques, iocs, priority, detections)
    for campaign-style articles without using an LLM.
    """
    if not text:
        return intel
    txt_low = text.lower()
    title_low = (intel.get("title") or "").lower()
    core_txt = txt_low.split(RELATED_ARTICLES_MARKER)[0]
    th = intel.setdefault("threat", {})
    _ensure_technique_list(th)

    heuristics = [
        {
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "confidence": 0.9,
            "reason": "Text references spear-phishing with attachments/archives.",
            "keywords": [
                "spear-phish",
                "spear phishing",
                "spear-phishing",
                "malicious zip",
                "resume",
                "attachment",
            ],
        },
        {
            "id": "T1574.002",
            "name": "DLL Side-Loading",
            "tactic": "Execution",
            "confidence": 0.8,
            "reason": "Text references DLL side-loading or pseudo-polyglot loader.",
            "keywords": [
                "dll side",
                "side-load",
                "pseudo-polyglot",
                "dll-based",
                "sideload",
            ],
        },
        {
            "id": "T1555.003",
            "name": "Credentials from Web Browsers",
            "tactic": "Credential Access",
            "confidence": 0.9,
            "reason": "Text references stealing browser credentials or history.",
            "keywords": [
                "browser credential",
                "steal cookies",
                "browser history",
                "steal browser",
                "chrome profile",
            ],
        },
        {
            "id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "confidence": 0.8,
            "reason": "Text references exfiltrating data to attacker server/C2.",
            "keywords": [
                "exfiltrat",
                "c2",
                "command and control",
                "send to server",
                "attacker-controlled server",
            ],
        },
    ]

    for h in heuristics:
        if any(kw in txt_low for kw in h["keywords"]):
            _add_technique_if_missing(
                th,
                tid=h["id"],
                name=h["name"],
                tactic=h["tactic"],
                confidence=h["confidence"],
                reason=h["reason"],
                source="heuristic_phrase",
            )

    iocs = intel.setdefault("iocs", [])
    seen = {
        (i.get("type"), (i.get("indicator") or i.get("value") or "").lower())
        for i in iocs
        if isinstance(i, dict)
    }
    fname_re = re.compile(
        r"[A-Za-z0-9][A-Za-z0-9 _.\-]{2,}\.(?:zip|rar|7z|lnk|dll|exe|iso|scr|pdf|png)",
        re.I,
    )
    for m in fname_re.finditer(text):
        raw = m.group(0).strip()
        if len(raw) > 80 or raw.count(" ") > 2:
            continue
        val = re.sub(r"\s+", "-", raw)
        key = ("filename", val.lower())
        if key in seen:
            continue
        seen.add(key)
        ctx = _get_excerpt(text, m.start())
        iocs.append(
            {
                "type": "filename",
                "indicator": val,
                "value": val,
                "context": ctx,
                "confidence": 0.9,
            }
        )

    malware_re = re.compile(r"\b[A-Z][A-Z0-9_-]{5,}\b")
    malware_ignore = {
        "HTTP",
        "HTTPS",
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "CVE",
        "SQL",
        "JSON",
        "HTML",
        "DLL",
        "EXE",
        "PDF",
        "ZIP",
        "FACEBOOK",
        "GOOGLE",
        "TWITTER",
        "LINKEDIN",
        "SEQRITE",
        "LOADER",
        "NEWS",
    }
    for m in malware_re.finditer(text):
        val = m.group(0)
        if val in malware_ignore:
            continue
        key = ("malware", val.lower())
        if key in seen:
            continue
        seen.add(key)
        ctx = _get_excerpt(text, m.start())
        iocs.append(
            {
                "type": "malware",
                "indicator": val,
                "value": val,
                "context": ctx,
                "confidence": 0.9,
            }
        )
    intel["iocs"] = iocs

    detections = intel.setdefault("detections", [])
    recs = intel.setdefault("recommendations", [])
    tech_ids = [t.get("id") for t in th.get("technique") or [] if isinstance(t, dict)]
    if "T1566.001" in tech_ids:
        detections.append(
            {
                "name": "Suspicious attachment execution",
                "type": "Endpoint",
                "idea": "Alert when attachments from email/archives spawn scripts, shortcuts, or loaders.",
            }
        )
        recs.append(
            {
                "type": "Process",
                "text": "Educate users to avoid opening unsolicited archives or shortcuts from email.",
            }
        )
    if "T1574.002" in tech_ids:
        detections.append(
            {
                "name": "DLL side-loading from user space",
                "type": "Endpoint",
                "idea": "Detect unsigned DLL loads from user-writable paths following archive extraction.",
            }
        )
        recs.append(
            {
                "type": "Technical",
                "text": "Block or restrict DLL loads from temp/download directories and enforce signature checks.",
            }
        )
    if "T1555.003" in tech_ids:
        detections.append(
            {
                "name": "Browser credential access by non-browser process",
                "type": "Endpoint",
                "idea": "Alert when non-browser processes access browser credential stores or history DBs.",
            }
        )
        recs.append(
            {
                "type": "Technical",
                "text": "Harden browser credential stores and monitor file/registry access from non-browser processes.",
            }
        )
    if "T1041" in tech_ids:
        detections.append(
            {
                "name": "Outbound C2-style exfiltration",
                "type": "Network",
                "idea": "Monitor unusual outbound connections carrying archive/data payloads after credential access.",
            }
        )
        recs.append(
            {
                "type": "Technical",
                "text": "Apply egress controls and DLP for browser credential files and history databases.",
            }
        )

    reasons = []
    rel_score = ((intel.get("threat") or {}).get("relevance") or {}).get("score") or 30
    base = min(rel_score, 35)
    score = base
    if "T1566.001" in tech_ids:
        score += 15
        reasons.append("spear-phishing attachment noted (+15)")
    if "T1555.003" in tech_ids:
        score += 20
        reasons.append("browser credential theft noted (+20)")
    if "T1041" in tech_ids:
        score += 10
        reasons.append("data exfiltration noted (+10)")
    if intel.get("iocs"):
        score += 3
        reasons.append("IOCs extracted (+3)")
    score = int(min(100, score))
    intel["priority"] = {
        "score": score,
        "label": _score_to_label(score),
        "reason": "; ".join(reasons)
        or "Derived from relevance and detected techniques.",
    }

    fin_score = 30
    fin_reasons = []
    fin_terms = [
        "bank",
        "financial",
        "payment",
        "swift",
        "atm",
        "fraud",
        "wire transfer",
    ]
    if any(t in txt_low for t in fin_terms):
        fin_score += 40
        fin_reasons.append("Financial-sector terminology present (+40)")
    if "T1555.003" in tech_ids:
        fin_score += 25
        fin_reasons.append("Credential theft could impact accounts (+25)")
    fin_score = max(0, min(100, fin_score))
    intel["financial_relevance"] = {
        "score": fin_score,
        "label": _score_to_label(
            fin_score, low="Low", medium="Medium", high="High", critical="Critical"
        ),
        "reason": "; ".join(fin_reasons)
        or "Default low/medium relevance (no explicit financial indicators).",
    }

    countries = intel.setdefault("countries", [])
    if "vietnam" in txt_low:
        countries.append({"name": "Vietnam", "role": "Target", "confidence": 0.7})
    intel["countries"] = countries

    if not (th.get("actor") or []):
        th["actor"] = [
            {
                "name": "Unknown",
                "type": "Cybercrime",
                "role": "Mentioned",
                "confidence": 0.3,
            }
        ]

    src = intel.get("source") or ""
    trust = "Medium"
    if src:
        try:
            host = urlparse(src).netloc.lower()
        except Exception:
            host = ""
        if host:
            intel["source_analysis"] = {
                "source_name": host,
                "source_url": src,
                "trust_level": trust,
                "reason": "Automated heuristic; no primary research validation.",
            }

    summary = intel.get("summary_text") or ""
    low_summary = summary.strip().lower()
    if (
        (not summary)
        or low_summary.startswith("iocs")
        or low_summary.startswith("topics")
        or low_summary.startswith("share")
    ):
        built = build_campaign_summary(text)
        if built:
            intel["summary_text"] = built
    core_focus = core_txt[:CORE_FOCUS_LIMIT]
    apim_hit = (
        ("azure api management" in title_low)
        or (
            ("azure" in core_focus)
            and (
                "api management" in core_focus
                or (" apim " in f" {core_focus} ")
            )
        )
    )
    if apim_hit:
        _add_technique_if_missing(
            th,
            tid="T1068",
            name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation",
            confidence=0.9,
            reason="Reader-level abuse of legacy ARM API to gain admin control.",
            source="azure_apim_heuristic",
        )
        _add_technique_if_missing(
            th,
            tid="T1552",
            name="Unsecured Credentials",
            tactic="Credential Access",
            confidence=0.8,
            reason="Subscription keys/SSO token dumping from APIM.",
            source="azure_apim_heuristic",
        )
        _add_technique_if_missing(
            th,
            tid="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            confidence=0.6,
            reason="Abuse of public ARM endpoints/legacy API versions.",
            source="azure_apim_heuristic",
        )
        tgt = th.setdefault("target", {})
        tgt.setdefault("vendor", [])
        if "Microsoft" not in tgt["vendor"]:
            tgt["vendor"].append("Microsoft")
        tgt.setdefault("product", [])
        if "Azure API Management" not in tgt["product"]:
            tgt["product"].append("Azure API Management")
        th["target"] = tgt
        if (not intel.get("summary_text")) or intel.get(
            "summary_text", ""
        ).lower().startswith("related"):
            ks = [
                "azure api management",
                "apim",
                "subscription key",
                "reader",
                "arm api",
                "disable old api versions",
            ]
            kws = build_keyword_summary(text, ks, max_sentences=3)
            if kws:
                intel["summary_text"] = kws
    npm_hit = any(p in core_focus for p in NPM_TRIGGER_PHRASES) or any(
        p in title_low for p in ("npm", "package")
    )
    if npm_hit:
        _add_technique_if_missing(
            th,
            tid="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            confidence=0.6,
            reason="Supply-chain compromise via malicious npm package installation.",
            source="npm_supply_chain",
        )
        _add_technique_if_missing(
            th,
            tid="T1059",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            confidence=0.7,
            reason="Postinstall scripts in npm package execute JavaScript on install.",
            source="npm_supply_chain",
        )
        _add_technique_if_missing(
            th,
            tid="T1547",
            name="Boot or Logon Autostart Execution",
            tactic="Persistence",
            confidence=0.5,
            reason="Install-time hooks may establish persistence or autorun behavior.",
            source="npm_supply_chain",
        )
        pkg_match = None
        try:
            backtick = re.search(r"`([^`]+)`", core_focus)
            if backtick:
                raw_pkg = backtick.group(1).strip().strip(".")
                if raw_pkg and len(raw_pkg) > 3:
                    pkg_match = re.sub(r"\s+", "-", raw_pkg.lower())
            if not pkg_match:
                generic = re.search(
                    r"(?:npm package|package (?:in question )?is)\s+([a-z0-9._\-\s]+)",
                    core_focus,
                )
                raw_pkg = generic.group(1).strip().strip(".") if generic else None
                if raw_pkg and len(raw_pkg) > 3:
                    pkg_match = re.sub(r"\s+", "-", raw_pkg.lower())
        except Exception:
            pkg_match = None
        if pkg_match:
            iocs = intel.setdefault("iocs", [])
            already = {
                (ioc.get("type"), (ioc.get("indicator") or ioc.get("value")))
                for ioc in iocs
                if isinstance(ioc, dict)
            }
            key = ("software_package", pkg_match)
            if key not in already:
                iocs.append(
                    {
                        "type": "software_package",
                        "indicator": pkg_match,
                        "context": "Malicious npm package distributing hidden scripts",
                        "confidence": 0.9,
                    }
                )
            intel["iocs"] = iocs
        # add simple detections/recommendations for npm supply chain
        try:
            dets = intel.setdefault("detections", [])
            dets.append(
                {
                    "name": "Suspicious npm package install with postinstall hook",
                    "type": "Endpoint / DevEnvironment",
                    "idea": "Alert on npm installs of packages with postinstall scripts or typosquatted names; monitor outbound exfiltration during install.",
                }
            )
            recs = intel.setdefault("recommendations", [])
            recs.append(
                {
                    "type": "Technical",
                    "text": "Lock dependencies and disallow unknown npm packages with postinstall hooks; vet typosquats before use.",
                }
            )
        except Exception:
            pass
        if not intel.get("summary_text"):
            ks = [
                "npm package",
                "postinstall",
                "typosquatting",
                "exfiltrate",
                "environment variables",
                "hidden prompt",
            ]
            kws = build_keyword_summary(text, ks, max_sentences=3)
            if pkg_match:
                intel["summary_text"] = (
                    f"Malicious npm package {pkg_match} uses postinstall/hidden scripts "
                    "to steal environment variables and exfiltrate data."
                )
            elif kws:
                intel["summary_text"] = kws
    return intel


def _score_to_label(
    score: int,
    *,
    low: str = "Low",
    medium: str = "Medium",
    high: str = "High",
    critical: str = "Critical",
) -> str:
    try:
        s = int(score)
    except Exception:
        s = 0
    if s >= 80:
        return critical
    if s >= 60:
        return high
    if s >= 30:
        return medium
    return low


def _dehyphenate_text(text: str) -> str:
    if not text:
        return ""
    t = text
    t = re.sub(r"(\w)\s*-\s*\n\s*(\w)", r"\1\2", t)
    t = re.sub(r"(\w)\s*-\s*(\w)", r"\1 \2", t)
    t = re.sub(r"\s+([,.;:!?%])", r"\1", t)
    t = re.sub(r"\s+([’'])\s*", r"\1", t)
    t = t.replace("\n", " ")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def save_full_text(text: str, filename: str) -> str:
    if not text:
        return ""
    out_dir = os.path.join(CONFIG.get("OUTPUT_DIR_UNSTRUCTURED", "."), "pdf_text")
    os.makedirs(out_dir, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    path = os.path.join(out_dir, f"extracted_{safe_name}.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        logger.warning(f"Failed to write extracted text to {path}")
    return path


def _make_id(prefix: str, title: str | None) -> str:
    base = _norm_key(title) if title else ""
    if not base:
        base = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{base}"


def extract_text_pdftotext(pdf_path: str, *, max_pages: int | None = None) -> str:
    if not HAS_PYMUPDF:
        logger.warning(
            "PyMuPDF (fitz) not available; cannot extract PDF text for %s", pdf_path
        )
        return ""
    try:
        doc = fitz.open(pdf_path)
        pages: list[str] = []
        pdf_max_pages = (
            max_pages if max_pages is not None else CONFIG.get("PDF_MAX_PAGES", 50)
        )
        for i, page in enumerate(doc):
            if pdf_max_pages and i >= pdf_max_pages:
                break
            try:
                text = page.get_text("text") or ""
            except Exception:
                try:
                    text = page.get_text() or ""
                except Exception:
                    text = ""
            pages.append(text)
        try:
            doc.close()
        except Exception:
            pass
        text = "\n".join(pages)
        text = _dehyphenate_text(text)
        return text
    except Exception as exc:
        logger.warning("PyMuPDF extraction failed for %s: %s", pdf_path, exc)
        return ""


def extract_top_findings(
    text: str, max_items: int = 5, k: int | None = None
) -> list[str]:
    if k is not None:
        max_items = k
    lines = [ln.strip() for ln in text.splitlines()]
    findings: list[str] = []
    bullet_re = BULLET_FINDING_RE
    for ln in lines:
        if not ln:
            continue
        if bullet_re.search(ln):
            findings.append(ln)
        if len(findings) >= max_items:
            break

    if not findings:
        paras = re.split(r"\n\s*\n+", text)
        for p in paras:
            p = p.strip()
            if not p:
                continue
            words = re.findall(r"\w+", p)
            min_words = CONFIG.get("TOP_FINDING_MIN_WORDS", 10)
            max_words = CONFIG.get("TOP_FINDING_MAX_WORDS", 80)
            if min_words <= len(words) <= max_words:
                findings.append(p)
            if len(findings) >= max_items:
                break
    return findings


def sanitize_article_text(text: str) -> str:
    if not text:
        return ""
    txt = text

    if "<html" in txt.lower():
        txt = html_to_main_text(txt, strip_boilerplate=True)

    txt = re.sub(r"^\s*", "", txt)
    txt = re.sub(r"\s+$", "", txt)
    txt = re.sub(r"[ \t]+\n", "\n", txt)
    txt = re.sub(r"\n{3,}", "\n\n", txt)

    lines = []
    promo_patterns = PROMO_PATTERNS or [
        re.compile(p, re.I)
        for p in [
            "^sign up for our newsletter",
            "^follow us on\\s+",
            "^related articles",
            "^sponsored content",
            "^about the author",
            "^share\\b",
            "^download now",
            "^topics acquisition",
            "^topics\\b",
        ]
    ]
    short_social_re = SHORT_SOCIAL_RE
    short_social_max = CONFIG.get("SHORT_SOCIAL_MAX_WORDS", 8)
    for p in re.split(r"\n{2,}", txt):
        if not p:
            continue
        s = p.strip()
        if not s:
            continue
        drop = False
        for pat in promo_patterns:
            try:
                if pat.search(s):
                    drop = True
                    break
            except Exception:
                continue
        if drop:
            continue

        if len(re.findall(r"\w+", s)) <= short_social_max and short_social_re.search(s):
            continue

        try:
            if re.match(
                r"^[A-Za-z0-9'\"\-]{1,20}(?:\s+[A-Za-z0-9'\"\-]{1,20}){9,}$", s
            ):
                continue
        except Exception:
            pass

        low = s.lower()
        if low.startswith("topics") or RELATED_ARTICLES_MARKER in low:
            continue

        lines.append(s)
    return "\n\n".join(lines)


def summarize_unstructured_description(text: str, max_sentences: int = 2) -> str:
    if not text:
        return ""

    try:
        sanitized = sanitize_article_text(text)
        text = sanitized or text
    except Exception:
        pass

    txt = re.sub(r"\s+", " ", text).strip()

    sents = re.split(r"(?<=[\.!?])\s+", txt)
    sents = [s.strip() for s in sents if s.strip()]
    banned_prefixes = [
        "topics",
        "tags",
        "follow us",
        "recent news",
        "hot this week",
    ]
    filtered = [
        s for s in sents if not any(s.lower().startswith(bp) for bp in banned_prefixes)
    ]
    if filtered:
        sents = filtered
    if not sents:
        words = txt.split()
        if words:
            return " ".join(words[: min(80, len(words))])
        return ""

    cve_re = CVE_RX
    vendor_keywords = CONFIG.get("VENDOR_KEYWORDS", []) or []
    attack_terms = [
        "ransomware",
        "remote code execution",
        "rce",
        "privilege escalation",
        "sql injection",
        "cross-site scripting",
        "xss",
        "zero-day",
        "zero day",
        "exploit",
        "malware",
        "botnet",
        "phishing",
        "spear-phish",
        "spear phishing",
        "campaign",
        "zip file",
        "lnk",
        "dll",
        "credential",
        "exfiltration",
        "browser",
    ]
    vendors_lower = [v.lower() for v in vendor_keywords]
    key_terms = [t.lower() for t in attack_terms]
    sector_keywords = ["bank", "financial", "fintech", "payment", "atm", "swift"]

    scored: list[tuple[int, str]] = []
    for s in sents:
        lower = s.lower()
        score = 0
        if cve_re.search(s):
            score += 40
        for v in vendors_lower:
            if v and v in lower:
                score += 40
        for sec in sector_keywords:
            if sec in lower:
                score += 25
        for kt in key_terms:
            if kt in lower:
                score += 12
        length_bonus = min(20, max(0, (len(s) - 80) // 10))
        score += length_bonus
        if len(re.findall(r"\w+", s)) < 6:
            score -= 10
        scored.append((score, s))

    scored.sort(key=lambda x: (x[0], len(x[1])), reverse=True)

    chosen: list[str] = []
    seen_norm: set[str] = set()
    for sc, s in scored:
        if len(chosen) >= max_sentences:
            break
        norm = re.sub(r"\W+", " ", s.lower()).strip()[:120]
        if not norm or norm in seen_norm:
            continue
        seen_norm.add(norm)
        chosen.append(s)

    if not chosen:
        chosen = sents[:max_sentences]

    summary = " ".join(chosen)
    if len(summary) > 500:
        summary = summary[:497].rstrip() + "..."
    return summary


def group_threat_items_by_vendor_or_sector(items: list[dict]) -> dict:
    by_vendor: dict[str, list[dict]] = {}
    by_sector: dict[str, list[dict]] = {}
    other: list[dict] = []
    for rec in items:
        th = rec.get("threat") or {}
        vendors = th.get("target", {}).get("vendor", []) or []
        sectors = th.get("target", {}).get("sector", []) or []
        if not vendors and not sectors:
            try:
                enriched = infer_missing_vendor_and_actor(dict(rec))
                th = enriched.get("threat") or {}
                vendors = th.get("target", {}).get("vendor", []) or []
                sectors = th.get("target", {}).get("sector", []) or []
            except Exception:
                pass
        if not vendors:
            try:
                txt = " ".join(
                    [str(rec.get(k) or "") for k in ("title", "summary", "text")]
                ).lower()
                for v in CONFIG.get("VENDORS", []) or []:
                    if v and v.lower() in txt:
                        vendors = [v]
                        break
            except Exception:
                pass
        if not sectors:
            try:
                txt = " ".join(
                    [str(rec.get(k) or "") for k in ("title", "summary", "text")]
                ).lower()
                if "bank" in txt or "financial" in txt:
                    sectors = ["Financial"]
            except Exception:
                pass

        if vendors:
            for v in vendors:
                if not v:
                    continue
                by_vendor.setdefault(v, []).append(rec)
        if sectors:
            for s in sectors:
                if not s:
                    continue
                by_sector.setdefault(s, []).append(rec)
        if not vendors and not sectors:
            other.append(rec)

    return {"by_vendor": by_vendor, "by_sector": by_sector, "other": other}


def infer_missing_vendor_and_actor(intel: dict) -> dict:
    text_parts = []
    for f in ("title", "summary_text", "summary", "text", "full_text", "description"):
        v = intel.get(f)
        if v:
            text_parts.append(str(v))
    aggregate_text = "\n".join(text_parts)
    if not aggregate_text:
        return intel

    compiled = load_compiled_patterns()
    vendor_pats = compiled.get("vendor", [])
    actor_pats = compiled.get("actor", [])

    vendors_found: set[str] = set()
    actors_found: set[str] = set()
    for item in vendor_pats:
        reg = item.get("regex")
        if not reg:
            continue
        m = reg.search(aggregate_text)
        if not m:
            continue
        vendors_found.add(m.group(0).strip())
    for item in actor_pats:
        reg = item.get("regex")
        if not reg:
            continue
        m = reg.search(aggregate_text)
        if not m:
            continue
        actors_found.add(m.group(0).strip())

    if vendors_found or actors_found:
        th = intel.setdefault("threat", {})
        tgt = th.setdefault("target", {})
        if vendors_found:
            tgt.setdefault("vendor", [])
            for v in vendors_found:
                if v not in tgt["vendor"]:
                    tgt["vendor"].append(v)
        if actors_found:
            th.setdefault("actor", [])
            for a in actors_found:
                if a not in th["actor"]:
                    th["actor"].append(a)

    return intel


def generate_markdown_summary_section(items: list[dict], title: str) -> str:
    return ""


def dedupe_records_by_title(
    records: list[dict],
    *,
    key_field: str = "title",
    fuzzy_threshold: float | None = None,
) -> list[dict]:
    from difflib import SequenceMatcher

    kept: list[dict] = []
    kept_norm: list[str] = []
    for rec in records:
        title_raw = rec.get(key_field) or ""
        title = str(title_raw).strip().lower()
        ts = rec.get("@timestamp") or rec.get("timestamp") or ""
        if not title:
            kept.append(rec)
            kept_norm.append(title)
            continue

        found_idx = None
        if title in kept_norm:
            found_idx = kept_norm.index(title)
        elif fuzzy_threshold:
            for i, k in enumerate(kept_norm):
                try:
                    if not k:
                        continue
                    ratio = SequenceMatcher(None, title, k).ratio()
                    if ratio >= float(fuzzy_threshold):
                        found_idx = i
                        break
                except Exception:
                    continue

        if found_idx is not None:
            idx = found_idx
            existing = kept[idx]
            existing_ts = existing.get("@timestamp") or existing.get("timestamp") or ""

            primary = existing
            secondary = rec
            try:
                if ts and existing_ts and ts > existing_ts:
                    primary = rec
                    secondary = existing
            except Exception:
                pass

            src1 = primary.get("source") or primary.get("source_url") or None
            src2 = secondary.get("source") or secondary.get("source_url") or None
            sources = []
            if src1:
                sources.append(src1)
            if src2 and src2 not in sources:
                sources.append(src2)
            if sources:
                primary["sources"] = sources

            prov1 = primary.get("provenance") or []
            prov2 = secondary.get("provenance") or []
            merged_prov = []
            for p in prov1 or []:
                if p not in merged_prov:
                    merged_prov.append(p)
            for p in prov2 or []:
                if p not in merged_prov:
                    merged_prov.append(p)
            if merged_prov:
                primary["provenance"] = merged_prov

            def _iocs_key(i):
                try:
                    return (
                        (i.get("type") or "").lower(),
                        (i.get("indicator") or i.get("value") or "").lower(),
                    )
                except Exception:
                    return None

            iocs1 = primary.get("iocs") or []
            iocs2 = secondary.get("iocs") or []
            norm_map = {}
            for i in iocs1 or []:
                k = _iocs_key(i)
                if k:
                    norm_map[k] = i
            for i in iocs2 or []:
                k = _iocs_key(i)
                if k and k not in norm_map:
                    norm_map[k] = i
            if norm_map:
                primary["iocs"] = list(norm_map.values())

            kept[idx] = primary
            kept_norm[idx] = (primary.get(key_field) or "").strip().lower()
        else:
            kept.append(rec)
            kept_norm.append(title)
    return kept


def detect_provenance(rec: dict | str) -> dict:
    is_string_input = False
    if isinstance(rec, str):
        is_string_input = True
        rec = {"text": rec}
    text_parts = []
    for f in ("title", "summary_text", "summary", "text", "full_text", "description"):
        v = rec.get(f)
        if v:
            text_parts.append(str(v))
    aggregate = "\n".join(text_parts)
    if not aggregate:
        return rec

    lower = aggregate.lower()
    indicators = []
    prov_keywords = (
        CONFIG.get(
            "PROVENANCE_KEYWORDS", ["chatgpt", "openai", "bard", "gemini", "copilot"]
        )
        or []
    )
    for k in prov_keywords:
        if not k:
            continue
        kl = k.lower()
        if kl in lower:
            if kl == "copilot" and "github" in lower:
                indicators.append("Code derived from Copilot/GitHub")
            else:
                indicators.append(f"LLM-generated content ({k})")

    prov_out = []
    for m in re.finditer(r"https?://[\w\-./?&=%#]+", aggregate):
        url = m.group(0)
        prov_out.append(
            {
                "source_url": url,
                "excerpt": _get_excerpt(aggregate, m.start()),
                "confidence": 0.9,
            }
        )

    src_match = re.search(r"(?i)source:\s*([A-Za-z0-9 .,&-]+)", aggregate)
    if src_match:
        name = src_match.group(1).strip()
        prov_out.append(
            {
                "source_name": name,
                "excerpt": _get_excerpt(aggregate, src_match.start(1)),
                "confidence": 0.85,
            }
        )

    for k in indicators:
        prov_out.append({"note": k, "confidence": 0.5})

    if is_string_input:
        return prov_out

    if prov_out:
        rec.setdefault("provenance", prov_out)
    return rec


def strip_provenance(text: str) -> str:
    if not text:
        return ""
    out = text
    if PROVENANCE_STRIP_PATTERNS:
        for pat in PROVENANCE_STRIP_PATTERNS:
            try:
                out = pat.sub("", out)
            except Exception:
                continue
        return out.strip()

    patterns = [
        r"(?i)generated by chatgpt.*?$",
        r"(?i)powered by openai.*?$",
        r"(?i)created with bard.*?$",
        r"(?i)content generated by an ai.*?$",
    ]
    for pat in patterns:
        out = re.sub(pat, "", out, flags=re.MULTILINE)
    return out.strip()


def _get_excerpt(text: str, idx: int, radius: int | None = None) -> str:
    if not text:
        return ""
    if radius is None:
        radius = CONFIG.get("EXCERPT_RADIUS", 160)
    text_len = len(text)
    start = max(0, idx - radius)
    end = min(text_len, idx + radius)

    try:

        sent_re = re.compile(r".*?[\.\!?\n]+", re.S)
        sentences = list(sent_re.finditer(text))
        if sentences:
            for i, m in enumerate(sentences):
                if m.start() <= idx < m.end():

                    s_start = m.start()
                    s_end = m.end()

                    combined = text[s_start:s_end]

                    if i > 0 and len(combined) < 80:
                        prev = sentences[i - 1]
                        s_start = prev.start()
                        combined = text[s_start:s_end]

                    if i + 1 < len(sentences) and len(combined) < 120:
                        nxt = sentences[i + 1]
                        s_end = nxt.end()
                    snippet = text[s_start:s_end]
                    snippet = snippet.strip()
                    snippet = re.sub(r"\s+", " ", snippet)
                    return snippet
    except Exception:
        pass

    snippet = text[start:end]
    snippet = snippet.strip()
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet


def normalize_and_merge_iocs(intel, source: str | None = None, context_text: str | None = None):
    if isinstance(intel, str):
        raw = extract_iocs(intel, source=source)
        out = []
        for i in raw:
            typ = (i.get("type") or "").lower()
            val = i.get("value") or i.get("indicator") or ""
            if not val:
                continue
            out.append({"type": typ, "value": val})
        return out
    elif isinstance(intel, dict):
        intel_dict = intel
    else:
        return {"iocs": []}

    iocs = intel_dict.get("iocs", []) or []
    ctx_low = (context_text or "").lower()

    def in_context(val: str) -> bool:
        if not ctx_low or not val:
            return True
        return val.lower() in ctx_low

    def looks_like_version_ip(val: str) -> bool:
        try:
            parts = [int(p) for p in val.split(".")]
        except Exception:
            return False
        if len(parts) != 4:
            return False
        if all(p <= 10 for p in parts):
            if ctx_low:
                idx = ctx_low.find(val)
                if idx != -1:
                    window = ctx_low[max(0, idx - 24) : idx + len(val) + 24]
                    for kw in ("cve", "version", "v", "release", "build"):
                        if kw in window:
                            return True
            return True
        return False

    if not iocs:
        intel_dict["iocs"] = []
        return intel_dict

    normed: Dict[tuple, dict] = {}
    for i in iocs:
        if not isinstance(i, dict):
            continue
        t = (i.get("type") or i.get("ioc_type") or "").strip().lower()
        v = (i.get("indicator") or i.get("value") or i.get("ioc") or "").strip()
        if not t or not v:
            continue
        if not in_context(v):
            continue
        if t == "malware" and v.lower() in {"exclusive", "submit", "hackernews25"}:
            continue
        if t == "ip" and looks_like_version_ip(v):
            continue
        key = (t, v.lower())
        ctx = i.get("context") or i.get("excerpt") or ""
        confidence = i.get("confidence") or 0.75
        if key in normed:
            existing = normed[key]
            if ctx and ctx not in existing.get("context", ""):
                existing["context"] = (existing.get("context", "") + " | " + ctx).strip(
                    " |"
                )
            existing["confidence"] = max(existing.get("confidence", 0.0), confidence)
        else:
            normed[key] = {
                "type": t,
                "indicator": v,
                "context": ctx,
                "confidence": confidence,
            }

    intel_dict["iocs"] = list(normed.values())
    return intel_dict


def generate_unstructured_markdown(items: list[dict]) -> str:
    if not items:
        return "# Unstructured Threat Intelligence\n\n_No new items._"

    items = dedupe_records_by_title(items)
    lines = ["# Unstructured Threat Intelligence\n"]
    for rec in items:
        title = rec.get("title") or "(no title)"
        src = rec.get("source") or ""
        ref_id = rec.get("id") or rec.get("text_id") or ""
        lines.append(f"## {title}")
        if src:
            lines.append(f"_Source: {src}_")
        if ref_id:
            lines.append(f"_Ref ID: {ref_id}_")
        summary = (
            rec.get("summary_text") or rec.get("summary") or rec.get("description")
        )
        if summary:
            lines.append("")
            lines.append(summary)
        lines.append("")
    return "\n".join(lines)


def classify_threat(text: str) -> str:
    if not text:
        return "Unknown"
    lower = text.lower()

    if any(
        word in lower
        for word in ("ransomware", "encrypts files", "double extortion", "ransom note")
    ):
        return "Ransomware"

    if any(
        word in lower
        for word in (
            "remote code execution",
            "rce",
            "arbitrary code execution",
            "unauthenticated attacker",
        )
    ):
        return "Remote Code Execution"

    if any(
        word in lower
        for word in ("privilege escalation", "elevation of privilege", "eop")
    ):
        return "Privilege Escalation"

    if any(word in lower for word in ("sql injection", "sqli")):
        return "Injection"

    if any(word in lower for word in ("cross-site scripting", "xss")):
        return "Cross-Site Scripting"

    if any(
        word in lower
        for word in (
            "data theft",
            "data exfiltration",
            "stole data",
            "exfiltrated",
            "leaked data",
        )
    ):
        return "Data Theft"

    if any(word in lower for word in ("phishing", "smishing", "vishing")):
        return "Phishing"

    if any(
        word in lower for word in ("botnet", "ddos", "distributed denial of service")
    ):
        return "DDoS/Botnet"
    return "Other"


def extract_enablers_detailed(text: str, *, radius: int = 160) -> list[dict]:
    if not text:
        return []

    def _strip_boilerplate(src: str) -> str:
        if not src:
            return src
        try:
            para_split = re.split(r"\n\s*\n", src)
            min_words = int(CONFIG.get("MIN_PARAGRAPH_WORDS", 20))
            promo_patterns = CONFIG.get("PROMO_PATTERNS") or []
            bp_keywords = [
                k.lower() for k in (CONFIG.get("BOILERPLATE_KEYWORDS") or [])
            ]
            short_social_re = CONFIG.get("SHORT_SOCIAL_REGEX") or None

            for i, p in enumerate(para_split):
                p_clean = re.sub(r"\s+", " ", p or "").strip()
                if not p_clean:
                    continue
                skip = False
                for pat in promo_patterns or []:
                    try:
                        if re.search(pat, p_clean, re.I):
                            skip = True
                            break
                    except Exception:
                        continue
                if skip:
                    continue
                try:
                    if short_social_re and re.search(short_social_re, p_clean, re.I):
                        continue
                except Exception:
                    pass
                words = p_clean.split()
                if len(words) < min_words:
                    low = p_clean.lower()
                    if any(k in low for k in bp_keywords):
                        continue
                    try:
                        if short_social_re and re.search(
                            short_social_re, p_clean, re.I
                        ):
                            continue
                    except Exception:
                        pass
                return "\n\n".join(para_split[i:]).strip()
        except Exception:
            pass
        return src

    agg_parts = []
    if isinstance(text, dict):
        rec = text
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
                agg_parts.append(str(v))
    elif isinstance(text, (list, tuple)):
        for el in text:
            if not el:
                continue
            agg_parts.append(str(el))
    else:
        agg_parts.append(str(text))

    aggregate = "\n".join(agg_parts)

    aggregate = _strip_boilerplate(aggregate)
    aggregate_lower = aggregate.lower()

    keywords = CONFIG.get("ENABLER_KEYWORDS") or load_enabler_keywords()
    results: list[dict] = []
    seen: set[str] = set()
    for kw in keywords:
        if not kw:
            continue
        try:
            pat = re.compile(r"\b" + re.escape(kw.lower()) + r"\b", re.I)
            for m in pat.finditer(aggregate):
                kn = kw.strip()
                if kn in seen:
                    continue
                seen.add(kn)
                start, end = m.start(), m.end()
                conf = 0.7
                excerpt = _get_excerpt(aggregate, start, radius=radius)
                results.append(
                    {
                        "enabler": kn,
                        "excerpt": excerpt.strip(),
                        "confidence": round(conf, 2),
                    }
                )
        except Exception:
            if kw.lower() in aggregate_lower and kw not in seen:
                seen.add(kw)
                idx = aggregate_lower.find(kw.lower())
                excerpt = _get_excerpt(aggregate, idx, radius=radius)
                results.append(
                    {"enabler": kw, "excerpt": excerpt.strip(), "confidence": 0.6}
                )
    return results


def score_actionability(title: str | None, description: str | None) -> dict:
    t = (title or "").lower()
    d = (description or "").lower()
    text = f"{t} {d}".strip()

    kw_weights = ACTIONABILITY_KEYWORD_WEIGHTS or {}

    score = 0
    matches: list[dict] = []
    for kw, weight in kw_weights.items():
        if kw in text:
            score += weight
            matches.append({"keyword": kw, "contribution": weight})

    if "authentication bypass" in text:
        score += 20
        matches.append({"keyword": "authentication bypass", "contribution": 20})

    if "financial sector" in text or "bank" in text or "payment" in text:
        score += 15
        matches.append({"keyword": "financial sector", "contribution": 15})

    score = min(100, max(0, score))
    label = _score_to_label(score, low="Informational")

    if matches:
        reason = "; ".join(
            [f"{m['keyword']} ({m['contribution']:+d})" for m in matches]
        )
    else:
        reason = "No significant keywords matched; default informational."

    return {"label": label, "score": score, "reason": reason, "matches": matches}


def generate_markdown_summary(parsed_threats: list[dict]) -> str:
    md: list[str] = ["# Threat Intelligence Summary\n"]

    stats = {
        "total": len(parsed_threats),
        "with_iocs": 0,
        "with_cves": 0,
        "with_mitre": 0,
        "with_actors": 0,
        "with_fin_sector": 0,
    }

    for thr in parsed_threats:
        th = thr.get("threat") or {}
        if thr.get("iocs"):
            stats["with_iocs"] += 1
        if thr.get("related_cves"):
            stats["with_cves"] += 1
        if th.get("technique"):
            stats["with_mitre"] += 1
        if th.get("actor"):
            stats["with_actors"] += 1
        sectors = ((th.get("target") or {}).get("sector") or []) or []
        if any(
            "financial" in str(s).lower() or "bank" in str(s).lower() for s in sectors
        ):
            stats["with_fin_sector"] += 1

    missing_threats = 0
    missing_actors = 0
    missing_mitre = 0
    complete_count = 0
    for thr in parsed_threats:
        th = thr.get("threat") or {}
        has_threat = bool(th)
        has_actor = bool(th.get("actor")) if th else False
        has_mitre = bool(th.get("technique")) if th else False
        if not has_threat:
            missing_threats += 1
        if not has_actor:
            missing_actors += 1
        if not has_mitre:
            missing_mitre += 1
        if has_threat and has_actor and has_mitre:
            complete_count += 1

    completeness_pct = (
        int(100 * (complete_count / stats["total"])) if stats["total"] else 0
    )

    md.append("\n## Detailed Entries\n")
    md.append(
        f"**Validation Summary:** missing threats: {missing_threats}, missing actors: {missing_actors}, missing MITRE: {missing_mitre}"
    )
    md.append(
        f"**Data Completeness:** {completeness_pct}% ({complete_count}/{stats['total']} entries have threats+actors+MITRE)"
    )

    try:
        ranked = sorted(
            parsed_threats,
            key=lambda r: (
                ((r.get("threat") or {}).get("relevance") or {}).get("score") or 0
            ),
            reverse=True,
        )
        try:
            rpt_n = int(CONFIG.get("REPORT_TOP_N") or 0)
        except Exception:
            rpt_n = 0
        if rpt_n and rpt_n > 0:
            top_records = ranked[:rpt_n]
        else:
            top_records = ranked
        for idx, rec in enumerate(top_records, start=1):
            title = rec.get("title") or "(no title)"
            md.append("")
            md.append(f"Entry {idx}")
            md.append(f"- [{idx}] {title}")

            cat = classify_threat(
                (
                    rec.get("summary_text")
                    or rec.get("summary")
                    or rec.get("text")
                    or title
                )
            )
            md.append(f"  - Category: {cat}")

            rel = (rec.get("threat") or {}).get("relevance") or {}
            rel_label = rel.get("label")
            rel_score = rel.get("score")
            if rel_label or rel_score is not None:
                if rel_score is not None:
                    md.append(f"  - Relevance: {rel_label} ({int(rel_score)})")
                else:
                    md.append(f"  - Relevance: {rel_label}")

            act = score_actionability(
                title, rec.get("summary_text") or rec.get("summary") or ""
            )
            if isinstance(act, dict):
                act_label = act.get("label")
                act_score = act.get("score")
                if act_label or act_score is not None:
                    if act_score is not None:
                        md.append(f"  - Actionability: {act_label} ({int(act_score)})")
                    else:
                        md.append(f"  - Actionability: {act_label}")
            elif act:
                md.append(f"  - Actionability: {act}")

            th = rec.get("threat") or {}
            try:
                techs = th.get("technique") or []
                tech_lines = []
                tech_ids = []
                for t in techs:
                    if isinstance(t, dict):
                        tid = t.get("id")
                        nm = t.get("name")
                        if tid and nm:
                            tech_lines.append(f"{tid} — {nm}")
                            tech_ids.append(tid.upper())
                        elif tid:
                            tech_lines.append(tid)
                            tech_ids.append(tid.upper())
                        elif nm:
                            tech_lines.append(str(nm))
                    elif isinstance(t, str):
                        tech_lines.append(t)
                if tech_lines:
                    md.append(
                        "  - MITRE Techniques:\n    - " + " \n    - ".join(tech_lines)
                    )

                try:
                    mitig_map = load_mitre_mitigations()
                except Exception:
                    mitig_map = {}
                mitig_snips = []
                seen_mitig = set()
                for tid in tech_ids:
                    mid = tid.upper()
                    mit = mitig_map.get(mid)
                    if not mit:
                        for _, mv in mitig_map.items():
                            rel = mv.get("related_techniques") or []
                            if tid in rel:
                                mit = mv
                                break
                    if not mit:
                        continue
                    if mid in seen_mitig:
                        continue
                    seen_mitig.add(mid)
                    recs = mit.get("recommendations") or []
                    sn = ""
                    if recs and isinstance(recs, list) and recs:
                        sn = recs[0].splitlines()[0]
                    elif isinstance(mit.get("snippets"), dict):
                        act = mit.get("snippets").get("action") or []
                        if act:
                            sn = act[0]
                    title = mit.get("title") or mit.get("name") or mid
                    if sn:
                        mitig_snips.append(f"{mid}: {sn[:300]}")
                    else:
                        mitig_snips.append(f"{mid}: {title}")
                if mitig_snips:
                    md.append(
                        "  - Mitigations:\n    - " + " \n    - ".join(mitig_snips[:5])
                    )
                else:
                    md.append("  - Mitigations: --")
            except Exception:
                pass

            try:
                ed = extract_enablers_detailed(rec)
            except Exception:
                ed = None
            if ed:
                enabler_names = ", ".join([e.get("enabler") for e in ed[:3]])
                md.append(f"  - Enablers: {enabler_names}")

            try:
                countries = rec.get("countries") or []
                if not countries:
                    countries = (
                        (rec.get("threat") or {}).get("target", {}).get("country", [])
                    )
                country_parts = []
                for c in countries:
                    if isinstance(c, dict):
                        nm = c.get("name") or c.get("country")
                        role = c.get("role")
                        if nm and role:
                            country_parts.append(f"{nm} ({role})")
                        elif nm:
                            country_parts.append(nm)
                    elif isinstance(c, str):
                        country_parts.append(c)
                if country_parts:
                    md.append(f"  - Countries: {', '.join(country_parts)}")
            except Exception:
                pass

            try:
                iocs = rec.get("iocs") or []
                if iocs:
                    from collections import defaultdict

                    grouped = defaultdict(list)
                    for i in iocs[:10]:
                        typ = (i.get("type") or "").lower() or "other"
                        val = i.get("value") or i.get("indicator") or ""
                        if not val:
                            continue
                        grouped[typ].append(val)
                    if grouped:
                        md.append("  - IOCs:")
                        for t, vals in grouped.items():
                            md.append(f"    - {t}: {', '.join(vals)}")
                    else:
                        md.append("  - IOCs: --")
                else:
                    md.append("  - IOCs: --")
            except Exception:
                md.append("  - IOCs: --")

            src = rec.get("source") or ""
            if src:
                md.append(f"  - Source: {src}")
    except Exception:
        pass

    return "\n".join(md)


def process_unstructured_sources(
    parsed_data: list[dict], enrich_markdown: bool = False
) -> str:
    if not parsed_data:
        return "# No new unstructured intelligence found."
    if enrich_markdown:
        return generate_markdown_summary(parsed_data)
    else:
        simple_lines = [
            f"- {t.get('title','(no title)')} ({t.get('source', 'Unknown')})"
            for t in parsed_data
        ]
        return "# Unstructured Threat Summary\n" + "\n".join(simple_lines)
