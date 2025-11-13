from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from .config import CONFIG, load_enabler_keywords

logger = logging.getLogger(__name__)

try:
    import fitz  # type: ignore  # PyMuPDF

    HAS_PYMUPDF = True
except Exception:
    HAS_PYMUPDF = False

CVE_RX = re.compile(CONFIG.get("CVE_REGEX", r"\bCVE-\d{4}-\d{4,7}\b"), re.I)
BULLET_FINDING_RE = re.compile(
    CONFIG.get(
        "BULLET_FINDING_REGEX",
        r"^[-*•]\s+|^\d+[.)]\s+|^(?:finding|finding\s+\d+)\s*[:\-]\s*",
    ),
    re.IGNORECASE,
)
SHORT_SOCIAL_RE = re.compile(CONFIG.get("SHORT_SOCIAL_REGEX", r"\b(follow|subscribe|share|like|google news|gbhackers)\b"), re.I)
PROMO_PATTERNS = [re.compile(p, re.I) for p in (CONFIG.get("PROMO_PATTERNS") or [])]
PROVENANCE_STRIP_PATTERNS = [re.compile(p, re.MULTILINE) for p in (CONFIG.get("PROVENANCE_STRIP_PATTERNS") or [])]


# =============================================================================
# CONFIG & PATTERN / MITRE LOADING
# =============================================================================
def load_patterns() -> Dict[str, List[dict]]:
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
            pat_str = item.get("pattern")
            if not pat_str:
                continue
            flags = re.IGNORECASE | re.MULTILINE
            try:
                comp = re.compile(pat_str, flags)
            except re.error:
                logger.warning("Invalid regex for key %s: %s", key, pat_str)
                continue
            new_item = dict(item)
            new_item["regex"] = comp
            compiled[key].append(new_item)
    return compiled


def load_mitre_map() -> Dict[str, dict]:
    mitre_path = CONFIG.get("MITRE_MAP_FILE") or os.path.join(
        os.path.dirname(__file__), "mitre_map.json"
    )
    try:
        with open(mitre_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    mapping: Dict[str, dict] = {}
    for entry in data:
        tid = entry.get("id") or entry.get("technique_id") or ""
        if not tid:
            continue
        mapping[tid.upper()] = entry
    return mapping


def load_mitre_mitigations() -> Dict[str, dict]:
    mitig_path = CONFIG.get("MITRE_MITIGATIONS_FILE") or os.path.join(
        os.path.dirname(__file__), "mitre_mitigations.json"
    )
    try:
        with open(mitig_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    mapping: Dict[str, dict] = {}
    for entry in data:
        mid = entry.get("id") or entry.get("mitigation_id") or ""
        if not mid:
            continue
        mapping[mid.upper()] = entry
    return mapping


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


def correlate_unstructured_with_cves(
    unstructured_items: list[dict], cves: list[dict]
) -> list[dict]:
    if not unstructured_items or not cves:
        return unstructured_items

    cve_index: Dict[str, dict] = {}
    for c in cves:
        cid = c.get("cve") or c.get("id")
        if not cid:
            continue
        cve_index[str(cid).upper()] = c

    for rec in unstructured_items:
        text = " ".join(
            str(rec.get(k) or "")
            for k in ("title", "summary_text", "summary", "text", "full_text")
        )
        if not text:
            continue
        found: Dict[str, dict] = {}
        for m in CVE_RX.finditer(text):
            cid = m.group(0).upper()
            if cid not in cve_index:
                continue
            if cid in found:
                continue
            found[cid] = cve_index[cid]
        if found:
            rec.setdefault("related_cves", [])
            for cid, cve in found.items():
                rec["related_cves"].append(
                    {
                        "cve": cid,
                        "summary": cve.get("summary") or cve.get("description"),
                        "cvss_score": cve.get("cvss", {}).get("score"),
                    }
                )
    return unstructured_items


# =============================================================================
# HTTP FETCHING & HTML EXTRACTION
# =============================================================================
def html_to_main_text(
    html: str, *, strip_boilerplate: bool = True, max_len: int | None = None
) -> str:
    if not html:
        return ""
    parser = CONFIG.get("HTML_PARSER", "html.parser")
    soup = BeautifulSoup(html, parser)

    strip_elems = CONFIG.get("HTML_STRIP_ELEMENTS", ["script", "style", "noscript", "header", "footer", "nav"]) or ["script", "style", "noscript", "header", "footer", "nav"]
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
        bp_keywords = [k.lower() for k in CONFIG.get("BOILERPLATE_KEYWORDS", ["cookies", "privacy", "terms", "all rights reserved", "subscribe", "advert", "promo"]) or []]
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
        status_forcelist=tuple(CONFIG.get("HTTP_STATUS_FORCELIST", (500, 502, 503, 504))),
        allowed_methods=frozenset(CONFIG.get("HTTP_ALLOWED_METHODS", ["GET", "HEAD"])),
    )
    adapter = HTTPAdapter(
        max_retries=retries,
        pool_connections=CONFIG.get("HTTP_POOL_CONNECTIONS", 100),
        pool_maxsize=CONFIG.get("HTTP_POOL_MAXSIZE", 100),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": CONFIG.get("USER_AGENT", "ThreatIntelCollector/5.0")})
    return s

def fetch_article_text(url: str, timeout: int | None = None) -> str:
    try:
        session = get_requests_session()
        timeout = int(timeout or CONFIG.get("REQUEST_TIMEOUT", 10))
        headers = {"User-Agent": CONFIG.get("USER_AGENT", session.headers.get("User-Agent"))}
        resp = session.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Error fetching url %s: %s", url, exc)
        return ""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype or "<html" in resp.text.lower():
        return html_to_main_text(resp.text)
    return resp.text

# =============================================================================
# IOC & TECHNIQUE EXTRACTION
# =============================================================================
def extract_threat_indicators(parsed_record: dict | str, source: str | None = None, title: str | None = None) -> dict:
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
    aggregate_text = "\n".join(text_parts)
    if not aggregate_text:
        return parsed_record

    compiled = load_compiled_patterns()

    found: Dict[str, set] = defaultdict(set)
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
                        tid = val.upper()
                        found["technique"].add(tid)
                    elif key == "actor":
                        found["actor"].add(val)
            except re.error:
                continue

    iocs = []
    for k in ("ip", "domain", "hash", "email"):
        for v in sorted(found.get(k, [])):
            iocs.append({"type": k, "indicator": v})

    techniques = []
    for tid in sorted(found.get("technique", [])):
        techniques.append({"id": tid})
    if not techniques:
        words = [w.lower() for w in re.findall(r"\w+", aggregate_text)]
        min_repeat = int(CONFIG.get("MIN_REPEAT_FOR_SHORT_MATCH", 2))
        from collections import Counter

        counts = Counter(words)
        repeated_label = None
        for w, c in counts.items():
            if c >= min_repeat and len(w) > 3:
                if any(w.startswith(prefix) for prefix in ("nav", "menu", "link", "item")):
                    continue
                repeated_label = w
                break

        if repeated_label:
            label = classify_threat(repeated_label)
            if label and label != "Unknown":
                th = parsed_record.setdefault("threat", {})
                th.setdefault("technique", {})
                if isinstance(th["technique"], dict):
                    th["technique"].setdefault("name", [])
                    if label not in th["technique"]["name"]:
                        th["technique"]["name"].append(label)
                else:
                    th["technique"] = {"name": [label]}
        else:
            min_words = CONFIG.get("MIN_WORDS_FOR_CLASSIFY", 6)
            if len(words) >= min_words:
                label = classify_threat(aggregate_text)
                if label and label != "Unknown":
                    th = parsed_record.setdefault("threat", {})
                    th.setdefault("technique", {})
                    if isinstance(th["technique"], dict):
                        th["technique"].setdefault("name", [])
                        if label not in th["technique"]["name"]:
                            th["technique"]["name"].append(label)
                    else:
                        th["technique"] = {"name": [label]}
    actors = []
    for a in sorted(found.get("actor", [])):
        actors.append({"name": a})

    if iocs:
        parsed_record["iocs"] = iocs
    if techniques or actors:
        th = parsed_record.setdefault("threat", {})
        if techniques:
            th.setdefault("technique", [])
            th["technique"].extend(techniques)
        if actors:
            th.setdefault("actor", [])
            th["actor"].extend(actors)
    parsed_record = attach_mitre_to_intel(parsed_record)
    th = parsed_record.setdefault("threat", {})
    tech = th.get("technique")
    if tech is None:
        th["technique"] = {"name": []}
    elif isinstance(tech, list):
        names = []
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

    return parsed_record

def extract_iocs(text_or_intel, source: str | None = None, title: str | None = None) -> list[dict]:
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
    iocs = []
    seen = set()
    patterns = {
        "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "url": re.compile(r"\bhttps?://[\w\-./?&=%#]+", re.I),
        "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
        "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I),
    }

    def _add(t, v):
        key = (t, v.lower())
        if key in seen:
            return
        seen.add(key)
        typ = "hash" if t in ("sha256", "sha1", "md5") else t
        val = v.lower()
        iocs.append({"type": typ, "indicator": val, "value": val})

    for t, p in patterns.items():
        for m in p.finditer(text):
            val = m.group(0)
            if t == "domain" and val.startswith("www."):
                val = val[4:]
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
        "suricata": ["alert http any any -> any any (msg:\"IOCs seen\"; sid:1000001;)"]
    }

    if rec_actions:
        out_items.append({"type": "operational", "description": "Review and deploy updated detection content for extracted IOCs."})

    return {"recommended_actions": rec_actions, "mitigation_snippets": mitigation_snippets, "mitigations": out_items}

def generate_actionable_summary(intel: dict) -> str:
    items = generate_actionable_items(intel)
    if not items:
        return ""
    items_list: list = []
    if isinstance(items, dict):
        items_list = items.get("mitigations") or []
        if not items_list and items.get("recommended_actions"):
            items_list = [{"type": "operational", "description": a} for a in items.get("recommended_actions")]
    elif isinstance(items, list):
        items_list = items

    parts = []
    for it in items_list:
        try:
            if isinstance(it, dict) and it.get("type") == "mitigation":
                parts.append(f"Mitigation {it.get('id')} for technique {it.get('technique')}: {it.get('description')}")
            elif isinstance(it, dict) and it.get("type") == "operational":
                parts.append(str(it.get("description")))
            elif isinstance(it, str):
                parts.append(it)
        except Exception:
            continue
    return " ".join(parts)

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
        if any("financial" in s.lower() or "bank" in s.lower() for s in sectors):
            boost += fin_boost
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
        if any(k in txt for k in ("bank", "financial", "credit", "atm", "swift")):
            boost += int(fin_boost / 2)
        score = int(min(100, score + boost))
    except Exception:
        pass
    label = _score_to_label(score)
    intel.setdefault("threat", {})
    intel["threat"]["relevance"] = {"score": score, "label": label}
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

# =============================================================================
# TEXT & PDF PROCESSING
# =============================================================================
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
    out_dir = os.path.join(CONFIG.get("OUTPUT_DIR", "."), "pdf_text")
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
    cmd = ["pdftotext", "-layout", "-q", pdf_path, "-"]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=CONFIG.get("PDFTOTEXT_TIMEOUT", 30),
        )
    except Exception as exc:
        logger.warning("pdftotext call failed: %s", exc)
        return ""

    if result.returncode != 0:
        logger.warning("pdftotext exited with code %s", result.returncode)
        return ""

    text = result.stdout.decode("utf-8", errors="replace")
    text = _dehyphenate_text(text)
    pdf_max_pages = max_pages if max_pages is not None else CONFIG.get("PDF_MAX_PAGES", 50)
    if pdf_max_pages and text.count("\f") > pdf_max_pages:
        parts: list[str] = []
        for i, page in enumerate(text.split("\f")):
            if i >= pdf_max_pages:
                break
            parts.append(page)
        text = "\n".join(parts)
    return text


def extract_top_findings(text: str, max_items: int = 5, k: int | None = None) -> list[str]:
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
    promo_patterns = PROMO_PATTERNS or [re.compile(p, re.I) for p in ["^sign up for our newsletter", "^follow us on\\s+", "^related articles", "^sponsored content", "^about the author"]]
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

        lines.append(s)
    return "\n\n".join(lines)

# =============================================================================
# SUMMARIZATION HELPERS
# =============================================================================
def summarize_unstructured_description(text: str, max_sentences: int = 2) -> str:
    if not text:
        return ""

    try:
        text = sanitize_article_text(text)
    except Exception:
        pass

    txt = re.sub(r"\s+", " ", text).strip()

    sents = re.split(r"(?<=[\.!?])\s+", txt)
    sents = [s.strip() for s in sents if s.strip()]
    if not sents:
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
        "credential theft",
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

def concise_one_sentence_summary(
    text: str, vendor: str | None = None, max_chars: int = 200
) -> str:
    if not text:
        return ""
    try:
        txt = sanitize_article_text(text)
    except Exception:
        txt = text

    sents = re.split(r"(?<=[\.!?])\s+", txt)
    sents = [s.strip() for s in sents if s.strip()]
    if not sents:
        return ""

    cve_re = CVE_RX
    max_chars = int(max_chars or CONFIG.get("SUMMARY_MAX_CHARS", 200))
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
        "credential theft",
        "supply chain",
    ]
    vendor_norm = (vendor or "").strip().lower()

    best = sents[0]
    best_score = -9999
    for s in sents:
        lower = s.lower()
        score = 0
        if cve_re.search(s):
            score += 40
        for kt in attack_terms:
            if kt in lower:
                score += 20
        if vendor_norm and vendor_norm in lower:
            score += 25
        length_bonus = min(15, max(0, (len(s) - 60) // 8))
        score += length_bonus
        if len(re.findall(r"\w+", s)) < 6:
            score -= 10
        if score > best_score:
            best_score = score
            best = s

    out = re.sub(r"<[^>]+>", "", best)
    out = re.sub(r"\s+", " ", out).strip()

    if vendor_norm and vendor_norm not in out.lower():
        vend = str(vendor).strip()
        if vend:
            if not out.endswith("."):
                out = out + "."
            out = f"{out} — affects {vend}."

    if len(out) > max_chars:
        out = out[: max_chars - 3].rstrip() + "..."
    return out

# =============================================================================
# AGGREGATION / DEDUPE / PROVENANCE
# =============================================================================
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
                txt = " ".join([str(rec.get(k) or "") for k in ("title", "summary", "text")]).lower()
                for v in CONFIG.get("VENDORS", []) or []:
                    if v and v.lower() in txt:
                        vendors = [v]
                        break
            except Exception:
                pass
        if not sectors:
            try:
                txt = " ".join([str(rec.get(k) or "") for k in ("title", "summary", "text")]).lower()
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
    if not items:
        return ""
    lines = [f"### {title}", ""]
    for rec in items:
        t = rec.get("title") or "(no title)"
        src = rec.get("source") or ""
        relevance = ((rec.get("threat") or {}).get("relevance") or {}).get("label")
        line = f"- **{t}**"
        if relevance:
            line += f" _(Relevance: {relevance})_"
        if src:
            line += f" — _Source: {src}_"
        lines.append(line)
    return "\n".join(lines)


def dedupe_records_by_title(
    records: list[dict], *, key_field: str = "title"
) -> list[dict]:
    kept: list[dict] = []
    kept_norm: list[str] = []
    for rec in records:
        title = (rec.get(key_field) or "").strip().lower()
        ts = rec.get("@timestamp") or rec.get("timestamp") or ""
        if not title:
            kept.append(rec)
            kept_norm.append(title)
            continue
        if title in kept_norm:
            idx = kept_norm.index(title)
            existing = kept[idx]
            existing_ts = existing.get("@timestamp") or existing.get("timestamp") or ""
            try:
                if ts and existing_ts and ts > existing_ts:
                    kept[idx] = rec
            except Exception:
                pass
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
    prov_keywords = CONFIG.get("PROVENANCE_KEYWORDS", ["chatgpt", "openai", "bard", "gemini", "copilot"]) or []
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
        prov_out.append({"source_url": url, "excerpt": _get_excerpt(aggregate, m.start()), "confidence": 0.9})

    src_match = re.search(r"(?i)source:\s*([A-Za-z0-9 .,&-]+)", aggregate)
    if src_match:
        name = src_match.group(1).strip()
        prov_out.append({"source_name": name, "excerpt": _get_excerpt(aggregate, src_match.start(1)), "confidence": 0.85})

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
    if radius is None:
        radius = CONFIG.get("EXCERPT_RADIUS", 160)
    start = max(0, idx - radius)
    end = min(len(text), idx + radius)
    snippet = text[start:end]
    snippet = snippet.strip()
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet


def normalize_and_merge_iocs(intel, source: str | None = None):
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
        key = (t, v.lower())
        ctx = i.get("context") or i.get("excerpt") or ""
        confidence = i.get("confidence") or 0.75
        if key in normed:
            existing = normed[key]
            if ctx and ctx not in existing.get("context", ""):
                existing["context"] = (existing.get("context", "") + " | " + ctx).strip(" |")
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
        summary = rec.get("summary_text") or rec.get("summary") or rec.get("description")
        if summary:
            lines.append("")
            lines.append(summary)
        lines.append("")
    return "\n".join(lines)

# =============================================================================
# CLASSIFICATION & ENABLER EXTRACTION
# =============================================================================
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

    if any(word in lower for word in ("botnet", "ddos", "distributed denial of service")):
        return "DDoS/Botnet"
    return "Other"

def extract_enablers(text: str):
    details = extract_enablers_detailed(text)
    seen = set()
    result = []
    for item in details or []:
        try:
            enabler = (item or {}).get("enabler")
        except Exception:
            enabler = None
        if not enabler:
            continue
        if enabler not in seen:
            seen.add(enabler)
            result.append(enabler)
    return result

def extract_enablers_detailed(text: str, *, radius: int = 160) -> list[dict]:
    if not text:
        return []

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

# =============================================================================
# SCORING & ACTIONABILITY
# =============================================================================
def assess_actionability(text: str, relevance: int | float | None = None) -> str:
    try:
        if relevance is not None:
            try:
                r = int(float(relevance))
            except Exception:
                r = None
            if isinstance(r, int):
                if r >= 80:
                    return "Critical"
                if r >= 60:
                    return "High"
                if r >= 30:
                    return "Medium"
                return "Informational"
    except Exception:
        pass

    lower = (text or "").lower()
    if not lower:
        return "Informational"

    if any(
        term in lower
        for term in [
            "zero-day",
            "zero day",
            "actively exploited",
            "in the wild",
            "mass scanning",
            "ransomware",
            "mass exploitation",
            "internet-facing",
            "public exploit",
            "poc available",
        ]
    ):
        return "Immediate"
    if any(
        term in lower
        for term in [
            "trend",
            "rising",
            "increase",
            "development",
            "pattern",
        ]
    ):
        return "Strategic"
    return "Informational"

def score_actionability(title: str | None, description: str | None) -> dict:
    t = (title or "").lower()
    d = (description or "").lower()
    text = f"{t} {d}".strip()

    kw_weights = {
        "zero-day": 30,
        "zero day": 30,
        "active exploit": 30,
        "exploit": 25,
        "ransomware": 25,
        "malware": 20,
        "cve": 15,
        "critical": 20,
        "remote code execution": 25,
        "rce": 25,
        "privilege escalation": 20,
        "elevation of privilege": 20,
        "sql injection": 18,
        "xss": 15,
        "cross-site scripting": 15,
        "phishing": 12,
        "botnet": 12,
        "ddos": 12,
        "mass scanning": 15,
        "internet-facing": 15,
        "public exploit": 20,
        "poc available": 20,
        "proof-of-concept": 20,
    }

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

# =============================================================================
# MARKDOWN GENERATION & ENTRYPOINT
# =============================================================================
def generate_markdown_summary(parsed_threats: list[dict]) -> str:
    md: list[str] = ["# Threat Intelligence Summary\n"]

    md.append(
        "\n## Threats to Watch (2025–2026)\n"
        "- Quantum readiness gaps across financial and critical infrastructure sectors\n"
        "- Abuse of AI for large-scale impersonation and disinformation\n"
        "- Exploitation of open-source supply chains (e.g., XZ backdoor)\n"
        "- Zero-day exploitation acceleration and patch latency risk\n"
        "- Credential theft economy expansion via infostealers\n"
    )

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
        if any("financial" in str(s).lower() or "bank" in str(s).lower() for s in sectors):
            stats["with_fin_sector"] += 1

    md.append("\n## Collection Overview\n")
    md.append(f"- Total unstructured items: **{stats['total']}**")
    md.append(f"- Items with IOCs: **{stats['with_iocs']}**")
    md.append(f"- Items with CVE references: **{stats['with_cves']}**")
    md.append(f"- Items with mapped MITRE techniques: **{stats['with_mitre']}**")
    md.append(f"- Items with named threat actors: **{stats['with_actors']}**")
    md.append(
        f"- Items explicitly mentioning financial/banking sector: **{stats['with_fin_sector']}**"
    )

    md.append("\n## Detailed Entries\n")
    if not parsed_threats:
        md.append("_No new unstructured intelligence items were processed._")
        return "\n".join(md)

    for idx, thr in enumerate(parsed_threats, start=1):
        title = thr.get("title") or "(no title)"
        source = thr.get("source") or "Unknown"
        ref_id = thr.get("text_id") or thr.get("id") or ""
        t_summary = (
            thr.get("summary_text")
            or thr.get("summary")
            or thr.get("description")
            or thr.get("text")
            or thr.get("full_text")
            or ""
        )

        md.append(f"\n### Entry {idx}: {title}")
        meta_bits = []
        if ref_id:
            meta_bits.append(f"Ref: `{ref_id}`")
        meta_bits.append(f"Source: {source}")
        if meta_bits:
            md.append("_" + " | ".join(meta_bits) + "_")

        one_liner = concise_one_sentence_summary(
            t_summary or (thr.get("text") or ""), vendor=None, max_chars=260
        )
        if one_liner:
            md.append("")
            md.append(one_liner)

        threat_type = classify_threat(t_summary or title)
        md.append(f"- Threat type: **{threat_type}**")

        rel = ((thr.get("threat") or {}).get("relevance") or {}).get("label")
        if rel:
            md.append(f"- Relevance: **{rel}**")

        actions = generate_actionable_summary(thr)
        if actions:
            md.append(f"- Suggested actions: {actions}")

        iocs = extract_iocs(thr)
        if iocs:
            md.append("- IOCs:")
            by_type: dict[str, list[str]] = defaultdict(list)
            for ioc in iocs:
                by_type[ioc["type"]].append(ioc["indicator"])
            for t, vals in by_type.items():
                joined = ", ".join(sorted(set(vals))[:10])
                if len(vals) > 10:
                    joined += " ..."
                md.append(f"  - {t}: {joined}")

        cves = thr.get("related_cves") or []
        if cves:
            md.append("- Referenced CVEs:")
            for c in cves[:5]:
                line = f"  - {c.get('cve')}"
                sc = c.get("cvss_score")
                if sc is not None:
                    line += f" (CVSS: {sc})"
                summary = c.get("summary")
                if summary:
                    short = (summary[:160] + "...") if len(summary) > 160 else summary
                    line += f" — {short}"
                md.append(line)
            if len(cves) > 5:
                md.append(f"  - ... and {len(cves) - 5} more CVEs.")

        enablers_details = extract_enablers_detailed(thr)
        if enablers_details:
            md.append("- Key enablers (selected):")
            for ed in enablers_details[:3]:
                enab = ed.get("enabler")
                ex = ed.get("excerpt") or ""
                ex_short = (ex[:160] + "...") if len(ex) > 160 else ex
                conf = ed.get("confidence")
                if conf is not None:
                    md.append(f"  - {enab} (conf: {conf}): {ex_short}")
                else:
                    md.append(f"  - {enab}: {ex_short}")

        full_text = thr.get("full_text") or ""
        if full_text:
            prov = detect_provenance({"text": full_text})
            prov_meta = (prov.get("metadata") or {}).get("provenance")
            if prov_meta:
                md.append(f"- Provenance indicators: {', '.join(prov_meta)}")
        md.append("")
    return "\n".join(md)

def process_unstructured_sources(parsed_data: list[dict], enrich_markdown: bool = False) -> str:
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