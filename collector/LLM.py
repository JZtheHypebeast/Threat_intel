from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import calendar
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# =========================
# ===== Third-Party =======
# =========================
from bs4 import BeautifulSoup
from dateutil import parser as dtparser
import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# ====== Local App ========
# =========================
from .config import CONFIG, logger
from .progress import progress_bar, start_live_progress, stop_live_progress

# =========================
# ===== Module Config =====
# =========================
RAWTEXT_LLM_PREFIX = "LLM-JSON_"
LLM_MD_PREFIX = "LLM-UnstructuredReport_"
RAW_TEXT_SNIPPET_MAX = 8000
OLLAMA_DEFAULT_HOST = "http://localhost:11434"

# =========================
# ===== Fetch Config ======
# =========================
OUTPUT_DIR = CONFIG.get("OUTPUT_DIR_UNSTRUCTURED", "")
DEFAULT_HOURS = 24
WEEKLY_RECAP_MARKER = "weekly recap"
MAX_WORKERS_DEFAULT = CONFIG.get("MAX_WORKERS", 6)
PROGRESS_PREFIX_FEEDS = "Feeds"
PROGRESS_PREFIX_ARTICLES = "Articles"
REQUEST_TIMEOUT = CONFIG.get("REQUEST_TIMEOUT", 25)
HTTP_CONNECT_TIMEOUT = CONFIG.get("HTTP_CONNECT_TIMEOUT", 5)
HTTP_READ_TIMEOUT = CONFIG.get("HTTP_READ_TIMEOUT", REQUEST_TIMEOUT)
HTTP_RETRIES_TOTAL = CONFIG.get("HTTP_RETRIES_TOTAL", 3)
HTTP_BACKOFF_FACTOR = CONFIG.get("HTTP_BACKOFF_FACTOR", 0.3)
HTTP_STATUS_FORCELIST = CONFIG.get("HTTP_STATUS_FORCELIST", [500, 502, 503, 504])
HTTP_POOL_CONNECTIONS = CONFIG.get("HTTP_POOL_CONNECTIONS", 50)
HTTP_POOL_MAXSIZE = CONFIG.get("HTTP_POOL_MAXSIZE", 50)
HTTP_MAX_CONTENT_LENGTH = CONFIG.get("HTTP_MAX_CONTENT_LENGTH", 5_000_000)
USER_AGENT = CONFIG.get("HTTP_USER_AGENT") or CONFIG.get(
    "USER_AGENT", "ThreatIntelCollector/5.0"
)

_SESSION: requests.Session | None = None


# =========================
# ======== Helpers ========
# =========================
def _ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", CONFIG.get("OLLAMA_HOST", OLLAMA_DEFAULT_HOST)).rstrip("/")


def _get_output_dir() -> Path:
    out = CONFIG.get("OUTPUT_DIR_LLM")
    if out:
        path = Path(out)
        logger.debug("LLM output dir from CONFIG: %s", path)
        return path
    base = Path(__file__).resolve().parent
    results_root = base / "results"
    today_stamp = datetime.now().strftime("%Y%m%d")
    path = results_root / today_stamp
    logger.debug("LLM output dir defaulting to: %s", path)
    return path


def _find_latest_rawtext_any(base_dir: Path) -> Optional[Path]:
    """
    Locate the newest rawtext-*.json anywhere under the rawtext results root.
    Assumes layout: <...>/results/llmrawtext/<YYYYMMDD>/<HHMMSS>/rawtext-<date>.json
    """
    if not base_dir.exists():
        logger.debug("Rawtext base dir does not exist: %s", base_dir)
        return None
    matches = list(base_dir.glob("**/rawtext-*.json"))
    if not matches:
        logger.debug("No rawtext matches under %s", base_dir)
        return None
    latest = max(matches, key=lambda p: p.stat().st_mtime)
    logger.debug("Latest rawtext (global search): %s", latest)
    return latest


# =========================
# ====== Formatting =======
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


# =========================
# ===== Fetch/Rawtext =====
# =========================
# =========================
# ======= HTTP I/O ========
# =========================
def _http_session() -> requests.Session:
    global _SESSION
    if _SESSION is not None:
        return _SESSION
    retries = Retry(
        total=HTTP_RETRIES_TOTAL,
        backoff_factor=HTTP_BACKOFF_FACTOR,
        status_forcelist=HTTP_STATUS_FORCELIST,
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retries,
        pool_connections=HTTP_POOL_CONNECTIONS,
        pool_maxsize=HTTP_POOL_MAXSIZE,
    )
    sess = requests.Session()
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": USER_AGENT})
    _SESSION = sess
    return sess


def _dehyphenate_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("-\n", "")
    text = text.replace("\r", "\n")
    text = "\n".join(ln.rstrip() for ln in text.splitlines())
    return text


def html_to_main_text(html: str, *, strip_boilerplate: bool = True) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
        try:
            tag.decompose()
        except Exception:
            continue
    text = soup.get_text(separator="\n")
    lines = [ln.strip() for ln in text.splitlines()]
    if strip_boilerplate:
        bp_keywords = [
            k.lower()
            for k in CONFIG.get(
                "BOILERPLATE_KEYWORDS",
                ["cookies", "privacy", "terms", "subscribe", "advert"],
            )
            or []
        ]
        cleaned = []
        for ln in lines:
            if not ln:
                continue
            low = ln.lower()
            if any(bk in low for bk in bp_keywords):
                continue
            cleaned.append(ln)
        lines = cleaned
    return "\n".join(lines)


def fetch_article_text(url: str, timeout: int = REQUEST_TIMEOUT) -> dict:
    if not url:
        return {"text": ""}
    proxies = CONFIG.get("PROXIES") or None
    try:
        resp = _http_session().get(
            url,
            timeout=(HTTP_CONNECT_TIMEOUT, timeout or HTTP_READ_TIMEOUT),
            proxies=proxies,
            stream=True,
        )
        resp.raise_for_status()
        ctype = (resp.headers.get("content-type") or "").lower()
        if ctype and not any(hint in ctype for hint in ("text/html", "application/xhtml")):
            logger.debug("Skipping non-HTML content for %s (%s)", url, ctype)
            return {"text": ""}
        collected = []
        total = 0
        for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
            if not chunk:
                continue
            total += len(chunk)
            if total > HTTP_MAX_CONTENT_LENGTH:
                logger.debug("Truncated response for %s at %s bytes", url, total)
                break
            collected.append(chunk)
        raw_bytes = b"".join(collected)
        if not raw_bytes:
            logger.debug("Empty body for %s", url)
            return {"text": ""}
        encoding = resp.encoding or "utf-8"
        text_body = raw_bytes.decode(encoding, errors="ignore")
        txt = html_to_main_text(text_body)
        return {"text": _dehyphenate_text(txt)}
    except Exception as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
        return {"text": ""}


# =========================
# ======= IOC Utils =======
# =========================
def extract_iocs(text: str, source: str | None = None, title: str | None = None):
    if not text:
        return []
    iocs = []
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url_re = re.compile(r"https?://[\\w\\-.\\/?&=%#]+", re.I)
    ip_re = re.compile(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
    domain_re = re.compile(r"\\b([A-Za-z0-9.-]+\\.[A-Za-z]{2,})\\b")
    hash_re = re.compile(r"\\b[a-fA-F0-9]{32,64}\\b")

    for m in email_re.finditer(text):
        iocs.append({"type": "email", "value": m.group(0).lower(), "source": source})
    for m in url_re.finditer(text):
        iocs.append({"type": "url", "value": m.group(0), "source": source})
    for m in ip_re.finditer(text):
        iocs.append({"type": "ip", "value": m.group(0), "source": source})
    for m in hash_re.finditer(text):
        iocs.append({"type": "hash", "value": m.group(0).lower(), "source": source})
    for m in domain_re.finditer(text):
        dom = m.group(1).lower()
        if dom.startswith("www."):
            dom = dom[4:]
        if dom.count(".") >= 1 and not dom.replace(".", "").isdigit():
            iocs.append({"type": "domain", "value": dom, "source": source})

    seen = set()
    deduped = []
    for i in iocs:
        key = (i["type"], i["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(i)
    return deduped


def generate_actionable_items(intel: dict) -> dict:
    actions = []
    snippets = []
    for i in intel.get("iocs") or []:
        t = (i.get("type") or "").lower()
        v = i.get("value")
        if not v:
            continue
        if t == "ip":
            actions.append(f"block_ip:{v}")
        elif t == "domain":
            actions.append(f"block_domain:{v}")
        elif t == "url":
            actions.append(f"block_url:{v}")
        elif t == "email":
            actions.append(f"block_sender:{v}")
    if actions:
        snippets.append("firewall")
        snippets.append("proxy")
        snippets.append("suricata")
        snippets.append("Update firewall/proxy blocks for observed IPs/domains/URLs.")
        snippets.append("Push indicators to SIEM/NDR for alerting.")
        snippets.append("Deploy Suricata/Snort signatures for the observed indicators.")
    return {"recommended_actions": actions, "mitigation_snippets": snippets}


# =========================
# ====== RSS Parsing ======
# =========================
def run_fetch_rawtext(hours: int = DEFAULT_HOURS) -> dict:
    feeds = CONFIG.get("RSS_FEEDS", []) or []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries = []
    for idx, f in enumerate(feeds, 1):
        parsed = feedparser.parse(f)
        feed_count = len(parsed.entries) if parsed and hasattr(parsed, "entries") else 0
        status = f"feed={idx}/{len(feeds)} entries={feed_count}"
        progress_bar(idx, len(feeds), prefix=PROGRESS_PREFIX_FEEDS, status=status)
        for e in parsed.entries:
            pub_dt = None
            try:
                if e.get("published_parsed"):
                    pub_dt = datetime.fromtimestamp(
                        calendar.timegm(e.published_parsed), timezone.utc
                    )
                elif e.get("updated_parsed"):
                    pub_dt = datetime.fromtimestamp(
                        calendar.timegm(e.updated_parsed), timezone.utc
                    )
                else:
                    pub = e.get("published") or e.get("updated")
                    pub_dt = dtparser.parse(pub).astimezone(timezone.utc) if pub else None
            except Exception:
                pub_dt = None
            if pub_dt and pub_dt < cutoff:
                continue
            if not pub_dt and not CONFIG.get("INCLUDE_ENTRIES_WITHOUT_DATE", True):
                continue
            link = e.get("link")
            title = e.get("title")
            summary = None
            try:
                summary = e.get("summary") or (
                    e.get("content")[0].get("value") if e.get("content") else None
                )
            except Exception:
                summary = e.get("summary") or None
            if link:
                if title and WEEKLY_RECAP_MARKER in str(title).lower():
                    continue
                entries.append((link, title, pub_dt, summary))

    seen = set()
    uniq = []
    for link, title, pub_dt, summary in entries:
        if link in seen:
            continue
        seen.add(link)
        uniq.append((link, title, pub_dt, summary))

    records = []
    total_entries = len(uniq)
    shared = {"current": 0, "status": ""}
    animator = None
    if total_entries:
        animator = start_live_progress(
            prefix=PROGRESS_PREFIX_ARTICLES, total=total_entries, shared=shared
        )
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_DEFAULT) as ex:
        futures = {
            ex.submit(fetch_article_text, link): (link, title, pub_dt, summary)
            for link, title, pub_dt, summary in uniq
        }
        completed = 0
        for fut in as_completed(futures):
            completed += 1
            elapsed = time.time() - start_time
            remaining = max(total_entries - completed, 0) * (elapsed / max(completed, 1))
            status = f"{completed}/{total_entries} {_format_eta(remaining)}"
            try:
                shared["current"] = completed
                shared["status"] = status
            except Exception:
                progress_bar(
                    completed, total_entries, prefix=PROGRESS_PREFIX_ARTICLES, status=status
                )

            link, title, pub_dt, summary = futures[fut]
            text = ""
            try:
                meta = fut.result()
                if isinstance(meta, dict):
                    text = meta.get("text", "") or ""
                else:
                    text = str(meta)
            except Exception:
                logger.debug(f"error fetching {link}")

            if not text:
                text = summary or ""
            text = _dehyphenate_text(text)
            record = {
                "title": title,
                "source": link,
                "@timestamp": (pub_dt or datetime.now(timezone.utc)).isoformat(),
                "raw_text": text,
            }
            records.append(record)

    if animator:
        try:
            stop_live_progress(animator[0], animator[1])
        except Exception:
            pass

    date_tag = datetime.now().strftime("%Y%m%d")
    raw_dir = (
        CONFIG.get("OUTPUT_DIR_LLM_RAW")
        or CONFIG.get("OUTPUT_DIR_LLM")
        or CONFIG.get("OUTPUT_DIR_UNSTRUCTURED")
        or OUTPUT_DIR
    )
    os.makedirs(raw_dir, exist_ok=True)
    rawtext_fn = f"rawtext-{date_tag}.json"
    out_raw = os.path.join(raw_dir, rawtext_fn)
    with open(out_raw, "w", encoding="utf-8") as rf:
        json.dump(records, rf, ensure_ascii=False, indent=2)
    progress_bar(1, 1, prefix="Write RawText", status=f"wrote={len(records)} file={rawtext_fn}")
    logger.info(
        "Fetch summary: discovered=%s deduped=%s written=%s path=%s",
        len(entries),
        len(uniq),
        len(records),
        out_raw,
    )
    return {
        "records_total": len(records),
        "rawtext_path": out_raw,
        "discovered_entries": len(entries),
        "after_url_dedupe": len(uniq),
    }


def run_unstructured_rss_analysis(hours: int = DEFAULT_HOURS) -> dict:
    logger.warning("run_unstructured_rss_analysis is deprecated; running rawtext fetch only.")
    return run_fetch_rawtext(hours=hours)


def run_fetch(hours: int = DEFAULT_HOURS) -> dict:
    return run_fetch_rawtext(hours=hours)


# =========================
# ====== LLM Helpers ======
# =========================
# =========================
# ===== Rawtext I/O =======
# =========================
def _load_rawtext_records(path: Path) -> List[Dict[str, Any]]:
    logger.info("Loading rawtext records from %s", path)
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        logger.warning("Rawtext file %s is empty", path)
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except Exception:
            logger.warning("Failed to parse rawtext array from %s", path)
            return []
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        return []
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    logger.info("Loaded %s rawtext records", len(records))
    return records


def _filter_by_hours(
    records: List[Dict[str, Any]], hours: Optional[int]
) -> List[Dict[str, Any]]:
    if not hours or hours <= 0:
        return records
    logger.info("Filtering records by last %s hours", hours)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    filtered: List[Dict[str, Any]] = []
    for rec in records:
        ts_val = rec.get("@timestamp") or rec.get("timestamp") or rec.get("time")
        if not ts_val:
            filtered.append(rec)
            continue
        try:
            ts = datetime.fromisoformat(str(ts_val))
        except Exception:
            filtered.append(rec)
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff:
            filtered.append(rec)
    logger.info("Records after hour filter: %s", len(filtered))
    return filtered


SYSTEM_INSTRUCTION = (
    "You are a senior threat intelligence analyst. "
    "You convert raw security articles into structured, actionable threat intelligence."
)

def _build_prompt_from_raw(record: Dict[str, Any]) -> str:
    logger.debug("Building prompt for title=%s source=%s", record.get("title"), record.get("source"))
    title = record.get("title") or "(no title)"
    source = record.get("source") or ""
    ts = record.get("@timestamp") or record.get("timestamp") or ""
    raw_text = record.get("raw_text") or record.get("text") or record.get("full_text") or ""
    snippet = str(raw_text)

    prompt = (
        "You will receive the full raw text of a cyber security article plus metadata.\n"
        "From this raw text alone, extract structured, actionable threat intelligence.\n\n"
        "Return a STRICT JSON object with these fields, in this order:\n\n"
        '- "summary": string (1–3 sentences, plain language, high-level summary of the entire article: who/what/impact)\n'
        '- "attack_summary": string (2–4 sentences, plain language description of the attacker’s flow/sequence; if no concrete attack flow is described, give a concise explanation or set to an empty string)\n'
        '- "category": string, one of ["Active Exploitation","Malware/Campaign","Tooling/Kit","Vulnerability (no exploitation known)","Patch","Product/Feature Update","Opinion/Editorial","Research","Other"]\n'
        '- "priority": object, representing overall threat relevance:\n'
        '    - "score": integer 0–100 (0 = informational only, 100 = critical/urgent)\n'
        '    - "label": one of ["Informational","Low","Medium","High","Critical"]\n'
        '    - "reason": short explanation based on impact, exploitability, and exposure, only using information in the article\n'
        '- "financial_relevance": object, for financial-sector (banks, PSPs, card schemes, trading, insurance, etc.):\n'
        '    - "score": integer 0–100\n'
        '    - "label": one of ["None","Low","Medium","High","Critical"]\n'
        '    - "reason": short explanation of why this is or is not important to financial institutions\n'
        '- "mitre_techniques": list of objects:\n'
        '    - "id": MITRE ATT&CK ID, e.g. "T1190", or null if unknown\n'
        '    - "name": technique name\n'
        '    - "tactic": ATT&CK tactic, e.g. "Initial Access"\n'
        '    - "confidence": float 0–1\n'
        '    - "reason": short explanation based on the article text\n'
        '- "threat_actors": list of objects:\n'
        '    - "name": actor/campaign name if stated (e.g. "Scattered Spider","Lazarus"), otherwise empty string\n'
        '    - "type": e.g. "APT","Cybercrime","Ransomware group","Insider","Unknown"\n'
        '    - "country": country/region if explicitly stated or strongly implied, otherwise empty string\n'
        '    - "motivation": e.g. "Financial","Espionage","Hacktivism","Unknown"\n'
        '    - "confidence": float 0–1\n'
        '- "countries": list of objects (countries mentioned as victims, infrastructure, or attribution):\n'
        '    - "name": country name\n'
        '    - "role": e.g. "victim","infrastructure","attributed actor","other"\n'
        '    - "confidence": float 0–1\n'
        '- "vendors": list of objects:\n'
        '    - "name": vendor name (e.g. "Microsoft","Cisco","GitLab")\n'
        '    - "product": product or service name if stated (e.g. "Exchange Server","GitLab CE/EE")\n'
        '    - "confidence": float 0–1\n'
        '- "iocs": list of objects (indicators of compromise, ONLY if explicitly present in text):\n'
        '    - "type": e.g. "domain","ip","url","hash","email","filename","registry","other"\n'
        '    - "value": the exact IOC string as seen in the text\n'
        '    - "context": short description of how this IOC is used (e.g. "phishing URL","payload hash","C2 domain","malicious Docker image")\n'
        '    - "confidence": float 0–1\n'
        '- "cves": list of objects (must include every CVE ID explicitly mentioned in the text):\n'
        '    - "id": string CVE identifier, e.g. "CVE-2025-12345"\n'
        '    - "severity": string or null (e.g. "Critical","High","Medium","Low") if stated\n'
        '    - "cvss": string or null if a CVSS score is stated\n'
        '    - "description": short description of what is affected and impact, based only on the article\n'
        '- "detections": list of objects describing practical detection ideas/analytics:\n'
        '    - "name": short name, e.g. "AMOS macOS infostealer execution"\n'
        '    - "type": e.g. "Network","Endpoint","Email","Cloud","Identity","Generic"\n'
        '    - "idea": 1–3 sentences describing what to look for (conditions, patterns, logs)\n'
        '- "recommendations": list of objects for actionable response/hardening:\n'
        '    - "type": e.g. "Technical","Process","Awareness"\n'
        '    - "text": 1–3 sentences with concrete mitigation or response guidance\n'
        '- "tags": list of short strings (e.g. ["ransomware","windows","cloud","ddos","apt","phishing","infostealer"])\n'
        '- "source_analysis": object:\n'
        '    - "source_name": short name (e.g. "BleepingComputer","Vendor advisory","NCSC")\n'
        '    - "source_url": the URL you see below\n'
        '    - "trust_level": one of ["Low","Medium","High"] based on how reliable the source appears\n'
        '    - "reason": why this source is low/medium/high confidence\n'
        "Guidelines:\n"
        "- Base everything only on the article text and general MITRE ATT&CK knowledge.\n"
        "- If the article does not clearly state an actor/country/vendor/IOC/CVE, omit it or set low confidence and explain; do NOT invent names, values, or vendors.\n"
        "- For MITRE, only provide an ID if the technique is clearly inferable from the described behavior. If unsure, set \"id\" to null or omit the technique.\n"
        "- For IOCs, ONLY extract values explicitly present in the text (domains, IPs, URLs, hashes, emails, filenames, registry keys, etc.). Do NOT fabricate or normalize beyond what is visible.\n"
        "- Do NOT treat generic service/platform domains (e.g. \"docker.com\",\"hub.docker.com\",\"chatgpt.com\") as IOCs unless the article explicitly states they are used as malicious infrastructure.\n"
        "- Empty lists for mitre_techniques, iocs, cves, detections, or recommendations are acceptable if the article does not provide that information. Do NOT guess just to fill fields.\n"
        "- Priority should reflect overall threat relevance and urgency based on impact, signs of active exploitation, availability of PoC/exploit, and breadth of exposure.\n"
        "- If the article is mainly a product feature update, minor bugfix, marketing, or high-level advice, set category accordingly (e.g. \"Product/Feature Update\" or \"Opinion/Editorial\") and keep priority.score low (e.g. <= 20).\n"
        "- Financial relevance is about banks, PSPs, card data, securities, trading platforms, insurance, and related financial infrastructure. Explain your reasoning.\n"
        "- The attack_summary should clearly describe any concrete attack steps at a conceptual level without reproducing raw commands or very low-level syntax.\n"
        "- Detections and recommendations should be concise but concrete enough to guide SOC and incident response teams.\n"
        "- Do NOT include any markdown, bullet points, or commentary outside the JSON object.\n\n"
        "Return ONLY the JSON object, no extra commentary.\n\n"
        f"Article metadata:\n- Title: {title}\n- URL: {source}\n- Timestamp: {ts}\n\n"
        f'Full raw text:\n"""{snippet}"""'
    )
    return prompt



def _call_llm(prompt: str) -> Optional[Dict[str, Any]]:
    if not CONFIG.get("LLM_ENABLED", True):
        logger.info("LLM disabled via config; skipping LLM call")
        return None
    if not prompt:
        logger.warning("LLM prompt is empty; skipping")
        return None
    try:
        model = CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1"))
        url = f"{_ollama_host()}/api/generate"
        payload = {
            "model": model,
            "prompt": f"{SYSTEM_INSTRUCTION}\n\n{prompt}",
            "stream": False,
            "temperature": float(CONFIG.get("LLM_TEMPERATURE", 0.2)),
        }
        logger.info(
            "Calling Ollama model=%s host=%s prompt_chars=%s",
            model,
            url,
            len(payload.get("prompt", "")),
        )
        resp = requests.post(
            url,
            json=payload,
            timeout=CONFIG.get(
                "LLM_REQUEST_TIMEOUT", CONFIG.get("REQUEST_TIMEOUT", 300)
            ),
        )
        if resp.status_code != 200:
            logger.warning(
                "LLM HTTP error status=%s body=%s", resp.status_code, resp.text[:500]
            )
            resp.raise_for_status()
        data = resp.json()
        text = data.get("response")
        if not text:
            logger.warning("LLM response missing 'response' field")
            return None

        try:
            enriched = json.loads(text)
        except Exception:
            s = text.find("{")
            e = text.rfind("}")
            if s != -1 and e != -1 and e > s:
                try:
                    enriched = json.loads(text[s : e + 1])
                except Exception as ex_sub:
                    logger.warning(
                        "Failed to parse JSON from LLM response substring: %s ...",
                        text[s : min(e + 1, s + 500)],
                    )
                    return None
            else:
                logger.warning(
                    "LLM response not JSON parsable. Snippet: %s", text[:500]
                )
                return None

        if not isinstance(enriched, dict):
            logger.warning("LLM response JSON is not an object")
            return None
        logger.info("LLM call succeeded")
        return enriched
    except Exception as exc:
        logger.warning(
            "LLM call failed: %s. If this is model-not-found, run `ollama pull %s` or set OLLAMA_MODEL.",
            exc,
            CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3")),
        )
        return None


def _normalize_llm_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize LLM output keys to expected schema."""
    if not isinstance(payload, dict):
        return {}
    out = dict(payload)
    if "iocs" not in out and "indicators_of_compromise" in out:
        out["iocs"] = out.get("indicators_of_compromise") or []
    for key in (
        "mitre_techniques",
        "threat_actors",
        "countries",
        "vendors",
        "iocs",
        "cves",
        "detections",
        "recommendations",
        "tags",
    ):
        if key not in out or out.get(key) is None:
            out[key] = []
    return out


def _enrich_record_with_llm(record: Dict[str, Any]) -> Dict[str, Any]:
    logger.debug("Enriching record title=%s", record.get("title"))
    prompt = _build_prompt_from_raw(record)
    enriched = _call_llm(prompt)
    if enriched and isinstance(enriched, dict):
        record["llm"] = _normalize_llm_payload(enriched)
        logger.info("LLM enrichment succeeded for title=%s", record.get("title"))
    else:
        logger.info("LLM enrichment skipped/failed for title=%s", record.get("title"))
    return record


def _strip_raw_text_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("raw_text", "text", "full_text"):
        if k in record:
            record.pop(k, None)
    return record


def _write_ndjson(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    logger.info("Writing LLM NDJSON to %s", path)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            rec = _strip_raw_text_fields(rec)
            f.write(json.dumps(rec, ensure_ascii=False, indent=2) + "\n\n")


def _load_ndjson_flexible(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [r for r in obj if isinstance(r, dict)]
        if isinstance(obj, dict):
            return [obj]
    except Exception:
        pass

    records: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                records.append(obj)
            idx = end
        except Exception:
            break
    return records

def _build_markdown(records: List[Dict[str, Any]], input_file: Path) -> str:
    logger.info("Building LLM markdown from %s records", len(records))
    lines: List[str] = []
    lines.append("# LLM Unstructured Threat Intelligence Report")
    lines.append("")
    lines.append(f"_Source file: {input_file.name}_")
    lines.append("")

    def _fmt_kv(label: str, value: str | None) -> str:
        return f"**{label}:** {value}" if value else f"**{label}:** N/A"

    relevant: List[Dict[str, Any]] = []
    low: List[Dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        llm_payload = rec.get("llm") or {}
        priority = llm_payload.get("priority") or {}
        category = (llm_payload.get("category") or "").lower()
        score = priority.get("score")
        label = (priority.get("label") or "").lower()
        is_relevant = False
        if isinstance(score, (int, float)) and score >= 40:
            is_relevant = True
        elif label in {"high", "critical"}:
            is_relevant = True
        elif category in {
            "active exploitation",
            "malware/campaign",
            "tooling/kit",
            "vulnerability (no exploitation known)",
            "patch",
        }:
            is_relevant = True
        if is_relevant:
            relevant.append(rec)
        else:
            low.append(rec)

    def _render_record(idx: int, rec: Dict[str, Any]) -> None:
        title = rec.get("title") or "(no title)"
        source = rec.get("source") or ""
        ts = rec.get("@timestamp") or rec.get("timestamp") or ""
        llm_payload = rec.get("llm") or {}
        priority = llm_payload.get("priority") or {}
        fin = llm_payload.get("financial_relevance") or {}
        category = llm_payload.get("category") or ""
        pri_label = priority.get("label")
        pri_score = priority.get("score")
        fin_label = fin.get("label")
        fin_score = fin.get("score")
        badge_parts: List[str] = []
        if pri_label:
            if pri_score is not None:
                badge_parts.append(f"{pri_label} {pri_score}")
            else:
                badge_parts.append(str(pri_label))
        if category:
            badge_parts.append(str(category))
        if fin_label:
            if fin_score is not None:
                badge_parts.append(f"FI {fin_label} {fin_score}")
            else:
                badge_parts.append(f"FI {fin_label}")
        badge = f"[{' | '.join(badge_parts)}]" if badge_parts else ""
        header = f"## {idx}. {badge + ' ' if badge else ''}{title}".rstrip()
        lines.append(header)
        meta_parts: List[str] = []
        if source:
            meta_parts.append(f"Source: {source}")
        if ts:
            meta_parts.append(f"Timestamp: {ts}")
        if meta_parts:
            lines.append("_" + " • ".join(meta_parts) + "_")
        summary = llm_payload.get("summary")
        attack_summary = llm_payload.get("attack_summary")
        if summary:
            lines.append("")
            lines.append(_fmt_kv("Summary", summary))
        if attack_summary:
            lines.append(_fmt_kv("Attack Summary", attack_summary))
        mitre_raw = llm_payload.get("mitre_techniques") or []
        mitre = [m for m in mitre_raw if isinstance(m, dict)]
        lines.append("")
        lines.append("**MITRE Techniques:**")
        if mitre:
            for t in mitre:
                tid = t.get("id") or "N/A"
                name = t.get("name") or ""
                tactic = t.get("tactic") or ""
                conf = t.get("confidence")
                reason = t.get("reason") or ""
                parts = [tid]
                if name:
                    parts.append(name)
                if tactic:
                    parts.append(f"({tactic})")
                extras: List[str] = []
                if conf is not None:
                    extras.append(f"conf {conf}")
                detail = ", ".join(extras)
                suffix = f" — {reason}" if reason else ""
                lines.append(f"- {' '.join(parts)}{f' [{detail}]' if detail else ''}{suffix}".strip())
        else:
            lines.append("- N/A")
        if priority:
            lines.append("")
            lines.append("**Priority:**")
            lines.append(
                f"- {priority.get('label','N/A')} {priority.get('score','N/A')} — {priority.get('reason','')}"
            )
        fin = llm_payload.get("financial_relevance") or {}
        if fin:
            lines.append("")
            lines.append("**Financial Relevance:**")
            lines.append(
                f"- {fin.get('label','N/A')} {fin.get('score','N/A')} — {fin.get('reason','')}"
            )
        actors = llm_payload.get("threat_actors") or []
        lines.append("")
        lines.append("**Threat Actors:**")
        if actors:
            for a in actors:
                name = a.get("name") or "Unknown"
                typ = a.get("type") or ""
                country = a.get("country") or ""
                motivation = a.get("motivation") or ""
                conf = a.get("confidence")
                parts: List[str] = [name]
                if typ:
                    parts.append(f"({typ})")
                if country:
                    parts.append(f"[{country}]")
                if motivation:
                    parts.append(f"- {motivation}")
                if conf is not None:
                    parts.append(f"(conf {conf})")
                lines.append("- " + " ".join(parts))
        else:
            lines.append("- N/A")
        countries = llm_payload.get("countries") or []
        lines.append("")
        lines.append("**Countries:**")
        if countries:
            for c in countries:
                nm = c.get("name") or "Unknown"
                role = c.get("role") or ""
                conf = c.get("confidence")
                parts: List[str] = [nm]
                if role:
                    parts.append(f"({role})")
                if conf is not None:
                    parts.append(f"conf {conf}")
                lines.append("- " + " ".join(parts))
        else:
            lines.append("- N/A")
        vendors = llm_payload.get("vendors") or []
        lines.append("")
        lines.append("**Vendors/Products:**")
        if vendors:
            for v in vendors:
                nm = v.get("name") or "Unknown"
                prod = v.get("product") or ""
                conf = v.get("confidence")
                txt = nm
                if prod:
                    txt += f" / {prod}"
                if conf is not None:
                    txt += f" (conf {conf})"
                lines.append(f"- {txt}")
        else:
            lines.append("- N/A")
        iocs = llm_payload.get("iocs") or []
        lines.append("")
        lines.append("**IOCs:**")
        if iocs:
            for i in iocs:
                if isinstance(i, dict):
                    typ = i.get("type") or ""
                    val = i.get("value") or i.get("indicator") or ""
                    ctx = i.get("context") or ""
                    conf = i.get("confidence")
                else:
                    typ = ""
                    val = str(i)
                    ctx = ""
                    conf = None
                ctx_str = f" — {ctx}" if ctx else ""
                conf_str = f" (conf {conf})" if conf is not None else ""
                lines.append(f"- {typ}: {val}{ctx_str}{conf_str}")
        else:
            lines.append("- N/A")
        cves = llm_payload.get("cves") or []
        lines.append("")
        lines.append("**CVEs:**")
        if cves:
            for cve in cves:
                cid = cve.get("id") or ""
                sev = cve.get("severity") or ""
                cvss = cve.get("cvss") or ""
                desc = cve.get("description") or ""
                parts: List[str] = [cid] if cid else []
                if sev:
                    parts.append(f"[{sev}]")
                if cvss:
                    parts.append(f"CVSS {cvss}")
                suffix = f" — {desc}" if desc else ""
                if parts:
                    lines.append(f"- {' '.join(parts)}{suffix}")
        else:
            lines.append("- N/A")
        detections = llm_payload.get("detections") or []
        lines.append("")
        lines.append("**Detections:**")
        if detections:
            for d in detections:
                name = d.get("name") or ""
                typ = d.get("type") or ""
                idea = d.get("idea") or ""
                lines.append(f"- {name}{f' ({typ})' if typ else ''}: {idea}")
        else:
            lines.append("- N/A")
        recos = llm_payload.get("recommendations") or []
        lines.append("")
        lines.append("**Recommendations:**")
        if recos:
            for r in recos:
                rtyp = r.get("type") or ""
                text = r.get("text") or ""
                lines.append(f"- {rtyp}: {text}" if rtyp else f"- {text}")
        else:
            lines.append("- N/A")
        tags = llm_payload.get("tags") or []
        if tags:
            lines.append("")
            lines.append("**Tags:** " + ", ".join(tags))
        src = llm_payload.get("source_analysis") or {}
        if src:
            lines.append("")
            lines.append("**Source Analysis:**")
            lines.append(
                f"- {src.get('source_name','N/A')} ({src.get('trust_level','N/A')}): {src.get('reason','')}"
            )
            if src.get("source_url"):
                lines.append(f"- URL: {src.get('source_url')}")
        lines.append("")

    for idx, rec in enumerate(relevant, start=1):
        _render_record(idx, rec)

    if low:
        lines.append("## Low Relevance / FYI")
        lines.append("")
        for rec in low:
            title = rec.get("title") or "(no title)"
            source = rec.get("source") or ""
            ts = rec.get("@timestamp") or rec.get("timestamp") or ""
            llm_payload = rec.get("llm") or {}
            priority = llm_payload.get("priority") or {}
            pri_label = priority.get("label") or "Informational"
            pri_score = priority.get("score")
            badge = f"[{pri_label}{f' {pri_score}' if pri_score is not None else ''}]"
            header = f"- {badge} {title}"
            meta_parts: List[str] = []
            if source:
                meta_parts.append(f"Source: {source}")
            if ts:
                meta_parts.append(f"Timestamp: {ts}")
            if meta_parts:
                header += " — " + " • ".join(meta_parts)
            lines.append(header)
        lines.append("")

    return "\n".join(lines)

# =========================
# ========= Runner ========
# =========================
def run_llm_rawtext(hours: Optional[int] = None) -> Dict[str, Any]:
    output_dir = _get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    llm_root = Path(CONFIG.get("OUTPUT_DIR_LLM_RAW") or output_dir)
    try:
        llm_root = llm_root.parents[1]
    except Exception:
        llm_root = llm_root.parent
    logger.debug("Searching for latest rawtext under %s", llm_root)
    raw_path = _find_latest_rawtext_any(llm_root)
    if raw_path is None:
        logger.warning("No rawtext file found under %s; skipping LLM run", llm_root)
        return {
            "input_file": None,
            "output_ndjson": None,
            "output_markdown": None,
            "records_total": 0,
            "records_processed": 0,
        }
    logger.info("Using rawtext file: %s", raw_path)
    records = _load_rawtext_records(raw_path)
    total = len(records)
    if hours:
        records = _filter_by_hours(records, hours)
        logger.info("Filtered records by last %s hours: %s -> %s", hours, total, len(records))
    if not records:
        logger.warning("No records to enrich after filtering; exiting LLM run")
        return {
            "input_file": str(raw_path),
            "output_ndjson": None,
            "output_markdown": None,
            "records_total": total,
            "records_processed": 0,
        }
    processed: List[Dict[str, Any]] = []
    avg_secs = 0.0
    success_count = 0
    progress_state = {"current": 0, "status": ""}
    animator = start_live_progress("LLM", len(records), progress_state)
    try:
        for idx, rec in enumerate(records, start=1):
            title = rec.get("title") or "(no title)"
            short_title = _shorten_title(title)
            remaining = len(records) - (idx - 1)
            eta_secs = avg_secs * remaining
            progress_state["current"] = idx - 1
            progress_state["status"] = f"{idx}/{len(records)} {_format_eta(eta_secs)} | {short_title}"

            start_ts = datetime.now()
            logger.info("LLM enriching %s/%s: %s", idx, len(records), title)
            rec = _enrich_record_with_llm(rec)
            rec = _strip_raw_text_fields(rec)
            elapsed = (datetime.now() - start_ts).total_seconds()
            avg_secs = ((avg_secs * (idx - 1)) + elapsed) / idx
            remaining = len(records) - idx
            eta_secs = avg_secs * remaining

            if rec.get("llm"):
                success_count += 1
            logger.info(
                "LLM completed %s/%s in %.1fs (avg %.1fs, ETA %s, remaining %s): %s",
                idx,
                len(records),
                elapsed,
                avg_secs,
                _format_eta(eta_secs),
                remaining,
                title,
            )
            processed.append(rec)
            progress_state["current"] = idx
            progress_state["status"] = f"{idx}/{len(records)} {_format_eta(eta_secs)} | {short_title}"
    finally:
        progress_state["current"] = len(records) if records else 0
        progress_state["status"] = f"{len(records)}/{len(records)} {_format_eta(0)}"
        stop_live_progress(animator[0], animator[1], wait=True)
    today_stamp = datetime.now().strftime("%Y%m%d")
    ndjson_path = output_dir / f"{RAWTEXT_LLM_PREFIX}{today_stamp}.ndjson"
    md_path = output_dir / f"{LLM_MD_PREFIX}{today_stamp}.md"
    _write_ndjson(ndjson_path, processed)
    md_text = _build_markdown(processed, raw_path)
    md_path.write_text(md_text, encoding="utf-8")
    logger.info(
        "LLM rawtext run complete: total=%s processed=%s ndjson=%s md=%s",
        total,
        len(processed),
        ndjson_path,
        md_path,
    )
    logger.info(
        "LLM enrichment summary: successes=%s failures=%s",
        success_count,
        len(processed) - success_count,
    )
    return {
        "input_file": str(raw_path),
        "output_ndjson": str(ndjson_path),
        "output_markdown": str(md_path),
        "records_total": total,
        "records_processed": len(processed),
    }
