from __future__ import annotations

import calendar
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from datetime import datetime, timezone, timedelta

import feedparser
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparser

from .config import CONFIG, logger, mute_console
from .progress import progress_bar, start_live_progress, stop_live_progress
# =========================
# ===== Module Config =====
# =========================
OUTPUT_DIR = CONFIG.get("OUTPUT_DIR_UNSTRUCTURED", "")
DEFAULT_HOURS = 24
WEEKLY_RECAP_MARKER = "weekly recap"
MAX_WORKERS_DEFAULT = CONFIG.get("MAX_WORKERS", 6)
PROGRESS_PREFIX_FEEDS = "Feeds"
PROGRESS_PREFIX_ARTICLES = "Articles"


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


def fetch_article_text(url: str, timeout: int = 15) -> dict:
    if not url:
        return {"text": ""}
    headers = {"User-Agent": CONFIG.get("HTTP_USER_AGENT", "Mozilla/5.0")}
    proxies = CONFIG.get("PROXIES") or None
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, proxies=proxies)
        resp.raise_for_status()
        txt = html_to_main_text(resp.text)
        return {"text": _dehyphenate_text(txt)}
    except Exception as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
        return {"text": ""}


def extract_iocs(text: str, source: str | None = None, title: str | None = None):
    if not text:
        return []
    iocs = []
    # Basic patterns
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url_re = re.compile(r"https?://[\w\-.\/?&=%#]+", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_re = re.compile(r"\b([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
    hash_re = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

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

    # Deduplicate by (type,value)
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


def run_fetch_rawtext(hours: int = DEFAULT_HOURS) -> dict:
    mute_console()
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

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_DEFAULT) as ex:
        futures = {
            ex.submit(fetch_article_text, link): (link, title, pub_dt, summary)
            for link, title, pub_dt, summary in uniq
        }
        completed = 0
        for fut in as_completed(futures):
            completed += 1
            status = f"fetched:{completed}/{total_entries}"
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
    logger.info("Wrote rawtext json: %s", out_raw)
    return {
        "records_total": len(records),
        "rawtext_path": out_raw,
        "discovered_entries": len(entries),
        "after_url_dedupe": len(uniq),
    }

def run_unstructured_rss_analysis(hours: int = DEFAULT_HOURS) -> dict:
    logger.warning("run_unstructured_rss_analysis is deprecated; running rawtext fetch only.")
    return run_fetch_rawtext(hours=hours)


# Preferred entry point name for clarity now that only fetching remains.
def run_fetch(hours: int = DEFAULT_HOURS) -> dict:
    return run_fetch_rawtext(hours=hours)
