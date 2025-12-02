from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# =========================
# ===== Third-Party =======
# =========================
import feedparser
from dateutil import parser as dtparser

# =========================
# ====== Local App ========
# =========================
from .config import CONFIG, fetch_json, logger, mute_console, safe_get, write_jsonl
from .progress import animate_progress, progress_bar

CRITICAL_THRESHOLD = CONFIG["CRITICAL_THRESHOLD"]
INTERESTING_MIN = CONFIG["INTERESTING_MIN"]
VENDORS = CONFIG["VENDORS"]
RSS_FEEDS = CONFIG["RSS_FEEDS"]
NVD_API_BASE = CONFIG["NVD_API_BASE"]
CISA_KEV_URL = CONFIG["CISA_KEV_URL"]
COMMUNITY_KEV_URL = CONFIG["COMMUNITY_KEV_URL"]
OUTPUT_DIR = CONFIG["OUTPUT_DIR_STRUCTURED"]
PROGRESS_TOTAL_STEPS = 6


def build_vendor_pattern(vendor: str) -> re.Pattern:
    if vendor.lower().startswith("forti"):
        return re.compile(r"(?i)\bForti\w*\b")
    if vendor.lower().startswith("palo alto"):
        return re.compile(r"(?i)(\bPalo\s*Alto(\s*Networks)?\b|\bPAN-[A-Za-z0-9]+\b)")
    escaped = re.escape(vendor).replace(r"\ ", r"\s+")
    return re.compile(rf"(?i)\b{escaped}\b")


def build_vendor_patterns(vendors: List[str]) -> List[Tuple[str, re.Pattern]]:
    return [(v, build_vendor_pattern(v)) for v in vendors]


def match_vendor(
    field_text: str, patterns: List[Tuple[str, re.Pattern]]
) -> Optional[str]:
    if not field_text:
        return None
    for vendor, pattern in patterns:
        if pattern.search(field_text):
            return vendor
    return None


def extract_vendor_from_cpes(
    cve: Dict[str, Any], patterns: List[Tuple[str, re.Pattern]]
) -> Optional[str]:
    cfg = cve.get("configurations") or {}
    nodes = cfg.get("nodes", []) if isinstance(cfg, dict) else []
    for node in nodes:
        for match in node.get("cpeMatch", []) or []:
            uri = match.get("cpe23Uri") or match.get("cpe23Uri")
            if not uri:
                continue
            v = match_vendor(uri, patterns)
            if v:
                return v
            parts = uri.split(":")
            if len(parts) > 3:
                vendor_comp = parts[3]
                v2 = match_vendor(vendor_comp, patterns)
                if v2:
                    return v2
    return None


def scan_text_fields_for_vendor(
    cve: Dict[str, Any], patterns: List[Tuple[str, re.Pattern]]
) -> Optional[str]:
    texts = []
    for d in cve.get("descriptions", []):
        if isinstance(d, dict):
            texts.append(d.get("value", ""))
        else:
            texts.append(str(d))
    refs = cve.get("references") or {}
    if isinstance(refs, dict):
        for rd in refs.get("reference_data", []) or refs.get("referenceData", []) or []:
            texts.append(rd.get("url", ""))
            texts.append(rd.get("description", ""))
    elif isinstance(refs, list):
        for rd in refs:
            if isinstance(rd, dict):
                texts.append(rd.get("url", ""))
                texts.append(rd.get("description", ""))
            else:
                texts.append(str(rd))

    combined = "\n".join([t for t in texts if t])
    return match_vendor(combined, patterns) if combined else None


def fetch_nvd_window(start: datetime, end: datetime, mode: str) -> List[Dict[str, Any]]:
    params = {"resultsPerPage": 2000}
    start_ts = start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_ts = end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if mode == "published":
        params["pubStartDate"] = start_ts
        params["pubEndDate"] = end_ts
    else:
        params["lastModStartDate"] = start_ts
        params["lastModEndDate"] = end_ts

    logger.info(f"NVD {mode} window: {start.isoformat()} → {end.isoformat()}")
    j = fetch_json(NVD_API_BASE, params)
    return j.get("vulnerabilities", [])


def fetch_nvd_single(cve_id: str) -> Optional[Dict[str, Any]]:
    j = fetch_json(NVD_API_BASE, {"cveId": cve_id})
    vulns = j.get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None


def fetch_kev_sources() -> set:
    kev_ids = set()
    for url in (CISA_KEV_URL, COMMUNITY_KEV_URL):
        j = fetch_json(url)
        for v in j.get("vulnerabilities", []):
            cve_id = v.get("cveID") or v.get("cve_id")
            if cve_id:
                kev_ids.add(cve_id.upper())
    logger.info(f"Loaded {len(kev_ids)} KEV IDs (CISA + community)")
    return kev_ids


def parse_rss_feeds() -> List[Dict[str, str]]:
    results = []
    for feed in RSS_FEEDS:
        try:
            parsed = feedparser.parse(feed)
            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                link = entry.get("link", "")
                matches = re.findall(
                    r"CVE-\d{4}-\d{4,7}", f"{title} {summary}", flags=re.I
                )
                for m in matches:
                    results.append({"cve": m.upper(), "link": link})
        except Exception as e:
            logger.warning(f"RSS parse failed for {feed}: {e}")
    return results


def extract_description(cve: Dict[str, Any]) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_cvss(cve: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics", {})
    for m in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        data = metrics.get(m)
        if not data:
            continue
        item = (
            data[0].get("cvssData", {})
            if isinstance(data, list)
            else data.get("cvssData", {})
        )
        return item.get("baseScore"), item.get("baseSeverity")
    return None, None


def normalize_cve(
    cve: Dict[str, Any], vendor: str, kev_ids: set, from_article=False, source=None
) -> Dict[str, Any]:
    score, severity = extract_cvss(cve)
    desc = extract_description(cve)
    pub = cve.get("published", cve.get("publishedDate"))
    mod = cve.get("lastModified", cve.get("lastModifiedDate"))

    try:
        pub_iso = (
            dtparser.parse(pub).astimezone(timezone.utc).isoformat() if pub else None
        )
    except Exception:
        pub_iso = None
    try:
        mod_iso = (
            dtparser.parse(mod).astimezone(timezone.utc).isoformat() if mod else None
        )
    except Exception:
        mod_iso = None

    return {
        "@timestamp": pub_iso,
        "vulnerability": {
            "id": cve.get("id"),
            "description": desc,
            "score": {"base": score},
            "severity": severity,
            "known_exploited": cve.get("id", "").upper() in kev_ids,
            "published": pub_iso,
            "last_modified": mod_iso,
        },
        "vendor": {"name": vendor},
        "source": {"url": source},
        "from_article": from_article,
    }


def generate_markdown(
    critical, interesting, modified, hours: int, output_dir: str
) -> str:
    date_stamp = datetime.now().strftime("%Y%m%d")
    md_path = os.path.join(output_dir, f"StructuredCVEReport_{date_stamp}.md")

    lines = [
        "# Structured CVE Intelligence Report\n",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n",
        f"**Window:** Last {hours} hours\n",
        "---\n",
    ]

    def fmt(r, show_modified=False):
        vuln = r["vulnerability"]
        src = r.get("source", {}).get("url")
        desc = (vuln["description"] or "").replace("\n", " ")[:400] + "..."
        parts = [
            f"### {vuln['id']}",
            f"**Vendor:** {r['vendor']['name']}",
            f"**CVSS Base Score:** {vuln['score']['base'] or 'N/A'}",
            f"**Severity:** {vuln['severity'] or 'N/A'}",
            f"**Published:** {vuln.get('published') or 'N/A'}",
        ]
        if show_modified:
            parts.append(f"**Last Modified:** {vuln.get('last_modified') or 'N/A'}")
        if vuln.get("known_exploited"):
            parts.append("**Known Exploited (KEV):** Yes")
        if src:
            parts.append(f"**Source:** [{src}]({src})")
        parts.append(f"**Description:** {desc}")
        parts.append("\n---\n")
        return "\n".join(parts)

    sections = [
        (f"## Critical CVEs (CVSS ≥ {CRITICAL_THRESHOLD})\n", critical),
        (
            f"## Interesting CVEs (CVSS {INTERESTING_MIN}–{CRITICAL_THRESHOLD})\n",
            interesting,
        ),
        (f"## Recently Modified CVEs (Last {hours}h)\n", modified),
    ]

    for title, group in sections:
        lines.append(title)
        if group:
            lines.extend(fmt(r, show_modified=(group == modified)) for r in group)
        else:
            lines.append("_None found._\n\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    logger.info(f"Wrote Markdown report: {md_path}")
    return md_path


def run_structured_collection(hours: int, skip_history=False) -> Dict[str, Any]:
    mute_console()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if skip_history:
        pass
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        progress_bar(0, PROGRESS_TOTAL_STEPS, prefix="Structured: initializing")

        animate_progress("Fetching KEV sources", 15)
        kev_ids = fetch_kev_sources()
        progress_bar(1, PROGRESS_TOTAL_STEPS, prefix="Structured: KEV fetched")

        animate_progress("Fetching NVD data", 25)
        patterns = build_vendor_patterns(VENDORS)
        published_data = fetch_nvd_window(start, end, mode="published")
        modified_data = fetch_nvd_window(start, end, mode="modified")
        results = {}

        for item in published_data:
            cve = item["cve"]
            vendor_field = (
                safe_get(cve, "vendorProject")
                or safe_get(cve, "sourceIdentifier")
                or ""
            )
            vendor = match_vendor(vendor_field, patterns)
            if not vendor:
                vendor = extract_vendor_from_cpes(
                    cve, patterns
                ) or scan_text_fields_for_vendor(cve, patterns)
            if vendor:
                entry = normalize_cve(cve, vendor, kev_ids)
                pub_str = entry.get("vulnerability", {}).get("published")
                if pub_str:
                    try:
                        pub_dt = dtparser.parse(pub_str).astimezone(timezone.utc)
                        if pub_dt < start:
                            entry["modified_only"] = True
                    except Exception:
                        entry["modified_only"] = True
                else:
                    entry["modified_only"] = True

                results[cve["id"]] = entry

        for item in modified_data:
            cve = item["cve"]
            vendor_field = (
                safe_get(cve, "vendorProject")
                or safe_get(cve, "sourceIdentifier")
                or ""
            )
            vendor = match_vendor(vendor_field, patterns)
            if not vendor:
                vendor = extract_vendor_from_cpes(
                    cve, patterns
                ) or scan_text_fields_for_vendor(cve, patterns)
            if vendor and cve["id"] not in results:
                entry = normalize_cve(cve, vendor, kev_ids)
                entry["modified_only"] = True
                results[cve["id"]] = entry

        progress_bar(
            3, PROGRESS_TOTAL_STEPS, prefix=f"Structured: {len(results)} vendor CVEs"
        )

        animate_progress("Parsing RSS feeds", 20)
        rss_hits = parse_rss_feeds()
        for feed_cve in rss_hits:
            cve_id = feed_cve["cve"]
            if cve_id in results:
                continue
            cve_obj = fetch_nvd_single(cve_id)
            if not cve_obj:
                continue
            vendor_field = (
                safe_get(cve_obj, "vendorProject")
                or safe_get(cve_obj, "sourceIdentifier")
                or ""
            )
            vendor = match_vendor(vendor_field, patterns)
            if not vendor:
                vendor = extract_vendor_from_cpes(
                    cve_obj, patterns
                ) or scan_text_fields_for_vendor(cve_obj, patterns)
            if vendor:
                entry = normalize_cve(
                    cve_obj, vendor, kev_ids, from_article=True, source=feed_cve["link"]
                )
                pub_str = entry.get("vulnerability", {}).get("published")
                if pub_str:
                    try:
                        pub_dt = dtparser.parse(pub_str).astimezone(timezone.utc)
                        if pub_dt < start:
                            entry["modified_only"] = True
                            entry["article_discovered"] = True
                    except Exception:
                        pass
                else:
                    entry["article_discovered"] = True

                results[cve_id] = entry

        records = list(results.values())
        new_cves = []
        modified_cves = []
        for r in records:
            if r.get("modified_only"):
                modified_cves.append(r)
                continue
            pub_str = r.get("vulnerability", {}).get("published")
            if not pub_str:
                modified_cves.append(r)
                continue
            try:
                pub_dt = dtparser.parse(pub_str).astimezone(timezone.utc)
                if pub_dt >= start:
                    new_cves.append(r)
                else:
                    modified_cves.append(r)
            except Exception:
                modified_cves.append(r)

        critical, interesting = [], []
        for r in new_cves:
            s = safe_get(r, "vulnerability.score.base")
            if not s:
                continue
            try:
                s = float(s)
            except Exception:
                continue
            if s >= CRITICAL_THRESHOLD:
                critical.append(r)
            elif INTERESTING_MIN <= s < CRITICAL_THRESHOLD:
                interesting.append(r)

        progress_bar(4, PROGRESS_TOTAL_STEPS, prefix="Structured: Categorized")

        date_stamp = datetime.now().strftime("%Y%m%d")
        ndjson_path = os.path.join(OUTPUT_DIR, f"StructuredCVEData_{date_stamp}.ndjson")
        try:
            progress_bar(0, 1, prefix="Write NDJSON")
        except Exception:
            pass
        write_jsonl(ndjson_path, records)
        try:
            progress_bar(1, 1, prefix="Write NDJSON")
        except Exception:
            pass

        try:
            progress_bar(0, 1, prefix="Write Markdown")
        except Exception:
            pass
        generate_markdown(critical, interesting, modified_cves, hours, OUTPUT_DIR)
        try:
            progress_bar(1, 1, prefix="Write Markdown")
        except Exception:
            pass

        progress_bar(6, PROGRESS_TOTAL_STEPS, prefix="Structured: done")

    finally:
        pass

    return {
        "records_total": len(results),
        "new": len(new_cves),
        "modified": len(modified_cves),
        "critical": len(critical),
        "interesting": len(interesting),
        "output": OUTPUT_DIR,
    }
