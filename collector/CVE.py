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
from .LLM import _call_llm
from .progress import animate_progress, progress_bar

CRITICAL_THRESHOLD = CONFIG["CRITICAL_THRESHOLD"]
INTERESTING_MIN = CONFIG["INTERESTING_MIN"]
VENDORS = CONFIG["VENDORS"]
EXCLUDED_SOFTWARE = {v.lower() for v in CONFIG.get("EXCLUDED_SOFTWARE") or []}
RSS_FEEDS = CONFIG["RSS_FEEDS"]
NVD_API_BASE = CONFIG["NVD_API_BASE"]
CISA_KEV_URL = CONFIG["CISA_KEV_URL"]
COMMUNITY_KEV_URL = CONFIG["COMMUNITY_KEV_URL"]
OUTPUT_DIR = CONFIG["OUTPUT_DIR_STRUCTURED"]
PROGRESS_TOTAL_STEPS = 6

# =========================
# ===== Vendor Helpers ====
# =========================


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


def collect_cpe_products(cve: Dict[str, Any]) -> List[str]:
    products: List[str] = []
    cfg = cve.get("configurations") or {}
    nodes = cfg.get("nodes", []) if isinstance(cfg, dict) else []
    for node in nodes:
        for match in node.get("cpeMatch", []) or []:
            uri = match.get("cpe23Uri") or match.get("criteria")
            if not uri:
                continue
            parts = uri.split(":")
            if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                prod = parts[4]
                if prod:
                    products.append(prod)
    return products


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
    logger.info("Fetching KEV sources (CISA + community)")
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


def _collect_cpes(cve: Dict[str, Any]) -> list[str]:
    cpes = []
    cfg = cve.get("configurations") or {}
    nodes = cfg.get("nodes", []) if isinstance(cfg, dict) else []
    for node in nodes:
        for match in node.get("cpeMatch", []) or []:
            uri = match.get("cpe23Uri") or match.get("criteria")
            if uri:
                cpes.append(uri)
    return cpes


def _llm_refine_cve(entry: Dict[str, Any], cve_raw: Dict[str, Any]) -> Dict[str, Any]:
    if not CONFIG.get("LLM_ENABLED", True):
        return entry

    cve_id = safe_get(entry, "vulnerability.id") or cve_raw.get("id")
    if not cve_id:
        return entry

    entry.setdefault("vendor", {})
    entry.setdefault("vulnerability", {})

    def _parse_cpe_vendor(cpe_uri: str) -> Optional[str]:
        try:
            parts = cpe_uri.split(":")
            if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                return parts[3] or None
        except Exception:
            return None
        return None

    cpes: List[str] = _collect_cpes(cve_raw) or []
    cpe_vendors = {
        v.strip()
        for v in (_parse_cpe_vendor(cpe) for cpe in cpes)
        if v and v.strip()
    }

    current_vendor = safe_get(entry, "vendor.name") or ""

    prompt_parts: List[str] = [
        "You are validating CVE metadata.",
        "You must use ONLY the information explicitly present in the provided description and CPE URIs.",
        "Do NOT infer, guess, or rely on any outside knowledge.",
        "",
        "Return a single JSON object with EXACTLY these keys:",
        '- \"vendor\": string',
        '- \"description\": string',
        '- \"affected\": list of objects with keys \"product\" (string) and \"version\" (string)',
        "",
        "STRICT RULES:",
        "1. VENDOR",
        "   - The vendor MUST come directly from the CPEs (cpe:2.3:a:<vendor>:<product>:...) if any exist.",
        "   - If NO CPEs exist, and the description explicitly names a clear software vendor, you MAY use that.",
        "   - If multiple vendors appear, choose the one associated with the affected product according to the CPEs or description.",
        "   - If you are not certain, set vendor to \"\" (empty string). Never guess.",
        "",
        "2. DESCRIPTION",
        "   - Produce a concise 1–3 sentence human-readable summary.",
        "   - Base it ONLY on the provided description text.",
        "   - Do NOT add details not explicitly stated.",
        "",
        "3. AFFECTED",
        "   - Derive ONLY from CPE URIs or explicit version ranges in the description.",
        "   - For each object in 'affected', include product and version.",
        "   - If no clear product/version information exists, return an empty list.",
        "",
        "4. PROHIBITIONS",
        "   - NEVER invent vendors, products, or versions.",
        "   - NEVER infer vendor from the organization reporting or fixing the issue.",
        "   - NEVER infer vendor from typical vendors of a vulnerability class.",
        "   - NEVER alter, omit, or restate the CVE ID.",
        "   - Do NOT include any extra keys beyond vendor, description, affected.",
        "",
        "5. FORMAT",
        "   - Return ONLY raw JSON.",
        "",
        f"CVE: {cve_id}",
        f"Current vendor: {current_vendor}",
        f"CVSS: {safe_get(entry,'vulnerability.score.base')} severity={safe_get(entry,'vulnerability.severity')}",
        f"Known exploited: {safe_get(entry,'vulnerability.known_exploited')}",
        "",
        "Description:",
        extract_description(cve_raw) or "",
        "",
        "CPE URIs:",
    ]

    if cpes:
        prompt_parts.extend(cpes)
    else:
        prompt_parts.append("(none)")

    prompt = "\n".join(prompt_parts)

    try:
        llm_resp = _call_llm(prompt)
    except Exception as exc:
        logger.debug("LLM CVE enrich failed for %s: %s", cve_id, exc)
        return entry

    if isinstance(llm_resp, str):
        try:
            llm_resp = json.loads(llm_resp)
        except Exception:
            return entry

    if not isinstance(llm_resp, Dict):
        return entry

    vendor_new = llm_resp.get("vendor")
    if isinstance(vendor_new, str):
        vendor_new = vendor_new.strip()

    def _is_generic_vendor(v: str) -> bool:
        return v.lower() in {"", "unknown", "n/a", "none", "null"}

    if isinstance(vendor_new, str) and not _is_generic_vendor(vendor_new):
        if cpe_vendors:
            normalized_new = vendor_new.casefold()
            normalized_cpe_vendors = {v.casefold() for v in cpe_vendors}
            if (
                normalized_new in normalized_cpe_vendors
                or (current_vendor and normalized_new == current_vendor.casefold())
            ):
                entry["vendor"]["name"] = vendor_new
            else:
                logger.debug(
                    "LLM vendor '%s' rejected for %s (CPE vendors: %s)",
                    vendor_new,
                    cve_id,
                    cpe_vendors,
                )
        else:
            entry["vendor"]["name"] = vendor_new

    desc_new = llm_resp.get("description")
    if isinstance(desc_new, str) and desc_new.strip():
        entry["vulnerability"]["description_llm"] = desc_new.strip()

    affected = llm_resp.get("affected")
    if isinstance(affected, list):
        clean: List[Dict[str, Any]] = []
        for a in affected:
            if not isinstance(a, dict):
                continue
            prod = a.get("product")
            ver = a.get("version")
            if not isinstance(prod, str):
                continue
            prod = prod.strip()
            if not prod:
                continue
            item: Dict[str, Any] = {"product": prod}
            if isinstance(ver, str) and ver.strip():
                item["version"] = ver.strip()
            clean.append(item)
        if clean:
            entry["vulnerability"]["affected_software"] = clean

    return entry


def generate_markdown(
    critical, interesting, modified, hours: int, output_dir: str
) -> str:
    date_stamp = datetime.now().strftime("%Y%m%d")
    md_path = os.path.join(output_dir, f"StructuredCVEReport_{date_stamp}.md")

    total_modified = len(modified)
    total_new = max(0, len((critical or [])) + len((interesting or [])) - total_modified)

    lines = [
        "# Structured CVE Intelligence Report\n",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n",
        f"**Window:** Last {hours} hours\n",
        f"**New CVEs:** {total_new}\n",
        f"**Modified CVEs:** {total_modified}\n",
        "---\n",
    ]

    def cve_link(cve_id: str) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    all_recs = (critical or []) + (interesting or []) + (modified or [])
    vendor_groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in all_recs:
        vendor = safe_get(r, "vendor.name") or "Unknown Vendor"
        vendor_groups.setdefault(vendor, []).append(r)

    if vendor_groups:
        top_vendor = max(vendor_groups.items(), key=lambda kv: len(kv[1]))
        lines.insert(4, f"**Top Vendor by Count:** {top_vendor[0]} ({len(top_vendor[1])})\n")

    def _parse_dt(val: Optional[str]) -> datetime:
        if not val:
            return datetime.min.replace(tzinfo=timezone.utc)
        try:
            return dtparser.parse(val).astimezone(timezone.utc)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    for vendor in sorted(vendor_groups.keys()):
        group = vendor_groups[vendor]
        modified_group = [g for g in group if g.get("modified_only")]
        new_group = [g for g in group if not g.get("modified_only")]

        modified_group.sort(
            key=lambda r: _parse_dt(safe_get(r, "vulnerability.last_modified")), reverse=True
        )
        new_group.sort(
            key=lambda r: _parse_dt(safe_get(r, "vulnerability.published")), reverse=True
        )

        ordered = modified_group + new_group

        lines.append(f"## Vendor: {vendor} (Total {len(group)})\n")
        for r in ordered:
            vuln = r.get("vulnerability", {})
            cve_id = vuln.get("id") or "Unknown CVE"
            score = vuln.get("score", {}).get("base")
            severity = vuln.get("severity") or "N/A"
            published = vuln.get("published") or "N/A"
            last_modified = vuln.get("last_modified") or "N/A"
            known = "Yes" if vuln.get("known_exploited") else "No"
            desc = (
                vuln.get("description_llm")
                or vuln.get("description")
                or ""
            ).replace("\n", " ").strip()
            header = f"### [{cve_id}]({cve_link(cve_id)})"
            if r.get("modified_only"):
                header += " (Modified)"
            lines.append(header)
            lines.append(f"- CVSS Base Score: {score if score is not None else 'N/A'}")
            lines.append(f"- Severity: {severity}")
            lines.append(f"- Published: {published}")
            lines.append(f"- Last Modified: {last_modified}")
            lines.append(f"- Known Exploited (KEV): {known}")
            lines.append(f"- Description: {desc if desc else 'N/A'}")

            affected = vuln.get("affected_software") or []
            if affected:
                for sw in affected:
                    prod = sw.get("product", "Unknown product")
                    ver = sw.get("version")
                    suffix = f" version {ver}" if ver else ""
                    lines.append(f"- Affected: {prod}{suffix}")
            else:
                lines.append("- Affected: N/A")

            mitigations = r.get("mitigations") or []
            if mitigations:
                lines.append("- Mitigations:")
                for m in mitigations:
                    if isinstance(m, dict):
                        txt = m.get("text") or m.get("mitigation") or ""
                    else:
                        txt = str(m)
                    if txt:
                        lines.append(f"  - {txt}")
            lines.append("\n")

    if not vendor_groups:
        lines.append("_No CVEs found in the selected window._\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    logger.info(f"Wrote Markdown report: {md_path}")
    return md_path


# =========================
# === Structured Pipeline =
# =========================
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

        logger.info(
            "Fetching NVD windows: published=%s modified=%s",
            start.isoformat(),
            end.isoformat(),
        )
        animate_progress("Fetching NVD data", 25)
        patterns = build_vendor_patterns(VENDORS)
        t0 = datetime.now(timezone.utc)
        published_data = fetch_nvd_window(start, end, mode="published")
        t1 = datetime.now(timezone.utc)
        logger.info(
            "Fetched NVD published window: items=%s duration=%.1fs",
            len(published_data),
            (t1 - t0).total_seconds(),
        )
        modified_data = fetch_nvd_window(start, end, mode="modified")
        t2 = datetime.now(timezone.utc)
        logger.info(
            "Fetched NVD modified window: items=%s duration=%.1fs",
            len(modified_data),
            (t2 - t1).total_seconds(),
        )
        results = {}
        total_llm = len(published_data) + len(modified_data)
        llm_done = 0

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
            if vendor and vendor.lower() not in EXCLUDED_SOFTWARE:
                products = collect_cpe_products(cve)
                if products:
                    normalized = [p.lower() for p in products]
                    if all(p in EXCLUDED_SOFTWARE for p in normalized):
                        llm_done += 1
                        try:
                            progress_bar(
                                llm_done,
                                total_llm if total_llm else 1,
                                prefix="Structured LLM",
                                status=f"{llm_done}/{total_llm}",
                            )
                        except Exception:
                            pass
                        continue
                entry = normalize_cve(cve, vendor, kev_ids)
                entry = _llm_refine_cve(entry, cve)
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
            llm_done += 1
            try:
                progress_bar(
                    llm_done,
                    total_llm if total_llm else 1,
                    prefix="Structured LLM",
                    status=f"{llm_done}/{total_llm}",
                )
            except Exception:
                pass

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
            if (
                vendor
                and vendor.lower() not in EXCLUDED_SOFTWARE
                and cve["id"] not in results
            ):
                products = collect_cpe_products(cve)
                if products:
                    normalized = [p.lower() for p in products]
                    if all(p in EXCLUDED_SOFTWARE for p in normalized):
                        llm_done += 1
                        try:
                            progress_bar(
                                llm_done,
                                total_llm if total_llm else 1,
                                prefix="Structured LLM",
                                status=f"{llm_done}/{total_llm}",
                            )
                        except Exception:
                            pass
                        continue
                entry = normalize_cve(cve, vendor, kev_ids)
                entry = _llm_refine_cve(entry, cve)
                entry["modified_only"] = True
                results[cve["id"]] = entry
            llm_done += 1
            try:
                progress_bar(
                    llm_done,
                    total_llm if total_llm else 1,
                    prefix="Structured LLM",
                    status=f"{llm_done}/{total_llm}",
                )
            except Exception:
                pass

        progress_bar(
            3, PROGRESS_TOTAL_STEPS, prefix=f"Structured: {len(results)} vendor CVEs"
        )

        animate_progress("Parsing RSS feeds", 20)
        rss_hits = parse_rss_feeds()
        total_llm += len(rss_hits)
        for feed_cve in rss_hits:
            cve_id = feed_cve["cve"]
            if cve_id in results:
                llm_done += 1
                try:
                    progress_bar(
                        llm_done,
                        total_llm if total_llm else 1,
                        prefix="Structured LLM",
                        status=f"{llm_done}/{total_llm}",
                    )
                except Exception:
                    pass
                continue
            cve_obj = fetch_nvd_single(cve_id)
            if not cve_obj:
                llm_done += 1
                try:
                    progress_bar(
                        llm_done,
                        total_llm if total_llm else 1,
                        prefix="Structured LLM",
                        status=f"{llm_done}/{total_llm}",
                    )
                except Exception:
                    pass
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
                products = collect_cpe_products(cve_obj)
                if products:
                    normalized = [p.lower() for p in products]
                    if all(p in EXCLUDED_SOFTWARE for p in normalized):
                        llm_done += 1
                        try:
                            progress_bar(
                                llm_done,
                                total_llm if total_llm else 1,
                                prefix="Structured LLM",
                                status=f"{llm_done}/{total_llm}",
                            )
                        except Exception:
                            pass
                        continue
                entry = normalize_cve(
                    cve_obj, vendor, kev_ids, from_article=True, source=feed_cve["link"]
                )
                entry = _llm_refine_cve(entry, cve_obj)
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
            llm_done += 1
            try:
                progress_bar(
                    llm_done,
                    total_llm if total_llm else 1,
                    prefix="Structured LLM",
                    status=f"{llm_done}/{total_llm}",
                )
            except Exception:
                pass

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
