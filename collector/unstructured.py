from __future__ import annotations

import os
import json
import calendar
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import feedparser
from dateutil import parser as dtparser

from .config import CONFIG, logger, mute_console
from .progress import progress_bar, start_live_progress, stop_live_progress
from . import delivery
from .unstructured_core import (
    fetch_article_text,
    html_to_main_text,
    extract_threat_indicators,
    extract_iocs,
    normalize_and_merge_iocs,
    detect_provenance,
    extract_top_findings,
    generate_actionable_items,
    generate_actionable_summary,
    compute_relevance_score,
    generate_unstructured_markdown,
    build_campaign_summary,
)
from .unstructured_core import (
    summarize_unstructured_description,
    score_actionability,
    dedupe_records_by_title,
    group_threat_items_by_vendor_or_sector,
    infer_missing_vendor_and_actor,
    extract_enablers_detailed,
    load_mitre_mitigations,
    load_mitre_phrase_map,
)

OUTPUT_DIR = CONFIG["OUTPUT_DIR_UNSTRUCTURED"]

def run_unstructured_rss_analysis(hours: int = 24) -> dict:
    mute_console()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    try:
        feeds = CONFIG.get("RSS_FEEDS", [])
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        entries = []
        for idx, f in enumerate(feeds, 1):
            parsed = feedparser.parse(f)
            try:
                feed_count = (
                    len(parsed.entries) if parsed and hasattr(parsed, "entries") else 0
                )
            except Exception:
                feed_count = 0
            status = f"feed={idx}/{len(feeds)} entries={feed_count}"
            progress_bar(idx, len(feeds), prefix="Feeds", status=status)
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
                        pub_dt = (
                            dtparser.parse(pub).astimezone(timezone.utc)
                            if pub
                            else None
                        )
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
                    # Skip weekly recap posts explicitly
                    if title and "weekly recap" in str(title).lower():
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
        max_workers = CONFIG.get("MAX_WORKERS", 6)
        total_entries = len(uniq)
        discovered_entries = len(entries)
        after_url_dedupe = len(uniq)
        pre_dedupe_count = 0
        post_dedupe_count = 0
        merged_count = 0
        merged_examples = []

        shared = {"current": 0, "status": ""}
        animator = None
        if total_entries:
            animator = start_live_progress(
                prefix="Articles", total=total_entries, shared=shared
            )
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(fetch_article_text, link): (link, title, pub_dt, summary)
                for link, title, pub_dt, summary in uniq
            }
            completed = 0
            for fut in as_completed(futures):
                completed += 1
                try:

                    status = f"fetched:{completed}/{total_entries} iocs:{articles_with_iocs if 'articles_with_iocs' in locals() else 0} enablers:{articles_with_enablers if 'articles_with_enablers' in locals() else 0} findings:{articles_with_findings if 'articles_with_findings' in locals() else 0}"

                    try:
                        shared["current"] = completed
                        shared["status"] = status
                    except Exception:

                        progress_bar(
                            completed, total_entries, prefix="Articles", status=status
                        )
                except Exception:
                    pass

                link, title, pub_dt, summary = futures[fut]
                text = ""
                fetch_meta = {}
                try:
                    meta = fut.result()
                    if isinstance(meta, dict):
                        text = meta.get("text", "") or ""
                        fetch_meta = {
                            k: meta.get(k)
                            for k in ("status_code", "attempts", "used_ua", "error")
                        }
                    else:
                        text = str(meta)
                except Exception:
                    logger.debug(f"error fetching {link}")

                extracted_source = "article_body" if text else None
                if not text:
                    if summary:
                        text = summary
                        extracted_source = "feed_summary"
                    else:
                        text = ""
                        extracted_source = "none"
                try:
                    from .unstructured_core import _dehyphenate_text as _dh

                    try:
                        text = _dh(text)
                    except Exception:
                        pass
                except Exception:
                    pass
                intel = extract_threat_indicators(text, source=link, title=title)

                try:
                    inferred = infer_missing_vendor_and_actor([intel])
                    if isinstance(inferred, list) and inferred:
                        intel = inferred[0]
                except Exception:
                    pass

                try:
                    if CONFIG.get("ENABLE_SUMMARIZATION"):
                        intel["summary_text"] = summarize_unstructured_description(
                            text, max_sentences=2
                        )
                        try:
                            built = build_campaign_summary(text)
                            low = (intel.get("summary_text") or "").strip().lower()
                            if built and (
                                not intel.get("summary_text")
                                or low.startswith("iocs")
                                or low.startswith("topics")
                            ):
                                intel["summary_text"] = built
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    intel = normalize_and_merge_iocs(intel, source=link)
                    extra_iocs = extract_iocs(text, source=link) or []
                    existing = {
                        (
                            i.get("type"),
                            (i.get("indicator") or i.get("value") or "").lower(),
                        )
                        for i in intel.get("iocs", []) or []
                        if isinstance(i, dict)
                    }
                    for i in extra_iocs:
                        key = (
                            i.get("type"),
                            (i.get("indicator") or i.get("value") or "").lower(),
                        )
                        if key in existing:
                            continue
                        existing.add(key)
                        intel.setdefault("iocs", []).append(i)
                    try:
                        src = (link or "").lower().rstrip("/")
                        filtered = []
                        for ioc in intel.get("iocs", []) or []:
                            ind = (
                                (ioc.get("indicator") or ioc.get("value") or "")
                                .lower()
                                .rstrip("/")
                            )
                            typ = ioc.get("type")
                            if typ == "url" and (ind == src or "gbhackers.com" in ind):
                                continue
                            if typ == "domain" and "gbhackers.com" in ind:
                                continue
                            filtered.append(ioc)
                        intel["iocs"] = filtered
                    except Exception:
                        pass
                except Exception:
                    try:
                        intel["iocs"] = extract_iocs(text, source=link)
                    except Exception:
                        intel["iocs"] = []

                try:
                    try:
                        from .unstructured_core import (
                            sanitize_article_text as _sanitize,
                        )

                        text_sanit = _sanitize(text) or text
                    except Exception:
                        text_sanit = text

                    try:
                        prov = detect_provenance(text_sanit) or []
                        if prov:
                            intel["provenance"] = prov
                    except Exception:
                        pass

                    try:
                        intel["raw_text"] = text_sanit
                    except Exception:
                        intel["raw_text"] = text

                    rec_for_enablers = dict(intel)
                    rec_for_enablers["text"] = text_sanit
                    ed = extract_enablers_detailed(rec_for_enablers)
                    intel["enablers"] = [e["enabler"] for e in ed]
                    intel["_enablers_detailed"] = ed
                except Exception:
                    intel["enablers"] = []
                try:
                    intel["top_findings"] = extract_top_findings(text, k=5)
                except Exception:
                    pass
                try:
                    prov = detect_provenance(text) or []
                    if prov:
                        intel["provenance"] = prov
                except Exception:
                    pass
                intel = compute_relevance_score(intel)

                try:
                    act = score_actionability(
                        intel.get("title"),
                        intel.get("summary_text")
                        or intel.get("top_findings", [])
                        and " ".join(intel.get("top_findings")),
                    )
                    if act:
                        intel.setdefault("threat", {})
                        intel["threat"]["actionability"] = act
                except Exception:
                    pass
                try:
                    intel["actionable_summary"] = generate_actionable_summary(intel)
                except Exception:
                    intel["actionable_summary"] = ""
                aats = generate_actionable_items(intel)
                intel.update(aats)
                try:

                    mit_items = []
                    if isinstance(aats, dict):
                        mit_items = aats.get("mitigations") or []
                    tech_mitigations = []
                    mit_seen = set()
                    for mi in mit_items:
                        try:
                            if not isinstance(mi, dict):
                                continue
                            if mi.get("type") != "mitigation":
                                continue
                            tech = mi.get("technique") or mi.get("technique_id") or None
                            mid = mi.get("id") or mi.get("mitigation_id") or None
                            desc = mi.get("description") or mi.get("title") or None
                            ref = mi.get("reference") or mi.get("url") or None
                            entry = {}
                            if tech:
                                entry["technique"] = tech
                            if mid:
                                entry["mitigation_id"] = mid
                            if desc:
                                entry["description"] = desc
                            if ref:
                                entry["reference"] = ref
                            key = (entry.get("technique"), entry.get("mitigation_id"))
                            if entry and key not in mit_seen:
                                mit_seen.add(key)
                                tech_mitigations.append(entry)
                        except Exception:
                            continue
                    if tech_mitigations:
                        intel.setdefault("threat", {})
                        tech_ids = set()
                        for t in intel.get("threat", {}).get("technique", []) or []:
                            if isinstance(t, dict) and t.get("id"):
                                tech_ids.add(str(t.get("id")).upper())
                        if tech_ids:
                            tech_mitigations = [
                                tm
                                for tm in tech_mitigations
                                if not tm.get("technique")
                                or str(tm.get("technique")).upper() in tech_ids
                            ]
                        intel["threat"]["technique_mitigations"] = tech_mitigations
                except Exception:
                    pass

                try:
                    if not intel.get("threat", {}).get("technique_mitigations"):
                        try:
                            mitig_map = load_mitre_mitigations()
                            phrase_map = load_mitre_phrase_map()
                        except Exception:
                            mitig_map = {}
                            phrase_map = {}

                        th_tmp = intel.get("threat") or {}
                        techs = th_tmp.get("technique") or []
                        names = []
                        if isinstance(techs, dict):
                            n = techs.get("name")
                            if isinstance(n, list):
                                names.extend(n)
                            elif n:
                                names.append(n)
                        elif isinstance(techs, list):
                            for titem in techs:
                                if isinstance(titem, str):
                                    names.append(titem)
                                elif isinstance(titem, dict):
                                    nn = titem.get("name")
                                    if nn:
                                        names.append(nn)

                        resolved = []
                        for name in names:
                            key = (name or "").strip().lower()
                            if not key:
                                continue
                            entries = phrase_map.get(key) or []
                            for ent in entries:
                                tid = (
                                    ent.get("id") or ent.get("technique_id") or ""
                                ).upper()
                                if not tid:
                                    continue
                                mit = mitig_map.get(tid)
                                if not mit:
                                    continue
                                entry = {
                                    "technique": tid,
                                    "mitigation_id": tid,
                                    "description": mit.get("title")
                                    or mit.get("description")
                                    or None,
                                }
                                if entry not in resolved:
                                    resolved.append(entry)
                        if resolved:
                            intel.setdefault("threat", {})
                            intel["threat"]["technique_mitigations"] = resolved
                except Exception:
                    pass
                intel["@timestamp"] = (pub_dt or datetime.now(timezone.utc)).isoformat()
                try:
                    intel["extracted_text_source"] = extracted_source
                    if fetch_meta:
                        intel["fetch"] = fetch_meta
                except Exception:
                    pass
                try:
                    intel.setdefault("iocs", [])
                    intel.setdefault("threat", {})
                    thtmp = intel["threat"]
                    if "technique" not in thtmp:
                        thtmp["technique"] = []
                    if "technique_mitigations" not in thtmp:
                        thtmp["technique_mitigations"] = []
                except Exception:
                    pass
                records.append(intel)

                try:
                    if "articles_with_iocs" not in locals():
                        articles_with_iocs = 0
                    if "articles_with_enablers" not in locals():
                        articles_with_enablers = 0
                    if "articles_with_findings" not in locals():
                        articles_with_findings = 0
                    if intel.get("iocs"):
                        articles_with_iocs += 1
                    if intel.get("enablers"):
                        articles_with_enablers += 1
                    if intel.get("top_findings"):
                        articles_with_findings += 1
                except Exception:
                    pass

            try:
                if animator:

                    stop_live_progress(animator[0], animator[1])
            except Exception:
                pass

        date_tag = datetime.now().strftime("%Y%m%d")
        ndjson_fn = f"UnstructuredRSSIntel_{date_tag}.ndjson"
        out_ndjson = os.path.join(OUTPUT_DIR, ndjson_fn)
        try:

            try:

                fuzzy_thresh = None
                if CONFIG.get("FUZZY_MATCHING_ENABLE"):
                    try:
                        fv = CONFIG.get("FUZZY_MATCH_THRESHOLD", 85)
                        fuzzy_thresh = float(fv) / 100.0 if fv is not None else None
                    except Exception:
                        fuzzy_thresh = 0.95

                from collections import defaultdict

                title_map = defaultdict(list)
                try:
                    for r in records:
                        t = (r.get("title") or "").strip()
                        title_map[t].append(r)
                except Exception:
                    title_map = defaultdict(list)

                pre_dedupe_count = len(records)
                # Deduplication disabled per request; keep all titles except weekly recap filtered earlier
                records = list(records)
                post_dedupe_count = len(records)
                merged_count = 0
                merged_examples = []

            except Exception:

                try:
                    _groups = group_threat_items_by_vendor_or_sector(records)
                except Exception:
                    _groups = None
            else:
                try:
                    _groups = group_threat_items_by_vendor_or_sector(records)
                except Exception:
                    _groups = None

            raw_items_snapshot = []
            for r in records:
                try:
                    raw_items_snapshot.append(
                        {
                            "title": r.get("title"),
                            "source": r.get("source") or r.get("source_url") or None,
                            "@timestamp": r.get("@timestamp"),
                            "raw_text": r.get("raw_text")
                            or r.get("summary_text")
                            or "",
                        }
                    )
                except Exception:
                    continue

            with open(out_ndjson, "w", encoding="utf-8") as fh:

                def _normalize_record(rec: dict) -> dict:
                    if not isinstance(rec, dict):
                        return rec

                    if "raw_text" in rec:
                        rec.pop("raw_text", None)

                    try:
                        th = rec.get("threat") or {}
                        if "mitre_details" in th and isinstance(
                            th.get("mitre_details"), list
                        ):
                            m_list = []
                            for md in th.get("mitre_details", []):
                                if not isinstance(md, dict):
                                    continue
                                entry = {}

                                if md.get("id"):
                                    entry["id"] = md.get("id")

                                if md.get("name"):
                                    entry["name"] = md.get("name")

                                conf = (
                                    md.get("priority_score")
                                    or md.get("score")
                                    or md.get("confidence")
                                )
                                try:
                                    if conf is not None:
                                        entry["confidence"] = float(conf)
                                except Exception:
                                    pass

                                if md.get("url"):
                                    entry["url"] = md.get("url")
                                m_list.append(entry)

                            th["mitre_details"] = m_list
                            rec["threat"] = th
                    except Exception:
                        pass

                    try:
                        prov = rec.get("provenance")
                        if isinstance(prov, list):
                            newp = []
                            for p in prov:
                                if not isinstance(p, dict):
                                    continue

                                source_name = (
                                    p.get("source_name")
                                    or p.get("note")
                                    or p.get("source")
                                )
                                source_url = (
                                    p.get("source_url")
                                    or p.get("source_url")
                                    or p.get("url")
                                )
                                excerpt = (
                                    p.get("excerpt") or p.get("note") or p.get("text")
                                )
                                confidence = p.get("confidence")
                                pos = p.get("pos")

                                new_entry = {
                                    "source_name": source_name,
                                    "source_url": source_url,
                                    "confidence": confidence,
                                }
                                if pos is not None:
                                    new_entry["pos"] = pos

                                for k in list(new_entry.keys()):
                                    if new_entry[k] is None:
                                        new_entry.pop(k)
                                newp.append(new_entry)
                            if newp:
                                rec["provenance"] = newp
                    except Exception:
                        pass

                    try:
                        th = rec.get("threat") or {}
                        tech_ids = set()
                        for t in th.get("technique", []) or []:
                            if isinstance(t, dict) and t.get("id"):
                                tech_ids.add(str(t.get("id")).upper())
                        tm_list = th.get("technique_mitigations") or []
                        if tm_list and tech_ids:
                            seen = set()
                            filtered = []
                            for tm in tm_list:
                                if not isinstance(tm, dict):
                                    continue
                                tid = tm.get("technique")
                                if tid and str(tid).upper() not in tech_ids:
                                    continue
                                key = (tm.get("technique"), tm.get("mitigation_id"))
                                if key in seen:
                                    continue
                                seen.add(key)
                                filtered.append(tm)
                            rec["threat"]["technique_mitigations"] = filtered
                    except Exception:
                        pass

                    forbidden = ("excerpt", "raw_text")

                    def _prune(obj):
                        if isinstance(obj, dict):
                            for k in list(obj.keys()):
                                if k in forbidden:
                                    obj.pop(k, None)
                                else:
                                    _prune(obj.get(k))
                        elif isinstance(obj, list):
                            for item in obj:
                                _prune(item)

                    try:
                        _prune(rec)
                    except Exception:

                        for f in forbidden:
                            rec.pop(f, None)

                    return rec

                for r in records:
                    try:

                        if isinstance(r, dict) and "event" not in r:
                            r["event"] = {
                                "kind": "intelligence",
                                "category": ["threat"],
                                "type": ["report"],
                                "dataset": "unstructured.intel",
                            }
                    except Exception:
                        pass

                    try:
                        if isinstance(r, dict):
                            r = _normalize_record(r)
                    except Exception:
                        pass
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            try:
                ndjson_name = os.path.basename(out_ndjson) if out_ndjson else "unknown"
                status = f"wrote={len(records)} file={ndjson_name}"
                progress_bar(1, 1, prefix="Write NDJSON", status=status)
            except Exception:
                pass
            logger.info(f"Wrote NDJSON: {out_ndjson}")
        except Exception as e:
            logger.error(f"Failed to write ndjson: {e}")

        try:
            out_raw = None
            rawtext_fn = f"rawtext-{date_tag}.json"
            raw_dir = CONFIG.get("OUTPUT_DIR_LLM") or OUTPUT_DIR
            os.makedirs(raw_dir, exist_ok=True)
            out_raw = os.path.join(raw_dir, rawtext_fn)

            with open(out_raw, "w", encoding="utf-8") as rf:
                json.dump(raw_items_snapshot, rf, ensure_ascii=False, indent=2)

            try:
                status = (
                    f"wrote={len(raw_items_snapshot)} file={os.path.basename(out_raw)}"
                )
                progress_bar(1, 1, prefix="Write RawText", status=status)
            except Exception:
                pass
            logger.info(f"Wrote rawtext json: {out_raw}")
        except Exception as e:
            logger.error(f"Failed to write rawtext json: {e}")

        md_fn = f"UnstructuredRSSReport_{date_tag}.md"
        try:
            progress_bar(0, 1, prefix="Write Markdown")
            try:

                try:
                    from collections import Counter

                    if _groups and isinstance(_groups, dict):
                        by_vendor = _groups.get("by_vendor", {})
                    else:
                        _tmp = group_threat_items_by_vendor_or_sector(records)
                        by_vendor = _tmp.get("by_vendor", {})

                    vendor_counts = [(v, len(lst)) for v, lst in by_vendor.items()]
                    vendor_counts.sort(key=lambda x: x[1], reverse=True)
                    top_vendors = (
                        ", ".join([f"{v} ({c})" for v, c in vendor_counts[:3]])
                        if vendor_counts
                        else "None"
                    )

                    try:
                        from .unstructured_core import classify_threat

                        tactics = [
                            classify_threat(
                                (
                                    r.get("summary_text")
                                    or r.get("summary")
                                    or r.get("text")
                                    or r.get("title")
                                    or ""
                                )
                            )
                            for r in records
                        ]
                        tact_counts = Counter([t for t in tactics if t])
                        most_common_tactics = (
                            ", ".join(
                                [f"{t} ({c})" for t, c in tact_counts.most_common(5)]
                            )
                            if tact_counts
                            else "None"
                        )
                    except Exception:
                        most_common_tactics = "None"

                    scores = []
                    for r in records:
                        try:
                            sc = ((r.get("threat") or {}).get("relevance") or {}).get(
                                "score"
                            )
                            if sc is not None:
                                scores.append(float(sc))
                        except Exception:
                            continue
                    avg_sev = round(sum(scores) / len(scores), 1) if scores else 0.0

                    summary_lines = ["## Summary", ""]
                    summary_lines.append(f"- Total findings: {len(records)}")
                    summary_lines.append(f"- Top vendors: {top_vendors}")
                    summary_lines.append(
                        f"- Most common tactics: {most_common_tactics}"
                    )
                    summary_lines.append(f"- Average severity: {avg_sev}")
                    summary_lines.append("")
                    summary_md = "\n".join(summary_lines)
                except Exception:
                    summary_md = "## Summary\n\n- Total findings: {0}\n\n".format(
                        len(records)
                    )

                try:
                    from .unstructured_core import process_unstructured_sources

                    full_md = process_unstructured_sources(
                        records, enrich_markdown=True
                    )
                except Exception:

                    full_md = generate_unstructured_markdown(records)

                md_path = os.path.join(OUTPUT_DIR, md_fn)
                with open(md_path, "w", encoding="utf-8") as mf:

                    mf.write(summary_md + "\n\n")
                    mf.write("---\n\n")
                    mf.write(full_md)
            except Exception:
                md_path = None
            try:
                completeness = (
                    int(100 * (len(records) / total_entries)) if total_entries else 100
                )
            except Exception:
                completeness = 0
            md_name = os.path.basename(md_path) if md_path else "unknown"
            status = (
                f"file={md_name} completeness={completeness}% records={len(records)}"
            )
            progress_bar(1, 1, prefix="Write Markdown", status=status)
        except Exception:
            md_path = None

        if CONFIG.get("DELIVER_ENABLED"):
            try:
                try:
                    progress_bar(0, 1, prefix="Deliver", status="starting")
                except Exception:
                    pass
                delivery.deliver_records(records, source="unstructured.rss")
                try:
                    progress_bar(1, 1, prefix="Deliver", status="done")
                except Exception:
                    pass
            except Exception:
                logger.debug("delivery failed")

        return {
            "records": len(records),
            "ndjson": out_ndjson,
            "markdown": md_path,
            "rawtext": out_raw,
            "diagnostics": {
                "discovered_entries": discovered_entries,
                "after_url_dedupe": after_url_dedupe,
                "pre_title_dedupe_count": pre_dedupe_count,
                "post_title_dedupe_count": post_dedupe_count,
                "merged_count": merged_count,
                "merged_examples": merged_examples,
            },
        }
    finally:
        pass


def extract_text_from_file(path: str) -> str:
    from .unstructured_pdf import extract_text_from_file as _pdf_extract

    return _pdf_extract(path)


def run_unstructured_pdf_analysis(path, hours: int = 24) -> dict:
    from . import unstructured_pdf as _pdf

    return _pdf.run_unstructured_pdf_analysis(path, hours=hours)
