from __future__ import annotations

import os
import json
import time
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
)
from .unstructured_core import (
    summarize_unstructured_description,
    score_actionability,
    dedupe_records_by_title,
    group_threat_items_by_vendor_or_sector,
    infer_missing_vendor_and_actor,
    correlate_unstructured_with_cves,
    generate_markdown_summary_section,
    extract_enablers_detailed,
)

# =============================================================================
#                                UNSTRUCTURED
# =============================================================================

# =============================================================================
#                              RSS PROCESSING
# =============================================================================
# Fetch RSS feeds, deduplicate links, fetch article text and enrich records.
# =============================================================================


def run_unstructured_rss_analysis(hours: int = 24) -> dict:
    mute_console()
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
                except Exception:
                    pass
                try:
                    intel["iocs"] = normalize_and_merge_iocs(text, source=link)
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
                intel = generate_actionable_summary(intel)
                aats = generate_actionable_items(intel)
                intel.update(aats)
                intel["@timestamp"] = (pub_dt or datetime.now(timezone.utc)).isoformat()
                try:
                    intel["extracted_text_source"] = extracted_source
                    if fetch_meta:
                        intel["fetch"] = fetch_meta
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

                    try:
                        progress_bar(
                            len(records),
                            total_entries,
                            prefix="Articles",
                            status=f"fetched:{len(records)}/{total_entries} iocs:{articles_with_iocs if 'articles_with_iocs' in locals() else 0} enablers:{articles_with_enablers if 'articles_with_enablers' in locals() else 0} findings:{articles_with_findings if 'articles_with_findings' in locals() else 0}",
                        )
                    except Exception:
                        pass
            except Exception:
                pass

        date_tag = datetime.now().strftime("%Y%m%d")
        ndjson_fn = f"UnstructuredRSSIntel_{date_tag}.ndjson"
        out_ndjson = os.path.join(CONFIG.get("OUTPUT_DIR", "."), ndjson_fn)
        try:

            try:
                records = dedupe_records_by_title(records, fuzzy_threshold=0.95)
            except Exception:
                pass

            try:
                _groups = group_threat_items_by_vendor_or_sector(records)
            except Exception:
                _groups = None

            with open(out_ndjson, "w", encoding="utf-8") as fh:
                for r in records:
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

        md_fn = f"UnstructuredRSSReport_{date_tag}.md"
        try:
            progress_bar(0, 1, prefix="Write Markdown")
            try:

                short_md = generate_markdown_summary_section(records)

                try:
                    from .unstructured_core import process_unstructured_sources

                    full_md = process_unstructured_sources(
                        records, enrich_markdown=True
                    )
                except Exception:

                    md_path = generate_unstructured_markdown(
                        records,
                        title=f"Unstructured RSS Intelligence {date_tag}",
                        filename=md_fn,
                    )

                    try:
                        with open(md_path, "r", encoding="utf-8") as fh:
                            full_md = fh.read()
                    except Exception:
                        full_md = ""

                md_path = os.path.join(CONFIG.get("OUTPUT_DIR", "."), md_fn)
                with open(md_path, "w", encoding="utf-8") as mf:

                    mf.write(short_md + "\n\n")
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

        return {"records": len(records), "ndjson": out_ndjson, "markdown": md_path}
    finally:
        pass


def extract_text_from_file(path: str) -> str:
    from .unstructured_pdf import extract_text_from_file as _pdf_extract

    return _pdf_extract(path)


def run_unstructured_pdf_analysis(path, hours: int = 24) -> dict:
    from . import unstructured_pdf as _pdf

    return _pdf.run_unstructured_pdf_analysis(path, hours=hours)
