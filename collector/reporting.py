from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import CONFIG
from .LLM import _call_llm

logger = logging.getLogger(__name__)

REPORT_FILE_PREFIX = "LLM-CumulativeReport"


def _reporting_output_dir() -> Path:
    out = CONFIG.get("OUTPUT_DIR_REPORTING")
    path = Path(out)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _parse_ndjson(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    buf: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            if buf:
                try:
                    obj = json.loads("\n".join(buf))
                    if isinstance(obj, dict):
                        records.append(obj)
                except Exception:
                    logger.debug("Skipping malformed block in %s", path)
                buf = []
            continue
        buf.append(line)
    if buf:
        try:
            obj = json.loads("\n".join(buf))
            if isinstance(obj, dict):
                records.append(obj)
        except Exception:
            logger.debug("Skipping trailing malformed block in %s", path)
    return records


def _collect_llm_records(days: int) -> List[Dict[str, Any]]:
    llm_root = Path(CONFIG.get("OUTPUT_DIR_LLM")).parents[1]
    if not llm_root.exists():
        logger.warning("LLM root does not exist: %s", llm_root)
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    ndjson_files = [
        p
        for p in llm_root.glob("**/rawtext-LLM_*.ndjson")
        if datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc) >= cutoff
    ]
    ndjson_files.sort()
    logger.info("Found %s LLM ndjson files in last %s days", len(ndjson_files), days)
    records: List[Dict[str, Any]] = []
    for f in ndjson_files:
        try:
            recs = _parse_ndjson(f)
            records.extend(recs)
        except Exception as exc:
            logger.warning("Failed parsing %s: %s", f, exc)
    logger.info("Collected %s records across %s files", len(records), len(ndjson_files))
    return records


def _build_reporting_prompt(days: int, records: List[Dict[str, Any]]) -> str:
    stats = _compute_stats(records)
    lines = []
    lines.append(
        "You are a senior threat intel analyst. Create a cumulative report summarizing the key findings across all entries below."
    )
    lines.append(
        f"Look-back window: last {days} days. Total entries: {len(records)}. Use ONLY the provided structured fields."
    )
    lines.append(
        "Focus on: top themes, notable actors, most common MITRE techniques, impacted vendors/products, observed IOCs (group by type), detections/recommendations trends, and overall risk for critical sectors."
    )
    lines.append("Aggregate stats (for context, keep consistency with these):")
    lines.append(f"- Top threat tags: {stats.get('top_tags')}")
    lines.append(f"- Top MITRE techniques: {stats.get('top_mitre')}")
    lines.append(f"- Top vendors/products: {stats.get('top_vendors')}")
    lines.append(f"- IOC counts by type: {stats.get('ioc_counts')}")
    lines.append("Input entries:")
    for idx, rec in enumerate(records, 1):
        llm = rec.get("llm") or {}
        lines.append(f"- Entry {idx}:")
        lines.append(f"  title: {rec.get('title')}")
        lines.append(f"  source: {rec.get('source')}")
        lines.append(f"  timestamp: {rec.get('@timestamp') or rec.get('timestamp')}")
        lines.append(f"  summary: {llm.get('summary')}")
        lines.append(f"  attack_summary: {llm.get('attack_summary')}")
        lines.append(f"  mitre_techniques: {llm.get('mitre_techniques')}")
        lines.append(f"  priority: {llm.get('priority')}")
        lines.append(f"  financial_relevance: {llm.get('financial_relevance')}")
        lines.append(f"  threat_actors: {llm.get('threat_actors')}")
        lines.append(f"  countries: {llm.get('countries')}")
        lines.append(f"  vendors: {llm.get('vendors')}")
        lines.append(f"  iocs: {llm.get('iocs')}")
        lines.append(f"  cves: {llm.get('cves')}")
        lines.append(f"  detections: {llm.get('detections')}")
        lines.append(f"  recommendations: {llm.get('recommendations')}")
        lines.append(f"  tags: {llm.get('tags')}")
    lines.append(
        "Return JSON with: summary, top_themes, mitre_stats, actor_insights, sector_risk, ioc_highlights, detections_overview, recommendations_overview, tags, and a markdown_section summarizing the report."
    )
    return "\n".join(lines)


def _write_reporting_outputs(
    out_dir: Path, period_label: str, llm_resp: Dict[str, Any]
) -> Dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d")
    md_name = f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.md"
    json_name = f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.json"
    pdf_name = f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.pdf"
    md_path = out_dir / md_name
    json_path = out_dir / json_name
    md_content = llm_resp.get("markdown_section") or ""
    if not md_content:
        md_content = f"# Cumulative Report ({period_label})\n\n{json.dumps(llm_resp, indent=2)}"
    md_path.write_text(md_content, encoding="utf-8")
    json_path.write_text(json.dumps(llm_resp, ensure_ascii=False, indent=2), encoding="utf-8")
    pdf_path = out_dir / pdf_name
    _render_pdf(md_content, pdf_path)
    return {"markdown": str(md_path), "json": str(json_path), "pdf": str(pdf_path)}


def _compute_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    from collections import Counter

    tags = Counter()
    mitre = Counter()
    vendors = Counter()
    ioc_counts = Counter()
    for rec in records:
        llm = rec.get("llm") or {}
        for t in llm.get("tags") or []:
            tags[t.lower()] += 1
        for m in llm.get("mitre_techniques") or []:
            name = (m.get("name") or "").lower()
            mid = (m.get("id") or "").upper()
            key = f"{mid} {name}".strip() if name else mid or None
            if key:
                mitre[key] += 1
        for v in llm.get("vendors") or []:
            nm = (v.get("name") or "").strip()
            if nm:
                vendors[nm.lower()] += 1
        for i in llm.get("iocs") or []:
            typ = (i.get("type") or "other").lower()
            ioc_counts[typ] += 1
    def top(counter: Counter, n=5):
        return [f"{k} ({v})" for k, v in counter.most_common(n)]
    return {
        "top_tags": top(tags, 5),
        "top_mitre": top(mitre, 5),
        "top_vendors": top(vendors, 5),
        "ioc_counts": dict(ioc_counts),
    }


def _render_pdf(markdown_text: str, out_path: Path) -> None:
    try:
        import fitz
    except Exception as exc:
        logger.warning("PyMuPDF not available for PDF render: %s", exc)
        return
    doc = fitz.open()
    page = doc.new_page()
    text = markdown_text.replace("# ", "").replace("## ", "").replace("### ", "")
    rect = fitz.Rect(40, 40, page.rect.width - 40, page.rect.height - 40)
    page.insert_textbox(rect, text, fontsize=11, fontname="helv", lineheight=1.2)
    doc.save(out_path)
    doc.close()


def run_reporting(period_days: int) -> Dict[str, Any]:
    records = _collect_llm_records(period_days)
    if not records:
        logger.warning("No LLM records found in last %s days; skipping reporting", period_days)
        return {"records": 0, "output": None}
    prompt = _build_reporting_prompt(period_days, records)
    llm_result = _call_llm(prompt) or {}
    outputs = _write_reporting_outputs(
        _reporting_output_dir(), f"{period_days}d", llm_result
    )
    logger.info(
        "Reporting complete for last %s days. Outputs: %s",
        period_days,
        outputs,
    )
    return {"records": len(records), "output": outputs, "llm": llm_result}
