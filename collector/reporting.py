from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import json
import re
import logging
import math
import os
import textwrap
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# =========================
# ===== Third-Party =======
# =========================
import requests

# =========================
# ====== Local App ========
# =========================
from .config import CONFIG
from .progress import start_live_progress, stop_live_progress

logger = logging.getLogger(__name__)

# =========================
# ===== Module Config =====
# =========================
REPORT_FILE_PREFIX = "ManagementReport"

# =========================
# ======== Helpers ========
# =========================
def _reporting_output_dir() -> Path:
    out = CONFIG.get("OUTPUT_DIR_REPORTING") or (Path.cwd() / "results" / "reporting")
    p = Path(out)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _llm_root_dir() -> Path:
    out_cfg = CONFIG.get("OUTPUT_DIR_LLM")
    if out_cfg:
        return Path(out_cfg)
    return Path.cwd() / "results" / "llm"

# =========================
# ======= LLM I/O =========
# =========================
def _ollama_host() -> str:
    return str(CONFIG.get("LLM_HOST", os.getenv("OLLAMA_HOST", "http://localhost:11434"))).rstrip("/")


def _ollama_model() -> str:
    return str(CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1")))


def _ollama_timeout() -> int:
    t = CONFIG.get("LLM_REQUEST_TIMEOUT", CONFIG.get("REQUEST_TIMEOUT", 300))
    try:
        return int(t)
    except Exception:
        return 300


def _ollama_temperature() -> float:
    try:
        return float(CONFIG.get("LLM_TEMPERATURE", 0.2))
    except Exception:
        return 0.2


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if not isinstance(text, str) or not text.strip():
        return None
    s = text.strip()
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    start = s.find("{")
    end = s.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = s[start : end + 1]
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def _ollama_json(prompt: str) -> Dict[str, Any]:
    url = f"{_ollama_host()}/api/generate"
    payload = {
        "model": _ollama_model(),
        "prompt": prompt,
        "stream": False,
        "temperature": _ollama_temperature(),
        "format": "json",
    }
    logger.info("Calling Ollama(model=%s) json-mode prompt_chars=%s", payload["model"], len(prompt))
    r = requests.post(url, json=payload, timeout=_ollama_timeout())
    if r.status_code != 200:
        logger.warning("LLM HTTP error status=%s body=%s", r.status_code, r.text[:600])
        r.raise_for_status()
    data = r.json()
    txt = data.get("response") or ""
    obj = _extract_json_object(txt)
    return obj or {}

# =========================
# ======= Records =========
# =========================
def _parse_ndjson(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    buf: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            if buf:
                try:
                    obj = json.loads("\n".join(buf))
                    if isinstance(obj, dict):
                        records.append(obj)
                except Exception:
                    pass
                buf = []
            continue
        buf.append(line)
    if buf:
        try:
            obj = json.loads("\n".join(buf))
            if isinstance(obj, dict):
                records.append(obj)
        except Exception:
            pass
    return records


def _collect_llm_records(days: int) -> List[Dict[str, Any]]:
    configured = _llm_root_dir()
    if configured.suffix.lower() == ".ndjson":
        configured = configured.parent

    candidates = [configured]
    if configured.name.isdigit() and configured.parent.name.isdigit():
        candidates.append(configured.parent.parent)
    candidates.append(Path(__file__).resolve().parent / "results" / "llm")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    seen: set[Path] = set()
    out: List[Dict[str, Any]] = []

    patterns = ["LLM-JSON_*.ndjson", "rawtext-LLM_*.ndjson"]
    for root in candidates:
        if not root.exists():
            continue
        files = []
        for pat in patterns:
            files.extend(root.rglob(pat))
        for f in files:
            if f in seen:
                continue
            seen.add(f)
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            except Exception:
                continue
            if mtime < cutoff:
                continue
            try:
                for obj in _parse_ndjson(f):
                    if isinstance(obj, dict) and obj.get("llm"):
                        out.append(obj)
            except Exception:
                continue

    if not out:
        logger.warning(
            "No LLM records found in last %s days (searched: %s)",
            days,
            [str(c) for c in candidates],
        )
    return out

# =========================
# ======== Scoring ========
# =========================
def _priority_score(rec: Dict[str, Any]) -> int:
    llm = rec.get("llm") or {}
    pri = llm.get("priority") or {}
    try:
        return int(pri.get("score") or 0)
    except Exception:
        return 0


def _compact_entry_line(rec: Dict[str, Any]) -> str:
    llm = rec.get("llm") or {}
    title = (rec.get("title") or llm.get("title") or "").strip().replace("\n", " ")
    summary = (llm.get("summary") or rec.get("summary") or "").strip().replace("\n", " ")
    if len(title) > 90:
        title = title[:87] + "..."
    if len(summary) > 220:
        summary = summary[:217] + "..."

    actors: List[str] = []
    for a in (llm.get("threat_actors") or [])[:2]:
        if isinstance(a, dict):
            nm = a.get("name") or a.get("group") or a.get("actor")
            if nm:
                actors.append(str(nm)[:36])
        else:
            actors.append(str(a)[:36])

    vendors: List[str] = []
    for v in (llm.get("vendors") or [])[:2]:
        if isinstance(v, dict):
            nm = v.get("name") or v.get("vendor") or v.get("product")
            if nm:
                vendors.append(str(nm)[:36])
        else:
            vendors.append(str(v)[:36])

    tags: List[str] = [str(t)[:24] for t in (llm.get("tags") or [])[:4]]

    score = _priority_score(rec)
    return f"- score={score} | title={title} | actors={actors} | vendors={vendors} | tags={tags} | summary={summary}"

# =========================
# ======== Metrics ========
# =========================
def _compute_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    from collections import Counter

    vendors = Counter()
    techniques = Counter()
    actors = Counter()
    tags = Counter()
    iocs = Counter()

    for r in records:
        llm = r.get("llm") or {}

        for v in llm.get("vendors") or []:
            name = v.get("name") if isinstance(v, dict) else v
            if name:
                vendors[str(name).lower()] += 1

        for t in llm.get("mitre_techniques") or []:
            if isinstance(t, dict):
                nm = t.get("name") or t.get("id")
            else:
                nm = str(t)
            if nm:
                techniques[str(nm).strip()] += 1

        for a in llm.get("threat_actors") or []:
            nm = a.get("name") if isinstance(a, dict) else a
            if nm:
                actors[str(nm).strip()] += 1

        for tg in llm.get("tags") or []:
            if tg:
                tags[str(tg).lower()] += 1

        for i in llm.get("iocs") or []:
            if isinstance(i, dict):
                typ = (i.get("type") or "other").lower()
            else:
                typ = "other"
            iocs[typ] += 1

    def top_with_counts(c: Counter, n: int) -> List[str]:
        return [f"{k} ({v})" for k, v in c.most_common(n)]

    def top_list(c: Counter, n: int) -> List[str]:
        return [k for k, _ in c.most_common(n)]

    return {
        "total_items": len(records),
        "top_vendors": top_with_counts(vendors, 5),
        "top_actors": top_with_counts(actors, 5),
        "top_tags": top_with_counts(tags, 6),
        "top_techniques_plain": top_list(techniques, 5),
        "ioc_counts": dict(iocs),
    }


# =========================
# ======= LLM Prompts =====
# =========================
def _batch_prompt(days: int, batch_lines: List[str], batch_idx: int, batch_total: int) -> str:
    p: List[str] = []
    p.append("You are a threat intelligence analyst writing for non-technical executive management.")
    p.append("Return ONLY strict JSON. No markdown. No code fences. No extra keys.")
    p.append("Do not use technical jargon. Do not list CVEs. Do not dump IOCs.")
    p.append(f"Window: last {days} days. Batch {batch_idx}/{batch_total}.")
    p.append("")
    p.append("Items (one line per item):")
    p.extend(batch_lines)
    p.append("")
    p.append("Schema (strict):")
    p.append("{")
    p.append('  "headline": "1 sentence, plain language",')
    p.append('  "themes": ["3-6 plain-language themes"],')
    p.append('  "business_risks": ["4-7 risks expressed as business outcomes"],')
    p.append('  "signals": ["3-6 short observations that support the assessment"],')
    p.append('  "actions": ["4-7 actions a CTO could sponsor"],')
    p.append('  "notable": [{"title":"...","why_it_matters":"..."}]')
    p.append("}")
    return "\n".join(p)


def _final_prompt(days: int, metrics: Dict[str, Any], batch_summaries: List[Dict[str, Any]]) -> str:
    p: List[str] = []
    p.append("You are a CTO briefing executive leadership. Write in plain business language.")
    p.append("Return ONLY strict JSON. No markdown. No code fences. No extra keys.")
    p.append("No CVEs. No IOC dumps. No MITRE IDs. If you mention techniques, describe them in plain language.")
    p.append(f"Reporting window: last {days} days.")
    p.append("")
    p.append("Metrics snapshot (truth source):")
    p.append(json.dumps(metrics, ensure_ascii=False))
    p.append("")
    p.append("Batch summaries (truth source):")
    p.append(json.dumps(batch_summaries, ensure_ascii=False))
    p.append("")
    p.append("Schema (strict):")
    p.append("{")
    p.append('  "executive_summary": "4–6 sentences that a CTO would say to executives",')
    p.append('  "what_changed": ["3-6 bullets describing what changed vs the prior period"],')
    p.append('  "top_business_risks": [{"risk":"...","impact":"...","likelihood":"Low/Medium/High"}],')
    p.append('  "decisions_requested": ["3-6 decisions needed from leadership"],')
    p.append('  "recommended_actions": ["6-10 concrete actions to execute"],')
    p.append('  "supporting_observations": ["6-10 observations that justify the above, grounded in data"]')
    p.append("}")
    return "\n".join(p)


# =========================
# ====== Markdown =========
# =========================
def _markdown_from_exec_json(days: int, exec_js: Dict[str, Any], metrics: Dict[str, Any], generated_at: str) -> str:
    def slist(x: Any) -> List[str]:
        return [str(i).strip() for i in x] if isinstance(x, list) else []

    def lod(x: Any) -> List[Dict[str, Any]]:
        return x if isinstance(x, list) else []

    lines: List[str] = []
    lines.append("# Threat Intelligence Management Report")
    lines.append(f"_Last {days} days (generated {generated_at})_")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    es = str(exec_js.get("executive_summary") or "").strip()
    lines.append(es if es else "Summary not available.")
    lines.append("")

    lines.append("## What Changed Since Last Period")
    lines.append("")
    wc = slist(exec_js.get("what_changed"))
    if wc:
        for x in wc:
            lines.append(f"- {x}")
    else:
        lines.append("- No period-over-period change narrative was produced for this run.")
    lines.append("")

    lines.append("## Top Business Risks")
    lines.append("")
    risks = lod(exec_js.get("top_business_risks"))
    if risks:
        for r in risks[:6]:
            risk = str(r.get("risk") or "").strip()
            impact = str(r.get("impact") or "").strip()
            lik = str(r.get("likelihood") or "").strip() or "Medium"
            if not risk and not impact:
                continue
            lines.append(f"- **{risk or 'Risk'}**")
            if impact:
                lines.append(f"  - Impact: {impact}")
            lines.append(f"  - Likelihood: {lik}")
    else:
        lines.append("- **Increased likelihood of disruption from external exploitation and credential compromise**")
        lines.append("  - Impact: Potential service disruption, data exposure, and incident response cost")
        lines.append("  - Likelihood: Medium")
    lines.append("")

    lines.append("## Decisions Requested")
    lines.append("")
    dr = slist(exec_js.get("decisions_requested"))
    if dr:
        for x in dr[:8]:
            lines.append(f"- {x}")
    else:
        lines.append("- Confirm prioritisation and resourcing for highest-risk mitigation work this period.")
    lines.append("")

    lines.append("## Recommended Actions")
    lines.append("")
    ra = slist(exec_js.get("recommended_actions"))
    if ra:
        for x in ra[:12]:
            lines.append(f"- {x}")
    else:
        lines.append("- Accelerate patching/mitigation for frequently targeted platforms and suppliers.")
        lines.append("- Validate monitoring and response readiness for initial-access and credential theft scenarios.")
    lines.append("")

    lines.append("## Supporting Observations")
    lines.append("")
    so = slist(exec_js.get("supporting_observations"))
    if so:
        for x in so[:14]:
            lines.append(f"- {x}")
    else:
        lines.append("- Supporting observations were not produced for this run.")
    lines.append("")

    lines.append("## Metrics Snapshot")
    lines.append("")

    total = int(metrics.get("total_items", 0) or 0)
    lines.append(f"- **Volume:** {total} relevant threat intelligence items reviewed in this period.")

    vendors = metrics.get("top_vendors") or []
    if isinstance(vendors, list) and vendors:
        leaders = ", ".join(vendors[:2])
        lines.append(
            "- **Concentration of risk:** Activity is heavily concentrated around a small number of vendors/platforms, "
            f"led by {leaders}, indicating systemic exposure rather than isolated issues."
        )

    actors = metrics.get("top_actors") or []
    if isinstance(actors, list) and actors:
        first = str(actors[0]).strip().lower()
        if first.startswith("unknown"):
            lines.append(
                "- **Threat attribution:** Most activity cannot be confidently attributed, which is consistent with "
                "opportunistic or automated exploitation rather than a single targeted campaign."
            )
        else:
            lines.append(
                "- **Threat attribution:** Repeated appearance of named groups suggests pockets of targeted activity "
                "alongside broad opportunistic threats."
            )

    tags = metrics.get("top_tags") or []
    if isinstance(tags, list) and tags:
        top_themes = ", ".join(tags[:3])
        lines.append(
            "- **Dominant themes:** The most frequently observed themes are concentrated around "
            f"{top_themes}, reinforcing that vulnerability-driven risk remains the primary driver this period."
        )

    techniques = metrics.get("top_techniques_plain") or []
    if isinstance(techniques, list) and techniques:
        lines.append(
            "- **Common attack patterns:** Recurring patterns indicate continued focus on gaining initial access, "
            "then expanding control (e.g., privilege escalation and post-compromise activity)."
        )

    ioc = metrics.get("ioc_counts") or {}
    if isinstance(ioc, dict) and ioc:
        domain = int(ioc.get("domain", 0) or 0)
        url = int(ioc.get("url", 0) or 0)
        ip = int(ioc.get("ip", 0) or 0)
        lines.append(
            "- **Operational exposure:** External infrastructure indicators remain present (domains/URLs/IPs), "
            "consistent with ongoing phishing, malware delivery, and command-and-control activity."
        )
        if domain or url or ip:
            bits = []
            if domain:
                bits.append(f"domains={domain}")
            if url:
                bits.append(f"urls={url}")
            if ip:
                bits.append(f"ips={ip}")
            lines.append(f"  - Supporting signal: {', '.join(bits)}")
    lines.append("")

    return "\n".join(lines)

# =========================
# ===== PDF Rendering =====
# =========================
def _render_pdf(markdown_text: str, out_path: Path) -> None:
    try:
        import fitz
    except Exception as exc:
        logger.warning("PyMuPDF not available; cannot render PDF: %s", exc)
        return

    def _strip_inline_md(s: str) -> str:
        s = re.sub(r"`([^`]+)`", r"\1", s)
        s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
        s = re.sub(r"_([^_]+)_", r"\1", s)
        return s

    def _draw_text(page, x, y, txt, fs, bold=False):
        page.insert_text((x, y), txt, fontsize=fs, fontname="helv")
        if bold:
            page.insert_text((x + 0.6, y), txt, fontsize=fs, fontname="helv")

    def _draw_link_lines(text, url, fs, indent=0):
        nonlocal y
        clean = _strip_inline_md(text).strip()
        if not clean:
            y += lh // 2
            return
        width = max(40, wrap_width - (indent // 2))
        for w in textwrap.wrap(clean, width=width):
            ensure_space(lh)
            _draw_text(page, margin + indent, y, w, fs, bold=False)
            if url:
                text_w = fitz.get_text_length(w, fontname="helv", fontsize=fs)
                rect = fitz.Rect(
                    margin + indent,
                    y - (fs * 0.8),
                    margin + indent + text_w,
                    y + 2,
                )
                page.insert_link({"from": rect, "uri": url, "kind": fitz.LINK_URI})
            y += lh

    doc = fitz.open()
    lines = markdown_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    margin = 44
    fs = 11
    fs_h1 = 16
    fs_h2 = 13
    fs_h3 = 12
    fs_h4 = 11
    lh = 14
    wrap_width = int(CONFIG.get("REPORT_PDF_WRAP", 92))

    page = doc.new_page()
    rect = page.rect
    x = margin
    y = margin
    max_y = rect.height - margin

    def new_page():
        nonlocal page, rect, y, max_y
        page = doc.new_page()
        rect = page.rect
        y = margin
        max_y = rect.height - margin

    def ensure_space(height):
        nonlocal y
        if y + height > max_y:
            new_page()

    def draw_rule():
        nonlocal y
        ensure_space(10)
        page.draw_line((margin, y), (rect.width - margin, y), width=0.6)
        y += 10

    def draw_block(text, fs, bold=False, indent=0, extra_after=0):
        nonlocal y
        clean = _strip_inline_md(text).strip()
        if not clean:
            y += lh // 2
            return
        width = max(40, wrap_width - (indent // 2))
        for w in textwrap.wrap(clean, width=width):
            ensure_space(lh)
            _draw_text(page, margin + indent, y, w, fs, bold=bold)
            y += lh
        if extra_after:
            y += extra_after

    for raw in lines:
        s = raw.rstrip()

        if re.match(r"^###\s+\d+\.\s+", s) and (y > margin + 2):
            new_page()

        if not s.strip():
            y += lh // 2
            continue

        if s.strip() == "---":
            draw_rule()
            continue

        if s.lstrip().startswith(">"):
            q = s.lstrip()[1:].lstrip()
            draw_block(q, fs, indent=18)
            continue

        if s.startswith("# "):
            draw_block(s[2:], fs_h1, bold=True, extra_after=6)
            continue
        if s.startswith("## "):
            draw_block(s[3:], fs_h2, bold=True, extra_after=4)
            continue
        if s.startswith("### "):
            draw_block(s[4:], fs_h3, bold=True, extra_after=2)
            continue
        if s.startswith("#### "):
            draw_block(s[5:], fs_h4, bold=True, extra_after=2)
            continue

        if s.startswith("Source:"):
            src = s[len("Source:"):].strip()
            url = src if src.startswith("http://") or src.startswith("https://") else ""
            draw_block("Source:", fs, bold=True)
            if url:
                _draw_link_lines(url, url, fs, indent=0)
            else:
                draw_block("-", fs, bold=False)
            continue

        m = re.match(r"^(\s*)([-*])\s+(.*)$", s)
        if m:
            indent_spaces = len(m.group(1))
            bullet_text = m.group(3).strip()
            base_indent = 14 + min(48, indent_spaces * 2)
            ensure_space(lh)
            _draw_text(page, margin + base_indent - 10, y, "•", fs)
            draw_block(bullet_text, fs, indent=base_indent)
            continue

        label_match = re.match(r"^\*\*([^*]+)\*\*:?$", s.strip())
        if label_match:
            draw_block(label_match.group(1) + ":", fs, bold=True)
            continue

        if s.strip().endswith(":"):
            draw_block(s.strip(), fs, bold=True)
            continue

        draw_block(s, fs)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out_path)
    doc.close()

# =========================
# ===== Output Writer =====
# =========================
def _write_outputs(out_dir: Path, period_label: str, markdown_text: str, meta: Dict[str, Any]) -> Dict[str, str]:
    date_str = datetime.now().strftime("%Y%m%d")
    md_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.md"
    pdf_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.pdf"
    json_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.json"

    md_path.write_text(markdown_text, encoding="utf-8")
    json_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    _render_pdf(markdown_text, pdf_path)

    return {"markdown": str(md_path), "pdf": str(pdf_path), "json": str(json_path)}

# =========================
# ========= Runner ========
# =========================
def run_reporting(period_days: int) -> Dict[str, Any]:
    records = _collect_llm_records(period_days)
    if not records:
        logger.warning("No LLM records found in last %s days; skipping reporting", period_days)
        return {"records": 0, "output": None}

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M %Z")

    records.sort(key=_priority_score, reverse=True)
    metrics = _compute_metrics(records)
    metrics["generated_at"] = generated_at

    max_entries = int(CONFIG.get("REPORT_MAX_ENTRIES", 30))
    max_entries = max(16, min(max_entries, len(records)))
    batch_size = int(CONFIG.get("REPORT_BATCH_SIZE", 6))
    batch_size = max(4, min(batch_size, 8))

    selected = records[:max_entries]
    batch_total = max(1, math.ceil(len(selected) / batch_size))

    total_steps = batch_total + 1
    progress_state = {"current": 0, "status": ""}
    start_time = time.time()
    stop_evt, thread = start_live_progress("Reporting", total_steps, progress_state)

    def _update_status():
        cur = progress_state.get("current", 0) or 0
        elapsed = time.time() - start_time
        remaining = max(total_steps - cur, 0)
        eta = ""
        if cur > 0 and total_steps > 0 and remaining > 0:
            avg = elapsed / cur
            eta_sec = int(avg * remaining)
            mins, secs = divmod(eta_sec, 60)
            hours, mins = divmod(mins, 60)
            if hours:
                eta = f"ETA {hours}h{mins:02d}m"
            else:
                eta = f"ETA {mins:02d}m{secs:02d}s"
        progress_state["status"] = f"{cur}/{total_steps} {eta}".strip()

    batch_summaries: List[Dict[str, Any]] = []
    for i in range(batch_total):
        batch = selected[i * batch_size : (i + 1) * batch_size]
        batch_lines = [_compact_entry_line(r) for r in batch]
        js = _ollama_json(_batch_prompt(period_days, batch_lines, i + 1, batch_total))
        if js:
            batch_summaries.append(js)
        progress_state["current"] = i + 1
        _update_status()

    exec_js = _ollama_json(_final_prompt(period_days, metrics, batch_summaries))
    progress_state["current"] = total_steps
    _update_status()
    stop_live_progress(stop_evt, thread, wait=True)

    markdown = _markdown_from_exec_json(period_days, exec_js or {}, metrics, generated_at)

    outputs = _write_outputs(
        _reporting_output_dir(),
        f"{period_days}d",
        markdown,
        {"metrics": metrics, "batches": batch_summaries, "final": exec_js},
    )
    return {"records": len(records), "output": outputs, "markdown": markdown, "batches": len(batch_summaries)}
