from __future__ import annotations




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




import requests




from .config import CONFIG
from .progress import start_live_progress, stop_live_progress

logger = logging.getLogger(__name__)




REPORT_FILE_PREFIX = "ManagementReport"




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
    unstructured_cfg = CONFIG.get("OUTPUT_DIR_UNSTRUCTURED")
    if unstructured_cfg:
        unstructured_path = Path(unstructured_cfg)
        if unstructured_path.suffix.lower() == ".ndjson":
            unstructured_path = unstructured_path.parent
        candidates.append(unstructured_path)
        if unstructured_path.name.isdigit() and unstructured_path.parent.name.isdigit():
            candidates.append(unstructured_path.parent.parent)
    base_results = Path(__file__).resolve().parent / "results"
    candidates.append(base_results / "llm")
    candidates.append(base_results / "articles")

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





def _markdown_from_exec_json(days: int, exec_js: Dict[str, Any], metrics: Dict[str, Any], generated_at: str) -> str:
    def slist(x: Any) -> List[str]:
        return [str(i).strip() for i in x] if isinstance(x, list) else []

    def lod(x: Any) -> List[Dict[str, Any]]:
        return x if isinstance(x, list) else []

    def _paragraphize(items: List[str], lead: str, per_paragraph: int = 3) -> List[str]:
        if not items:
            return [lead.rstrip() + " Not available for this run."]
        out: List[str] = []
        for i in range(0, len(items), per_paragraph):
            chunk = "; ".join([c for c in items[i : i + per_paragraph] if c])
            if not chunk:
                continue
            if not out:
                out.append(f"{lead.rstrip()} {chunk}.")
            else:
                out.append(f"{chunk}.")
        return out

    lines: List[str] = []
    lines.append("# Management Report Summary")
    lines.append("")
    lines.append(f"Window: last {days} days")
    lines.append(f"Generated: {generated_at}")
    total_items = int(metrics.get("total_items", 0) or 0)
    lines.append(f"Collected: {total_items} items")
    lines.append("")

    es = str(exec_js.get("executive_summary") or "").strip()
    if es:
        lines.append(f"**Executive summary:** {es}")
    else:
        lines.append("**Executive summary:** Summary not available.")
    lines.append("")

    wc = slist(exec_js.get("what_changed"))
    lines.extend(_paragraphize(wc, "**What changed since the prior period:**"))
    lines.append("")

    risks = lod(exec_js.get("top_business_risks"))
    risk_lines: List[str] = []
    for r in risks[:8]:
        risk = str(r.get("risk") or "").strip()
        impact = str(r.get("impact") or "").strip()
        lik = str(r.get("likelihood") or "").strip() or "Medium"
        if not risk and not impact:
            continue
        frag = risk or "Risk"
        if impact:
            frag = f"{frag} (impact: {impact}, likelihood: {lik})"
        else:
            frag = f"{frag} (likelihood: {lik})"
        risk_lines.append(frag)
    lines.extend(_paragraphize(risk_lines, "**Top business risks:**"))
    lines.append("")

    dr = slist(exec_js.get("decisions_requested"))
    lines.extend(_paragraphize(dr, "**Decisions requested:**"))
    lines.append("")

    ra = slist(exec_js.get("recommended_actions"))
    lines.extend(_paragraphize(ra, "**Recommended actions:**"))
    lines.append("")

    so = slist(exec_js.get("supporting_observations"))
    lines.extend(_paragraphize(so, "**Supporting observations:**"))
    lines.append("")
    lines.append("[[PAGE_BREAK]]")
    lines.append("")
    lines.append("## Metrics Snapshot")
    lines.append("")

    total = int(metrics.get("total_items", 0) or 0)
    lines.append(f"- Volume: {total} relevant threat intelligence items reviewed in this period.")

    vendors = metrics.get("top_vendors") or []
    if isinstance(vendors, list) and vendors:
        leaders = ", ".join(vendors[:2])
        lines.append(
            "- Concentration of risk: Activity is heavily concentrated around a small number of vendors/platforms, "
            f"led by {leaders}, indicating systemic exposure rather than isolated issues."
        )

    actors = metrics.get("top_actors") or []
    if isinstance(actors, list) and actors:
        first = str(actors[0]).strip().lower()
        if first.startswith("unknown"):
            lines.append(
                "- Threat attribution: Most activity cannot be confidently attributed, which is consistent with "
                "opportunistic or automated exploitation rather than a single targeted campaign."
            )
        else:
            lines.append(
                "- Threat attribution: Repeated appearance of named groups suggests pockets of targeted activity "
                "alongside broad opportunistic threats."
            )

    tags = metrics.get("top_tags") or []
    if isinstance(tags, list) and tags:
        top_themes = ", ".join(tags[:3])
        lines.append(
            "- Dominant themes: The most frequently observed themes are concentrated around "
            f"{top_themes}, reinforcing that vulnerability-driven risk remains the primary driver this period."
        )

    techniques = metrics.get("top_techniques_plain") or []
    if isinstance(techniques, list) and techniques:
        lines.append(
            "- Common attack patterns: Recurring patterns indicate continued focus on gaining initial access, "
            "then expanding control (e.g., privilege escalation and post-compromise activity)."
        )

    ioc = metrics.get("ioc_counts") or {}
    if isinstance(ioc, dict) and ioc:
        domain = int(ioc.get("domain", 0) or 0)
        url = int(ioc.get("url", 0) or 0)
        ip = int(ioc.get("ip", 0) or 0)
        lines.append(
            "- Operational exposure: External infrastructure indicators remain present (domains/URLs/IPs), "
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




def _render_pdf(markdown_text: str, out_path: Path) -> None:

    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            PageBreak,
            ListFlowable,
            ListItem,
            KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except Exception as exc:
        logger.warning("ReportLab not available; cannot render PDF: %s", exc)
        return

    styles = getSampleStyleSheet()
    Body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10.5,
        leading=14,
        spaceAfter=6,
    )
    H1 = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        spaceBefore=6,
        spaceAfter=10,
    )
    H2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13.5,
        leading=18,
        spaceBefore=12,
        spaceAfter=6,
    )
    H3 = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        spaceBefore=10,
        spaceAfter=4,
    )
    H4 = ParagraphStyle(
        "H4",
        parent=styles["Heading4"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        spaceBefore=8,
        spaceAfter=2,
    )
    Meta = ParagraphStyle(
        "Meta",
        parent=Body,
        textColor=colors.grey,
        fontSize=9.5,
        leading=12,
        spaceAfter=8,
    )
    Label = ParagraphStyle(
        "Label",
        parent=Body,
        fontName="Helvetica-Bold",
        spaceAfter=2,
    )

    def md_inline_to_rl(s: str) -> str:
        s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        s = s.replace("↗ Escalating", "Escalating (up)")
        s = s.replace("↘ De-escalating", "De-escalating (down)")
        s = s.replace("↗", "up")
        s = s.replace("↘", "down")
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", s)
        s = re.sub(r"_([^_]+)_", r"<i>\1</i>", s)
        s = s.replace("**", "").replace("__", "")
        return s

    def add_para(flow, text, style=Body):
        t = (text or "").strip()
        if not t:
            flow.append(Spacer(1, 6))
            return
        flow.append(Paragraph(md_inline_to_rl(t), style))

    def parse_bullets(lines, start_idx):
        items = []
        i = start_idx
        bullet_re = re.compile(r"^(\s*)([-*])\s+(.*)$")
        while i < len(lines):
            m = bullet_re.match(lines[i])
            if not m:
                break
            indent_spaces = len(m.group(1))
            txt = m.group(3).strip()
            level = 0
            if indent_spaces >= 4:
                level = 1
            if indent_spaces >= 8:
                level = 2
            items.append((level, txt))
            i += 1
        return items, i

    def build_nested_list(items):
        root = []
        stack = [(0, root)]
        for lvl, txt in items:
            while stack and lvl < stack[-1][0]:
                stack.pop()
            if lvl > stack[-1][0]:
                parent_list = stack[-1][1]
                if not parent_list:
                    lvl = stack[-1][0]
                else:
                    nested = []
                    last_item = parent_list[-1]
                    parent_list[-1] = KeepTogether(
                        [last_item, ListFlowable(nested, bulletType="bullet", leftIndent=18)]
                    )
                    stack.append((lvl, nested))

            cur_list = stack[-1][1]
            cur_list.append(ListItem(Paragraph(md_inline_to_rl(txt), Body), leftIndent=12))

        return ListFlowable(root, bulletType="bullet", leftIndent=18)

    title_line = ""
    for ln in markdown_text.splitlines():
        if ln.startswith("# "):
            title_line = ln[2:].strip()
            break
    if not title_line:
        title_line = "GeoFeed Summary"

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillGray(0.35)
        canvas.drawString(doc.leftMargin, doc.pagesize[1] - 0.6 * inch, title_line)
        canvas.setFillGray(0.5)
        canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 0.5 * inch, f"Page {doc.page}")
        canvas.restoreState()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.85 * inch,
        rightMargin=0.85 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.8 * inch,
        title=title_line,
        author="GeoFeed",
    )

    flow = []
    lines = markdown_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i = 0
    while i < len(lines):
        s = lines[i].rstrip()

        if not s.strip():
            flow.append(Spacer(1, 6))
            i += 1
            continue

        if s.strip() == "[[PAGE_BREAK]]":
            flow.append(PageBreak())
            i += 1
            continue

        if s.startswith("# "):
            add_para(flow, s[2:], H1)
            i += 1
            continue
        if s.startswith("## "):
            add_para(flow, s[3:], H2)
            i += 1
            continue
        if s.startswith("### "):
            add_para(flow, s[4:], H3)
            i += 1
            continue
        if s.startswith("#### "):
            add_para(flow, s[5:], H4)
            i += 1
            continue

        label_match = re.match(r"^\*\*([^*]+)\*\*:?$", s.strip())
        if label_match:
            add_para(flow, label_match.group(1) + ":", Label)
            i += 1
            continue

        if re.match(r"^\s*[-*]\s+", s):
            items, j = parse_bullets(lines, i)
            if items:
                flow.append(build_nested_list(items))
                flow.append(Spacer(1, 6))
            i = j
            continue

        if s.strip().startswith("_") and s.strip().endswith("_") and len(s.strip()) > 2:
            add_para(flow, s.strip().strip("_"), Meta)
        else:
            add_para(flow, s, Body)

        i += 1

    doc.build(flow, onFirstPage=on_page, onLaterPages=on_page)




def _write_outputs(out_dir: Path, period_label: str, markdown_text: str, meta: Dict[str, Any]) -> Dict[str, str]:
    date_str = datetime.now().strftime("%Y%m%d")
    md_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.md"
    pdf_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.pdf"
    json_path = out_dir / f"{REPORT_FILE_PREFIX}_{period_label}_{date_str}.json"

    md_path.write_text(markdown_text, encoding="utf-8")
    json_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    _render_pdf(markdown_text, pdf_path)

    return {"markdown": str(md_path), "pdf": str(pdf_path), "json": str(json_path)}




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
