from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import os
import json
import re
from datetime import datetime, timezone

# =========================
# ===== Third-Party =======
# =========================
from pypdf import PdfReader
try:
    import fitz
    HAS_PYMUPDF = True
except Exception:
    HAS_PYMUPDF = False

# =========================
# ===== Local Imports =====
# =========================
from .config import CONFIG, logger, mute_console
from .progress import animate_progress
from .LLM import _call_llm
from . import delivery

SUMMARY_SENTENCES = 3

# =========================
# ===== Helper Utils ======
# =========================
def summarize_unstructured_description(text: str, max_sentences: int = 3) -> str:
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(sentences[:max_sentences]).strip()


def score_actionability(title: str | None, summary: str | None):
    if not (title or summary):
        return {}
    text = (title or "") + " " + (summary or "")
    if any(w in text.lower() for w in ["ransom", "credential", "privilege", "exploit"]):
        return {"score": 70, "label": "Medium"}
    return {"score": 40, "label": "Low"}


def dedupe_records_by_title(records: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for rec in records:
        title = (rec.get("title") or "").strip().lower()
        if title in seen:
            continue
        seen.add(title)
        out.append(rec)
    return out


def _pdf_prompt(title: str, source: str, text: str) -> str:
    return (
        "You are a senior cyber threat intelligence analyst creating an executive summary for management.\n"
        "You will receive raw text extracted from a PDF report. It may include headers, footers, navigation text, and boilerplate; ignore those and focus on the main content.\n\n"
        "Return ONLY a single JSON object with these keys:\n"
        '- "summary": string (2–4 sentences, plain-language executive summary of the whole report: what it is, time frame, and its main conclusions)\n'
        '- "top_insights": list of 3–7 objects, each with:\n'
        '    - "title": short string headline for the insight\n'
        '    - "detail": 1–3 sentences explaining the point in business terms\n'
        '- "financial_relevance": object with:\n'
        '    - "score": integer 0–100\n'
        '    - "label": one of ["None","Low","Medium","High","Critical"]\n'
        '    - "reason": short explanation of why this matters (or not) for financial institutions (banks, PSPs, card schemes, trading, insurance)\n'
        '- "recommended_actions": list of 3–7 objects, each with:\n'
        '    - "owner": e.g. "Board","CISO","Security Operations","Risk Management","Fraud","IT Operations"\n'
        '    - "priority": one of ["Low","Medium","High"]\n'
        '    - "text": 1–3 sentences describing a concrete action or decision\n'
        '- "tags": list of short strings (e.g. ["ransomware","phishing","geopolitics","regulation","cloud","identity"])\n'
        '- "threat_actors": optional list of objects, only if the report clearly names them:\n'
        '    - "name": actor or campaign name\n'
        '    - "role": e.g. "key actor in case studies","example group","mentioned only"\n'
        '- "iocs": optional list of objects, ONLY if the report clearly lists them in an Indicators of Compromise section or equivalent:\n'
        '    - "type": e.g. "domain","ip","url","hash","email"\n'
        '    - "value": exact string as shown in the report\n'
        '    - "context": short description of what the IOC represents\n'
        "Rules:\n"
        "- Do NOT invent actors, IOCs, statistics, or recommendations that are not supported by the text.\n"
        "- If the text does not clearly define a field, leave it empty or use an empty list.\n"
        "- Ignore generic contact details and benign corporate domains (e.g. microsoft.com, europol.europa.eu, fi-isac.nl) as IOCs unless the report explicitly labels them as malicious infrastructure or indicators.\n"
        "- Focus on strategic themes, trends, risks, and high-level recommendations suitable for senior management.\n"
        "- Many such PDFs include lengthy introductions, legal text, and navigation hints; ignore them in your analysis.\n"
        "- Return ONLY raw JSON with the specified keys, no markdown or explanatory text.\n\n"
        f"Title: {title or ''}\n"
        f"Source: {source or ''}\n"
        f'Text:\n"""{text}"""'
    )


def _normalize_pdf_llm(payload: dict) -> dict:
    out = dict(payload) if isinstance(payload, dict) else {}
    if out.get("summary") is None:
        out["summary"] = ""
    if out.get("top_insights") is None:
        out["top_insights"] = []
    if out.get("financial_relevance") is None:
        out["financial_relevance"] = {}
    if out.get("recommended_actions") is None:
        out["recommended_actions"] = []
    for key in ("threat_actors", "countries", "vendors", "iocs", "detections", "recommendations", "tags"):
        if out.get(key) is None:
            out[key] = []
    return out


# =========================
# ===== PDF Extraction ====
# =========================
def extract_text_pdftotext(pdf_path: str, *, max_pages: int | None = None) -> str:
    if not HAS_PYMUPDF:
        logger.warning(
            "PyMuPDF (fitz) not available; cannot extract PDF text for %s", pdf_path
        )
        return ""
    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        logger.warning("Failed to open PDF via PyMuPDF %s: %s", pdf_path, e)
        return ""
    text_parts = []
    try:
        for page_index, page in enumerate(doc):
            if max_pages is not None and page_index >= max_pages:
                break
            try:
                text_parts.append(page.get_text("text"))
            except Exception as e:
                logger.debug("Failed to extract text from page %s in %s: %s", page_index, pdf_path, e)
    finally:
        try:
            doc.close()
        except Exception:
            pass
    return "\n".join(text_parts)


def extract_text_pypdf(pdf_path: str, *, max_pages: int | None = None) -> str:
    try:
        reader = PdfReader(pdf_path)
    except Exception as e:
        logger.warning("Failed to read PDF with pypdf %s: %s", pdf_path, e)
        return ""
    text_parts = []
    for idx, page in enumerate(reader.pages):
        if max_pages is not None and idx >= max_pages:
            break
        try:
            text_parts.append(page.extract_text() or "")
        except Exception as e:
            logger.debug("Failed to extract text from page %s in %s: %s", idx, pdf_path, e)
    return "\n".join(text_parts)


def extract_text_from_pdf(pdf_path: str, *, max_pages: int | None = None) -> str:
    if HAS_PYMUPDF:
        text = extract_text_pdftotext(pdf_path, max_pages=max_pages)
        if text.strip():
            return text
    return extract_text_pypdf(pdf_path, max_pages=max_pages)


def discover_pdf_files(base_path: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not os.path.exists(base_path):
        logger.warning("PDF base path does not exist: %s", base_path)
        return out
    if os.path.isfile(base_path) and base_path.lower().endswith(".pdf"):
        out.append((os.path.basename(base_path), base_path))
        return out
    for root, _, files in os.walk(base_path):
        for fn in files:
            if not fn.lower().endswith(".pdf"):
                continue
            fp = os.path.join(root, fn)
            out.append((fn, fp))
    return out


def extract_text_from_file(base_path: str) -> list[tuple[str, str, str, dict]]:
    files = discover_pdf_files(base_path)
    out: list[tuple[str, str, str, dict]] = []
    for name, fp in files:
        logger.info("Extracting PDF: %s", fp)
        t = extract_text_from_pdf(fp)
        meta = {"title": name, "source": fp}
        out.append((name, t, fp, meta))
    return out


def _dehyphenate_text(text: str) -> str:
    text = re.sub(r"(\w+)-\n(\w+)", r"\1\2\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text


def _pdf_llm_analyze(title: str, source: str, text: str) -> dict | None:
    if not text or not text.strip():
        return None
    prompt = _pdf_prompt(title, source, text)
    try:
        resp = _call_llm(prompt)
    except Exception as e:
        logger.warning("PDF LLM call failed for %s: %s", title, e)
        return None
    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except Exception:
            logger.debug("PDF LLM response not JSON for %s", title)
            return None
    if not isinstance(resp, dict):
        return None
    return _normalize_pdf_llm(resp)


def normalize_and_merge_iocs(intel, source: str | None = None, context_text: str | None = None):
    if isinstance(intel, str):
        return []
    if not isinstance(intel, dict):
        return []
    iocs = intel.get("iocs") or []
    normed = []
    for i in iocs:
        if not isinstance(i, dict):
            continue
        t = (i.get("type") or "").strip().lower()
        v = (i.get("value") or "").strip()
        ctx = (i.get("context") or "").strip()
        if not v:
            continue
        if t in {"domain", "url"}:
            if any(dom in v for dom in ("microsoft.com", "europol.europa.eu", "fi-isac.nl")) and "malicious" not in ctx.lower():
                continue
        normed.append(
            {
                "type": t or "other",
                "value": v,
                "context": ctx,
                "source": source or "",
            }
        )
    if not normed:
        return []
    if not context_text:
        return normed
    lowered = context_text.lower()
    enriched = []
    for i in normed:
        v = i["value"]
        idx = lowered.find(v.lower())
        snippet = ""
        if idx != -1:
            start = max(0, idx - 80)
            end = min(len(context_text), idx + len(v) + 80)
            snippet = context_text[start:end].replace("\n", " ")
        j = dict(i)
        if snippet:
            j["excerpt"] = snippet
        enriched.append(j)
    return enriched


def generate_unstructured_markdown(items: list[dict]) -> str:
    if not items:
        return "# PDF Threat Intelligence (Management View)\n\n_No new items._"

    items = dedupe_records_by_title(items)
    lines: list[str] = ["# PDF Threat Intelligence (Management View)\n"]
    for rec in items:
        title = rec.get("title") or "(no title)"
        src = rec.get("source") or ""
        ref_id = rec.get("id") or rec.get("text_id") or ""
        lines.append(f"## {title}")
        meta_parts: list[str] = []
        if src:
            meta_parts.append(f"Source: {src}")
        if ref_id:
            meta_parts.append(f"Ref ID: {ref_id}")
        if meta_parts:
            lines.append("_" + " • ".join(meta_parts) + "_")

        llm = rec.get("llm") or {}
        summary = (
            llm.get("summary")
            or rec.get("summary_text")
            or rec.get("summary")
            or rec.get("description")
        )
        if summary:
            lines.append("")
            lines.append(f"**Executive Summary:** {summary}")

        top_insights = llm.get("top_insights") or []
        if isinstance(top_insights, list) and top_insights:
            lines.append("")
            lines.append("**Top Insights:**")
            for ti in top_insights:
                if not isinstance(ti, dict):
                    txt = str(ti)
                    if txt:
                        lines.append(f"- {txt}")
                    continue
                t_title = ti.get("title") or ""
                detail = ti.get("detail") or ""
                if t_title and detail:
                    lines.append(f"- **{t_title}** — {detail}")
                elif detail:
                    lines.append(f"- {detail}")

        fin = llm.get("financial_relevance") or {}
        if isinstance(fin, dict) and (fin.get("label") or fin.get("score") is not None or fin.get("reason")):
            label = fin.get("label") or "N/A"
            score = fin.get("score")
            score_str = str(score) if score is not None else "N/A"
            reason = fin.get("reason") or ""
            lines.append("")
            lines.append(f"**Financial Relevance:** {label} {score_str} — {reason}")

        recs = llm.get("recommended_actions") or []
        if isinstance(recs, list) and recs:
            lines.append("")
            lines.append("**Recommended Actions:**")
            for r in recs:
                if not isinstance(r, dict):
                    txt = str(r)
                    if txt:
                        lines.append(f"- {txt}")
                    continue
                owner = r.get("owner") or ""
                prio = r.get("priority") or ""
                text = r.get("text") or ""
                if not text:
                    continue
                prefix_parts: list[str] = []
                if owner:
                    prefix_parts.append(owner)
                if prio:
                    prefix_parts.append(prio)
                prefix = f"[{', '.join(prefix_parts)}] " if prefix_parts else ""
                lines.append(f"- {prefix}{text}")

        actors = llm.get("threat_actors") or []
        if isinstance(actors, list) and actors:
            lines.append("")
            lines.append("**Mentioned Threat Actors:**")
            for a in actors:
                if not isinstance(a, dict):
                    txt = str(a)
                    if txt:
                        lines.append(f"- {txt}")
                    continue
                name = a.get("name") or "Unknown"
                role = a.get("role") or ""
                parts = [name]
                if role:
                    parts.append(f"({role})")
                lines.append("- " + " ".join(parts))

        tags = llm.get("tags") or []
        if isinstance(tags, list) and tags:
            tag_strs = [str(t) for t in tags if t]
            if tag_strs:
                lines.append("")
                lines.append(f"**Tags:** {', '.join(tag_strs)}")

        lines.append("")
    return "\n".join(lines)


def build_pdf_record(name: str, text: str, path: str, meta: dict | None = None) -> dict:
    meta = meta or {}
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "title": meta.get("title") or name,
        "source": meta.get("source") or path,
        "@timestamp": ts,
        "text": text,
        "full_text_path": None,
        "meta": meta,
    }


def compute_record_id(source: str | None, ts: str | None) -> str:
    try:
        import hashlib

        h = hashlib.sha256()
        h.update(str(source or "").encode("utf-8"))
        if ts:
            h.update(str(ts).encode("utf-8"))
        return h.hexdigest()[:16]
    except Exception:
        return ""


def save_full_text(text: str, name: str) -> str | None:
    try:
        date_tag = datetime.now().strftime("%Y%m%d")
        out_dir = CONFIG.get("OUTPUT_DIR_PDF") or "."
        os.makedirs(out_dir, exist_ok=True)
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name) or "pdf"
        path = os.path.join(out_dir, f"{safe_name}_{date_tag}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path
    except Exception as e:
        logger.warning("Failed to save full text for %s: %s", name, e)
        return None


def run_pdf_analysis(path=None, hours=24):
    mute_console()
    out_dir = CONFIG.get("OUTPUT_DIR_PDF") or "."
    os.makedirs(out_dir, exist_ok=True)
    if not path:
        path = os.path.join(os.getcwd(), "data", "PDF")
    files = extract_text_from_file(path)
    total = len(files)
    results = []
    max_workers = CONFIG.get("MAX_WORKERS", 4)
    if total:
        completed = 0

        def _process_pdf(item):
            meta = {}
            try:
                name, text, fp, meta = item
            except Exception:
                try:
                    name, text, fp = item
                except Exception:
                    return None
            animate_progress(f"Analyzing {name}", 20)
            try:
                text = _dehyphenate_text(text)
            except Exception:
                pass
            llm_payload = _pdf_llm_analyze(
                meta.get("title") or name,
                meta.get("source") or fp,
                text,
            )
            record = build_pdf_record(name, text, fp, meta)
            record["llm"] = llm_payload or {}
            return record

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(_process_pdf, it): it for it in files}
            for future in as_completed(future_map):
                rec = future.result()
                if not rec:
                    completed += 1
                    continue
                results.append(rec)
                completed += 1
                animate_progress(
                    f"Completed {completed}/{total} PDF analyses", 20
                )

    sanitized = []
    for r in results:
        rid = compute_record_id(r.get("source"), r.get("@timestamp"))
        r["id"] = rid
        full_path = save_full_text(r.get("text") or "", rid or r.get("title") or "pdf")
        if full_path:
            r["full_text_path"] = full_path
        sanitized.append(r)

    date_stamp = datetime.now().strftime("%Y%m%d")
    ndjson_path = os.path.join(out_dir, f"UnstructuredPDFIntel_{date_stamp}.ndjson")
    try:
        for r in results:
            try:
                if CONFIG.get("ENABLE_SUMMARIZATION"):
                    r["summary_text"] = summarize_unstructured_description(
                        r.get("full_text_path") and "" or r.get("text", ""),
                        max_sentences=SUMMARY_SENTENCES,
                    )
            except Exception:
                pass
            try:
                act = score_actionability(
                    r.get("title"),
                    r.get("summary_text") or " ".join(r.get("top_findings") or []),
                )
                if isinstance(act, dict):
                    r["actionability"] = act
            except Exception:
                pass

        with open(ndjson_path, "w", encoding="utf-8") as f:
            for r in sanitized:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("Failed to write PDF NDJSON %s: %s", ndjson_path, e)

    md_path = os.path.join(out_dir, f"UnstructuredPDFReport_{date_stamp}.md")
    try:
        markdown = generate_unstructured_markdown(sanitized)
        with open(md_path, "w", encoding="utf-8") as mf:
            mf.write(str(markdown))
    except Exception as e:
        logger.warning(f"Failed to generate or write PDF markdown {md_path}: {e}")
    try:
        if CONFIG.get("SIEM_ENABLED") and CONFIG.get("SIEM_TYPE") == "elastic":
            delivery.send_batch_to_elastic(sanitized)
    except Exception as e:
        logger.warning(f"SIEM delivery failed: {e}")

    record_count = len(results)
    logger.info(
        "PDF summary: files=%s records=%s ndjson=%s markdown=%s",
        len(files),
        record_count,
        ndjson_path,
        md_path,
    )

    return {"records": record_count, "ndjson": ndjson_path}
