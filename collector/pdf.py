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
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except Exception:
    fitz = None
    HAS_PYMUPDF = False

# =========================
# ====== Local App ========
# =========================
from .config import CONFIG, logger, write_jsonl, mute_console, safe_get
from .progress import progress_bar, animate_progress
from . import delivery
from .fetch import extract_iocs

# =========================
# ===== Module Config =====
# =========================
PDF_DEFAULT_DIR = os.path.join(os.getcwd(), "data", "PDF")
SUMMARY_SENTENCES = CONFIG.get("SUMMARY_MAX_SENTENCES", 2)
TOP_FINDINGS_DEFAULT = 5
SUMMARY_MAX_CHARS = CONFIG.get("SUMMARY_MAX_CHARS", 480)


# =========================
# ===== Helpers ===========
# =========================
def _dehyphenate_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("-\n", "")
    text = text.replace("\r", "\n")
    text = "\n".join(ln.rstrip() for ln in text.splitlines())
    return text


def _make_id(source: str, ts: float | None = None) -> str:
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
        time_tag = datetime.now().strftime("%H%M%S")
        base_dir = CONFIG.get("OUTPUT_DIR_PDF") or "."
        out_dir = os.path.join(base_dir, date_tag, time_tag, "fulltext")
        os.makedirs(out_dir, exist_ok=True)
        fname = f"{_make_id(name)}.txt" if name else f"{time_tag}.txt"
        path = os.path.join(out_dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text or "")
        return path
    except Exception:
        return None


def summarize_unstructured_description(text: str, max_sentences: int = 2) -> str:
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\\s+", text.strip())
    summary = " ".join(sentences[:max_sentences]).strip()
    if len(summary) > SUMMARY_MAX_CHARS:
        summary = summary[: SUMMARY_MAX_CHARS - 3] + "..."
    return summary


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


def extract_top_findings(text: str, k: int = 5) -> list[str]:
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    bullets = [ln for ln in lines if ln[:1] in {"-", "*", "•"}]
    return bullets[:k]


def detect_provenance(text: str) -> list[dict]:
    out = []
    if not text:
        return out
    for m in re.finditer(r"https?://[\\w\\-./?&=%#]+", text):
        url = m.group(0)
        out.append({"source_url": url, "confidence": 0.7, "excerpt": url})
    return out


def normalize_and_merge_iocs(intel, source: str | None = None, context_text: str | None = None):
    # For PDF path we keep this minimal; returns normalized list of dicts with type/value
    if isinstance(intel, str):
        return []
    if not isinstance(intel, dict):
        return []
    iocs = intel.get("iocs") or []
    normed = []
    for i in iocs:
        if not isinstance(i, dict):
            continue
        typ = (i.get("type") or i.get("ioc_type") or "").strip().lower()
        val = (i.get("value") or i.get("indicator") or i.get("ioc") or "").strip()
        if typ and val:
            normed.append({"type": typ, "indicator": val, "confidence": i.get("confidence", 0.5)})
    return normed


def extract_threat_indicators(text: str, source: str | None = None, title: str | None = None):
    th = {"technique": {"name": []}}
    lower = (text or "").lower()
    if "ransom" in lower:
        th["technique"]["name"].append("Ransomware")
    if "phish" in lower:
        th["technique"]["name"].append("Phishing")
    iocs = extract_iocs(text or "", source=source, title=title)
    return {"threat": th, "iocs": iocs}


def strip_provenance(rec: dict) -> dict:
    if not isinstance(rec, dict):
        return rec
    out = dict(rec)
    if "provenance" in out:
        out["provenance"] = []
    return out


def score_actionability(title: str | None, summary: str | None):
    if not (title or summary):
        return {}
    text = (title or "") + " " + (summary or "")
    if any(w in text.lower() for w in ["ransom", "credential", "privilege", "exploit"]):
        return {"score": 70, "label": "Medium"}
    return {"score": 40, "label": "Low"}


def compute_relevance_score(intel: dict) -> dict:
    intel = dict(intel)
    intel.setdefault("priority", {})
    intel["priority"].setdefault("score", 50)
    intel["priority"].setdefault("label", "Medium")
    return intel


def generate_actionable_items(intel: dict):
    return {}


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
        pages: list[str] = []
        pdf_max_pages = (
            max_pages if max_pages is not None else CONFIG.get("PDF_MAX_PAGES", 50)
        )
        for i, page in enumerate(doc):
            if pdf_max_pages and i >= pdf_max_pages:
                break
            try:
                text = page.get_text("text") or ""
            except Exception:
                try:
                    text = page.get_text() or ""
                except Exception:
                    text = ""
            pages.append(text)
        try:
            doc.close()
        except Exception:
            pass
        text = "\n".join(pages)
        text = _dehyphenate_text(text)
        return text
    except Exception as exc:
        logger.warning("PyMuPDF extraction failed for %s: %s", pdf_path, exc)
        return ""


def extract_text_from_file(path):
    texts = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for fname in filenames:
                if not fname.lower().endswith(".pdf"):
                    continue
                fp = os.path.join(root, fname)
                try:
                    text = extract_text_pdftotext(fp) or None
                    meta = {}
                    if not text:
                        reader = PdfReader(fp)
                        text = " ".join([p.extract_text() or "" for p in reader.pages])
                        try:
                            md = reader.metadata
                            if md:
                                if hasattr(md, "items"):
                                    meta = {
                                        k.replace("/", ""): v for k, v in md.items()
                                    }
                                else:
                                    try:
                                        meta = dict(md)
                                    except Exception:
                                        meta = {}
                        except Exception:
                            meta = {}
                    texts.append((os.path.basename(fp), text or "", fp, meta))
                except Exception as e:
                    logger.warning(f"Failed to extract PDF {fp}: {e}")
    else:
        if str(path).lower().endswith(".pdf"):
            try:
                text = extract_text_pdftotext(path) or None
                meta = {}
                if not text:
                    reader = PdfReader(path)
                    text = " ".join([p.extract_text() or "" for p in reader.pages])
                    try:
                        md = reader.metadata
                        if md:
                            if hasattr(md, "items"):
                                meta = {k.replace("/", ""): v for k, v in md.items()}
                            else:
                                try:
                                    meta = dict(md)
                                except Exception:
                                    meta = {}
                    except Exception:
                        meta = {}
                texts.append((os.path.basename(path), text or "", path, meta))
            except Exception as e:
                logger.warning(f"Failed to extract PDF {path}: {e}")
    return texts


# =========================
# == Markdown Generation ==
# =========================
def generate_unstructured_markdown(items: list[dict]) -> str:
    if not items:
        return "# Unstructured Threat Intelligence\n\n_No new items._"

    items = dedupe_records_by_title(items)
    lines = ["# Unstructured Threat Intelligence\n"]
    for rec in items:
        title = rec.get("title") or "(no title)"
        src = rec.get("source") or ""
        ref_id = rec.get("id") or rec.get("text_id") or ""
        lines.append(f"## {title}")
        if src:
            lines.append(f"_Source: {src}_")
        if ref_id:
            lines.append(f"_Ref ID: {ref_id}_")
        summary = (
            rec.get("summary_text") or rec.get("summary") or rec.get("description")
        )
        if summary:
            lines.append("")
            lines.append(summary)
        lines.append("")
    return "\n".join(lines)


# =========================
# ==== PDF Processing =====
# =========================
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

            intel = {"title": name, "text": text}
            try:
                full_text_path = save_full_text(text, name)
            except Exception:
                full_text_path = None

            try:
                mtime = os.path.getmtime(fp) if fp else None
            except Exception:
                mtime = None
            try:
                text_id = _make_id(fp or name, mtime)
            except Exception:
                text_id = None

            ti = extract_threat_indicators(text, source=fp or name, title=name)
            intel.update(ti)
            try:
                intel["iocs"] = normalize_and_merge_iocs(ti, source=fp or name)
            except Exception:
                try:
                    intel["iocs"] = extract_iocs(text, source=fp or name, title=name)
                except Exception:
                    intel["iocs"] = []
            if CONFIG.get("ENABLE_SUMMARIZATION"):
                try:
                    intel["summary_text"] = summarize_unstructured_description(
                        text, max_sentences=SUMMARY_SENTENCES
                    )
                except Exception:
                    pass
            if CONFIG.get("ENABLE_SCORING"):
                intel = compute_relevance_score(intel)
            try:
                actions = generate_actionable_items(intel)
                if isinstance(actions, dict):
                    intel.update(actions)
            except Exception:
                pass
            try:
                mtime = os.path.getmtime(fp)
                intel["@timestamp"] = datetime.fromtimestamp(
                    mtime, timezone.utc
                ).isoformat()
            except Exception:
                intel["@timestamp"] = datetime.now(timezone.utc).isoformat()
            intel["source"] = fp
            intel["full_text_path"] = full_text_path
            intel["text_id"] = text_id
            try:
                intel["top_findings"] = extract_top_findings(
                    text, k=TOP_FINDINGS_DEFAULT
                )
            except Exception:
                intel["top_findings"] = []

            try:
                prov = detect_provenance(text) or []
            except Exception:
                prov = []

            try:
                if meta:
                    t = meta.get("Title") or meta.get("title")
                    if t:
                        prov.append(
                            {
                                "source_name": t,
                                "source_url": None,
                                "confidence": 0.7,
                                "excerpt": "PDF metadata: Title",
                                "pos": 0,
                            }
                        )
                    a = meta.get("Author") or meta.get("author")
                    if a:
                        prov.append(
                            {
                                "source_name": a,
                                "source_url": None,
                                "confidence": 0.6,
                                "excerpt": "PDF metadata: Author",
                                "pos": 0,
                            }
                        )
            except Exception:
                pass

            try:
                intel["provenance"] = prov
            except Exception:
                intel["provenance"] = []
            return intel

        completed = 0
        for f in files:
            completed += 1
            progress_bar(completed, total, prefix="PDF analyzed")
            try:
                res = _process_pdf(f)
            except Exception as e:
                fp = None
                try:
                    fp = f[2]
                except Exception:
                    fp = None
                logger.warning(f"Error processing PDF {fp or '<unknown>'}: {e}")
                res = None
            if res:
                results.append(res)
                try:
                    print(f"DEBUG: appended result source={res.get('source')}")
                except Exception:
                    pass

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
                if act:
                    r.setdefault("threat", {})
                    r["threat"]["actionability"] = act
            except Exception:
                pass

        try:
            results = dedupe_records_by_title(results)
        except Exception:
            pass

        sanitized = [strip_provenance(r) for r in results]
    except Exception:
        sanitized = results

    write_jsonl(ndjson_path, sanitized)
    try:
        if CONFIG.get("EXPORT_NAVIGATOR"):
            from collections import Counter

            counts = Counter()
            for r in results:
                for m in safe_get(r, "threat.technique.mitre", []) or []:
                    tid = m.get("id")
                    if tid:
                        counts[tid] += 1
            if counts:
                top = max(counts.values())
                layer = {
                    "name": "Observed Techniques",
                    "description": "Auto-generated layer",
                    "techniques": [],
                }
                for tid, c in counts.items():
                    score = int((c / top) * 100) if top else 0
                    layer["techniques"].append(
                        {
                            "techniqueID": tid,
                            "score": score,
                            "comment": f"{c} occurrences",
                        }
                    )
                nav_path = os.path.join(
                    out_dir,
                    f"navigator_layer_{date_stamp}.json"
                )
                with open(nav_path, "w", encoding="utf-8") as nf:
                    json.dump(layer, nf, indent=2)
    except Exception:
        pass

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
