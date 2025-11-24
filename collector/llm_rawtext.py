from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import os

from .config import CONFIG

logger = logging.getLogger(__name__)

def _get_openai_client() -> Optional[Any]:
    """Create and return an OpenAI client if an API key is available.

    Returns None if the OPENAI_API_KEY environment variable is not set,
    if the `openai` package is not installed, or if client creation fails.
    """
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        logger.warning("OPENAI_API_KEY not set; skipping LLM calls")
        return None
    try:
        try:
            from openai import OpenAI
        except ImportError:
            logger.warning("`openai` package not installed; skipping LLM calls")
            return None
        return OpenAI(api_key=key)
    except Exception as exc:
        logger.warning("Failed to create OpenAI client: %s", exc)
        return None

_llm_quota_exhausted: bool = False

def _get_output_dir() -> Path:
    out = CONFIG.get("OUTPUT_DIR")
    if out:
        return Path(out)
    base = Path(__file__).resolve().parent
    results_root = base / "results"
    today_stamp = datetime.now().strftime("%Y%m%d")
    return results_root / today_stamp


def _find_latest_rawtext_file(output_dir: Path) -> Optional[Path]:
    candidates = sorted(output_dir.glob("rawtext-*.json"))
    if not candidates:
        return None
    return candidates[-1]


def _load_rawtext_records(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except Exception:
            return []
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        return []
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _filter_by_hours(records: List[Dict[str, Any]], hours: Optional[int]) -> List[Dict[str, Any]]:
    if not hours or hours <= 0:
        return records
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    filtered: List[Dict[str, Any]] = []
    for rec in records:
        ts_val = rec.get("@timestamp") or rec.get("timestamp") or rec.get("time")
        if not ts_val:
            filtered.append(rec)
            continue
        try:
            ts = datetime.fromisoformat(str(ts_val))
        except Exception:
            filtered.append(rec)
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff:
            filtered.append(rec)
    return filtered


SYSTEM_INSTRUCTION = (
    "You are a senior threat intelligence analyst. "
    "You convert raw security articles into structured, actionable threat intelligence."
)


def _build_prompt_from_raw(record: Dict[str, Any]) -> str:
    title = record.get("title") or "(no title)"
    source = record.get("source") or ""
    ts = record.get("@timestamp") or record.get("timestamp") or ""
    raw_text = record.get("raw_text") or record.get("text") or record.get("full_text") or ""
    snippet = str(raw_text)[:8000]
    prompt = (
        "You will receive the full raw text of a cyber security article plus metadata.\n"
        "From this raw text alone, extract structured, actionable threat intelligence.\n\n"
        "Return a STRICT JSON object with these fields:\n\n"
        '- "summary": string (1–3 sentences plain language)\n'
        '- "mitre_techniques": list of objects:\n'
        '    - "id": MITRE ATT&CK ID, e.g. "T1190", or null if unknown\n'
        '    - "name": technique name\n'
        '    - "tactic": ATT&CK tactic, e.g. "Initial Access"\n'
        '    - "confidence": float 0–1\n'
        '    - "reason": short explanation\n'
        '- "priority": object:\n'
        '    - "score": integer 0–100\n'
        '    - "label": one of ["Informational","Low","Medium","High","Critical"]\n'
        '    - "reason": short explanation (impact, exploitability, exposure)\n'
        '- "financial_relevance": object:\n'
        '    - "score": integer 0–100\n'
        '    - "label": one of ["None","Low","Medium","High","Critical"]\n'
        '    - "reason": describe relevance to financial institutions\n'
        '- "threat_actors": list of objects:\n'
        '    - "name": actor/family name if given, else "Unknown"\n'
        '    - "type": e.g. "Financially motivated","State-sponsored","Cybercrime","Hacktivist","Unknown"\n'
        '    - "country": country or region, or null\n'
        '    - "confidence": float 0–1\n'
        '    - "role": e.g. "Attributed","Suspected","Mentioned","Targeted"\n'
        '    - "reason": short justification\n'
        '- "countries": list of objects:\n'
        '    - "name": country or region mentioned as victim/target/origin\n'
        '    - "role": e.g. "Victim","Target","Origin","Infrastructure"\n'
        '    - "confidence": float 0–1\n'
        '- "vendors": list of objects:\n'
        '    - "name": vendor/organization producing affected product/service\n'
        '    - "product": product/service name if mentioned\n'
        '    - "confidence": float 0–1\n'
        '- "source_analysis": object:\n'
        '    - "source_name": short name (e.g. "BleepingComputer","Vendor advisory")\n'
        '    - "source_url": the URL you see below\n'
        '    - "trust_level": one of ["Low","Medium","High"]\n'
        '    - "reason": why this source is low/med/high confidence\n'
        '- "markdown_section": string (markdown formatted summary for a human analyst)\n\n'
        "Guidelines:\n"
        "- Base everything only on the article text and general MITRE knowledge.\n"
        "- If the article does not state an actor/country/vendor, either omit it or set confidence low and explain.\n"
        '- For MITRE, do not invent IDs; if unsure, set id to null and confidence low.\n'
        '- Priority should reflect technique criticality, exploit status ("zero-day","actively exploited","PoC/public exploit"), and business impact.\n'
        "- Financial relevance is about banks, PSPs, card data, securities, insurance, etc.\n\n"
        "Return ONLY the JSON object, no extra commentary.\n\n"
        f"Article metadata:\n- Title: {title}\n- URL: {source}\n- Timestamp: {ts}\n\n"
        f'Full raw text:\n"""{"".join(snippet)}"""'
    )
    return prompt


def _call_llm(prompt: str) -> Optional[Dict[str, Any]]:
    if not CONFIG.get("LLM_ENABLED", True):
        return None
    try:
        global _llm_quota_exhausted
        if _llm_quota_exhausted:
            logger.warning("LLM quota previously exhausted; skipping further LLM calls")
            return None
        client = _get_openai_client()
        if client is None:
            return None
        model = CONFIG.get("LLM_MODEL", "gpt-4o-mini")
        response = client.responses.create(
            model=model,
            instructions=SYSTEM_INSTRUCTION,
            input=prompt,
        )

        text = getattr(response, "output_text", None)
        if not text:
            out = getattr(response, "output", None)
            if not out and isinstance(response, dict):
                out = response.get("output")
            parts: List[str] = []
            if out:
                for item in out:
                    content = None
                    if isinstance(item, dict):
                        content = item.get("content")
                    else:
                        content = getattr(item, "content", None)
                    if content:
                        for c in content:
                            if isinstance(c, dict):
                                txt = c.get("text") or c.get("content")
                            else:
                                txt = getattr(c, "text", None) or getattr(c, "content", None)
                            if txt:
                                parts.append(str(txt))
                    else:
                        parts.append(str(item))
            text = "\n".join(parts) if parts else None

        if not text:
            return None

        try:
            enriched = json.loads(text)
        except Exception:
            s = text.find("{")
            e = text.rfind("}")
            if s != -1 and e != -1 and e > s:
                try:
                    enriched = json.loads(text[s : e + 1])
                except Exception:
                    return None
            else:
                return None

        if not isinstance(enriched, dict):
            return None
        return enriched
    except Exception as exc:
        msg = str(exc)
        if "insufficient_quota" in msg or "quota" in msg.lower():
            logger.warning("LLM quota error detected: %s", exc)
            _llm_quota_exhausted = True
            return None
        logger.warning("LLM call failed: %s", exc)
        return None


def _enrich_record_with_llm(record: Dict[str, Any]) -> Dict[str, Any]:
    prompt = _build_prompt_from_raw(record)
    enriched = _call_llm(prompt)
    if enriched and isinstance(enriched, dict):
        record["llm"] = enriched
    return record


def _write_ndjson(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _build_markdown(records: List[Dict[str, Any]], input_file: Path) -> str:
    lines: List[str] = []
    lines.append("# LLM Unstructured Threat Intelligence Report")
    lines.append("")
    lines.append(f"_Source file: {input_file.name}_")
    lines.append("")
    for idx, rec in enumerate(records, start=1):
        title = rec.get("title") or "(no title)"
        source = rec.get("source") or ""
        lines.append(f"## {idx}. {title}")
        if source:
            lines.append(f"_Source: {source}_")
        llm_block = (rec.get("llm") or {}).get("markdown_section")
        if llm_block:
            lines.append("")
            lines.append(llm_block)
        lines.append("")
    return "\n".join(lines)


def run_llm_rawtext(hours: Optional[int] = None) -> Dict[str, Any]:
    output_dir = _get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = _find_latest_rawtext_file(output_dir)
    if raw_path is None:
        return {
            "input_file": None,
            "output_ndjson": None,
            "output_markdown": None,
            "records_total": 0,
            "records_processed": 0,
        }
    records = _load_rawtext_records(raw_path)
    total = len(records)
    if hours:
        records = _filter_by_hours(records, hours)
    processed: List[Dict[str, Any]] = []
    for rec in records:
        rec = _enrich_record_with_llm(rec)
        processed.append(rec)
    today_stamp = datetime.now().strftime("%Y%m%d")
    ndjson_path = output_dir / f"rawtext-LLM_{today_stamp}.ndjson"
    md_path = output_dir / f"LLM-UnstructuredReport_{today_stamp}.md"
    _write_ndjson(ndjson_path, processed)
    md_text = _build_markdown(processed, raw_path)
    md_path.write_text(md_text, encoding="utf-8")
    return {
        "input_file": str(raw_path),
        "output_ndjson": str(ndjson_path),
        "output_markdown": str(md_path),
        "records_total": total,
        "records_processed": len(processed),
    }
