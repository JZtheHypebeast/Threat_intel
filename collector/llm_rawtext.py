from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import os
import requests

# =========================
# ===== Module Config =====
# =========================
RAWTEXT_GLOB = "rawtext-*.json"
RAWTEXT_LLM_PREFIX = "rawtext-LLM_"
LLM_MD_PREFIX = "LLM-UnstructuredReport_"
RAW_TEXT_SNIPPET_MAX = 8000
OLLAMA_DEFAULT_HOST = "http://localhost:11434"

from .config import CONFIG

logger = logging.getLogger(__name__)


def _ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", CONFIG.get("OLLAMA_HOST", OLLAMA_DEFAULT_HOST)).rstrip("/")


def _get_output_dir() -> Path:
    out = CONFIG.get("OUTPUT_DIR_LLM")
    if out:
        return Path(out)
    base = Path(__file__).resolve().parent
    results_root = base / "results"
    today_stamp = datetime.now().strftime("%Y%m%d")
    return results_root / today_stamp


def _find_latest_rawtext_file(output_dir: Path) -> Optional[Path]:
    candidates = sorted(output_dir.glob(RAWTEXT_GLOB))
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


def _filter_by_hours(
    records: List[Dict[str, Any]], hours: Optional[int]
) -> List[Dict[str, Any]]:
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
    raw_text = (
        record.get("raw_text") or record.get("text") or record.get("full_text") or ""
    )
    snippet = str(raw_text)[:RAW_TEXT_SNIPPET_MAX]

    prompt = (
        "You will receive the full raw text of a cyber security article plus metadata.\n"
        "From this raw text alone, extract structured, actionable threat intelligence.\n\n"
        "Return a STRICT JSON object with these fields, in this order:\n\n"
        '- "summary": string (1–3 sentences, plain language, high-level summary of the entire article: who/what/impact)\n'
        '- "attack_summary": string (2–4 sentences, plain language, explaining how the attack or issue works end-to-end in simple terms)\n'
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
        '- "vendors": list of objects (must include every vendor or product explicitly mentioned in the text):\n'
        '    - "name": vendor/organization producing affected product/service\n'
        '    - "product": product/service name if mentioned\n'
        '    - "confidence": float 0–1\n'
        '- "iocs": list of objects (only what is explicitly in the text, do NOT invent values):\n'
        '    - "type": one of ["ip","domain","url","email","hash","filename","registry_key","artifact","other"]\n'
        '    - "value": the exact IOC string as seen in the text\n'
        '    - "context": short description of how this IOC is used (e.g. "C2 server","phishing URL","payload hash")\n'
        '    - "confidence": float 0–1\n'
        '- "detections": list of objects describing practical detection ideas/analytics:\n'
        '    - "name": short name, e.g. "Yurei ransomware filesystem behavior"\n'
        '    - "type": e.g. "Network","Endpoint","Email","Cloud","Identity","Generic"\n'
        '    - "idea": 1–3 sentences describing what to look for (conditions, patterns, logs)\n'
        '- "recommendations": list of objects for actionable response/hardening:\n'
        '    - "type": e.g. "Technical","Process","Awareness"\n'
        '    - "text": 1–3 sentences with concrete mitigation or response guidance\n'
        '- "tags": list of short strings (e.g. ["ransomware","windows","cloud","ddos","apt"])\n'
        '- "source_analysis": object:\n'
        '    - "source_name": short name (e.g. "BleepingComputer","Vendor advisory")\n'
        '    - "source_url": the URL you see below\n'
        '    - "trust_level": one of ["Low","Medium","High"]\n'
        '    - "reason": why this source is low/med/high confidence\n'
        "Guidelines:\n"
        "- Base everything only on the article text and general MITRE knowledge.\n"
        "- If the article does not state an actor/country/vendor/IOC, either omit it or set confidence low and explain.\n"
        "- For MITRE, do not invent IDs; if unsure, set id to null and confidence low.\n"
        "- For IOCs, ONLY extract values explicitly present in the text (IPs, domains, URLs, hashes, emails, filenames, registry keys, etc.); do NOT fabricate or normalize beyond what is visible.\n"
        "- Be exhaustive with IOCs and vendors: systematically scan the entire text and ensure that every IOC-like artifact and every vendor/product mention is captured in the respective lists, with no omissions and no duplicates.\n"
        "- If you are unsure whether something is an IOC, include it with type \"other\" and low confidence, and explain in the context.\n"
        "- Priority should reflect technique criticality, exploit status (e.g. 'zero-day','actively exploited','PoC/public exploit'), and business impact.\n"
        "- Financial relevance is about banks, PSPs, card data, securities, insurance, etc.\n"
        "- The attack_summary should clearly describe the end-to-end flow (initial access, execution, persistence, lateral movement, impact) in simple language.\n"
        "- Detections and recommendations should be concise but concrete enough to guide SOC and incident response teams.\n"
        "- Do NOT include any markdown, bullet points, or commentary outside the JSON object.\n\n"
        "Return ONLY the JSON object, no extra commentary.\n\n"
        f"Article metadata:\n- Title: {title}\n- URL: {source}\n- Timestamp: {ts}\n\n"
        f'Full raw text:\n"""{"".join(snippet)}"""'
    )
    return prompt

def _call_llm(prompt: str) -> Optional[Dict[str, Any]]:
    if not CONFIG.get("LLM_ENABLED", True):
        return None
    if not prompt:
        return None
    try:
        model = CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3"))
        url = f"{_ollama_host()}/api/generate"
        payload = {
            "model": model,
            "prompt": f"{SYSTEM_INSTRUCTION}\n\n{prompt}",
            "stream": False,
            "temperature": float(CONFIG.get("LLM_TEMPERATURE", 0.2)),
        }
        resp = requests.post(
            url, json=payload, timeout=CONFIG.get("REQUEST_TIMEOUT", 20)
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("response")
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
    ndjson_path = output_dir / f"{RAWTEXT_LLM_PREFIX}{today_stamp}.ndjson"
    md_path = output_dir / f"{LLM_MD_PREFIX}{today_stamp}.md"
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
