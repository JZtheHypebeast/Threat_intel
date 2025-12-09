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
        path = Path(out)
        logger.debug("LLM output dir from CONFIG: %s", path)
        return path
    base = Path(__file__).resolve().parent
    results_root = base / "results"
    today_stamp = datetime.now().strftime("%Y%m%d")
    path = results_root / today_stamp
    logger.debug("LLM output dir defaulting to: %s", path)
    return path


def _find_latest_rawtext_file(output_dir: Path) -> Optional[Path]:
    candidates = sorted(output_dir.glob(RAWTEXT_GLOB))
    if not candidates:
        logger.debug("No rawtext files found in %s", output_dir)
        return None
    latest = candidates[-1]
    logger.debug("Latest rawtext file: %s", latest)
    return latest


def _find_latest_rawtext_any(base_dir: Path) -> Optional[Path]:
    """
    Locate the newest rawtext-*.json anywhere under the llm results root.
    Assumes layout: <...>/results/llm/<YYYYMMDD>/<HHMMSS>/rawtext-<date>.json
    """
    if not base_dir.exists():
        logger.debug("LLM base dir does not exist: %s", base_dir)
        return None
    matches = list(base_dir.glob("**/rawtext-*.json"))
    if not matches:
        logger.debug("No rawtext matches under %s", base_dir)
        return None
    latest = max(matches, key=lambda p: p.stat().st_mtime)
    logger.debug("Latest rawtext (global search): %s", latest)
    return latest


def _load_rawtext_records(path: Path) -> List[Dict[str, Any]]:
    logger.info("Loading rawtext records from %s", path)
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        logger.warning("Rawtext file %s is empty", path)
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except Exception:
            logger.warning("Failed to parse rawtext array from %s", path)
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
    logger.info("Loaded %s rawtext records", len(records))
    return records


def _filter_by_hours(
    records: List[Dict[str, Any]], hours: Optional[int]
) -> List[Dict[str, Any]]:
    if not hours or hours <= 0:
        return records
    logger.info("Filtering records by last %s hours", hours)
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
    logger.info("Records after hour filter: %s", len(filtered))
    return filtered


SYSTEM_INSTRUCTION = (
    "You are a senior threat intelligence analyst. "
    "You convert raw security articles into structured, actionable threat intelligence."
)

def _build_prompt_from_raw(record: Dict[str, Any]) -> str:
    logger.debug("Building prompt for title=%s source=%s", record.get("title"), record.get("source"))
    title = record.get("title") or "(no title)"
    source = record.get("source") or ""
    ts = record.get("@timestamp") or record.get("timestamp") or ""
    raw_text = record.get("raw_text") or record.get("text") or record.get("full_text") or ""
    snippet = str(raw_text)

    prompt = (
        "You will receive the full raw text of a cyber security article plus metadata.\n"
        "From this raw text alone, extract structured, actionable threat intelligence.\n\n"
        "Return a STRICT JSON object with these fields, in this order:\n\n"
        '- "summary": string (1–3 sentences, plain language, high-level summary of the entire article: who/what/impact)\n'
        '- "attack_summary": string (2–4 sentences, plain language, explaining how the attack or issue works end-to-end in simple terms; if the article describes a step-by-step flow or shows commands/scripts, briefly describe that sequence at a high level without copying commands)\n'
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
        '    - "type": one of ["ip","domain","url","email","hash","filename","registry_key","artifact","cve","other"]\n'
        '    - "value": the exact IOC string as seen in the text\n'
        '    - "context": short description of how this IOC is used (e.g. "C2 server","phishing URL","payload hash","vulnerable endpoint","CVE reference")\n'
        '    - "confidence": float 0–1\n'
        '- "cves": list of objects (must include every CVE ID explicitly mentioned in the text):\n'
        '    - "id": string CVE identifier, e.g. "CVE-2025-12345"\n'
        '    - "severity": string or null (e.g. "Critical","High","Medium","Low") if stated in the article\n'
        '    - "cvss": string or null if a CVSS score is stated in the article\n'
        '    - "description": short description of what is affected and impact, based only on the article\n'
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
        "- If the article does not state an actor/country/vendor/IOC/CVE, either omit it or set confidence low and explain.\n"
        "- For MITRE, do not invent IDs; if unsure, set id to null and confidence low.\n"
        "- For IOCs, ONLY extract values explicitly present in the text (IPs, domains, URLs, hashes, emails, filenames, registry keys, CVE strings, etc.); do NOT fabricate or normalize beyond what is visible.\n"
        "- Be exhaustive with IOCs, CVEs, and vendors: systematically scan the entire text and ensure that every IOC-like artifact, every CVE, and every vendor/product mention is captured in the respective lists, with no omissions and no exact-duplicate entries.\n"
        "- If you are unsure whether something is an IOC, include it with type \"other\" and low confidence, and explain in the context.\n"
        "- Priority should reflect technique criticality, exploit status (e.g. 'zero-day','actively exploited','PoC/public exploit'), and business impact.\n"
        "- Financial relevance is about banks, PSPs, card data, securities, insurance, etc.\n"
        "- The attack_summary should clearly describe the end-to-end flow (initial access, execution, persistence, lateral movement, impact) in simple language. If the article shows specific commands, scripts, or a step-by-step guide, explicitly mention that the article provides such a sequence and summarize the steps at a conceptual level without reproducing raw commands.\n"
        "- Detections and recommendations should be concise but concrete enough to guide SOC and incident response teams.\n"
        "- Do NOT include any markdown, bullet points, or commentary outside the JSON object.\n\n"
        "Return ONLY the JSON object, no extra commentary.\n\n"
        f"Article metadata:\n- Title: {title}\n- URL: {source}\n- Timestamp: {ts}\n\n"
        f'Full raw text:\n"""{"".join(snippet)}"""'
    )
    return prompt


def _call_llm(prompt: str) -> Optional[Dict[str, Any]]:
    if not CONFIG.get("LLM_ENABLED", True):
        logger.info("LLM disabled via config; skipping LLM call")
        return None
    if not prompt:
        logger.warning("LLM prompt is empty; skipping")
        return None
    try:
        model = CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1"))
        url = f"{_ollama_host()}/api/generate"
        payload = {
            "model": model,
            "prompt": f"{SYSTEM_INSTRUCTION}\n\n{prompt}",
            "stream": False,
            "temperature": float(CONFIG.get("LLM_TEMPERATURE", 0.2)),
        }
        logger.info(
            "Calling Ollama model=%s host=%s prompt_chars=%s",
            model,
            url,
            len(payload.get("prompt", "")),
        )
        resp = requests.post(
            url,
            json=payload,
            timeout=CONFIG.get(
                "LLM_REQUEST_TIMEOUT", CONFIG.get("REQUEST_TIMEOUT", 300)
            ),
        )
        if resp.status_code != 200:
            logger.warning(
                "LLM HTTP error status=%s body=%s", resp.status_code, resp.text[:500]
            )
            resp.raise_for_status()
        data = resp.json()
        text = data.get("response")
        if not text:
            logger.warning("LLM response missing 'response' field")
            return None

        try:
            enriched = json.loads(text)
        except Exception:
            s = text.find("{")
            e = text.rfind("}")
            if s != -1 and e != -1 and e > s:
                try:
                    enriched = json.loads(text[s : e + 1])
                except Exception as ex_sub:
                    logger.warning(
                        "Failed to parse JSON from LLM response substring: %s ...",
                        text[s : min(e + 1, s + 500)],
                    )
                    return None
            else:
                logger.warning(
                    "LLM response not JSON parsable. Snippet: %s", text[:500]
                )
                return None

        if not isinstance(enriched, dict):
            logger.warning("LLM response JSON is not an object")
            return None
        logger.info("LLM call succeeded")
        return enriched
    except Exception as exc:
        logger.warning(
            "LLM call failed: %s. If this is model-not-found, run `ollama pull %s` or set OLLAMA_MODEL.",
            exc,
            CONFIG.get("LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3")),
        )
        return None


def _enrich_record_with_llm(record: Dict[str, Any]) -> Dict[str, Any]:
    logger.debug("Enriching record title=%s", record.get("title"))
    prompt = _build_prompt_from_raw(record)
    enriched = _call_llm(prompt)
    if enriched and isinstance(enriched, dict):
        record["llm"] = enriched
        logger.info("LLM enrichment succeeded for title=%s", record.get("title"))
    else:
        logger.info("LLM enrichment skipped/failed for title=%s", record.get("title"))
    return record


def _strip_raw_text_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("raw_text", "text", "full_text"):
        if k in record:
            record.pop(k, None)
    return record


def _write_ndjson(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    logger.info("Writing LLM NDJSON to %s", path)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            rec = _strip_raw_text_fields(rec)
            f.write(json.dumps(rec, ensure_ascii=False, indent=2) + "\n\n")


def _build_markdown(records: List[Dict[str, Any]], input_file: Path) -> str:
    logger.info("Building LLM markdown from %s records", len(records))
    lines: List[str] = []
    lines.append("# LLM Unstructured Threat Intelligence Report")
    lines.append("")
    lines.append(f"_Source file: {input_file.name}_")
    lines.append("")

    def _fmt_kv(label: str, value: str | None) -> str:
        return f"**{label}:** {value}" if value else f"**{label}:** N/A"

    for idx, rec in enumerate(records, start=1):
        title = rec.get("title") or "(no title)"
        source = rec.get("source") or ""
        ts = rec.get("@timestamp") or rec.get("timestamp") or ""
        lines.append(f"## {idx}. {title}")
        if source:
            lines.append(f"_Source: {source}_")
        if ts:
            lines.append(f"_Timestamp: {ts}_")
        llm_payload = rec.get("llm") or {}
        # Always render markdown from structured fields (ignore llm-provided markdown blobs)
        summary = llm_payload.get("summary")
        attack_summary = llm_payload.get("attack_summary")
        if summary:
            lines.append("")
            lines.append(_fmt_kv("Summary", summary))
        if attack_summary:
            lines.append(_fmt_kv("Attack Summary", attack_summary))

        mitre = llm_payload.get("mitre_techniques") or []
        lines.append("")
        lines.append("**MITRE Techniques:**")
        if mitre:
            for t in mitre:
                tid = t.get("id") or "N/A"
                name = t.get("name") or ""
                tactic = t.get("tactic") or ""
                conf = t.get("confidence")
                reason = t.get("reason") or ""
                conf_str = f" (conf {conf})" if conf is not None else ""
                tactic_str = f" ({tactic})" if tactic else ""
                reason_str = f" — {reason}" if reason else ""
                lines.append(f"- {tid} {name}{tactic_str}{conf_str}{reason_str}".strip())
        else:
            lines.append("- N/A")

        priority = llm_payload.get("priority") or {}
        if priority:
            lines.append("")
            lines.append("**Priority:**")
            lines.append(
                f"- {priority.get('label','N/A')} {priority.get('score','N/A')} — {priority.get('reason','')}"
            )

        fin = llm_payload.get("financial_relevance") or {}
        if fin:
            lines.append("")
            lines.append("**Financial Relevance:**")
            lines.append(
                f"- {fin.get('label','N/A')} {fin.get('score','N/A')} — {fin.get('reason','')}"
            )

        actors = llm_payload.get("threat_actors") or []
        lines.append("")
        lines.append("**Threat Actors:**")
        if actors:
            for a in actors:
                name = a.get("name") or "Unknown"
                typ = a.get("type") or ""
                country = a.get("country") or ""
                role = a.get("role") or ""
                conf = a.get("confidence")
                reason = a.get("reason") or ""
                parts = [name]
                if typ:
                    parts.append(f"({typ})")
                extras = []
                if country:
                    extras.append(country)
                if role:
                    extras.append(role)
                if conf is not None:
                    extras.append(f"conf {conf}")
                detail = ", ".join(extras)
                suffix = f" — {reason}" if reason else ""
                lines.append(f"- {' '.join(parts)}{f' [{detail}]' if detail else ''}{suffix}")
        else:
            lines.append("- N/A")

        countries = llm_payload.get("countries") or []
        lines.append("")
        lines.append("**Countries:**")
        if countries:
            for c in countries:
                nm = c.get("name") or "Unknown"
                role = c.get("role") or ""
                conf = c.get("confidence")
                lines.append(f"- {nm} {f'({role})' if role else ''}{f' conf {conf}' if conf is not None else ''}".strip())
        else:
            lines.append("- N/A")

        vendors = llm_payload.get("vendors") or []
        lines.append("")
        lines.append("**Vendors/Products:**")
        if vendors:
            for v in vendors:
                nm = v.get("name") or "Unknown"
                prod = v.get("product") or ""
                conf = v.get("confidence")
                lines.append(f"- {nm}{f' / {prod}' if prod else ''}{f' (conf {conf})' if conf is not None else ''}")
        else:
            lines.append("- N/A")

        iocs = llm_payload.get("iocs") or []
        lines.append("")
        lines.append("**IOCs:**")
        if iocs:
            for i in iocs:
                typ = i.get("type") or ""
                val = i.get("value") or i.get("indicator") or ""
                ctx = i.get("context") or ""
                conf = i.get("confidence")
                ctx_str = f" — {ctx}" if ctx else ""
                conf_str = f" (conf {conf})" if conf is not None else ""
                lines.append(f"- {typ}: {val}{ctx_str}{conf_str}")
        else:
            lines.append("- N/A")

        cves = llm_payload.get("cves") or []
        lines.append("")
        lines.append("**CVEs:**")
        if cves:
            for cve in cves:
                cid = cve.get("id") or ""
                sev = cve.get("severity") or ""
                cvss = cve.get("cvss") or ""
                desc = cve.get("description") or ""
                parts = [cid]
                if sev:
                    parts.append(f"[{sev}]")
                if cvss:
                    parts.append(f"CVSS {cvss}")
                suffix = f" — {desc}" if desc else ""
                lines.append(f"- {' '.join(parts)}{suffix}")
        else:
            lines.append("- N/A")

        detections = llm_payload.get("detections") or []
        lines.append("")
        lines.append("**Detections:**")
        if detections:
            for d in detections:
                name = d.get("name") or ""
                typ = d.get("type") or ""
                idea = d.get("idea") or ""
                lines.append(f"- {name}{f' ({typ})' if typ else ''}: {idea}")
        else:
            lines.append("- N/A")

        recommendations = llm_payload.get("recommendations") or []
        lines.append("")
        lines.append("**Recommendations:**")
        if recommendations:
            for r in recommendations:
                typ = r.get("type") or ""
                txt = r.get("text") or ""
                lines.append(f"- {f'[{typ}] ' if typ else ''}{txt}")
        else:
            lines.append("- N/A")

        tags = llm_payload.get("tags") or []
        if tags:
            lines.append("")
            lines.append("**Tags:** " + ", ".join(tags))

        src = llm_payload.get("source_analysis") or {}
        if src:
            lines.append("")
            lines.append("**Source Analysis:**")
            lines.append(
                f"- {src.get('source_name','N/A')} ({src.get('trust_level','N/A')}): {src.get('reason','')}"
            )
            if src.get("source_url"):
                lines.append(f"- URL: {src.get('source_url')}")
        lines.append("")
    return "\n".join(lines)


def run_llm_rawtext(hours: Optional[int] = None) -> Dict[str, Any]:
    output_dir = _get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    # Find latest rawtext across llm results root
    llm_root = output_dir
    try:
        llm_root = output_dir.parents[1]
    except Exception:
        llm_root = output_dir.parent
    logger.debug("Searching for latest rawtext under %s", llm_root)
    raw_path = _find_latest_rawtext_any(llm_root)
    if raw_path is None:
        logger.warning("No rawtext file found under %s; skipping LLM run", llm_root)
        return {
            "input_file": None,
            "output_ndjson": None,
            "output_markdown": None,
            "records_total": 0,
            "records_processed": 0,
        }
    logger.info("Using rawtext file: %s", raw_path)
    records = _load_rawtext_records(raw_path)
    total = len(records)
    if hours:
        records = _filter_by_hours(records, hours)
        logger.info("Filtered records by last %s hours: %s -> %s", hours, total, len(records))
    if not records:
        logger.warning("No records to enrich after filtering; exiting LLM run")
        return {
            "input_file": str(raw_path),
            "output_ndjson": None,
            "output_markdown": None,
            "records_total": total,
            "records_processed": 0,
        }
    processed: List[Dict[str, Any]] = []
    overall_start = datetime.now()
    avg_secs = 0.0
    success_count = 0
    for idx, rec in enumerate(records, start=1):
        start_ts = datetime.now()
        title = rec.get("title") or "(no title)"
        logger.info("LLM enriching %s/%s: %s", idx, len(records), title)
        rec = _enrich_record_with_llm(rec)
        rec = _strip_raw_text_fields(rec)
        elapsed = (datetime.now() - start_ts).total_seconds()
        # update rolling average for ETA
        avg_secs = ((avg_secs * (idx - 1)) + elapsed) / idx
        remaining = len(records) - idx
        eta_secs = avg_secs * remaining
        if rec.get("llm"):
            success_count += 1
        logger.info(
            "LLM completed %s/%s in %.1fs (avg %.1fs, ETA %.1fs, remaining %s): %s",
            idx,
            len(records),
            elapsed,
            avg_secs,
            eta_secs,
            remaining,
            title,
        )
        processed.append(rec)
    today_stamp = datetime.now().strftime("%Y%m%d")
    ndjson_path = output_dir / f"{RAWTEXT_LLM_PREFIX}{today_stamp}.ndjson"
    md_path = output_dir / f"{LLM_MD_PREFIX}{today_stamp}.md"
    _write_ndjson(ndjson_path, processed)
    md_text = _build_markdown(processed, raw_path)
    md_path.write_text(md_text, encoding="utf-8")
    logger.info(
        "LLM rawtext run complete: total=%s processed=%s ndjson=%s md=%s",
        total,
        len(processed),
        ndjson_path,
        md_path,
    )
    logger.info(
        "LLM enrichment summary: successes=%s failures=%s",
        success_count,
        len(processed) - success_count,
    )
    return {
        "input_file": str(raw_path),
        "output_ndjson": str(ndjson_path),
        "output_markdown": str(md_path),
        "records_total": total,
        "records_processed": len(processed),
    }
