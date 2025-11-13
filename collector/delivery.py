from __future__ import annotations

import hashlib
import json
import time
from typing import List

import requests

from .config import CONFIG, logger


def _make_id(doc: dict) -> str:

    base = (
        str(doc.get("source", ""))
        + "|"
        + str(doc.get("title", ""))
        + "|"
        + str(doc.get("@timestamp", ""))
    )
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def _format_bulk_payload(docs: List[dict], index: str) -> str:
    lines = []
    for d in docs:
        _id = d.get("_id") or _make_id(d)
        action = {"index": {"_index": index, "_id": _id}}
        lines.append(json.dumps(action, ensure_ascii=False))
        lines.append(json.dumps(d, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def send_batch_to_elastic(docs: List[dict]) -> bool:

    if not docs:
        return True

    endpoint = CONFIG.get("ELASTIC_ENDPOINT")
    index = CONFIG.get("ELASTIC_INDEX")
    batch_size = CONFIG.get("SIEM_BATCH_SIZE", 50)
    max_retries = CONFIG.get("SIEM_MAX_RETRIES", 3)
    timeout = CONFIG.get("SIEM_TIMEOUT", 15)
    dry = CONFIG.get("SIEM_DRY_RUN", True)

    session = requests.Session()
    headers = {"Content-Type": "application/x-ndjson"}
    api_key = CONFIG.get("ELASTIC_API_KEY")
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    else:
        user = CONFIG.get("ELASTIC_USER")
        pw = CONFIG.get("ELASTIC_PASS")
        if user and pw:
            session.auth = (user, pw)

    if dry:
        logger.info(
            f"SIEM dry-run enabled. Would send {len(docs)} docs to Elastic {endpoint}/{index}"
        )
        try:
            preview = docs[:3]
            logger.debug(
                "SIEM payload preview: %s", json.dumps(preview, ensure_ascii=False)
            )
        except Exception:
            pass
        return True

    for i in range(0, len(docs), batch_size):
        batch = docs[i : i + batch_size]
        payload = _format_bulk_payload(batch, index)
        url = endpoint.rstrip("/") + "/_bulk"
        success = False
        backoff = 1
        for attempt in range(1, max_retries + 1):
            try:
                r = session.post(
                    url, data=payload.encode("utf-8"), headers=headers, timeout=timeout
                )
                if r.status_code in (200, 201):
                    try:
                        resp = r.json()
                        if resp.get("errors"):
                            logger.warning(
                                f"Elastic bulk reported errors on attempt {attempt}: %s",
                                resp,
                            )
                        else:
                            success = True
                            break
                    except Exception:
                        success = True
                        break
                else:
                    logger.warning(
                        f"Elastic bulk returned status {r.status_code} on attempt {attempt}: {r.text[:200]}"
                    )
            except Exception as e:
                logger.warning(f"Elastic bulk request attempt {attempt} failed: {e}")
            time.sleep(backoff)
            backoff *= 2

        if not success:
            logger.error(
                f"Failed to send batch starting at {i} to Elastic after {max_retries} attempts"
            )
            return False

    logger.info(f"Sent {len(docs)} documents to Elastic index {index}")
    return True
