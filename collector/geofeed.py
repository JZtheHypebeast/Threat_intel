from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
import warnings
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from .progress import start_live_progress, stop_live_progress

RESULTS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
CFG: Optional[Dict[str, Any]] = None
CONFIG_IMPORT_ERROR: Optional[Exception] = None

try:
    from urllib3.exceptions import NotOpenSSLWarning

    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
    from .config import CONFIG as CFG
    from .config import RESULTS_ROOT as _RESULTS_ROOT

    RESULTS_ROOT = _RESULTS_ROOT
except Exception as exc:
    CONFIG_IMPORT_ERROR = exc
    CFG = None

warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*SWIG.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fitz.*")


# =========================
# ====== Config ===========
# =========================


def _require_config() -> Dict[str, Any]:
    if CFG is None:
        raise RuntimeError(
            "GeoFeed requires CONFIG from collector.config; import failed"
        ) from CONFIG_IMPORT_ERROR
    return CFG


# =========================
# ====== Models ===========
# =========================


@dataclass
class FeedItem:
    title: str
    url: str
    published: str
    summary: str


# =========================
# ===== Fetch/Parse =======
# =========================


def _http_get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; geofeed/1.0)",
            "Accept": "application/xml, text/xml, application/rss+xml, text/html, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode(errors="replace")


def _strip_html(s: str) -> str:
    s = re.sub(r"<script[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<style[\s\S]*?</style>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _parse_rss(xml_text: str) -> List[FeedItem]:
    items: List[FeedItem] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items

    channel = root.find("channel")
    if channel is None:
        feed = root.find("{http://www.w3.org/2005/Atom}feed")
        if feed is None:
            return items
        ns = "{http://www.w3.org/2005/Atom}"
        for entry in feed.findall(f"{ns}entry"):
            title = (entry.findtext(f"{ns}title") or "").strip()
            link = ""
            for lnk in entry.findall(f"{ns}link"):
                href = lnk.attrib.get("href")
                if href:
                    link = href
                    break
            published = (entry.findtext(f"{ns}updated") or entry.findtext(f"{ns}published") or "").strip()
            summary = (entry.findtext(f"{ns}summary") or entry.findtext(f"{ns}content") or "").strip()
            items.append(FeedItem(title=title, url=link, published=published, summary=summary))
        return items

    for it in channel.findall("item"):
        title = (it.findtext("title") or "").strip()
        url = (it.findtext("link") or "").strip()
        published = (it.findtext("pubDate") or "").strip()
        summary = (it.findtext("description") or "").strip()
        items.append(FeedItem(title=title, url=url, published=published, summary=summary))

    return items


def _parse_published(s: str) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc)
    except Exception:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d.astimezone(dt.timezone.utc)
        except Exception:
            return None


# =========================
# ====== Scoring ==========
# =========================


def _stable_id(title: str, url: str) -> str:
    h = hashlib.sha1(f"{title}|{url}".encode("utf-8", errors="ignore")).hexdigest()
    return h[:24]


def find_watchlist_hits(text: str, locations: List[str], assets: List[str]) -> Tuple[List[str], List[str]]:
    t = text.lower()
    loc_hits = []
    asset_hits = []
    for x in locations:
        if x and x.lower() in t:
            loc_hits.append(x)
    for x in assets:
        if x and x.lower() in t:
            asset_hits.append(x)
    return loc_hits[:12], asset_hits[:12]


def classify_domain(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["sanction", "embargo", "ultimatum", "border", "airspace", "intercept", "navy", "military"]):
        return "geopolitics"
    if any(k in t for k in ["oil", "gas", "pipeline", "refinery", "offshore", "rig", "fpso"]):
        return "energy"
    return "unknown"


def infer_event_type(text: str) -> str:
    t = text.lower()
    if "sanction" in t:
        return "sanctions"
    if any(k in t for k in ["border", "dispute", "essequibo", "esequibo"]):
        return "territorial_dispute"
    if any(k in t for k in ["navy", "military", "intercept", "drone", "airspace"]):
        return "military_activity"
    return "unspecified"


def escalation_score(
    text: str,
    weights: Dict[str, float],
    amplifiers: Dict[str, float],
    dampeners: Dict[str, float],
) -> Tuple[float, List[str]]:
    t = text.lower()
    score = 0.0
    reasons: List[str] = []
    for k, w in weights.items():
        if k.lower() in t:
            score += float(w)
            reasons.append(k)
    for k, w in amplifiers.items():
        if k.lower() in t:
            score += float(w)
            reasons.append(k)
    for k, w in dampeners.items():
        if k.lower() in t:
            score -= float(w)
            reasons.append(f"-{k}")

    reasons = list(dict.fromkeys(reasons))[:8]
    return score, reasons


def extractive_summary(text: str, max_chars: int = 280) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"


# =========================
# ===== Summaries =========
# =========================


def _ollama_generate_summary(
    host: str,
    model: str,
    title: str,
    text: str,
    max_chars: int,
    timeout: int,
) -> Optional[str]:
    try:
        prompt = (
            "Summarize this news article for a geopolitical early-warning brief.\n"
            "Return ONE paragraph, plain text. Include what happened, where, and who.\n"
            f"Hard limit: {max_chars} characters.\n\n"
            f"TITLE: {title}\n\n"
            f"TEXT: {text[:6000]}"
        )
        payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
        url = host.rstrip("/") + "/api/generate"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "geofeed/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        s = (data.get("response") or "").strip()
        if not s:
            return None
        return s[:max_chars].strip()
    except Exception:
        return None


# =========================
# ====== Output ===========
# =========================


def _write_ndjson(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _make_summary(rows: List[Dict[str, Any]], hours: int, min_score: float) -> str:
    lines = ["# GeoFeed Summary", ""]
    lines.append(f"Window: last {hours} hours")
    lines.append(f"Generated: {dt.datetime.utcnow().isoformat()}Z")
    lines.append(f"Collected: {len(rows)} items (showing score >= {min_score})")
    lines.append("")

    if not rows:
        lines.append("No items collected.")
        lines.append("")
        return "\n".join(lines)

    above = [r for r in rows if float(r.get("score", 0.0)) >= float(min_score)]
    if not above:
        lines.append(f"No items met min_score={min_score}. (Collected {len(rows)} total.)")
        lines.append("")
        return "\n".join(lines)

    def _published_key(row: Dict[str, Any]) -> dt.datetime:
        parsed = _parse_published((row.get("published") or "").strip())
        if parsed is None:
            return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        return parsed

    top = sorted(above, key=_published_key, reverse=True)[:25]
    lines.append("## Top signals")
    lines.append("")
    for idx, r in enumerate(top, start=1):
        title = (r.get("title", "") or "").strip()
        url = (r.get("url", "") or "").strip()
        score = float(r.get("score", 0.0))
        if score >= 8.0:
            severity = "High"
        elif score >= 6.0:
            severity = "Medium"
        elif score >= 4.0:
            severity = "Low"
        else:
            severity = "Info"
        domain = r.get("domain") or "-"
        event_type = r.get("event_type") or "-"
        published = (r.get("published") or "").strip()
        llm_summary = (r.get("LLM_summary") or "").strip()

        if url:
            lines.append(f"{idx}. **[{title}]({url})**")
        else:
            lines.append(f"{idx}. **{title}**")
        lines.append(f"   - Score: {score:.1f} ({severity}) | Domain: {domain} | Event: {event_type}")
        if published:
            lines.append(f"   - Published: {published}")
        wl = r.get("watchlist") or {}
        loc = wl.get("locations") or []
        assets = wl.get("assets") or []
        if loc or assets:
            where_parts = []
            if loc:
                where_parts.append(", ".join(loc))
            if assets:
                where_parts.append(f"assets={', '.join(assets)}")
            lines.append(f"   - Where/Who: {'; '.join(where_parts)}")
        if llm_summary:
            lines.append(f"   - What happened: {llm_summary}")
        why = r.get("reasons") or []
        if why:
            lines.append(f"   - Why it matters: {', '.join(why)}")
        lines.append("")

    return "\n".join(lines)


# =========================
# ===== CLI/Runner ========
# =========================


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "ETA 00s"
    mins, secs = divmod(int(seconds), 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"ETA {hours}h{mins:02d}m"
    if mins:
        return f"ETA {mins:02d}m{secs:02d}s"
    return f"ETA {secs:02d}s"


def _update_progress(
    progress_state: Dict[str, Any],
    processed: int,
    total_expected: int,
    started_at: float,
) -> None:
    progress_state["current"] = processed
    if total_expected <= 0:
        return
    elapsed = time.time() - started_at
    remaining = max(total_expected - processed, 0) * (elapsed / max(processed, 1))
    progress_state["status"] = f"{processed}/{total_expected} {_format_eta(remaining)}"


def build_argparser() -> argparse.ArgumentParser:
    cfg = _require_config()
    p = argparse.ArgumentParser(description="GeoFeed collector (NDJSON + markdown summary).")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--outdir", type=str, default="")
    p.add_argument(
        "--results-root",
        type=str,
        default=os.getenv("TI_RESULTS_ROOT", RESULTS_ROOT),
        help="Root output directory (defaults to collector RESULTS_ROOT)",
    )
    p.add_argument("--timeout", type=int, default=int(cfg["GEOFEED_REQUEST_TIMEOUT"]))
    p.add_argument("--max-items", type=int, default=int(cfg["GEOFEED_MAX_ITEMS_PER_FEED"]))
    p.add_argument("--min-score", type=float, default=None)
    return p


def _default_outdir(results_root: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    return os.path.join(results_root, "geofeed", now.strftime("%Y%m%d"), now.strftime("%H%M%S"))


def run_geofeed(hours: int, outdir: str, results_root: str, timeout: int, max_items: int, min_score: Optional[float]) -> int:
    cfg = _require_config()

    feeds = cfg.get("GEOFEED_RSS_FEEDS") or []
    if not feeds:
        print("No GEOFEED_RSS_FEEDS configured.")
        return 0

    if not results_root:
        results_root = RESULTS_ROOT

    if not outdir:
        outdir = _default_outdir(results_root)

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=int(hours))

    wl_locations = cfg.get("GEOFEED_WATCHLIST_LOCATIONS") or []
    wl_assets = cfg.get("GEOFEED_WATCHLIST_ASSETS") or []

    weights = cfg.get("GEOFEED_SIGNAL_WEIGHTS") or {}
    amplifiers = cfg.get("GEOFEED_AMPLIFIERS") or {}
    dampeners = cfg.get("GEOFEED_DAMPENERS") or {}

    use_ollama = bool(cfg.get("GEOFEED_USE_OLLAMA", False))
    ollama_model = str(cfg.get("GEOFEED_OLLAMA_MODEL", cfg.get("LLM_MODEL")))
    ollama_host = str(cfg.get("OLLAMA_HOST", "http://localhost:11434"))
    summary_max_chars = int(cfg.get("GEOFEED_LLM_SUMMARY_MAX_CHARS", 280))
    add_llm_summary = bool(cfg.get("GEOFEED_ADD_LLM_SUMMARY", False))

    min_score_val = float(min_score if min_score is not None else cfg["GEOFEED_MIN_SCORE"])

    rows: List[Dict[str, Any]] = []
    seen_ids = set()
    total_expected = int(max_items) * len(feeds)
    progress_state = {"current": 0, "status": ""}
    stop_evt, thread = start_live_progress(
        "GeoFeed", total_expected if total_expected > 0 else 1, progress_state
    )
    started_at = time.time()
    processed = 0

    try:
        for feed_url in feeds:
            try:
                xml_text = _http_get(feed_url, timeout=timeout)
                items = _parse_rss(xml_text)[:max_items]
            except Exception:
                items = []

            for it in items:
                pub_dt = _parse_published(it.published)
                if pub_dt is not None and pub_dt < cutoff:
                    processed += 1
                    _update_progress(progress_state, processed, total_expected, started_at)
                    continue

                sid = _stable_id(it.title, it.url)
                if sid in seen_ids:
                    processed += 1
                    _update_progress(progress_state, processed, total_expected, started_at)
                    continue
                seen_ids.add(sid)

                url = it.url.strip()

                page_text = ""
                try:
                    page_html = _http_get(url, timeout=timeout)
                    page_text = _strip_html(page_html)
                except Exception:
                    page_text = _strip_html(it.summary or "")

                blob = f"{it.title}\n\n{page_text}"
                domain = classify_domain(blob)
                event_type = infer_event_type(blob)
                score, reasons = escalation_score(blob, weights=weights, amplifiers=amplifiers, dampeners=dampeners)
                loc_hits, asset_hits = find_watchlist_hits(blob, wl_locations, wl_assets)
                below_threshold = score < min_score_val

                llm_summary: Optional[str] = None
                if add_llm_summary:
                    if use_ollama:
                        llm_summary = _ollama_generate_summary(
                            host=ollama_host,
                            model=ollama_model,
                            title=it.title,
                            text=page_text,
                            max_chars=summary_max_chars,
                            timeout=max(timeout, 45),
                        )
                    if not llm_summary:
                        llm_summary = extractive_summary(page_text, max_chars=summary_max_chars) or None

                now = dt.datetime.now(dt.timezone.utc)
                rows.append(
                    {
                        "id": sid,
                        "ts": now.isoformat(),
                        "title": it.title,
                        "url": url,
                        "published": it.published,
                        "domain": domain,
                        "event_type": event_type,
                        "score": round(float(score), 2),
                        "below_threshold": bool(below_threshold),
                        "reasons": reasons,
                        "watchlist": {"locations": loc_hits, "assets": asset_hits},
                        "source_feed": feed_url,
                        "LLM_summary": llm_summary,
                    }
                )

                processed += 1
                _update_progress(progress_state, processed, total_expected, started_at)
    finally:
        progress_state["current"] = total_expected if total_expected > 0 else processed
        progress_state["status"] = f"{processed}/{total_expected} {_format_eta(0)}"
        stop_live_progress(stop_evt, thread, wait=True)

    rows = sorted(rows, key=lambda r: float(r.get("score", 0.0)), reverse=True)

    run_date = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    ndjson_path = os.path.join(outdir, "geofeed.ndjson")
    md_path = os.path.join(outdir, f"geofeed_summary_{run_date}.md")

    _write_ndjson(ndjson_path, rows)
    _write_text(md_path, _make_summary(rows, hours=hours, min_score=min_score_val))

    print(f"Wrote {len(rows)} items -> {ndjson_path}")
    print(f"Wrote summary -> {md_path}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    return run_geofeed(
        hours=args.hours,
        outdir=args.outdir,
        results_root=args.results_root,
        timeout=args.timeout,
        max_items=args.max_items,
        min_score=args.min_score,
    )


if __name__ == "__main__":
    raise SystemExit(main())
