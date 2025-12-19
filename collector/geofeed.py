from __future__ import annotations

import warnings
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except Exception:
    pass
warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*SWIG.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fitz.*")

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
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .progress import start_live_progress, stop_live_progress
try:
    from .reporting import _render_pdf
except Exception:
    try:
        from reporting import _render_pdf  # type: ignore
    except Exception:
        _render_pdf = None  # type: ignore

RESULTS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
ENV_GEOFEED_RSS_FEEDS = [
    s.strip()
    for s in os.getenv("GEOFEED_RSS_FEEDS", "").split(",")
    if s.strip()
]
CFG: Optional[Dict[str, Any]] = None
CONFIG_IMPORT_ERROR: Optional[Exception] = None

try:
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
        try:
            return raw.decode("utf-8-sig", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")


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


# =========================
# ===== Summaries =========
# =========================


def _ollama_situation_summary(
    host: str,
    model: str,
    title: str,
    text: str,
    timeout: int,
) -> Optional[Dict[str, Any]]:
    try:
        prompt = (
            "You are a geopolitical early-warning analyst.\n"
            "Read the article and return JSON ONLY with exactly these keys:\n"
            "title, llm_summary, domain, event_type, state, change, countries_affected, "
            "primary_actors, key_indicators, osint_indicators, drivers, risk, watch, "
            "what_happened, domain_category.\n"
            "Rules:\n"
            "- Each value must be a short string; no lists.\n"
            "- 'title' should be a concise, corrected headline.\n"
            "- 'llm_summary' should be 1-2 sentences, factual, no speculation.\n"
            "- 'domain' should be a short label (air, maritime, land, multi, unknown).\n"
            "- 'event_type' should be a short, concrete label (e.g., border clash, sanctions, naval deployment).\n"
            "- 'risk' must be one of: Low, Moderate, Elevated, Severe.\n"
            "- 'domain_category' must be one of: air, maritime, land, multi, unknown.\n"
            "- Use 'multi' only if two or more domains are clearly present.\n"
            "- Do not add extra keys.\n\n"
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
        parsed = json.loads(s)
        if not isinstance(parsed, dict):
            return None
        return parsed
    except Exception:
        return None


# =========================
# ====== Output ===========
# =========================


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _strip_markdown_inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"_([^_]+)_", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def _prepare_pdf_text(markdown_text: str) -> str:
    lines = markdown_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cleaned = [_strip_markdown_inline(line) for line in lines]
    return "\n".join(cleaned)


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
    lines.append("## Entries by Domain")
    lines.append("")
    lines.append("Domains: air (aviation/airspace), maritime (naval/shipping), land (ground/border), multi (more than one domain), unknown.")
    lines.append("")
    buckets = {"air": [], "maritime": [], "land": [], "multi": [], "unknown": []}
    for r in top:
        situation = r.get("situation") or {}
        category = str(situation.get("domain_category") or "unknown").lower()
        if category not in buckets:
            category = "unknown"
        buckets[category].append(r)

    idx = 1
    for label in ("air", "maritime", "land", "multi", "unknown"):
        group = buckets[label]
        if not group:
            continue
        title_label = label.capitalize()
        lines.append(f"### {title_label}")
        lines.append("")
        for r in group:
            situation = r.get("situation") or {}
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
            domain = situation.get("domain") or r.get("domain") or "-"
            event_type = situation.get("event_type") or r.get("event_type") or "-"
            published = (r.get("published") or "").strip()

            if url:
                lines.append(f"{idx}. **[{title}]({url})**")
            else:
                lines.append(f"{idx}. **{title}**")
            lines.append(f"   - Score: {score:.1f} ({severity}) | Domain: {domain} | Event: {event_type}")
            if published:
                lines.append(f"   - Published: {published}")
            lines.append(f"   - LLM Summary: {situation.get('llm_summary') or '-'}")
            lines.append("")
            lines.append("## Situation Summary")
            lines.append("")
            lines.append("**State:**")
            lines.append(f"_{situation.get('state') or '-'}_")
            lines.append("")
            lines.append("**Change:**")
            lines.append(f"_{situation.get('change') or '-'}_")
            lines.append("")
            lines.append("**What happened:**")
            lines.append(f"_{situation.get('what_happened') or '-'}_")
            lines.append("")
            lines.append("**Countries Affected:**")
            lines.append(f"_{situation.get('countries_affected') or '-'}_")
            lines.append("")
            lines.append("**Primary Actors:**")
            lines.append(f"_{situation.get('primary_actors') or '-'}_")
            lines.append("")
            lines.append("**Key Indicators & Signals:**")
            lines.append(f"_{situation.get('key_indicators') or '-'}_")
            lines.append("")
            lines.append("**OSINT Indicators:**")
            lines.append(f"_{situation.get('osint_indicators') or '-'}_")
            lines.append("")
            lines.append("**Drivers:**")
            lines.append(f"_{situation.get('drivers') or '-'}_")
            lines.append("")
            lines.append("**Risk:**")
            lines.append(f"_{situation.get('risk') or '-'}_")
            lines.append("")
            lines.append("**Watch:**")
            lines.append(f"_{situation.get('watch') or '-'}_")
            lines.append("")
            idx += 1

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


def _shorten_title(title: str, max_len: int = 60) -> str:
    if not title:
        return "-"
    title = str(title).strip()
    if len(title) <= max_len:
        return title
    return title[: max_len - 3].rstrip() + "..."


def _update_progress(
    progress_state: Dict[str, Any],
    processed: int,
    total_expected: int,
    started_at: float,
    item_title: Optional[str] = None,
) -> None:
    progress_state["current"] = processed
    if total_expected <= 0:
        return
    elapsed = time.time() - started_at
    remaining = max(total_expected - processed, 0) * (elapsed / max(processed, 1))
    status = f"{processed}/{total_expected} {_format_eta(remaining)}"
    if item_title:
        status = f"{status} | {_shorten_title(item_title)}"
    progress_state["status"] = status

def build_argparser() -> argparse.ArgumentParser:
    cfg = _require_config()
    p = argparse.ArgumentParser(description="GeoFeed collector (markdown summary only).")
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
    p.add_argument("--pdf", action="store_true", help="Also render the markdown summary as PDF")
    return p


def _default_outdir(results_root: str) -> str:
    now = dt.datetime.now()
    return os.path.join(results_root, "geofeed", now.strftime("%Y%m%d"), now.strftime("%H%M%S"))


def run_geofeed(
    hours: int,
    outdir: str,
    results_root: str,
    timeout: int,
    max_items: int,
    min_score: Optional[float],
    render_pdf: bool = False,
) -> int:
    cfg = _require_config()

    feeds = cfg.get("GEOFEED_RSS_FEEDS") or ENV_GEOFEED_RSS_FEEDS
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
    add_llm_summary = bool(cfg.get("GEOFEED_ADD_LLM_SUMMARY", False))

    min_score_val = float(min_score if min_score is not None else cfg["GEOFEED_MIN_SCORE"])

    rows: List[Dict[str, Any]] = []
    seen_ids = set()
    feed_items: List[Tuple[str, List[FeedItem]]] = []
    for feed_url in feeds:
        try:
            xml_text = _http_get(feed_url, timeout=timeout)
            items = _parse_rss(xml_text)[:max_items]
        except Exception:
            items = []
        feed_items.append((feed_url, items))

    total_expected = sum(len(items) for _, items in feed_items)
    progress_state = {"current": 0, "status": ""}
    stop_evt, thread = start_live_progress(
        "GeoFeed", total_expected if total_expected > 0 else 1, progress_state
    )
    started_at = time.time()
    processed = 0

    try:
        for feed_url, items in feed_items:
            for it in items:
                pub_dt = _parse_published(it.published)
                if pub_dt is not None and pub_dt < cutoff:
                    processed += 1
                    _update_progress(
                        progress_state, processed, total_expected, started_at, it.title
                    )
                    continue

                sid = _stable_id(it.title, it.url)
                if sid in seen_ids:
                    processed += 1
                    _update_progress(
                        progress_state, processed, total_expected, started_at, it.title
                    )
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

                situation: Optional[Dict[str, Any]] = None
                if add_llm_summary and use_ollama:
                    situation = _ollama_situation_summary(
                        host=ollama_host,
                        model=ollama_model,
                        title=it.title,
                        text=page_text,
                        timeout=max(timeout, 45),
                    )

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
                        "situation": situation,
                    }
                )

                processed += 1
                _update_progress(
                    progress_state, processed, total_expected, started_at, it.title
                )
    finally:
        progress_state["current"] = total_expected if total_expected > 0 else processed
        progress_state["status"] = f"{processed}/{total_expected} {_format_eta(0)}"
        stop_live_progress(stop_evt, thread, wait=True)

    rows = sorted(rows, key=lambda r: float(r.get("score", 0.0)), reverse=True)

    run_date = dt.datetime.now().strftime("%Y%m%d")
    md_path = os.path.join(outdir, f"geofeed_summary_{run_date}.md")
    pdf_path = os.path.join(outdir, f"geofeed_summary_{run_date}.pdf")

    summary_text = _make_summary(rows, hours=hours, min_score=min_score_val)
    _write_text(md_path, summary_text)
    if render_pdf and _render_pdf is not None:
        _render_pdf(summary_text, Path(pdf_path))
        print(f"Wrote PDF -> {pdf_path}")

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
        render_pdf=args.pdf,
    )


if __name__ == "__main__":
    raise SystemExit(main())
