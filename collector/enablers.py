from __future__ import annotations
import re
from typing import List
from .config import CONFIG

DEFAULT_ENABLER_KEYWORDS = [
    "ai",
    "artificial intelligence",
    "machine learning",
    "third-party",
    "outsourcing",
    "zero-day",
    "unpatched",
    "cryptocurrency",
    "quantum",
    "geopolitical",
    "open-source",
]


def _get_excerpt(text: str, pos: int, radius: int = 120) -> str:
    if not text:
        return ""
    text_len = len(text)
    start = max(0, pos - radius)
    end = min(text_len, pos + radius)

    try:
        sent_re = re.compile(r".*?[\.\!?\n]+", re.S)
        sentences = list(sent_re.finditer(text))
        if sentences:
            for i, m in enumerate(sentences):
                if m.start() <= pos < m.end():
                    s_start = m.start()
                    s_end = m.end()
                    combined = text[s_start:s_end]
                    if i > 0 and len(combined) < 80:
                        prev = sentences[i - 1]
                        s_start = prev.start()
                        combined = text[s_start:s_end]
                    if i + 1 < len(sentences) and len(combined) < 120:
                        nxt = sentences[i + 1]
                        s_end = nxt.end()
                    excerpt = text[s_start:s_end]
                    excerpt = re.sub(r"\s+", " ", excerpt).strip()
                    return excerpt
    except Exception:
        pass

    excerpt = text[start:end]
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    return excerpt


def _build_texts(text_or_record) -> tuple[str, str, str | None]:
    # prefer the article body as the primary text source to avoid site chrome
    prov_parts = []
    primary = ""
    primary_short = None
    if isinstance(text_or_record, dict):
        rec = text_or_record
        # Prefer the sanitized article body first
        for f in ("text", "full_text", "summary_text", "summary", "title", "description"):
            v = rec.get(f)
            if v:
                try:
                    primary = str(v)
                    break
                except Exception:
                    continue

        # collect provenance excerpts separately
        for p in rec.get("provenance") or []:
            try:
                if isinstance(p, dict):
                    ex = p.get("excerpt") or p.get("source_name") or p.get("source_url")
                    if ex:
                        prov_parts.append(str(ex))
                else:
                    prov_parts.append(str(p))
            except Exception:
                continue

        try:
            primary_short = rec.get("summary_text") or rec.get("summary")
            if primary_short:
                primary_short = str(primary_short)
        except Exception:
            primary_short = None
    else:
        primary = str(text_or_record or "")

    prov_text = "\n".join([p for p in prov_parts if p])

    try:
        def _strip_boilerplate_local(src: str) -> str:
            if not src:
                return src
            # remove obvious single-line site chrome like "Topics ...", "Share" and "Follow us"
            lines = [l for l in src.splitlines() if l and not re.match(r"^\s*(topics|share|follow)\b", l, re.I)]
            cleaned = "\n".join(lines)

            para_split = re.split(r"\n\s*\n", cleaned)
            try:
                min_words = int(CONFIG.get("MIN_PARAGRAPH_WORDS", 20))
            except Exception:
                min_words = 20
            promo_patterns = CONFIG.get("PROMO_PATTERNS") or []
            bp_keywords = [k.lower() for k in (CONFIG.get("BOILERPLATE_KEYWORDS") or [])]
            short_social_re = CONFIG.get("SHORT_SOCIAL_REGEX") or None

            for i, p in enumerate(para_split):
                p_clean = re.sub(r"\s+", " ", p or "").strip()
                if not p_clean:
                    continue
                skip = False
                for pat in promo_patterns or []:
                    try:
                        if re.search(pat, p_clean, re.I):
                            skip = True
                            break
                    except Exception:
                        continue
                if skip:
                    continue
                try:
                    if short_social_re and re.search(short_social_re, p_clean, re.I):
                        continue
                except Exception:
                    pass
                words = p_clean.split()

                if len(words) < min_words:
                    if any(k in p_clean.lower() for k in bp_keywords):
                        continue
                    try:
                        if short_social_re and re.search(short_social_re, p_clean, re.I):
                            continue
                    except Exception:
                        pass

                return "\n\n".join(para_split[i:]).strip()
            return cleaned

        primary = _strip_boilerplate_local(primary or "")
    except Exception:
        pass

    return primary, prov_text, primary_short


def extract_enablers(
    text_or_record, detailed: bool = False, radius: int | None = None
) -> List:
    try:
        keywords = CONFIG.get("ENABLER_KEYWORDS") or DEFAULT_ENABLER_KEYWORDS
    except Exception:
        keywords = DEFAULT_ENABLER_KEYWORDS

    primary, prov_text, primary_short = _build_texts(text_or_record)
    primary_lower = (primary or "").lower()
    prov_lower = (prov_text or "").lower()
    primary_short_lower = (primary_short or "").lower() if primary_short else None

    if radius is None:
        try:
            radius = int(CONFIG.get("EXCERPT_RADIUS", 120))
        except Exception:
            radius = 120

    results = []
    seen = set()
    for kw in keywords:
        if not kw:
            continue
        try:
            pat = re.compile(r"\b" + re.escape(kw.lower()) + r"\b", re.I)

            mobj = None
            source_text = None
            source_lower = None
            # Prefer the full article body (primary) over the shorter summary
            if primary:
                mobj = pat.search(primary)
                source_text = primary
                source_lower = primary_lower
            if not mobj and primary_short_lower is not None:
                mobj = pat.search(primary_short)
                source_text = primary_short
                source_lower = primary_short_lower
            if not mobj and prov_text:
                mobj = pat.search(prov_text)
                source_text = prov_text
                source_lower = prov_lower

            if not mobj:
                continue

            kn = kw.strip()
            if kn in seen:
                continue
            seen.add(kn)
            start = mobj.start()
            excerpt = _get_excerpt(source_text, start, radius=radius)
            def _clean_excerpt_local(s: str) -> str:
                if not s:
                    return s
                try:
                    # remove large share blocks starting with SHARE or Share
                    s = re.sub(r"SHARE[\s\S]*$", "", s, flags=re.I)
                    s = re.sub(r"Share on [A-Za-z \-]+", "", s, flags=re.I)
                    # remove common social icon glyphs
                    s = re.sub(r"[]+", " ", s)
                    # strip leading lists like 'Topics Acquisition ...' or 'Download Now ...' or 'Related Articles:'
                    s = re.sub(r"(?m)^(?:Topics Acquisition|Topics|Download Now|Related Articles?):.*$", "", s, flags=re.I)
                    # remove lines that are just long tag/keyword lists (10+ short tokens, no punctuation)
                    s = re.sub(r"(?m)^[A-Za-z0-9'\"\-]{1,20}(?:\s+[A-Za-z0-9'\"\-]{1,20}){9,}$", "", s)
                    # collapse whitespace
                    s = re.sub(r"\s+", " ", s).strip()
                    if len(s) < 20 or re.match(r"^[\W_]+$", s):
                        return ""
                except Exception:
                    return s
                return s

            conf = 0.6
            if len(kw) > 6:
                conf += 0.08
            if re.search(r"observed|confirmed|reported|seen|exploited", excerpt, re.I):
                conf += 0.18
            try:

                try:
                    count_primary_short = (
                        len(list(pat.finditer(primary_short_lower)))
                        if primary_short_lower
                        else 0
                    )
                except Exception:
                    count_primary_short = 0
                try:
                    count_primary = (
                        len(list(pat.finditer(primary_lower))) if primary_lower else 0
                    )
                except Exception:
                    count_primary = 0
                try:
                    count_prov = (
                        len(list(pat.finditer(prov_lower))) if prov_lower else 0
                    )
                except Exception:
                    count_prov = 0
                if (count_primary_short + count_primary + count_prov) > 1:
                    conf += 0.08
            except Exception:
                pass

            conf = min(0.99, conf)

            cleaned = _clean_excerpt_local(excerpt).strip()
            # suppress very short / empty excerpts
            try:
                min_chars = int(CONFIG.get("MIN_EXCERPT_CHARS", 30))
            except Exception:
                min_chars = 30
            if cleaned and len(cleaned) < min_chars:
                cleaned = ""

            if detailed:
                results.append(
                    {
                        "enabler": kn,
                        "excerpt": cleaned,
                        "confidence": round(conf, 2),
                    }
                )
            else:
                results.append(kn)
        except Exception:
            try:
                if kw.lower() in primary_lower or kw.lower() in prov_lower:
                    kn = kw.strip()
                    if detailed:
                        results.append(
                            {"enabler": kn, "excerpt": "", "confidence": 0.6}
                        )
                    else:
                        results.append(kn)
            except Exception:
                continue
    return results


def extract_enablers_detailed(text_or_record, radius: int = 120) -> List[dict]:
    return extract_enablers(text_or_record, detailed=True, radius=radius)
