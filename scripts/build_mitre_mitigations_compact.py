import json
import os
import re

IN = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "mitre_mitigations.json"
)
OUT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "mitre_mitigations_compact.json"
)

# =============================================================================
#         SCRIPTS - BUILD_MITRE_MITIGATIONS_COMPACT
# =============================================================================
# Create a compact, short-form mapping of mitigation recommendations/snippets
# for quick inclusion in generated reports (data/mitre_mitigations_compact.json).
# =============================================================================

SENTENCE_RE = re.compile(r"([^.!?\n]{10,}?[.!?])\s*")


def first_sentence(text):
    if not text:
        return ""
    m = SENTENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    for sep in [".\n", "\n", "."]:
        if sep in text:
            part = text.split(sep)[0].strip()
            if part:
                return part + ("." if sep == "." else "")
    return text.strip()


def compact_recs(recs):
    if not recs:
        return []
    short = [r.strip() for r in recs if r and len(r.strip()) <= 120]
    chosen = []
    for r in short:
        if r not in chosen:
            chosen.append(r)
        if len(chosen) >= 2:
            break
    if len(chosen) >= 2:
        return chosen[:2]
    for r in recs:
        s = first_sentence(r)
        if s and s not in chosen:
            chosen.append(s)
        if len(chosen) >= 2:
            break
    out = []
    for c in chosen:
        c = c.strip()
        if len(c) > 140:
            c = c[:137].rstrip() + "..."
        out.append(c)
    return out


def compact_snippets(snips):
    out = {}
    for k, arr in (snips or {}).items():
        taken = []
        for s in arr:
            if not s:
                continue
            s2 = s.strip()
            if len(s2) > 140:
                s2 = s2[:137].rstrip() + "..."
            if s2 not in taken:
                taken.append(s2)
            if len(taken) >= 2:
                break
        if taken:
            out[k] = taken
    return out


def main():
    # BUILD SCRIPT #
    with open(IN, "r", encoding="utf-8") as f:
        data = json.load(f)

    out = {}
    for tid, info in data.items():
        recs = info.get("recommendations", []) or []
        snippets = info.get("snippets", {}) or {}
        compact = compact_recs(recs)
        compact_snip = compact_snippets(snippets)
        if not compact and not compact_snip:
            continue
        out[tid] = {
            "title": info.get("title", ""),
            "recommendations": compact,
            "snippets": compact_snip,
        }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"Wrote compact mitigations for {len(out)} techniques -> {OUT}")


if __name__ == "__main__":
    main()
