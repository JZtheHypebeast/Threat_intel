#!/usr/bin/env python3
import json
import os
import shutil
import sys


def sanitize_record(rec):
    for k in ("text", "raw_text", "summary_text", "extracted_text_source"):
        if k in rec:
            rec.pop(k, None)
    if "provenance" in rec and isinstance(rec["provenance"], list):
        try:
            newp = []
            for p in rec["provenance"]:
                if isinstance(p, dict):
                    p2 = {
                        k: v
                        for k, v in p.items()
                        if k in ("source_name", "source_url", "confidence")
                    }
                    newp.append(p2)
                else:
                    newp.append(p)
            rec["provenance"] = newp
        except Exception:
            pass
    return rec


def sanitize_ndjson(path):
    bak = path + ".bak"
    shutil.copy2(path, bak)
    out_lines = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n\r")
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                # leave line unchanged if not JSON
                out_lines.append(line)
                continue
            rec = sanitize_record(rec)
            out_lines.append(json.dumps(rec, ensure_ascii=False))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out_lines) + "\n")
    print(f"Sanitized {path}, backup at {bak}")


def sanitize_rawjson(path):
    bak = path + ".bak"
    shutil.copy2(path, bak)
    try:
        with open(path, "r", encoding="utf-8") as rf:
            data = json.load(rf)
    except Exception as e:
        print(f"Failed to read {path}: {e}")
        return
    if not isinstance(data, list):
        print(f"Skipping {path}: not a JSON list")
        return
    out = []
    for item in data:
        if isinstance(item, dict):
            out.append(sanitize_record(item))
        else:
            out.append(item)
    with open(path, "w", encoding="utf-8") as wf:
        json.dump(out, wf, ensure_ascii=False, indent=2)
    print(f"Sanitized {path}, backup at {bak}")


def main():
    if len(sys.argv) > 1:
        d = sys.argv[1]
    else:
        d = os.path.join(
            os.path.dirname(__file__), "..", "collector", "results", "20251114"
        )
        d = os.path.normpath(d)
    if not os.path.isdir(d):
        print(f"Results dir not found: {d}")
        sys.exit(1)
    ndjson = os.path.join(d, "UnstructuredRSSIntel_20251114.ndjson")
    rawjson = os.path.join(d, "rawtext-20251114.json")
    if os.path.isfile(ndjson):
        sanitize_ndjson(ndjson)
    else:
        print(f"NDJSON not found: {ndjson}")
    if os.path.isfile(rawjson):
        sanitize_rawjson(rawjson)
    else:
        print(f"Rawtext JSON not found: {rawjson}")


if __name__ == "__main__":
    main()
