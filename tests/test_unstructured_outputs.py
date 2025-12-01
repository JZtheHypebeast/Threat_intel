import os
import json

import pytest

from collector.unstructured import run_unstructured_rss_analysis
from collector.config import CONFIG


def test_unstructured_writes_three_files(tmp_path, monkeypatch):
    outdir = tmp_path / "results"
    outdir.mkdir()
    monkeypatch.setitem(CONFIG, "OUTPUT_DIR", str(outdir))
    monkeypatch.setitem(CONFIG, "RSS_FEEDS", [])

    res = run_unstructured_rss_analysis(hours=1)

    assert isinstance(res, dict)
    assert "ndjson" in res and "markdown" in res and "rawtext" in res

    ndjson_path = res["ndjson"]
    md_path = res["markdown"]
    raw_path = res["rawtext"]

    assert os.path.isfile(ndjson_path), f"NDJSON file missing: {ndjson_path}"
    assert os.path.isfile(md_path), f"Markdown file missing: {md_path}"
    assert os.path.isfile(raw_path), f"Rawtext file missing: {raw_path}"

    with open(ndjson_path, "r", encoding="utf-8") as fh:
        nd_lines = [l for l in fh.readlines() if l.strip()]
    with open(raw_path, "r", encoding="utf-8") as rf:
        raw_items = json.load(rf)

    assert isinstance(raw_items, list)
    assert len(raw_items) == len(nd_lines)

    with open(md_path, "r", encoding="utf-8") as mf:
        md_text = mf.read()
    assert "## Summary" in md_text
