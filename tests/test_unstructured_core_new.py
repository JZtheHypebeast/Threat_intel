import os
from datetime import datetime

import re

from collector import unstructured_core as uc
from collector.config import CONFIG


def test_score_actionability_detects_high():
    title = "Active exploit CVE-2025-12345 affecting Fortinet"
    desc = "Ransomware observed in the wild; vendors urged to patch."
    out = uc.score_actionability(title, desc)
    assert isinstance(out, dict)
    assert "label" in out and "score" in out and "reason" in out
    # With active exploit + CVE + ransomware and a patch mention the score
    # may resolve to High or Critical depending on weight summation and capping.
    assert out["label"] in ("High", "Critical")
    assert any(m["keyword"] in out["reason"] for m in out.get("matches", []))


def test_summarize_unstructured_description_prefers_cve():
    text = (
        "Some background information about the product. "
        "CVE-2025-9999: A critical remote code execution was exploited in the wild against Fortinet devices. "
        "Attackers observed privilege escalation."
    )
    s = uc.summarize_unstructured_description(text, max_sentences=2)
    assert isinstance(s, str)
    assert "CVE-2025-9999" in s or re.search(r"CVE-\d{4}-\d+", s)


def test_group_threat_items_by_vendor_or_sector():
    # use a vendor known to be in CONFIG (Fortinet is in defaults)
    rec1 = {"title": "Fortinet FortiGate vulnerability disclosed", "summary": "Exploit observed"}
    rec2 = {"title": "Massive data leak at Example Bank", "summary": "Customer data leaked"}
    out = uc.group_threat_items_by_vendor_or_sector([rec1, rec2])
    assert isinstance(out, dict)
    # Fortinet record should be grouped by vendor
    by_vendor = out.get("by_vendor", {})
    assert any("Forti" in k or k.lower().startswith("forti") or k == "Fortinet" for k in by_vendor.keys())
    # Bank record should match the Financial sector
    by_sector = out.get("by_sector", {})
    assert "Financial" in by_sector or any("bank" in k.lower() for k in by_sector.keys())


def test_dedupe_records_by_title_keeps_most_recent():
    title = "Important vulnerability in X Product"
    old = {"title": title, "@timestamp": "2020-01-01T00:00:00Z"}
    new = {"title": title, "@timestamp": "2025-01-01T00:00:00Z"}
    res = uc.dedupe_records_by_title([old, new])
    assert isinstance(res, list)
    assert len(res) == 1
    kept = res[0]
    assert kept.get("@timestamp") == "2025-01-01T00:00:00Z"


def test_generate_markdown_summary_basic():
    parsed = [
        {"title": "T1", "text": "some text", "source": "src1", "top_findings": ["f1"], "threat": {"technique": {"name": ["X"]}}, "threat": {"relevance": {"score": 70, "label": "High"}}},
        {"title": "T2", "text": "other text", "source": "src2", "top_findings": ["f2"], "threat": {"technique": {"name": ["Y"]}}, "threat": {"relevance": {"score": 30, "label": "Medium"}}},
    ]
    md = uc.generate_markdown_summary(parsed)
    assert isinstance(md, str)
    assert "Threat Intelligence Summary" in md
    assert "Entry 1" in md and "Entry 2" in md
