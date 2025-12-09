import pathlib

from collector.llm_rawtext import _build_markdown, _normalize_llm_payload


def test_normalize_llm_payload_maps_ioc_alias():
    payload = {
        "summary": "example",
        "indicators_of_compromise": [{"type": "ip", "value": "1.2.3.4"}],
    }
    normalized = _normalize_llm_payload(payload)
    assert "iocs" in normalized
    assert normalized["iocs"] == [{"type": "ip", "value": "1.2.3.4"}]
    # ensure list fields are present even if missing
    for key in (
        "mitre_techniques",
        "threat_actors",
        "countries",
        "vendors",
        "cves",
        "detections",
        "recommendations",
        "tags",
    ):
        assert key in normalized
        assert isinstance(normalized[key], list)


def test_build_markdown_renders_structured_fields(tmp_path: pathlib.Path):
    input_file = tmp_path / "rawtext-sample.json"
    input_file.write_text("[]", encoding="utf-8")
    record = {
        "title": "Sample Article",
        "source": "https://example.com",
        "@timestamp": "2025-12-09T00:00:00Z",
        "llm": {
            "summary": "A short summary.",
            "attack_summary": "An end-to-end attack description.",
            "mitre_techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.9}
            ],
            "priority": {"score": 80, "label": "High", "reason": "Critical exposure."},
            "financial_relevance": {"score": 70, "label": "High", "reason": "Finance impact."},
            "threat_actors": [{"name": "Actor", "type": "Cybercrime", "country": "US", "role": "Mentioned", "confidence": 0.5}],
            "countries": [{"name": "US", "role": "Target", "confidence": 0.8}],
            "vendors": [{"name": "Vendor", "product": "Product", "confidence": 0.9}],
            "iocs": [{"type": "ip", "value": "1.2.3.4", "context": "C2", "confidence": 0.8}],
            "cves": [{"id": "CVE-2025-1234", "severity": "High", "cvss": "8.0", "description": "Test CVE"}],
            "detections": [{"name": "Detect C2", "type": "Network", "idea": "Look for 1.2.3.4"}],
            "recommendations": [{"type": "Technical", "text": "Block 1.2.3.4"}],
            "tags": ["ransomware"],
            "source_analysis": {"source_name": "Example", "trust_level": "Medium", "reason": "Test", "source_url": "https://example.com"},
        },
    }
    md = _build_markdown([record], input_file)
    # Check key sections are present
    assert "Sample Article" in md
    assert "Summary:" in md
    assert "MITRE Techniques" in md
    assert "1.2.3.4" in md
    assert "CVE-2025-1234" in md
