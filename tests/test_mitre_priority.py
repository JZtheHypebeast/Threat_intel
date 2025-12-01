import pytest

from collector import unstructured_core as uc


def test_compute_mitre_priority_unit(monkeypatch):
    monkeypatch.setattr(uc, "load_mitre_map", lambda: {"T1000": {"priority": 70}})

    intel = {
        "title": "Example Exfiltration campaign",
        "summary_text": "This campaign performs exfiltration.",
        "iocs": [{"type": "ip", "value": "1.2.3.4"}],
        "related_cves": [{"cve": "CVE-2025-0001"}],
        "threat": {
            "technique": [{"id": "T1000", "name": "Exfiltration", "inferred": True}],
            "mitre_details": [
                {"id": "T1000", "name": "Exfiltration", "inferred": True}
            ],
        },
    }

    out = uc.compute_mitre_priority(intel)
    th = out.get("threat") or {}
    assert "mitre_priority" in th
    assert isinstance(th["mitre_priority"]["score"], int)
    det = th.get("mitre_details") or []
    assert det and isinstance(det[0].get("priority_score"), int)


def test_compute_mitre_priority_from_relevance(monkeypatch):
    monkeypatch.setattr(uc, "load_mitre_map", lambda: {"T2000": {"priority": 40}})

    intel = {
        "title": "Test",
        "summary_text": "T2000 observed in the wild",
        "iocs": [],
        "threat": {"technique": [{"id": "T2000", "name": "T2000"}]},
    }

    intel = uc.compute_mitre_relevance(intel)
    intel = uc.compute_mitre_priority(intel)

    th = intel.get("threat") or {}
    assert "mitre_details" in th
    assert any("priority_score" in d for d in th.get("mitre_details", []))
    assert "mitre_priority" in th
