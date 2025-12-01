import json

from types import SimpleNamespace


def test_unstructured_writer_does_not_emit_mitre_classifier(monkeypatch, tmp_path):

    fake_entry = {
        "link": "http://example.local/article/1",
        "title": "Test Ransomware",
        "published": "2025-11-28T12:00:00Z",
    }

    def fake_parse(_):
        return SimpleNamespace(entries=[fake_entry])

    def fake_fetch_article_text(link):
        return "This ransomware campaign encrypts files and demands ransom."

    monkeypatch.setattr("feedparser.parse", fake_parse)
    monkeypatch.setattr(
        "collector.unstructured.fetch_article_text", fake_fetch_article_text
    )

    from collector import config

    monkeypatch.setitem(config.CONFIG, "OUTPUT_DIR", str(tmp_path))

    from collector.unstructured import run_unstructured_rss_analysis

    result = run_unstructured_rss_analysis(hours=24)
    ndjson_path = result.get("ndjson")
    assert ndjson_path

    found_mitre = False
    with open(ndjson_path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            th = rec.get("threat") or {}
            tech = th.get("technique")
            if isinstance(tech, dict):
                if "mitre" in tech:
                    found_mitre = True
                    break
            elif isinstance(tech, list):
                for t in tech:
                    if isinstance(t, dict) and "mitre" in t:
                        found_mitre = True
                        break
                if found_mitre:
                    break

    assert (
        not found_mitre
    ), "The writer should not emit a `mitre` classifier under `threat.technique`."
