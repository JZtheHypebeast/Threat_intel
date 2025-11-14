from collector.unstructured_core import detect_provenance


def test_detect_provenance_urls_and_source():
    text = "This is a report. Source: ACME Research\nMore text. Refer to https://example.com/report for details."
    prov = detect_provenance(text)
    assert isinstance(prov, list)

    assert any(
        p.get("source_url") and "example.com" in p.get("source_url") for p in prov
    )
    assert any(
        p.get("source_name") and "acme" in p.get("source_name").lower() for p in prov
    )

    assert all("confidence" in p for p in prov)
    assert all("excerpt" in p for p in prov)
