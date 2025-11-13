"""Test: IOC normalization helpers"""

# MODULE: TEST - IOC NORMALIZATION #

from collector.unstructured_core import normalize_and_merge_iocs


def test_normalize_url_and_domain():
    text = "Visit https://Example.COM/path?query=1 and http://example.com/other"
    res = normalize_and_merge_iocs(text, source="t")
    types = {r["type"] for r in res}

    assert any(r["type"] == "url" for r in res)
    assert any(r["type"] == "domain" for r in res)

    assert any(r["value"] == "example.com" for r in res)


def test_normalize_ip():
    text = "Contact 192.168.1.1:8080 or 192.168.1.1"
    res = normalize_and_merge_iocs(text, source="t")
    assert any(r["type"] == "ip" and r["value"] == "192.168.1.1" for r in res)


def test_normalize_email():
    text = "Reach out to Admin@Example.COM for details"
    res = normalize_and_merge_iocs(text, source="t")
    assert any(r["type"] == "email" and r["value"] == "admin@example.com" for r in res)
