import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from collector import CVE
from collector.config import CONFIG


class TestStructuredHelpers(unittest.TestCase):

    def test_build_vendor_pattern_and_match(self):
        pat = CVE.build_vendor_pattern("Palo Alto Networks")
        self.assertIsNotNone(pat.search("Palo Alto Networks product"))
        pat2 = CVE.build_vendor_pattern("Forti")
        self.assertIsNotNone(pat2.search("FortiGate"))

    def test_extract_cvss_and_description(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            },
            "published": "2025-11-05T10:00:00Z",
            "lastModified": "2025-11-05T11:00:00Z",
            "id": "CVE-2025-0001",
        }
        score, severity = CVE.extract_cvss(cve)
        desc = CVE.extract_description(cve)
        self.assertEqual(score, 9.8)
        self.assertEqual(severity, "CRITICAL")
        self.assertIn("Test vulnerability", desc)

    @patch("collector.CVE.fetch_json")
    def test_fetch_kev_sources(self, mock_fetch):
        mock_fetch.side_effect = [
            {"vulnerabilities": [{"cveID": "CVE-2025-0001"}]},
            {"vulnerabilities": [{"cve_id": "CVE-2025-0002"}]},
        ]
        kev = CVE.fetch_kev_sources()
        self.assertIn("CVE-2025-0001", kev)
        self.assertIn("CVE-2025-0002", kev)

    def test_normalize_cve_and_timestamps(self):
        cve = {
            "id": "CVE-2025-0003",
            "descriptions": [{"lang": "en", "value": "Desc"}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                ]
            },
            "published": "2025-11-04T12:00:00Z",
            "lastModified": "2025-11-04T13:00:00Z",
        }
        entry = CVE.normalize_cve(
            cve, "Microsoft", set(), from_article=False, source="http://example"
        )
        self.assertEqual(entry["vendor"]["name"], "Microsoft")
        self.assertEqual(entry["vulnerability"]["id"], "CVE-2025-0003")
        self.assertIsNotNone(entry["vulnerability"]["published"])

    def test_collect_cpe_products(self):
        cve = {
            "configurations": {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "cpe23Uri": "cpe:2.3:a:atlassian:confluence:1.0:*:*:*:*:*:*:*",
                            },
                            {
                                "criteria": "cpe:2.3:a:atlassian:jira:9.1:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        }
        products = CVE.collect_cpe_products(cve)
        self.assertIn("confluence", [p.lower() for p in products])
        self.assertIn("jira", [p.lower() for p in products])


if __name__ == "__main__":
    unittest.main()
