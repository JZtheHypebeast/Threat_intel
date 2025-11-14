import unittest

from collector.unstructured import extract_iocs, generate_actionable_items


class TestActionableHelpers(unittest.TestCase):
    def test_extract_iocs_basic(self):
        text = (
            "Contact: admin@example.com\n"
            "Callback: http://mal.example.org/path?x=1\n"
            "Server: 192.0.2.123 and fallback 192.0.2.123\n"
            "Domain: www.evil-domain.COM\n"
            "MD5: d41d8cd98f00b204e9800998ecf8427e\n"
            "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        )

        iocs = extract_iocs(text, source="unit-test", title="sample")
        types = {i["type"] for i in iocs}
        vals = {i["value"] for i in iocs}

        self.assertIn("email", types)
        self.assertIn("url", types)
        self.assertIn("ip", types)
        self.assertIn("domain", types)
        self.assertIn("hash", types)

        ip_vals = [i["value"] for i in iocs if i["type"] == "ip"]
        self.assertEqual(len(ip_vals), 1)

        self.assertIn("evil-domain.com", vals)

    def test_generate_actionable_items_high_score(self):
        intel = {
            "threat": {
                "relevance": {"score": 90, "label": "Critical"},
                "technique": {"name": ["ransomware"]},
                "actor": {"name": ["APT-Unit"]},
                "software": {"name": []},
                "target": {"region": []},
            },
            "iocs": [
                {"type": "ip", "value": "203.0.113.5", "source": "u"},
                {"type": "domain", "value": "bad.test", "source": "u"},
                {"type": "url", "value": "http://bad.test/p", "source": "u"},
            ],
        }

        out = generate_actionable_items(intel)
        self.assertIsInstance(out, dict)
        self.assertIn("recommended_actions", out)
        self.assertIn("mitigation_snippets", out)

        ra = out["recommended_actions"]
        self.assertTrue(any(a.startswith("block_ip:") for a in ra))
        self.assertTrue(any(a.startswith("block_domain:") for a in ra))

        ms = out["mitigation_snippets"]
        self.assertTrue(any(k in ms for k in ("firewall", "proxy", "suricata")))


if __name__ == "__main__":
    unittest.main()
