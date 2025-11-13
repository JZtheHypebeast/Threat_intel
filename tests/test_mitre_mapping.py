"""Test: mitre mapping"""

# MODULE: TEST - MITRE MAPPING #

import unittest

from collector.unstructured import extract_threat_indicators


class TestMitreMapping(unittest.TestCase):

    def test_ransomware_mapping(self):
        text = "A new ransomware campaign is encrypting files and demanding payment."
        intel = extract_threat_indicators(text)
        tech = intel.get("threat", {}).get("technique", {})
        mitre = tech.get("mitre") or tech.get("mitre", [])
        if mitre:
            ids = [m.get("id") for m in mitre]
            self.assertIn("T1486", ids)
        else:
            names = tech.get("name", [])
            self.assertTrue(any("ransomware" in (n or "").lower() for n in names))


if __name__ == "__main__":
    unittest.main()
