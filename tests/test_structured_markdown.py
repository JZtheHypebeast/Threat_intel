import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from collector import CVE


class TestStructuredMarkdown(unittest.TestCase):
    def test_generate_markdown_creates_file(self):
        critical = [
            {
                "vulnerability": {
                    "id": "CVE-2025-0001",
                    "description": "desc",
                    "score": {"base": 9.0},
                    "severity": "CRITICAL",
                    "published": datetime.now(timezone.utc).isoformat(),
                },
                "vendor": {"name": "Microsoft"},
                "source": {"url": "http://example"},
            }
        ]
        interesting = []
        modified = []
        tmpdir = tempfile.mkdtemp()
        try:
            path = CVE.generate_markdown(
                critical, interesting, modified, hours=24, output_dir=tmpdir
            )
            self.assertTrue(os.path.exists(path))
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Structured CVE Intelligence Report", content)
        finally:
            try:
                os.remove(path)
                os.rmdir(tmpdir)
            except Exception:
                pass

    def test_generate_markdown_orders_new_before_modified_by_score(self):
        vendor = "Acme"
        now = datetime.now(timezone.utc).isoformat()
        critical = [
            {
                "vulnerability": {
                    "id": "CVE-2025-0001",
                    "description": "desc",
                    "score": {"base": 9.8},
                    "severity": "CRITICAL",
                    "published": now,
                },
                "vendor": {"name": vendor},
                "source": {"url": "http://example/1"},
            },
            {
                "vulnerability": {
                    "id": "CVE-2025-0002",
                    "description": "desc",
                    "score": {"base": 7.2},
                    "severity": "HIGH",
                    "published": now,
                },
                "vendor": {"name": vendor},
                "source": {"url": "http://example/2"},
            },
            {
                "vulnerability": {
                    "id": "CVE-2025-0003",
                    "description": "desc",
                    "score": {"base": 8.1},
                    "severity": "HIGH",
                    "published": now,
                    "last_modified": now,
                },
                "vendor": {"name": vendor},
                "source": {"url": "http://example/3"},
                "modified_only": True,
            },
            {
                "vulnerability": {
                    "id": "CVE-2025-0004",
                    "description": "desc",
                    "published": now,
                },
                "vendor": {"name": vendor},
                "source": {"url": "http://example/4"},
            },
        ]
        tmpdir = tempfile.mkdtemp()
        try:
            path = CVE.generate_markdown(critical, [], [], hours=24, output_dir=tmpdir)
            content = Path(path).read_text(encoding="utf-8")
            vendor_idx = content.find(f"## Vendor: {vendor}")
            self.assertNotEqual(vendor_idx, -1)
            section = content[vendor_idx:]
            next_vendor = section.find("## Vendor:", len("## Vendor:"))
            if next_vendor != -1:
                section = section[:next_vendor]
            cves = [
                line.split("[", 1)[1].split("]", 1)[0]
                for line in section.splitlines()
                if line.startswith("### [CVE-")
            ]
            self.assertEqual(cves[0], "CVE-2025-0001")
            self.assertEqual(cves[1], "CVE-2025-0002")
            self.assertEqual(cves[2], "CVE-2025-0003")
            self.assertEqual(cves[3], "CVE-2025-0004")
        finally:
            try:
                os.remove(path)
                os.rmdir(tmpdir)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
