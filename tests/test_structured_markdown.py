"""Test: structured markdown generation"""

# MODULE: TEST - STRUCTURED MARKDOWN #

import os
import tempfile
import unittest
from datetime import datetime, timezone

from collector import structured


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
            path = structured.generate_markdown(
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


if __name__ == "__main__":
    unittest.main()
