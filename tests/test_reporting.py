import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from collector import reporting
from collector.config import CONFIG


class TestReportingCollector(unittest.TestCase):
    def test_collect_llm_records_from_articles_dir(self):
        old_unstructured = CONFIG.get("OUTPUT_DIR_UNSTRUCTURED")
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                CONFIG["OUTPUT_DIR_UNSTRUCTURED"] = tmpdir
                path = Path(tmpdir) / "LLM-JSON_20260115.ndjson"
                record = {
                    "title": "Sample",
                    "llm": {"summary": "ok", "priority": {"score": 50}},
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                }
                path.write_text(json.dumps(record) + "\n", encoding="utf-8")
                records = reporting._collect_llm_records(1)
                self.assertTrue(any(r.get("title") == "Sample" for r in records))
        finally:
            CONFIG["OUTPUT_DIR_UNSTRUCTURED"] = old_unstructured


if __name__ == "__main__":
    unittest.main()
