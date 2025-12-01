import os
import tempfile
import unittest

from collector.config import write_jsonl


class TestConfigHelpers(unittest.TestCase):
    def test_write_jsonl_creates_file(self):
        records = [{"a": 1}, {"b": 2}]
        fd, path = tempfile.mkstemp(suffix=".ndjson")
        os.close(fd)
        try:
            write_jsonl(path, records)
            self.assertTrue(os.path.exists(path))
            with open(path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            self.assertEqual(len(lines), 2)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
