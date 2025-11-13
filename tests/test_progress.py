"""Test: progress helpers"""

# MODULE: TEST - PROGRESS HELPERS #

import io
import sys
import unittest

from collector import progress


class TestProgressHelpers(unittest.TestCase):
    def test_progress_bar_full(self):
        old_stdout = sys.stdout
        try:
            buf = io.StringIO()
            sys.stdout = buf
            progress.progress_bar(10, 10, prefix="Test")
            output = buf.getvalue()
            self.assertIn("Test", output)
            self.assertIn("100%", output)
        finally:
            sys.stdout = old_stdout

    def test_animate_progress_runs(self):
        progress.animate_progress("A", steps=2, delay=0)


if __name__ == "__main__":
    unittest.main()
