import sys
import unittest
from unittest.mock import patch


class TestMainCLI(unittest.TestCase):
    @patch("collector.main.run_structured_collection")
    @patch("collector.main.run_unstructured_rss_analysis")
    @patch("collector.main.run_unstructured_pdf_analysis")
    def test_main_invokes_selected_modules(self, mock_pdf, mock_rss, mock_struct):
        mock_struct.return_value = {"records_total": 0}
        mock_rss.return_value = {"records": 0}
        mock_pdf.return_value = {"records": 0}
        old_argv = sys.argv
        try:
            sys.argv = ["-m", "--structured", "--unstructured-rss"]

            from collector import main

            main.main()
            mock_struct.assert_called()
            mock_rss.assert_called()
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
