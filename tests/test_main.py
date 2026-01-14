import sys
import unittest
from unittest.mock import patch


class TestMainCLI(unittest.TestCase):
    @patch("collector.main.run_structured_collection")
    @patch("collector.main.run_fetch")
    @patch("collector.main.run_llm_rawtext")
    @patch("collector.main.run_unstructured_pdf_analysis")
    def test_main_invokes_selected_modules(
        self, mock_pdf, mock_llm_rawtext, mock_fetch, mock_struct
    ):
        mock_struct.return_value = {"records_total": 0}
        mock_fetch.return_value = {"records_total": 0}
        mock_llm_rawtext.return_value = {"records_total": 0}
        mock_pdf.return_value = {"records": 0}
        old_argv = sys.argv
        try:
            sys.argv = [
                "collector.main",
                "--cve",
                "--articles",
                "--unstructured-pdf",
                "/tmp/sample.pdf",
            ]

            from collector import main

            main.main()
            mock_struct.assert_called()
            mock_fetch.assert_called()
            mock_llm_rawtext.assert_called()
            mock_pdf.assert_called()
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
