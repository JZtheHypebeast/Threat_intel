import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from collector import pdf
from collector.config import CONFIG


class TestPDFPipeline(unittest.TestCase):

    @patch("collector.pdf._pdf_llm_analyze")
    @patch("collector.pdf.generate_unstructured_markdown")
    @patch("collector.pdf.extract_text_from_file")
    def test_run_unstructured_pdf_analysis_with_mocked_files(
        self, mock_extract, mock_md, mock_llm
    ):
        mock_extract.return_value = [
            (
                "report1.pdf",
                "Ransomware attack reported in the wild",
                "/tmp/report1.pdf",
                {"title": "report1.pdf", "source": "/tmp/report1.pdf"},
            ),
            (
                "report2.pdf",
                "Phishing campaigns targeting customers",
                "/tmp/report2.pdf",
                {"title": "report2.pdf", "source": "/tmp/report2.pdf"},
            ),
        ]
        mock_llm.return_value = {}
        mock_md.return_value = "markdown"
        old_out = CONFIG.get("OUTPUT_DIR_PDF")
        with tempfile.TemporaryDirectory() as tmpdir:
            CONFIG["OUTPUT_DIR_PDF"] = tmpdir
            res = pdf.run_pdf_analysis("/tmp", hours=24)
            self.assertEqual(res.get("records"), 2)
            ndjson_path = Path(res.get("ndjson"))
            self.assertTrue(ndjson_path.exists())
            md_path = Path(tmpdir) / f"UnstructuredPDFReport_{datetime.now().strftime('%Y%m%d')}.md"
            self.assertTrue(md_path.exists())
        CONFIG["OUTPUT_DIR_PDF"] = old_out
        mock_md.assert_called()


if __name__ == "__main__":
    unittest.main()
