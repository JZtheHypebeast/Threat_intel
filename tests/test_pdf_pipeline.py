import unittest
from unittest .mock import patch

from collector import unstructured

class TestPDFPipeline (unittest .TestCase ):

    @patch ("collector.unstructured_pdf.write_jsonl")
    @patch ("collector.unstructured_pdf.generate_unstructured_markdown")
    @patch ("collector.unstructured_pdf.extract_text_from_file")
    def test_run_unstructured_pdf_analysis_with_mocked_files (
    self ,mock_extract ,mock_md ,mock_write
    ):
        mock_extract .return_value =[
        (
        "report1.pdf",
        "Ransomware attack reported in the wild",
        "/tmp/report1.pdf",
        ),
        (
        "report2.pdf",
        "Phishing campaigns targeting customers",
        "/tmp/report2.pdf",
        ),
        ]
        res =unstructured .run_unstructured_pdf_analysis ("/tmp",hours =24 )
        self .assertEqual (res .get ("records"),2 )
        mock_write .assert_called ()
        mock_md .assert_called ()

if __name__ =="__main__":
    unittest .main ()
