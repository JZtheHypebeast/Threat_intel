"""Test: unstructured extraction"""

# MODULE: TEST - UNSTRUCTURED EXTRACTION #

import unittest

from collector import unstructured
from collector.config import CONFIG


class TestUnstructuredExtraction(unittest.TestCase):

    def test_html_main_text_prefers_article(self):
        html = """
        <html>
            <nav>Phishing</nav>
            <article><p>Ransomware continues to cause outages and data loss.</p></article>
            <footer>subscribe</footer>
        </html>
        """
        main = unstructured.html_to_main_text(html)
        self.assertIn("Ransomware", main)
        self.assertNotIn("Phishing", main)

    def test_sentence_context_accept(self):
        text = "Today analysts reported a major ransomware attack across several organizations in Europe where many systems were encrypted."
        res = unstructured.extract_threat_indicators(text, source="test", title="")
        self.assertIn("Ransomware", res["threat"]["technique"]["name"])

    def test_short_nav_reject(self):
        text = "nav: phishing"
        res = unstructured.extract_threat_indicators(text, source="test", title="")
        self.assertNotIn("Phishing", res["threat"]["technique"]["name"])

    def test_repeat_threshold_allows_short(self):
        old = CONFIG.get("MIN_REPEAT_FOR_SHORT_MATCH")
        try:
            CONFIG["MIN_REPEAT_FOR_SHORT_MATCH"] = 2
            text = "phishing. phishing."
            res = unstructured.extract_threat_indicators(text, source="test", title="")
            self.assertIn("Phishing", res["threat"]["technique"]["name"])
        finally:
            CONFIG["MIN_REPEAT_FOR_SHORT_MATCH"] = old

    def test_title_match_allowed(self):
        content = "nav item only"
        title = "Phishing campaign spotted"
        res = unstructured.extract_threat_indicators(
            content, source="test", title=title
        )
        self.assertIn("Phishing", res["threat"]["technique"]["name"])


if __name__ == "__main__":
    unittest.main()
