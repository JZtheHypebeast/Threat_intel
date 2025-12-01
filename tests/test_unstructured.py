import unittest
import pytest

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


@pytest.mark.parametrize(
    "content,title,config_override,expected_in",
    [
        ("nav: phishing", "", None, False),
        ("phishing. phishing.", "", {"MIN_REPEAT_FOR_SHORT_MATCH": 2}, True),
        ("nav item only", "Phishing campaign spotted", None, True),
    ],
)
def test_shortnav_repeat_and_title(content, title, config_override, expected_in):

    old = None
    if config_override:
        old = {k: CONFIG.get(k) for k in config_override}
        try:
            for k, v in config_override.items():
                CONFIG[k] = v
            res = unstructured.extract_threat_indicators(
                content, source="test", title=title
            )
        finally:
            for k, v in (old or {}).items():
                CONFIG[k] = v
    else:
        res = unstructured.extract_threat_indicators(
            content, source="test", title=title
        )

    if expected_in:
        assert "Phishing" in res["threat"]["technique"]["name"]
    else:
        assert "Phishing" not in res["threat"]["technique"]["name"]


if __name__ == "__main__":
    unittest.main()
