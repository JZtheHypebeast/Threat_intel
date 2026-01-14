import unittest

from collector import geofeed


class TestGeoFeedCanonicalization(unittest.TestCase):
    def test_canonicalize_entry_normalizes_lists_and_whitespace(self):
        entry = {
            "title": "  Test Title  ",
            "url": "https://example.com/article ",
            "date": " 2025-01-01 ",
            "risk": "High",
            "trend": "Escalating (up)",
            "decision": "Monitor",
            "primary_actors": [" Actor A ", "Actor A", "Actor B"],
            "countries_involved": "US, NL , US",
            "summary": "Line 1\\n\\n\\nLine 2",
            "why_it_matters": [" Impact: X ", "Risk Level: High "],
            "key_signals": ["Signal A", " Signal B "],
        }
        canon = geofeed._canonicalize_entry(entry)
        self.assertEqual(canon["title"], "Test Title")
        self.assertEqual(canon["url"], "https://example.com/article")
        self.assertEqual(canon["trend"], "Escalating")
        self.assertEqual(canon["primary_actors"], ["Actor A", "Actor B"])
        self.assertEqual(canon["countries_involved"], ["NL", "US"])
        self.assertIn("Line 1", canon["summary"])
        self.assertTrue(canon["id"])

    def test_entries_signature_is_order_invariant(self):
        entries_a = [
            {"title": "A", "url": "u1", "date": "d1"},
            {"title": "B", "url": "u2", "date": "d2"},
        ]
        entries_b = list(reversed(entries_a))
        sig_a = geofeed._entries_signature(entries_a)
        sig_b = geofeed._entries_signature(entries_b)
        self.assertEqual(sig_a, sig_b)

    def test_normalize_summary_entry_returns_canonical_form(self):
        entry = {
            "title": "Example",
            "url": "https://example.com",
            "date": "01 Jan 2025",
            "risk": "High",
            "trend": "Stable",
            "decision": "Monitor",
            "primary_actors": ["Group X"],
            "countries_involved": ["US"],
            "summary": "Summary text",
            "why_it_matters": ["Impact: Medium", "Risk Level: High"],
            "key_signals": ["Signal 1", "Signal 2"],
        }
        norm = geofeed._normalize_summary_entry(entry)
        self.assertIn("id", norm)
        self.assertEqual(norm["title"], "Example")
        self.assertEqual(norm["countries_involved"], ["US"])


if __name__ == "__main__":
    unittest.main()
