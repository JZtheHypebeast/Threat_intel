"""Test: delivery to SIEM"""

# MODULE: TEST - DELIVERY #

import unittest
from unittest.mock import Mock, patch

from collector import delivery
from collector.config import CONFIG


class TestDeliveryElastic(unittest.TestCase):
    @patch("requests.Session.post")
    def test_send_batch_to_elastic_calls_post(self, mock_post):

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"errors": False}
        mock_post.return_value = mock_resp

        CONFIG["SIEM_DRY_RUN"] = False
        CONFIG["ELASTIC_ENDPOINT"] = "http://example.local:9200"
        CONFIG["ELASTIC_INDEX"] = "test-index"
        CONFIG["SIEM_BATCH_SIZE"] = 10
        CONFIG["SIEM_MAX_RETRIES"] = 2

        docs = [
            {
                "source": "unit",
                "title": "t1",
                "@timestamp": "2025-11-05T00:00:00Z",
                "threat": {},
            }
        ]

        ok = delivery.send_batch_to_elastic(docs)
        self.assertTrue(ok)

        self.assertTrue(mock_post.called)

        args, kwargs = mock_post.call_args
        url = args[0]
        self.assertTrue(url.endswith("/_bulk"))
        data = kwargs.get("data")
        self.assertIsNotNone(data)
        self.assertIn("test-index", data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
