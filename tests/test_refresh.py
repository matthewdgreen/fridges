import copy
import unittest
from unittest.mock import patch
from urllib.error import URLError
from scripts.refresh import QUERY, refresh, fetch_count
from scripts.validate import validate


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.original = {"query": QUERY, "status": "ok", "lastSuccessAt": "2026-10-30T12:00:00Z", "history": [{"date": "2026-10-30", "collectedAt": "2026-10-30T12:00:00Z", "count": 12, "countries": {"FR": 7}}]}
        self.now = "2026-11-02T11:17:00Z"

    def test_missing_key_preserves_real_measurement(self):
        data, failed = refresh(copy.deepcopy(self.original), None, self.now)
        self.assertFalse(failed)
        self.assertEqual(data["status"], "awaiting_key")
        self.assertEqual(data["history"], self.original["history"])
        self.assertEqual(data["lastSuccessAt"], self.original["lastSuccessAt"])

    def test_failure_preserves_real_measurement(self):
        def fail(_):
            raise URLError("sensitive request URL must not be logged")
        data, failed = refresh(copy.deepcopy(self.original), "test", self.now, fail)
        self.assertTrue(failed)
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["history"], self.original["history"])
        self.assertEqual(data["lastSuccessAt"], self.original["lastSuccessAt"])

    def test_success_and_same_day_rerun(self):
        data, _ = refresh(copy.deepcopy(self.original), "test", self.now, lambda _: (15, {"FR": 9}))
        data, _ = refresh(data, "test", self.now, lambda _: (16, {"FR": 10}))
        self.assertEqual(len(data["history"]), 2)
        self.assertEqual(data["history"][-1]["count"], 16)
        self.assertEqual(data["lastSuccessAt"], self.now)

    def test_actual_zero_is_valid(self):
        data, failed = refresh(copy.deepcopy(self.original), "test", self.now, lambda _: (0, {}))
        self.assertFalse(failed)
        self.assertEqual(data["history"][-1]["count"], 0)

    def test_query_drift_is_rejected(self):
        data = copy.deepcopy(self.original)
        data["query"] = "different fingerprint"
        with self.assertRaises(ValueError):
            refresh(data, "test", self.now)

    def test_invalid_api_data_is_rejected(self):
        with patch('scripts.refresh.urlopen') as request:
            request.return_value.__enter__.return_value.read.return_value = b'{"total": true}'
            with self.assertRaises(ValueError):
                fetch_count('test')

    def test_editorial_data(self):
        validate()


if __name__ == "__main__":
    unittest.main()
