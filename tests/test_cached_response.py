import io
import unittest
from unittest.mock import patch

from scripts.measure_hosts import CachedResponseLimit, read_cached_json


class CachedResponseTests(unittest.TestCase):
    def test_complete_json_and_size_limit(self):
        self.assertEqual(read_cached_json(io.BytesIO(b'{"data":[]}')), {'data': []})
        with self.assertRaisesRegex(CachedResponseLimit, 'size_limit'):
            read_cached_json(io.BytesIO(b'{"data":[]}'), max_bytes=5)

    def test_continuing_partial_response_cannot_extend_total_budget(self):
        class Trickle:
            def read1(self, count):
                return b' '
        with patch('scripts.measure_hosts.time.monotonic', side_effect=[0, 0, 6, 11]):
            with self.assertRaisesRegex(CachedResponseLimit, 'time_limit'):
                read_cached_json(Trickle(), seconds=10)
