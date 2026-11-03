import copy
import unittest
from scripts.collect_versions import infer
from scripts.refresh_versions import QUERY, collect_snapshot, empty_data, fingerprint_query, refresh

NOW = '2026-11-03T02:00:00Z'


class CountAPI:
    def __init__(self):
        self.queries = []

    def request(self, route, query):
        assert route == '/shodan/host/count', 'Only aggregate queries are allowed'
        self.queries.append(query)
        filtered = '-tag:honeypot' in query
        if 'Last-Modified:' not in query:
            return {'total': 6 if filtered else 8}
        if '31 Jul 2025 08:18:58' in query:
            return {'total': 2 if filtered else 3}
        if '07 Apr 2026' in query:
            return {'total': 1}
        return {'total': 0}


class VersionTests(unittest.TestCase):
    def test_exact_and_ambiguous_fingerprints(self):
        self.assertEqual(infer({'http':{'headers':{'Last-Modified':'Thu, 31 Jul 2025 08:18:58 GMT'}}})[0], '4.3.1')
        self.assertIn('ambiguous', infer({'data':'HTTP/1.1 200 OK\r\nLast-Modified: Thu, 03 Sep 2020 18:39:16 GMT\r\n'})[0])
        self.assertTrue(infer({})[0].startswith('Unknown'))
        self.assertEqual(infer({'http':{'headers':{'last-modified':['Thu, 31 Jul 2025 08:18:58 GMT','Fri, 19 May 2023 13:40:11 GMT']}}})[0], 'Unknown: conflicting headers')

    def test_queries_and_accounting(self):
        api = CountAPI()
        sample = collect_snapshot(api, NOW, pause=lambda _: None)
        self.assertEqual(sample['all']['versions']['5.0.19'], 2)
        self.assertEqual(sample['all']['versions']['Unknown/unmapped'], 3)
        self.assertEqual(sample['excludingHoneypots']['versions']['Unknown/unmapped'], 2)
        self.assertEqual(sample['honeypotServicesExcluded'], 2)
        self.assertEqual(sum(sample['all']['versions'].values()), sample['all']['total'])
        self.assertIn('"Last-Modified: Thu, 31 Jul 2025 08:18:58 GMT"', fingerprint_query(QUERY, '2025-07-31T08:18:58Z'))

    def test_index_drift_rejected(self):
        api = CountAPI()
        original = api.request
        calls = 0
        def drift(route, query):
            nonlocal calls
            if query == QUERY:
                calls += 1
                return {'total': 8 if calls == 1 else 9}
            return original(route, query)
        api.request = drift
        with self.assertRaisesRegex(ValueError, 'changed'):
            collect_snapshot(api, NOW, pause=lambda _: None)

    def test_overlapping_counts_rejected(self):
        api = CountAPI()
        original = api.request
        api.request = lambda route, query: {'total': 99} if 'Last-Modified:' in query else original(route,query)
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            collect_snapshot(api, NOW, pause=lambda _: None)

    def test_failure_preserves_last_good_snapshot(self):
        good = collect_snapshot(CountAPI(), NOW, pause=lambda _: None)
        data = empty_data()
        data, failed = refresh(data, 'test', NOW, collect=lambda api,now: good)
        history = copy.deepcopy(data['history'])
        def fail(api, now):
            raise RuntimeError('Unavailable')
        data, failed = refresh(data, 'test', '2026-11-04T02:00:00Z', collect=fail)
        self.assertTrue(failed)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['history'], history)
        self.assertEqual(data['lastSuccessAt'], NOW)

    def test_rerun_and_missing_key(self):
        sample = collect_snapshot(CountAPI(), NOW, pause=lambda _: None)
        data = empty_data()
        for _ in range(2):
            data, _ = refresh(data, 'test', NOW, collect=lambda api,now: sample)
        self.assertEqual(len(data['history']),1)
        data, failed = refresh(data, None, NOW)
        self.assertFalse(failed)
        self.assertEqual(data['history'],[sample])
        self.assertEqual(data['status'],'awaiting_key')


if __name__ == '__main__':
    unittest.main()
