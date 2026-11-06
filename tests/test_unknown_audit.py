import json
import unittest

from scripts.audit_unknown_versions import aggregate_records, classify, is_candidate, run


class UnknownAuditTests(unittest.TestCase):
    def test_missing_invalid_unmapped_and_noncanonical_known(self):
        self.assertEqual(classify({})[0], 'missing_header')
        self.assertEqual(classify({'http': {'headers': {'last-modified': 'garbage'}}})[0], 'invalid_header')
        self.assertEqual(classify({'data': 'Last-Modified: Mon, 02 Nov 2026 01:02:03 GMT\r\n'})[0], 'unmapped_timestamp')
        row = {'http': {'title': 'Danfoss StoreView'},
               'data': 'Last-Modified: Thu, 31 Jul 2025 08:18:58 GMT\r\n'}
        self.assertFalse(is_candidate(row))
        row['data'] = 'Last-Modified: Thu, 31 Jul 2025 08:18:58 +0000\r\n'
        self.assertTrue(is_candidate(row))
        self.assertEqual(classify(row)[0], 'known_timestamp_search_mismatch')

    def test_aggregate_filters_tags_and_does_not_persist_identities(self):
        rows = [{'ip': '192.0.2.10', 'asn': 'AS12345', 'port': port,
                 'tagged': port == 443, 'reason': 'unmapped_timestamp',
                 'stamp': '2026-11-02T01:02:03Z', 'date': '2026-11-06'} for port in (80, 443)]
        report = aggregate_records(rows)
        self.assertEqual(report['all']['uniqueIPs'], 1)
        self.assertEqual(report['all']['ipConcentration']['largestGroupServices'], 2)
        self.assertEqual(report['excludingTaggedServices']['services'], 1)
        self.assertNotIn('192.0.2.10', json.dumps(report))
        self.assertNotIn('AS12345', json.dumps(report))

    def test_only_cached_routes_and_empty_population(self):
        class EmptyAPI:
            def request(self, route, **params):
                assert route == '/shodan/host/count'
                return {'total': 0, 'facets': {'ip': []}}
        report = run(EmptyAPI(), 500)
        self.assertEqual(report['status'], 'bounded_sample')
        self.assertEqual(report['cachedCandidates']['all']['services'], 0)
