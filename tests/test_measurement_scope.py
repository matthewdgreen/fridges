import copy
import json
import unittest
from unittest.mock import patch

from scripts.measurement_scope import POLICY_ID, excluded_addresses, scoped_query
from scripts.refresh_screened import update_data
from scripts.measure_hosts import endpoint


class MeasurementScopeTests(unittest.TestCase):
    def test_missing_exclusions_fail_closed(self):
        with patch.dict('os.environ', {'EXCLUDED_STOREVIEW_IPS': ''}):
            with self.assertRaises(ValueError):
                excluded_addresses()

    def test_addresses_validated_and_query_restricts_population(self):
        with patch.dict('os.environ', {'EXCLUDED_STOREVIEW_IPS': '["192.0.2.10", "192.0.2.11"]'}):
            addresses = excluded_addresses()
            self.assertEqual(scoped_query('base', addresses), 'base -ip:192.0.2.10,192.0.2.11')
        with patch.dict('os.environ', {'EXCLUDED_STOREVIEW_IPS': '["192.0.2.10", "192.0.2.10"]'}):
            with self.assertRaises(ValueError):
                excluded_addresses()

    def test_policy_boundary_keeps_old_observations_and_hides_addresses(self):
        original = {'query': 'http.title:"Danfoss StoreView"', 'history': [
            {'date': '2026-11-05', 'collectedAt': '2026-11-05T00:00:00Z', 'count': 12, 'countries': {}}]}
        private_query = scoped_query(original['query'], {'192.0.2.10', '192.0.2.11'})
        with patch('scripts.refresh.fetch_count', return_value=(8, {})) as fetch:
            data, failed = update_data(copy.deepcopy(original), 'test', '2026-11-06T00:00:00Z', 'shodan', private_query)
        self.assertFalse(failed)
        self.assertEqual(data['history'][0]['count'], 12)
        self.assertEqual(data['history'][0]['populationPolicy'], 'original-title-query')
        self.assertEqual(data['history'][1]['populationPolicy'], POLICY_ID)
        self.assertIn('-ip:', fetch.call_args.kwargs['query'])
        self.assertNotIn('192.0.2.', json.dumps(data))

    def test_manual_measurement_excludes_even_an_untagged_candidate(self):
        row = {'ip_str': '8.8.8.8', 'port': 80, 'http': {'title': 'Danfoss StoreView'}}
        with patch.dict('os.environ', {'EXCLUDED_STOREVIEW_IPS': '["8.8.8.8", "9.9.9.9"]'}):
            self.assertIsNone(endpoint(row))
