import copy
import unittest
from scripts.refresh_hosts import cardinality, empty_data, refresh


class HostCountTests(unittest.TestCase):
    def test_complete_facet(self):
        value=cardinality({'total':5,'facets':{'ip':[{'value':'8.8.8.8','count':4},{'value':'9.9.9.9','count':1}]}})
        self.assertEqual(value['uniqueIPs'],2)
        self.assertEqual(value['cardinalityMethod'],'complete-facet')
    def test_singleton_tail(self):
        value=cardinality({'total':12,'facets':{'ip':[{'value':1,'count':5},{'value':2,'count':2},{'value':3,'count':1}]}},cap=3)
        self.assertEqual(value['uniqueIPs'],7)
        self.assertEqual(value['cardinalityMethod'],'singleton-tail')
    def test_ambiguous_truncated_tail_rejected(self):
        with self.assertRaises(ValueError):
            cardinality({'total':12,'facets':{'ip':[{'value':1,'count':5},{'value':2,'count':2},{'value':3,'count':2}]}},cap=3)
    def test_duplicate_facet_addresses_rejected(self):
        with self.assertRaises(ValueError):
            cardinality({'total':2,'facets':{'ip':[{'value':1,'count':1},{'value':1,'count':1}]}})
    def test_failed_collection_preserves_last_observation(self):
        data=empty_data();old={'date':'2026-11-02','collectedAt':'2026-11-02T12:00:00Z'}
        data['history']=[old];data['lastSuccessAt']=old['collectedAt']
        def fail(api,now):raise ValueError('Unreconciled facets')
        result,failed=refresh(copy.deepcopy(data),'test','2026-11-03T12:00:00Z',collect=fail)
        self.assertTrue(failed);self.assertEqual(result['history'],[old]);self.assertEqual(result['lastSuccessAt'],old['collectedAt'])
    def test_real_zero_population(self):
        self.assertEqual(cardinality({'total':0,'facets':{'ip':[]}})['uniqueIPs'],0)


if __name__=='__main__':unittest.main()
