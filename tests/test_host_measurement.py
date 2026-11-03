import http.server
import threading
import unittest
from scripts.measure_hosts import API, endpoint, read_page


class Page(http.server.BaseHTTPRequestHandler):
    requests=[]
    mode='page'
    release=threading.Event()
    def do_GET(self):
        type(self).requests.append((self.path,self.headers.get('Authorization'),self.headers.get('Cookie')))
        if self.mode=='redirect':
            self.send_response(302); self.send_header('Location','/must-not-follow'); self.end_headers(); return
        if self.mode=='denied':
            self.send_response(401); self.end_headers(); return
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.send_header('Last-Modified','Thu, 31 Jul 2025 08:18:58 GMT')
        self.end_headers()
        self.wfile.write(b'<title>Danfoss StoreView</title><p>Version: 1.2.3</p>')
        self.wfile.flush()
        if self.mode=='held_open':
            self.release.wait(4)
    def log_message(self,*args): pass


class HostMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=http.server.HTTPServer(('127.0.0.1',0),Page)
        cls.worker=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.worker.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.worker.join()
    def setUp(self):
        Page.requests=[];Page.mode='page';Page.release.clear()
        self.target={'url':f'http://127.0.0.1:{self.server.server_port}/','version':'4.3.1'}
    def test_one_get_and_inferred_version(self):
        result=read_page(self.target)
        self.assertEqual(Page.requests,[('/',None,None)])
        self.assertEqual(result['status'],'storeview_landing_page')
        self.assertEqual(result['inferredVersion'],'4.3.1')
        self.assertTrue(result['uiVersionVisible'])
    def test_title_recognized_before_server_closes_body(self):
        Page.mode='held_open'
        try:
            result=read_page(self.target)
            self.assertEqual(result['status'],'storeview_landing_page')
            self.assertEqual(result['httpStatus'],200)
            self.assertEqual(Page.requests,[('/',None,None)])
        finally:
            Page.release.set()
    def test_redirect_not_followed(self):
        Page.mode='redirect';result=read_page(self.target)
        self.assertEqual(len(Page.requests),1)
        self.assertEqual(result['status'],'redirect_not_followed')
    def test_access_denied_not_retried(self):
        Page.mode='denied';result=read_page(self.target)
        self.assertEqual(len(Page.requests),1)
        self.assertEqual(result['status'],'access_denied')
    def test_target_restrictions(self):
        row={'ip_str':'8.8.8.8','port':80,'http':{'title':'Danfoss StoreView'}}
        self.assertIsNotNone(endpoint(row))
        self.assertIsNone(endpoint(dict(row,ip_str='127.0.0.1')))
        self.assertIsNone(endpoint(dict(row,tags=['honeypot'])))
        self.assertIsNone(endpoint(dict(row,org='Department of Defense')))
        self.assertIsNone(endpoint(dict(row,port=443)))
    def test_facet_drift_is_recorded(self):
        api=API('test')
        def fake(route,query,facets):
            if 'net:0.0.0.0/1' in query:
                return {'total':1,'facets':{'ip':[{'value':'8.8.8.8','count':1}]}}
            if 'net:128.0.0.0/1' in query:
                return {'total':1,'facets':{'ip':[{'value':'200.1.1.1','count':1}]}}
            return {'total':1002,'facets':{'ip':[{'value':i+1,'count':1} for i in range(1000)]}}
        api.request=fake
        values,total=api.ips('test')
        self.assertEqual(len(values),2)
        self.assertEqual(total,1002)
        self.assertEqual(api.facet_drift,[{'advertisedServices':1002,'partitionedServices':2}])


if __name__=='__main__': unittest.main()
