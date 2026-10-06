import importlib.util
from pathlib import Path
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

spec=importlib.util.spec_from_file_location('validation',str(ROOT / 'scripts/validate-rules.py'))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
requests=[]
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        data=self.rfile.read(int(self.headers.get('Content-Length','0')))
        body=json.loads(data) if data else None
        requests.append((self.path,body))
        if '/_pit?' in self.path:
            assert body is None
            result={'id':'PIT_START','_shards':{'failed':0}}
        elif '/_eql/search?' in self.path:
            assert 'filter_path=hits.events._index,hits.events._id' in self.path
            result={'hits':{'events':[{'_index':'test','_id':'1'}]},'is_partial':False}
        elif '/_search?' in self.path:
            if body.get('query',{}).get('partial'):
                result={'timed_out':True}
            elif body['size']==0:
                result={'hits':{'total':{'relation':'eq','value':1}},'pit_id':'PIT_NEXT'}
            else:
                assert body['_source'] is False
                result={'hits':{'hits':[{'_index':'test','_id':'1'}]},'pit_id':'PIT_NEXT'}
        else: raise AssertionError(self.path)
        payload=json.dumps(result).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(payload)
    def do_DELETE(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body=={'id':'PIT_NEXT'}
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"succeeded":true}')
server=HTTPServer(('localhost',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
try:
    with patch.dict(os.environ,{'ES':f'http://localhost:{server.server_port}','ES_LOCAL_PASSWORD':'OFFLINE_DUMMY'}):
        client=m.Rest(); snapshot=m.Snapshot(client)
        assert snapshot.count({'match_all':{}})==1
        assert snapshot.ids({'match_all':{}})=={('test','1')}
        assert snapshot.id=='PIT_NEXT'
        assert m.eql_ids(client,'any where event.code:"1"',{'match_all':{}})==({('test','1')},1)
        try: snapshot.count({'partial':True})
        except m.ProbeError: pass
        else: raise AssertionError('Partial results must fail')
        snapshot.close()
finally:
    server.shutdown(); server.server_close()
print('Passed: local HTTP request encoding, body-free PIT creation, PIT ID rotation, exact-count parsing, metadata-only EQL results, partial-result rejection, and PIT closure.')
