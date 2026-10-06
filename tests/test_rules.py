import contextlib
import copy
import importlib.util
import io
import json
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

spec = importlib.util.spec_from_file_location('validation', str(ROOT / 'scripts/validate-rules.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
suite = m.load_suite()
queries = {item[0].stem: item[4] for item in suite}

def get(doc, field):
    for part in field.split('.'):
        if not isinstance(doc, dict): return None
        doc = doc.get(part)
    return doc

def wildcard(pattern, text):
    regex = ''
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == '\\':
            i += 1
            regex += re.escape(pattern[i])
        elif char == '*': regex += '.*'
        elif char == '?': regex += '.'
        else: regex += re.escape(char)
        i += 1
    return re.fullmatch(regex, text, re.I | re.S) is not None

def matches(query, doc):
    if 'wildcard' in query:
        return all(any(wildcard(info['value'], str(v)) for v in (get(doc, field) if isinstance(get(doc, field), list) else [get(doc, field)]) if v is not None) for field, info in query['wildcard'].items())
    if 'exists' in query: return get(doc, query['exists']['field']) is not None
    if 'term' in query: return all(value in get(doc, field) if isinstance(get(doc, field), list) else value == get(doc, field) for field, value in query['term'].items())
    if 'bool' in query:
        b = query['bool']
        return all(matches(q,doc) for q in b.get('filter', [])) and not any(matches(q,doc) for q in b.get('must_not', [])) and sum(matches(q,doc) for q in b.get('should', [])) >= b.get('minimum_should_match', 0)
    raise AssertionError(query)

def event(code, channel='Microsoft-Windows-Sysmon/Operational', **data):
    return dict(event={'code':str(code)}, winlog={'channel':channel, 'event_data':{}}, **data)

lsass = event(10)
lsass['winlog']['event_data']={'TargetImage':r'C:\Windows\System32\LSASS.EXE', 'GrantedAccess':'0x1410'}
assert matches(queries['lsass_selected_read_access'], lsass)
query_only = copy.deepcopy(lsass); query_only['winlog']['event_data']['GrantedAccess']='0x1000'
assert not matches(queries['lsass_selected_read_access'], query_only)
ps = event(1, process={'executable':r'C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE','command_line':'powershell.exe -ENC PRIVATE_BASE64'})
assert matches(queries['powershell_encoded_command'], ps)
ps_plain = copy.deepcopy(ps); ps_plain['process']['command_line']='powershell.exe -NoProfile'
assert not matches(queries['powershell_encoded_command'], ps_plain)
task = event(1,process={'executable':r'C:\Windows\System32\schtasks.exe','command_line':'schtasks.exe /CREATE /tn test /TR benign.exe /sc daily'})
assert matches(queries['schtasks_create_task'], task)
task_query = copy.deepcopy(task); task_query['process']['command_line']='schtasks.exe /query'
assert not matches(queries['schtasks_create_task'], task_query)
run = event(13,registry={'path':r'HKU\S-1-5-21-test\Software\Microsoft\Windows\CurrentVersion\Run\test','data':{'strings':[r'C:\Users\public\AppData\test.exe']}})
assert matches(queries['run_key_suspicious_value'], run)
run_clean = copy.deepcopy(run); run_clean['registry']['data']['strings']=[r'C:\Program Files\Vendor\app.exe']
assert not matches(queries['run_key_suspicious_value'], run_clean)
assert matches(queries['wmi_consumer_filter_binding'], event(21))
assert not matches(queries['wmi_consumer_filter_binding'], event(19))
assert matches(queries['windows_event_log_cleared'], event(1102, 'Security'))
assert matches(queries['windows_event_log_cleared'], event(104, 'System'))
assert not matches(queries['windows_event_log_cleared'], event(104, 'Security'))
assert not matches(queries['windows_event_log_cleared'], event(1102, 'System'))
for name in queries:
    assert '.caseless' not in json.dumps(queries[name])
for doc, name in ((lsass,'lsass_selected_read_access'),(ps,'powershell_encoded_command'),(task,'schtasks_create_task'),(run,'run_key_suspicious_value')):
    other = copy.deepcopy(doc); other['winlog']['channel']='Security'
    assert not matches(queries[name], other)
# Preserve literal Sigma wildcard characters and Windows path separators.
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionNOT
from sigma.types import SigmaString
literal = m.dsl(ConditionFieldEqualsValueExpression('x', SigmaString(r'C:\path\literal\*name')))
assert matches(literal, {'x':r'C:\path\literal*name'})
assert not matches(literal, {'x':r'C:\path\literalZZname'})
try: m.dsl(ConditionNOT([ConditionFieldEqualsValueExpression('x', SigmaString('test'))]))
except m.ProbeError: pass
else: raise AssertionError('General negation must fail')
# Validate a complete run using a synthetic, isolated response harness.
# Fixtures never become real measurements or enter Elasticsearch.
fixtures=[]
for index, doc in enumerate((lsass,ps,task,run,event(21),event(1102,'Security'))):
    for corpus in ('attack','host','win10','win11'):
        source=copy.deepcopy(doc)
        source['tags']=[{'attack':'attack-sample','host':'baseline','win10':'benign-corpus','win11':'benign-corpus'}[corpus]]
        source['fields']={'corpus':{'win10':'win10-client','win11':'win11-client'}.get(corpus,'unused'), 'sample_file':f'public-{index}.evtx','sample_tactic':'test'}
        fixtures.append((corpus,source))
class FakeRest:
    def post(self,path,body):
        assert path.endswith('_field_caps')
        fields={'tags','fields.corpus','fields.sample_file','fields.sample_tactic'}
        for item in suite:
            for query in (item[4],item[5],item[6],item[7]): fields |= m.field_names(query)
        return {'fields':{f:{'keyword':{'searchable':True,'aggregatable':True}} for f in fields}}
class FakeSnapshot:
    closed=False
    def __init__(self,client): pass
    def count(self,query): return sum(matches(query,doc) for corpus,doc in fixtures)
    def ids(self,query): return {('index',str(i)) for i,(corpus,doc) in enumerate(fixtures) if matches(query,doc)}
    def files(self,query,file_field,tactic_field):
        return {(doc['fields']['sample_tactic'],doc['fields']['sample_file']):1 for corpus,doc in fixtures if matches(query,doc)}
    def close(self): FakeSnapshot.closed=True

def fake_eql(client,eql,corpus):
    original=next(item[4] for item in suite if item[3]==eql)
    ids={('index',str(i)) for i,(name,doc) in enumerate(fixtures) if matches(m.both(corpus,original),doc)}
    return ids,len(ids)
with tempfile.TemporaryDirectory() as folder:
    output=io.StringIO()
    with patch.object(m,'ROOT',Path(folder)), patch.object(m,'Rest',FakeRest), patch.object(m,'Snapshot',FakeSnapshot), patch.object(m,'eql_ids',fake_eql), contextlib.redirect_stdout(output):
        m.validate(suite)
    assert 'PRIVATE_' not in output.getvalue()
    report=json.loads(next((Path(folder)/'coverage/runs').glob('*/results.json')).read_text())
    assert report['status']=='measurement_complete' and len(report['rules'])==6
    assert all(c['eql_check']=='MATCH' for r in report['rules'] for c in r['corpora'].values())
    assert FakeSnapshot.closed
print('Passed: positive/negative rule semantics, channel isolation, case-insensitive matching, Windows escaping and literal wildcards, unsupported-negation rejection, count-report flow, PIT cleanup, and output privacy. Fixtures stayed offline; no measured lab results are claimed.')

# Evidence-driven additions: selected read masks and XML task creation.
for mask in ['0x101ffb', '0x1f1fff']:
    doc = copy.deepcopy(lsass)
    doc['winlog']['event_data']['GrantedAccess'] = mask
    assert int(mask, 16) & 0x10 and matches(queries['lsass_selected_read_access'], doc)
    doc['winlog']['event_data']['TargetImage'] = r'C:\Windows\System32\other.exe'
    assert not matches(queries['lsass_selected_read_access'], doc)
for cmd, expected in [
    ('schtasks.exe /create /tn demo /xml demo.xml', True),
    ('schtasks.exe /CREATE /XML demo.xml /tn demo', True),
    ('schtasks.exe /run /xml demo.xml', False),
    ('schtasks.exe /query /xml demo.xml', False),
    ('schtasks.exe /create /tn demo', False),
    ('schtasks.exe /delete /tn demo /tr demo.exe', False),
]:
    doc = event(1, process={'executable': r'C:\Windows\System32\schtasks.exe', 'command_line': cmd})
    assert matches(queries['schtasks_create_task'], doc) == expected
print('Passed: selected mask additions and XML creation scope. Synthetic fixtures remained offline.')
