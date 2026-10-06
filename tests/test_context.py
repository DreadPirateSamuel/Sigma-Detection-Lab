import importlib.util, json, sys, contextlib, io, tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "context", str(ROOT / "scripts/review-rule-context.py")
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from probe import ProbeError, both

secret = "PRIVATE_SENTINEL"
s = {
    "tags": ["benign-corpus"],
    "fields": {"corpus": "win11-client", "corpus_file": "Sysmon.evtx"},
    "event": {"code": "10"},
    "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_data": {
            "SourceImage": rf"C:\Users\{secret}\AppData\agent.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1010",
        },
    },
    "process": {
        "executable": rf"C:\Users\{secret}\AppData\agent.exe",
        "command_line": rf'agent.exe /create /tr "C:\Users\{secret}\Temp\worker.exe" -secret {secret}',
        "parent": {"executable": r"C:\Windows\System32\explorer.exe"},
    },
    "registry": {
        "path": rf"HKU\{secret}\Software\Microsoft\Windows\CurrentVersion\Run\{secret}",
        "data": {
            "strings": [rf'"C:\Users\{secret}\AppData\worker.exe" -secret {secret}']
        },
    },
}
stems = [
    "lsass_selected_read_access",
    "powershell_encoded_command",
    "schtasks_create_task",
    "run_key_suspicious_value",
    "windows_event_log_cleared",
    "wmi_consumer_filter_binding",
]
for stem in stems:
    result = m.features(stem, s)
    data = json.dumps(result)
    assert secret not in data and "C:" not in data and "/tr" not in data, (stem, data)
assert m.features(stems[0], s)["access_mask"] == "0x1010"
assert m.features(stems[2], s)["literal_create_tr_spaces"]
assert m.features(stems[3], s)["appdata_reference"]
assert "worker.exe" in m.features(stems[3], s)["referenced_executables"]
assert m.field({"process.command_line": "flat"}, "process.command_line") == "flat"
assert m.public_label("evil\nlog.evtx", ".evtx") == "(missing/withheld)"


class One:
    def count(self, q):
        return 1

    def search(self, b):
        assert b["_source"] == m.SOURCE_FIELDS
        return {
            "hits": {"hits": [{"_source": dict(s, tags=["benign-corpus", "baseline"])}]}
        }


try:
    m.get_records(One(), {}, "benign-corpus", SimpleNamespace(ProbeError=ProbeError))
except ProbeError:
    pass
else:
    raise AssertionError("Mixed host label accepted")


class TooMany:
    def count(self, q):
        return m.CAP + 1


try:
    m.get_records(
        TooMany(), {}, "benign-corpus", SimpleNamespace(ProbeError=ProbeError)
    )
except ProbeError:
    pass
else:
    raise AssertionError("Cap accepted")


# Exercise full output/report flow using simulated datasets. No localhost access.
def find(q, name):
    if isinstance(q, dict):
        if name in q:
            return q[name]
        for k, x in q.items():
            if k == "must_not":
                continue
            y = find(x, name)
            if y is not None:
                return y
    if isinstance(q, list):
        for x in q:
            y = find(x, name)
            if y is not None:
                return y
    return None


class Snap:
    def __init__(self, c):
        self.closed = False

    def rows(self, q):
        tag = find(q, "tags")
        rule = find(q, "rule") or find(q, "opportunity")
        if not rule:
            return []
        if tag == "attack-sample":
            a = json.loads(json.dumps(s))
            a["tags"] = ["attack-sample"]
            a["fields"] = {
                "sample_tactic": "Credential Access",
                "sample_file": "recorded.evtx",
            }
            return [{"_index": "winlogbeat-test", "_id": "a", "_source": a}]
        if tag == "benign-corpus":
            return [{"_index": "winlogbeat-test", "_id": "p", "_source": s}]
        return []

    def count(self, q):
        return len(self.rows(q))

    def ids(self, q):
        return {(r["_index"], r["_id"]) for r in self.rows(q)}

    def search(self, b):
        return {"hits": {"hits": self.rows(b["query"])}}

    def close(self):
        self.closed = True


with tempfile.TemporaryDirectory() as d:
    v = SimpleNamespace(
        Rest=lambda: object(),
        Snapshot=Snap,
        ROOT=Path(d),
        ProbeError=ProbeError,
        both=both,
        atomic_json=lambda p, x: p.write_text(json.dumps(x)),
    )
    suite = []
    for stem in stems:
        p = Path(d) / (stem + ".yml")
        p.write_text("synthetic test fixture")
        suite.append(
            (
                p,
                {"id": "test"},
                {"label": stem},
                None,
                {"term": {"rule": stem}},
                None,
                {"term": {"opportunity": stem}},
                None,
            )
        )
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        m.review(v, suite)
    files = list(Path(d).glob("coverage/reviews/*/context.json"))
    assert len(files) == 1
    result = json.loads(files[0].read_text())
    assert result["status"] == "review_complete" and len(result["rules"]) == 6
    joined = out.getvalue() + files[0].read_text()
    assert (
        secret not in joined and "C:" + chr(92) not in joined and "/tr" not in joined
    ), [
        (x, joined.find(x), joined[max(0, joined.find(x) - 80) : joined.find(x) + 160])
        for x in [secret, "C:", "/tr"]
        if x in joined
    ]
print(
    "PASS: six classifiers, basename privacy, mixed-label rejection, truncation rejection, and complete sanitized report flow."
)
