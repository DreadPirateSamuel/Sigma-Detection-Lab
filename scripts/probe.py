#!/usr/bin/env python3
"""Read-only candidate discovery for a localhost Windows detection lab.

Only counts, field names, and status messages are printed. No event contents
or credentials are written. Broad candidate probes are not detection rules.
Requires Python 3.12 standard library only. Authentication: ES_LOCAL_PASSWORD.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


class ProbeError(Exception):
    pass


class Client:
    def __init__(self):
        self.url = os.environ.get("ES", "http://localhost:9200").rstrip("/")
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ProbeError("ES must point to the localhost lab.")
        password = os.environ.get("ES_LOCAL_PASSWORD", "")
        if not password:
            raise ProbeError("ES_LOCAL_PASSWORD is unset; source the lab .env first.")
        token = base64.b64encode(f"elastic:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}",
                        "Content-Type": "application/json"}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def post(self, path, body):
        request = urllib.request.Request(self.url + path, json.dumps(body).encode(),
                                         self.headers, method="POST")
        try:
            with self.opener.open(request, timeout=60) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            # Do not echo raw server responses or request headers.
            raise ProbeError(f"HTTP {error.code} for {path.split('?')[0]}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProbeError("Cannot reach Elasticsearch; check the lab is running.") from None
        except ValueError:
            raise ProbeError("Elasticsearch returned invalid JSON.") from None
        if (result.get("timed_out") or result.get("is_partial")
                or result.get("is_running") or result.get("shard_failures")
                or result.get("_shards", {}).get("failed", 0)):
            raise ProbeError("Incomplete search results; counts were rejected.")
        return result

    def count(self, query):
        result = self.post("/winlogbeat-*/_count", {"query": query})
        return result["count"]

    def files(self, query, file_field, tactic_field):
        # Enumerate all buckets, rather than estimate distinct file counts.
        sources = []
        if tactic_field:
            sources.append({"tactic": {"terms": {"field": tactic_field,
                                                 "missing_bucket": True}}})
        sources.append({"file": {"terms": {"field": file_field}}})
        composite = {"size": 500, "sources": sources}
        total = 0
        while True:
            result = self.post("/winlogbeat-*/_search?allow_partial_search_results=false",
                               {"size": 0, "query": query,
                                "aggs": {"files": {"composite": composite}}})
            page = result["aggregations"]["files"]
            total += len(page["buckets"])
            if not page["buckets"] or "after_key" not in page:
                return total
            composite["after"] = page["after_key"]


def both(*queries):
    return {"bool": {"filter": list(queries)}}


def either(queries):
    return ({"bool": {"should": queries, "minimum_should_match": 1}}
            if queries else {"match_none": {}})


def main():
    client = Client()
    caps = client.post("/winlogbeat-*/_field_caps", {"fields": [
        "event.code*", "winlog.event_id*", "winlog.channel*", "tags*",
        "fields.sample_file*", "fields.sample_tactic*", "process.executable*",
        "process.command_line*", "registry.path*", "winlog.event_data.*"
    ]})["fields"]
    missing = set()

    def pick(base, numeric=False, aggregate=False):
        allowed = {"keyword", "constant_keyword", "wildcard"}
        if numeric:
            allowed |= {"byte", "short", "integer", "long", "unsigned_long"}
        for name in (base, base + ".keyword"):
            types = {k: v for k, v in caps.get(name, {}).items() if k != "unmapped"}
            if types and set(types) <= allowed and all(
                    v.get("searchable") and not v.get("non_searchable_indices")
                    and (not aggregate or (v.get("aggregatable")
                                           and not v.get("non_aggregatable_indices")))
                    for v in types.values()):
                return name
        missing.add(base)
        return None

    code = pick("event.code", numeric=True) or pick("winlog.event_id", numeric=True)
    tags = pick("tags")
    file_field = pick("fields.sample_file", aggregate=True)
    tactic_field = pick("fields.sample_tactic", aggregate=True)
    channel = pick("winlog.channel")
    if not code or not tags or not file_field:
        raise ProbeError("Required code/tags/sample-file fields unavailable: "
                         + ", ".join(sorted(missing)))

    def ids(*values):
        return {"terms": {code: [str(v) for v in values]}}

    def wild(bases, patterns):
        fields = [f for base in bases if (f := pick(base))]
        # Escape literal Windows path separators for the wildcard parser.
        return either([{"wildcard": {f: {"value": pattern.replace(chr(92), chr(92) * 2), "case_insensitive": True}}}
                       for f in fields for pattern in patterns])

    def log(name, *values):
        return both(ids(*values), {"term": {channel: name}}) if channel else ids(*values)

    images = ["process.executable", "winlog.event_data.Image", "winlog.event_data.NewProcessName"]
    commands = ["process.command_line", "winlog.event_data.CommandLine"]
    sysmon_channel = "Microsoft-Windows-Sysmon/Operational"
    process_events = either([log(sysmon_channel, 1), log("Security", 4688)])
    service = log("System", 7045)
    ps = wild(images, ["*\\powershell.exe", "*\\pwsh.exe"])
    candidates = [
        ("T1003.001 LSASS access (broad)", both(log(sysmon_channel, 10), wild(
            ["winlog.event_data.TargetImage"], ["*\\lsass.exe"]))),
        ("T1003.006 Directory access 4662 (broad)", log("Security", 4662)),
        ("T1059.001 Encoded PowerShell flags", both(process_events, ps, wild(
            commands, ["*-enc *", "*-encodedcommand *"]))),
        ("T1059.001 PowerShell process start", both(process_events, ps)),
        ("T1053.005 Task created 4698", log("Security", 4698)),
        ("T1053.005 schtasks process", both(process_events, wild(images, ["*\\schtasks.exe"]))),
        ("T1547.001 Run/RunOnce value set", both(log(sysmon_channel, 13), wild(
            ["registry.path", "winlog.event_data.TargetObject"],
            ["*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
             "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"]))),
        ("T1546.003 WMI subscription events", log(sysmon_channel, 19, 20, 21)),
        ("T1543.003 Service installed (broad)", service),
        ("T1569.002 PSEXESVC service name/path", both(service, wild(
            ["winlog.event_data.ServiceName", "winlog.event_data.ImagePath"], ["*psexesvc*"]))),
        ("T1070.001 Event log cleared", either([log("Security", 1102), log("System", 104)])),
        ("T1136.001 Account created 4720 (broad)", log("Security", 4720)),
        ("T1055 CreateRemoteThread (broad)", log(sysmon_channel, 8)),
        ("T1218 Proxy-execution tools (broad)", both(process_events, wild(
            images, ["*\\mshta.exe", "*\\regsvr32.exe", "*\\rundll32.exe"]))),
        ("T1105 Transfer tools (broad)", both(process_events, wild(
            images, ["*\\certutil.exe", "*\\bitsadmin.exe"]))),
    ]
    corpora = {name: {"term": {tags: tag}} for name, tag in [
        ("attack", "attack-sample"), ("host", "baseline"), ("public", "benign-corpus")
    ]}
    print("UTC:", datetime.now(timezone.utc).isoformat())
    print("Counts only; broad probes are NOT validated detections.")
    print("Event-code field:", code, "| sample field:", file_field)
    print("Distinct files use tactic + filename when both fields are available.")
    if not channel:
        print("WARNING: channel is unavailable; event-ID probes are less specific.")
    for name, query in corpora.items():
        print(f"Corpus {name}: {client.count(query):,} events")
    print("Attack files:", client.files(corpora["attack"], file_field, tactic_field))
    unlabeled = client.count(both(corpora["attack"], {"bool": {"must_not": [
        {"exists": {"field": file_field}}]}}))
    print("Attack events missing sample-file labels:", unlabeled)
    print(f"\n{'Candidate':<48} {'Attack':>9} {'Files':>6} {'Host':>9} {'Public':>9}")
    for label, query in candidates:
        aq = both(corpora["attack"], query)
        counts = [client.count(both(cq, query)) for cq in corpora.values()]
        files = client.files(aq, file_field, tactic_field)
        print(f"{label:<48} {counts[0]:>9,} {files:>6} {counts[1]:>9,} {counts[2]:>9,}", flush=True)
    if missing:
        print("\nUnavailable optional fields:", ", ".join(sorted(missing)))

    # Stable attack corpus avoids comparison races with live host ingestion.
    exact = client.count(both(corpora["attack"], service))
    numeric = any(t in caps[code] for t in ["byte", "short", "integer", "long", "unsigned_long"])
    eql_query = f'any where {code} == ' + ('7045' if numeric else '"7045"')
    if channel:
        eql_query += f' and {channel} == "System"'
    result = client.post("/winlogbeat-*/_eql/search?allow_partial_search_results=false",
                         {"query": eql_query, "filter": corpora["attack"], "size": 10000})
    returned = len(result["hits"].get("events", []))
    status = ("NO DATA" if exact == 0 else "CAPPED / INCONCLUSIVE" if exact >= 10000
              else "MATCH" if exact == returned else "MISMATCH")
    print(f"\n7045 check (attack only): exact={exact}, EQL returned={returned} -> {status}")
    print("No raw events or credentials were printed or saved.")


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Probe interrupted.", file=sys.stderr)
        sys.exit(130)
