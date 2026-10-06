#!/usr/bin/env python3
"""Back up and normalize public Sysmon documents in the localhost SOC lab.

Install beside probe.py. --apply performs the repair after simulation and
backup checks. Default is simulation only. Backups remain in local Elastic
under soc-lab-backup-* (excluded from winlogbeat-* searches). State receipts
contain only counts, index names, queries, task IDs, and status, never events
or credentials. Resume a recorded task by rerunning the same command.
"""
import argparse
import copy
import fcntl
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from probe import Client, ProbeError, both

PIPELINE = "winlogbeat-9.5.4-routing"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
STATE_ROOT = Path("/mnt/c/soc-lab/normalization")


def value(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


class RepairClient(Client):
    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.url + path, data, self.headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            raise ProbeError(f"Local Elasticsearch request returned HTTP {error.code}; raw details withheld.") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise ProbeError("Local Elasticsearch request failed; raw details withheld. Recorded tasks can be resumed.") from None
        if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
            raise ProbeError("Incomplete Elasticsearch response rejected.")
        return result

    def count_at(self, index, query):
        return self.post(f"/{index}/_count", {"query": query})["count"]


def write_state(path, state):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def finish_task(client, task, label):
    if not re.fullmatch(r"[A-Za-z0-9_-]+:\d+", task):
        raise ProbeError("Unexpected task identifier.")
    last_report = -30.0
    started = time.monotonic()
    while True:
        result = client.request("GET", "/_tasks/" + task)
        if result.get("completed"):
            if result.get("error"):
                raise ProbeError(f"{label} task failed; original backup retained. Raw details withheld.")
            response = result.get("response", {})
            if response.get("failures") or response.get("version_conflicts") or response.get("timed_out"):
                raise ProbeError(f"{label} reported failures/conflicts; original backup retained. Raw details withheld.")
            return response
        elapsed = time.monotonic() - started
        if elapsed - last_report >= 30:
            status = result.get("task", {}).get("status", {})
            print(f"  {label}: {int(elapsed)}s; processed={status.get('created', 0) + status.get('updated', 0):,} / {status.get('total', 0):,}", flush=True)
            last_report = elapsed
        time.sleep(3)


def run_operation(client, path, body, entry, kind, state, state_file):
    task_key = kind + "_task"
    if task_key not in entry:
        # An uncertain submission must never be blindly repeated after a timeout.
        if entry.get(kind + "_submitting"):
            raise ProbeError(f"Uncertain {kind} submission from an earlier run; task status needs review before retrying.")
        entry[kind + "_submitting"] = True
        write_state(state_file, state)
        result = client.request("POST", path, body)
        task = result.get("task")
        if not isinstance(task, str):
            raise ProbeError("Async operation did not return a task identifier.")
        entry[task_key] = task
        entry.pop(kind + "_submitting", None)
        write_state(state_file, state)
    return finish_task(client, entry[task_key], kind)


def fields(client):
    caps = client.post("/winlogbeat-*/_field_caps", {"fields": [
        "tags*", "winlog.channel*", "event.code*", "event.module*", "agent.version*",
        "fields.corpus*", "fields.dataset_release*"
    ]})["fields"]
    chosen = {}
    for base in ("tags", "winlog.channel", "event.code", "event.module", "agent.version", "fields.corpus", "fields.dataset_release"):
        for name in (base, base + ".keyword"):
            types = {k: v for k, v in caps.get(name, {}).items() if k != "unmapped"}
            if types and set(types) <= {"keyword", "constant_keyword", "wildcard"} and all(
                v.get("searchable") and not v.get("non_searchable_indices") for v in types.values()
            ):
                chosen[base] = name
                break
        else:
            raise ProbeError("Required keyword field unavailable: " + base)
    return chosen


def queries(f):
    public = {"term": {f["tags"]: "benign-corpus"}}
    scope = both(public, {"term": {f["winlog.channel"]: CHANNEL}},
                 {"term": {f["agent.version"]: "9.5.4"}},
                 {"term": {f["fields.dataset_release"]: "v0.8.5"}},
                 {"terms": {f["fields.corpus"]: ["win10-client", "win11-client"]}},
                 {"bool": {"must_not": [{"terms": {f["tags"]: ["baseline", "attack-sample"]}}]}})
    def missing(name):
        return {"bool": {"must_not": [{"exists": {"field": name}}]}}
    pending = both(scope, {"bool": {"should": [
        {"bool": {"must_not": [{"term": {f["event.module"]: "sysmon"}}]}},
        both({"term": {f["event.code"]: "1"}}, missing("process.executable")),
        both({"term": {f["event.code"]: "13"}}, missing("registry.path"))
    ], "minimum_should_match": 1}})
    return public, scope, pending


def simulate(client, pending, f):
    tested = 0
    distribution = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
        "size": 0, "query": pending,
        "aggs": {"codes": {"terms": {"field": f["event.code"], "size": 100}}}
    })["aggregations"]["codes"]
    if distribution.get("sum_other_doc_count"):
        raise ProbeError("Too many event codes for complete simulation coverage.")
    # Sample each affected event code, including less common Sysmon events.
    for bucket in distribution["buckets"]:
        event_id = str(bucket["key"])
        if not event_id.isdigit():
            raise ProbeError("Unexpected Sysmon event code; raw value withheld.")
        query = both(pending, {"term": {f["event.code"]: event_id}})
        hits = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
            "size": 100, "query": query, "sort": ["_doc"], "_source": True
        })["hits"]["hits"]
        if not hits:
            continue
        docs = [{"_index": h["_index"], "_id": h["_id"], "_source": h["_source"]} for h in hits]
        results = client.post(f"/_ingest/pipeline/{PIPELINE}/_simulate", {"docs": copy.deepcopy(docs)}).get("docs", [])
        if len(results) != len(docs):
            raise ProbeError("Simulation document count mismatch.")
        for before, result in zip(docs, results):
            source = result.get("doc", {}).get("_source", {})
            if result.get("error") or not source:
                raise ProbeError("Pipeline simulation failed; no indexed documents changed.")
            if value(source, "error.message") and value(source, "error.message") != value(before["_source"], "error.message"):
                raise ProbeError("Simulation added an error; no indexed documents changed.")
            if value(source, "event.module") != "sysmon":
                raise ProbeError("Simulation did not supply Sysmon categorization; no indexed documents changed.")
            if event_id in {"1", "13", "10", "8"} and not value(source, "event.category"):
                raise ProbeError("Simulation did not categorize candidate events; no indexed documents changed.")
            needed = {"1": ["process.executable", "process.command_line"],
                      "13": ["registry.path"]}.get(event_id, [])
            if any(value(source, name) is None for name in needed):
                raise ProbeError("Simulation did not supply required ECS fields; no indexed documents changed.")
            for name in ("fields.corpus", "fields.corpus_file", "fields.dataset_release", "tags", "event.code", "winlog.channel"):
                if value(source, name) != value(before["_source"], name):
                    raise ProbeError("Simulation changed a corpus identity field; no indexed documents changed.")
        tested += len(docs)
        print(f"Simulation Sysmon {event_id}: {len(docs)}/{len(docs)} passed", flush=True)
    if not tested:
        raise ProbeError("No supported candidate events available for simulation; repair stopped.")


def verify(client, public, scope, pending, f, expected_public, expected_errors=None):
    actual = client.count(public)
    remaining = client.count(pending)
    print(f"Public event total: {actual:,} (before {expected_public:,})")
    print(f"Sysmon documents still pending normalization: {remaining:,}")
    bad = 0
    errors = client.count(both(scope, {"exists": {"field": "error.message"}}))
    print(f"Public Sysmon with error.message: {errors:,}")
    if expected_errors is not None:
        bad += errors > expected_errors
    for code, names in (("1", ("process.executable", "process.command_line")),
                        ("13", ("registry.path", "registry.data.strings"))):
        query = both(scope, {"term": {f["event.code"]: code}})
        total = client.count(query)
        for name in names:
            populated = client.count(both(query, {"exists": {"field": name}}))
            print(f"Sysmon {code} with {name}: {populated:,}/{total:,}")
            # Binary registry data can use other ECS fields; strings are
            # reported for coverage but are not required for every value type.
            if name != "registry.data.strings":
                bad += populated != total
    if actual != expected_public or remaining or bad:
        raise ProbeError("Post-repair verification did not pass; backups retained. Do not report validated detection results yet.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    client = RepairClient()
    f = fields(client)
    public, scope, pending = queries(f)
    print("Repair UTC:", datetime.now(timezone.utc).isoformat(), flush=True)
    print("Scope: public v0.8.5 Sysmon only; installed routing pipeline", PIPELINE)
    if not args.apply:
        print(f"Pending documents: {client.count(pending):,}")
        simulate(client, pending, f)
        print("Simulation only; pass --apply to back up and repair.")
        return
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with (STATE_ROOT / "public-sysmon.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProbeError("Another normalization repair is running.") from None
        state_file = STATE_ROOT / "public-sysmon-v1.json"
        if state_file.exists():
            state = json.loads(state_file.read_text())
            if state.get("pipeline") != PIPELINE or state.get("query") != pending:
                raise ProbeError("Saved repair plan differs; review needed before proceeding.")
        else:
            count = client.count(pending)
            if not count:
                verify(client, public, scope, pending, f, client.count(public))
                print("Already normalized; no changes needed.")
                return
            simulate(client, pending, f)
            distribution = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
                "size": 0, "query": pending,
                "aggs": {"indices": {"terms": {"field": "_index", "size": 100}}}
            })["aggregations"]["indices"]
            if distribution.get("sum_other_doc_count"):
                raise ProbeError("Too many indices for this repair plan.")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            entries = []
            for i, bucket in enumerate(distribution["buckets"], 1):
                source = bucket["key"]
                if not re.fullmatch(r"\.?[a-z0-9_.-]+", source):
                    raise ProbeError("Unexpected source index identifier.")
                entries.append({"source": source, "expected": bucket["doc_count"],
                                "backup": f"soc-lab-backup-public-sysmon-{stamp}-{i:03d}"})
            if sum(entry["expected"] for entry in entries) != count:
                raise ProbeError("Source count changed while planning; no repair started.")
            state = {"pipeline": PIPELINE, "query": pending, "before_public": client.count(public),
                     "before_sysmon_errors": client.count(both(scope, {"exists": {"field": "error.message"}})),
                     "entries": entries, "complete": False}
            write_state(state_file, state)
        print(f"Repair plan: {sum(e['expected'] for e in state['entries']):,} documents across {len(state['entries'])} indices", flush=True)
        # Every backup is completed and counted before any original is updated.
        for entry in state["entries"]:
            if entry.get("backup_verified"):
                continue
            if not entry.get("backup_created"):
                client.request("PUT", "/" + entry["backup"], {
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0,
                                 "index.default_pipeline": "_none", "index.final_pipeline": "_none"},
                    "mappings": {"dynamic": False, "_source": {"enabled": True}}
                })
                entry["backup_created"] = True
                write_state(state_file, state)
            print("Creating original-data backup:", entry["backup"], flush=True)
            result = run_operation(client, "/_reindex?wait_for_completion=false&refresh=true", {
                "source": {"index": entry["source"], "query": pending, "size": 500},
                "dest": {"index": entry["backup"], "op_type": "create", "pipeline": "_none"}
            }, entry, "backup", state, state_file)
            count = client.count_at(entry["backup"], {"match_all": {}})
            if count != entry["expected"] or result.get("created") != entry["expected"]:
                raise ProbeError("Backup count mismatch; original documents have not been updated.")
            entry["backup_verified"] = True
            write_state(state_file, state)
            print(f"  Backup verified: {count:,} originals", flush=True)
        for entry in state["entries"]:
            if entry.get("repair_verified"):
                continue
            print("Normalizing backed-up source documents...", flush=True)
            result = run_operation(client, f"/{entry['source']}/_update_by_query?wait_for_completion=false&refresh=true&pipeline={PIPELINE}&scroll_size=500", {
                "query": pending
            }, entry, "repair", state, state_file)
            if result.get("updated") != entry["expected"] or result.get("deleted", 0):
                raise ProbeError("Repair update count mismatch; backups retained.")
            entry["repair_verified"] = True
            write_state(state_file, state)
            print(f"  Updated: {result['updated']:,}; failures=0; conflicts=0", flush=True)
        verify(client, public, scope, pending, f, state["before_public"], state["before_sysmon_errors"])
        state["complete"] = True
        write_state(state_file, state)
        print("REPAIR VERIFIED. Original-data backups remain local and outside normal detection searches.")
        print("Re-running candidate probes against corrected fields...", flush=True)
        import probe
        probe.main()


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        print("STOPPED:", str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted. Server tasks may still be running; rerun this script to resume recorded tasks.", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("STOPPED: Unexpected local state or response; raw details withheld. Keep repair receipts and backups.", file=sys.stderr)
        sys.exit(1)
