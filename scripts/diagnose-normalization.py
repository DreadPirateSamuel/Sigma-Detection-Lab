#!/usr/bin/env python3
"""Read-only diagnosis of public EVTX normalization, beside probe.py.

Uses installed PyYAML. Reads config locally but never prints credentials or
config contents. Samples only public benign events, keeps them in memory,
and uses Elasticsearch pipeline simulation without indexing documents.
"""
import copy
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from probe import Client, ProbeError, both


def get(obj, path, default=None):
    if not isinstance(obj, dict):
        return default
    if path in obj:
        return obj[path]
    parts = path.split(".")
    for i in range(len(parts)-1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in obj:
            return get(obj[prefix], ".".join(parts[i:]), default)
    return default


def read_pipeline(client, name):
    path = "/_ingest/pipeline/" + urllib.parse.quote(name, safe="")
    request = urllib.request.Request(client.url + path, headers=client.headers)
    try:
        with client.opener.open(request, timeout=60) as response:
            return json.load(response).get(name)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise ProbeError(f"Pipeline read returned HTTP {error.code}.") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ProbeError("Could not read the local pipeline.") from None


def safe_settings(root=Path("/mnt/c/soc-lab/benign-replay/configs")):
    configs = sorted(root.glob("*.yml"))
    if not configs:
        raise ProbeError("Replay configs not found.")
    pipelines = Counter()
    overrides = inputs = 0
    for path in configs:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
        output = data.get("output.elasticsearch", {})
        value = output.get("pipeline", "")
        safe = value if isinstance(value, str) and re.fullmatch(
            r"winlogbeat-(?:%\{\[agent\.version\]\}|[0-9.]+)-routing", value
        ) else "unexpected pipeline value (withheld)"
        pipelines[safe] += 1
        overrides += bool(output.get("pipelines"))
        for entry in data.get("winlogbeat.event_logs", []):
            inputs += bool(entry.get("processors"))
    print(f"Replay config files inspected: {len(configs)}")
    for pipeline, count in sorted(pipelines.items()):
        print(f"  Pipeline {pipeline}: {count} configs")
    print(f"Configs with output pipeline-selection overrides: {overrides}")
    print(f"Inputs with additional processors: {inputs}")


def warning_details(root=Path("/mnt/c/soc-lab/benign-replay/logs")):
    print("\n=== Warning metadata (no messages) ===")
    groups = Counter()
    kinds = Counter()
    for folder in sorted(root.glob("win*-client-*")):
        logs = sorted(folder.glob("replay-*-err.txt"))
        if not logs:
            continue
        for path in (logs[-1], logs[-1].with_name(logs[-1].name.replace("-err.txt", "-out.txt"))):
            if not path.exists():
                continue
            with path.open(encoding="utf-8-sig", errors="replace") as stream:
                for line in stream:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(row, dict) or get(row, "log.level") != "warn":
                        continue
                    location = get(row, "log.origin.file.line", 0)
                    location = location if isinstance(location, int) else 0
                    event_id = row.get("event_id", "unavailable")
                    event_id = str(event_id) if str(event_id).isdigit() else "unavailable"
                    groups[(location, event_id)] += 1
                    message = str(row.get("message", "")).lower()
                    # Fixed categories; never interpolate any part of a message.
                    if "salvag" in message:
                        kinds["message salvage"] += 1
                    elif "event data parameters" in message:
                        kinds["event-data/template parameter mismatch"] += 1
                    elif "template" in message:
                        kinds["template lookup/processing"] += 1
                    elif "metadata" in message:
                        kinds["provider/publisher metadata"] += 1
                    elif "format" in message or "render" in message:
                        kinds["message formatting/rendering"] += 1
                    else:
                        kinds["unclassified"] += 1
    for (line_no, event_id), count in sorted(groups.items()):
        print(f"  Renderer source line={line_no} event_id={event_id}: {count}")
    for kind, count in sorted(kinds.items()):
        print(f"  Heuristic category {kind}: {count}")


def main():
    print("Normalization diagnostic UTC:", datetime.now(timezone.utc).isoformat(), flush=True)
    safe_settings()
    warning_details()
    client = Client()
    caps = client.post("/winlogbeat-*/_field_caps", {"fields": [
        "tags*", "winlog.channel*", "event.code*", "agent.version*"
    ]})["fields"]

    def field(base):
        for name in (base, base + ".keyword"):
            types = {k: v for k, v in caps.get(name, {}).items() if k != "unmapped"}
            if types and set(types) <= {"keyword", "constant_keyword", "wildcard"} and all(
                v.get("searchable") and v.get("aggregatable")
                and not v.get("non_searchable_indices")
                and not v.get("non_aggregatable_indices") for v in types.values()
            ):
                return name
        raise ProbeError("Required keyword field unavailable: " + base)

    tags, channel, code, version = map(field, ("tags", "winlog.channel", "event.code", "agent.version"))
    public = {"term": {tags: "benign-corpus"}}
    result = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
        "size": 0, "query": public, "aggs": {"versions": {"terms": {"field": version, "size": 20}}}
    })
    versions = result["aggregations"]["versions"]
    if versions.get("sum_other_doc_count"):
        raise ProbeError("Too many agent versions for this diagnostic.")
    known = []
    print("\n=== Public agent versions and installed pipelines ===")
    for bucket in versions["buckets"]:
        name = str(bucket["key"])
        if not re.fullmatch(r"\d+\.\d+\.\d+", name):
            raise ProbeError("Unexpected agent version; value withheld.")
        known.append(name)
        print(f"Agent version {name}: {bucket['doc_count']:,} events")
        for module in ("routing", "sysmon", "powershell", "security"):
            pipeline = f"winlogbeat-{name}-{module}"
            definition = read_pipeline(client, pipeline)
            print(f"  {pipeline}: {'present' if definition is not None else 'MISSING'}")
            if module == "routing" and definition:
                for step in definition.get("processors", []):
                    inner = step.get("pipeline", {})
                    condition = str(inner.get("if", ""))
                    target = str(inner.get("name", ""))
                    # Print only fixed booleans about route definitions, not their code.
                    if "sysmon" in target.lower():
                        print(f"  Sysmon route tests channel: {'winlog.channel' in condition or 'winlog?.channel' in condition}")
    if not known:
        raise ProbeError("No public corpus agent version found.")

    sysmon = "Microsoft-Windows-Sysmon/Operational"
    cases = [
        ("Sysmon 1", sysmon, "1", ["process.executable", "process.command_line"], ["winlog.event_data.Image", "winlog.event_data.CommandLine"]),
        ("Sysmon 13", sysmon, "13", ["registry.path", "registry.data.strings"], ["winlog.event_data.TargetObject", "winlog.event_data.Details"]),
        ("PowerShell 4104", "Microsoft-Windows-PowerShell/Operational", "4104", ["powershell.file.script_block_text"], ["winlog.event_data.ScriptBlockText"]),
    ]
    print("\n=== Public raw/ECS availability and simulation ===", flush=True)
    for label, log_channel, event_id, ecs_fields, raw_fields in cases:
        query = both(public, {"term": {channel: log_channel}}, {"term": {code: event_id}})
        print(f"\n{label}: total {client.count(query):,}", flush=True)
        for name in raw_fields + ecs_fields:
            print(f"  Exists {name}: {client.count(both(query, {'exists': {'field': name}})):,}")
        sample = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
            "size": 10, "query": query, "_source": True, "sort": ["_doc"]
        })["hits"]["hits"]
        if not sample:
            continue
        keys = Counter()
        for hit in sample:
            for key in get(hit.get("_source", {}), "winlog.event_data", {}):
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key):
                    keys[key] += 1
        print(f"  Sample size: {len(sample)}; raw field names only:")
        print("  " + ", ".join(f"{key}({count})" for key, count in sorted(keys.items())))
        docs = [{"_index": hit["_index"], "_id": hit["_id"], "_source": hit["_source"]} for hit in sample]
        for name in known:
            version_docs = [doc for doc in docs if get(doc["_source"], "agent.version") == name]
            if not version_docs:
                continue
            for module in ("routing", "sysmon" if log_channel == sysmon else "powershell"):
                pipeline = f"winlogbeat-{name}-{module}"
                if read_pipeline(client, pipeline) is None:
                    continue
                simulated = client.post("/_ingest/pipeline/" + pipeline + "/_simulate", {
                    "docs": copy.deepcopy(version_docs)
                }).get("docs", [])
                if len(simulated) != len(version_docs):
                    raise ProbeError("Simulation returned an unexpected document count.")
                failed = changed_errors = 0
                present = Counter()
                for before, result in zip(version_docs, simulated):
                    if result.get("error") or not isinstance(result.get("doc"), dict):
                        failed += 1
                        continue
                    source = result["doc"].get("_source", {})
                    changed_errors += get(source, "error.message") != get(before["_source"], "error.message") and get(source, "error.message") is not None
                    for key in ecs_fields:
                        present[key] += get(source, key) is not None
                print(f"  SIMULATE {pipeline}: docs={len(simulated)} failures={failed} added/changed-error.message={changed_errors}")
                for key in ecs_fields:
                    print(f"    Result has {key}: {present[key]}/{len(simulated)}")
    print("\nDiagnostic complete. No indexed documents changed; no event values or credentials printed/saved.")


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        print("STOPPED:", str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("STOPPED: Unexpected local input/response format; raw details withheld.", file=sys.stderr)
        sys.exit(1)
