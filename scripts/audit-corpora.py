#!/usr/bin/env python3
"""Read-only SOC corpus audit. Install beside the existing scripts/probe.py.

Prints counts and fixed diagnostic categories only, never log messages, event
contents, config contents, or credentials. Uses Python's standard library.
No replay, refresh, writes to Elasticsearch, or registry changes are performed.
"""

import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from probe import Client, ProbeError, both


def get(obj, dotted, default=None):
    if not isinstance(obj, dict):
        return default
    if dotted in obj:
        return obj[dotted]
    parts = dotted.split(".")
    for length in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:length])
        if prefix in obj:
            return get(obj[prefix], ".".join(parts[length:]), default)
    return default


def warning_kind(message):
    """Heuristic categories only; no message text is returned."""
    message = str(message).lower()
    if "publisher metadata" in message or "publishermetadata" in message:
        return "publisher metadata (review rendering impact)"
    if "event data parameters" in message or "parameter count" in message:
        return "event-data/template parameters (review field impact)"
    if "evtformatmessage" in message or "render" in message or "message file" in message:
        return "message rendering (review rendering impact)"
    if any(word in message for word in ("evtquery", "evtnext", "missing channel")):
        return "event reading/channel (review possible data loss)"
    return "unclassified (needs review)"


def log_audit(root=Path("/mnt/c/soc-lab/benign-replay")):
    print("\n=== Replay logs: safe summary ===", flush=True)
    plan_file = root / "replay-manifest.json"
    if not plan_file.exists():
        print("Replay manifest not found; log audit unavailable.")
        return
    plan = json.loads(plan_file.read_text(encoding="utf-8-sig"))
    warnings = Counter()
    origins = Counter()
    metrics = Counter()
    errors = nonjson = done = totals = attempts = no_logs = 0
    batches = plan.get("batches", [])
    for batch in batches:
        # Only validated generated IDs are used to construct local paths.
        batch_id = batch.get("id", "")
        if not re.fullmatch(r"win(?:10|11)-client-\d{3}", batch_id):
            raise ProbeError("Unexpected batch identifier; log audit stopped.")
        marker = root / "state" / batch_id / "replay-complete.json"
        if marker.exists():
            receipt = json.loads(marker.read_text(encoding="utf-8-sig"))
            done += receipt.get("ExitCode") == 0
        folder = root / "logs" / batch_id
        runs = sorted(folder.glob("replay-*-err.txt"))
        if not runs:
            no_logs += 1
            continue
        attempts += len(runs) > 1
        latest = runs[-1]
        total_row = None
        for path in (latest, latest.with_name(latest.name.replace("-err.txt", "-out.txt"))):
            if not path.exists():
                continue
            with path.open(encoding="utf-8-sig", errors="replace") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        nonjson += 1
                        continue
                    if not isinstance(row, dict):
                        nonjson += 1
                        continue
                    level = get(row, "log.level", row.get("level"))
                    if level == "error":
                        errors += 1
                    if level == "warn":
                        warnings[warning_kind(row.get("message", ""))] += 1
                        # Static Go source locations help identify the warning.
                        origin = get(row, "log.origin.file.name", "")
                        line_no = get(row, "log.origin.file.line", 0)
                        if (isinstance(origin, str) and len(origin) <= 100
                                and re.fullmatch(r"[A-Za-z0-9_./-]+\.go", origin)
                                and isinstance(line_no, int)):
                            origins[f"{origin}:{line_no}"] += 1
                        else:
                            origins["source location unavailable"] += 1
                    if str(row.get("message", "")).startswith("Total metrics"):
                        candidate = get(row, "monitoring.metrics")
                        if isinstance(candidate, dict):
                            total_row = candidate
        if total_row is not None:
            totals += 1
            for key in ("libbeat.pipeline.events.total", "libbeat.pipeline.events.filtered",
                        "libbeat.pipeline.events.published", "libbeat.pipeline.events.dropped",
                        "libbeat.pipeline.events.active", "libbeat.output.events.acked",
                        "libbeat.output.events.failed", "libbeat.output.events.dropped",
                        "libbeat.output.events.dead_letter", "libbeat.output.events.failure_store"):
                value = get(total_row, key, 0)
                if isinstance(value, int):
                    metrics[key] += value
    print(f"Completion markers with exit 0: {done}/{len(batches)}")
    print(f"Batches missing replay logs: {no_logs}; multiple attempts: {attempts}")
    print(f"Latest-run errors: {errors}; warnings: {sum(warnings.values())}; non-JSON lines: {nonjson}")
    for category, count in sorted(warnings.items()):
        print(f"  {category}: {count}")
    for origin, count in origins.most_common():
        print(f"  Warning source {origin}: {count}")
    print("Warning categories are heuristics; they do not establish that warnings are harmless.")
    print(f"Shutdown 'Total metrics' available: {totals}/{len(batches)} batches")
    if totals:
        for key, count in sorted(metrics.items()):
            print(f"  {key}: {count:,}")
        print("Metrics sum only shutdown totals from each latest run; missing metric keys count as 0.")
    if totals != len(batches) or attempts:
        print("Metrics are incomplete or cover only the latest attempts; do not treat them as corpus totals.")


def es_audit():
    client = Client()
    caps = client.post("/winlogbeat-*/_field_caps", {"fields": [
        "tags*", "fields.corpus*", "fields.dataset_release*", "event.code*",
        "winlog.event_id*", "winlog.channel*"
    ]})["fields"]

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
        raise ProbeError("Required field unavailable or incompatible: " + base)

    tags = pick("tags")
    corpus = pick("fields.corpus")
    file_field = pick("fields.corpus_file", aggregate=True)
    release = pick("fields.dataset_release")
    code = pick("event.code", numeric=True) if "event.code" in caps else pick("winlog.event_id", numeric=True)
    channel = pick("winlog.channel")

    def tag(value):
        return {"term": {tags: value}}

    def exists(field):
        return {"exists": {"field": field}}

    def log(name, *ids):
        return both({"term": {channel: name}}, {"terms": {code: [str(i) for i in ids]}})

    public = tag("benign-corpus")
    queries = [tag("attack-sample"), tag("baseline")]
    queries += [both(public, {"term": {corpus: name}})
                for name in ("win10-client", "win11-client")]
    print("\n=== Indexed corpus counts ===", flush=True)
    counts = []
    for name, query in zip(("attack", "live host", "public Win10", "public Win11"), queries):
        count = client.count(query)
        counts.append(count)
        print(f"{name}: {count:,}", flush=True)
    all_public = client.count(public)
    print(f"All benign-corpus tagged events: {all_public:,}")
    print(f"Public with missing corpus label: {client.count(both(public, {'bool': {'must_not': [exists(corpus)]}})):,}")
    print(f"Public outside expected corpus labels: {client.count(both(public, {'bool': {'must_not': [{'terms': {corpus: ['win10-client', 'win11-client']}}]}})):,}")
    print(f"Public missing file label: {client.count(both(public, {'bool': {'must_not': [exists(file_field)]}})):,}")
    print(f"Public missing/wrong release label: {client.count(both(public, {'bool': {'must_not': [{'term': {release: 'v0.8.5'}}]}})):,}")
    print(f"Public also tagged baseline: {client.count(both(public, tag('baseline'))):,}")
    print(f"Public also tagged attack-sample: {client.count(both(public, tag('attack-sample'))):,}")
    for name, expected, query in zip(("Win10", "Win11"), (352, 355), queries[2:]):
        files = client.files(query, file_field, None)
        print(f"{name} distinct indexed file labels: {files} / {expected} prepared files", flush=True)
    print("Empty EVTX files produce no indexed file label; fewer labels alone does not prove loss.")

    sysmon = "Microsoft-Windows-Sysmon/Operational"
    process = log(sysmon, 1)
    registry = log(sysmon, 13)
    access = log(sysmon, 10)
    task = log("Security", 4698)
    script = log("Microsoft-Windows-PowerShell/Operational", 4104)
    checks = [
        ("Sysmon 1 process creation", process),
        ("  with process.executable", both(process, exists("process.executable"))),
        ("  with process.command_line", both(process, exists("process.command_line"))),
        ("Security 4688 process creation", log("Security", 4688)),
        ("Sysmon 10 process access", access),
        ("  with TargetImage + GrantedAccess", both(access, exists("winlog.event_data.TargetImage"), exists("winlog.event_data.GrantedAccess"))),
        ("Sysmon 13 registry value set", registry),
        ("  with registry.path", both(registry, exists("registry.path"))),
        ("  with registry.data.strings", both(registry, exists("registry.data.strings"))),
        ("Sysmon 19 WMI filter", log(sysmon, 19)),
        ("Sysmon 20 WMI consumer", log(sysmon, 20)),
        ("Sysmon 21 WMI binding", log(sysmon, 21)),
        ("Security 4698 task created", task),
        ("  with TaskContent", both(task, exists("winlog.event_data.TaskContent"))),
        ("PowerShell 4104 script block", script),
        ("  with ScriptBlockText", both(script, exists("winlog.event_data.ScriptBlockText"))),
        ("Security 1102 log cleared", log("Security", 1102)),
        ("System 104 log cleared", log("System", 104)),
        ("Events with error.message", exists("error.message")),
    ]
    print("\n=== Telemetry counts (not detection hits) ===", flush=True)
    print(f"{'Event / available field':43} {'Attack':>10} {'Host':>10} {'Win10':>10} {'Win11':>10}")
    # A filters aggregation returns exact document counts for all checks per corpus.
    columns = []
    for query in queries:
        result = client.post("/winlogbeat-*/_search?allow_partial_search_results=false", {
            "size": 0, "query": query,
            "aggs": {"checks": {"filters": {"filters": {
                str(i): check for i, (_, check) in enumerate(checks)
            }}}}
        })
        columns.append(result["aggregations"]["checks"]["buckets"])
    for i, (label, _) in enumerate(checks):
        values = [column[str(i)]["doc_count"] for column in columns]
        print(f"{label:43}" + "".join(f"{v:>11,}" for v in values))
    print("Live host counts can change during this audit. Zero hits without eligible telemetry are inconclusive.")


def main():
    print("SOC corpus audit UTC:", datetime.now(timezone.utc).isoformat(), flush=True)
    log_audit()
    es_audit()
    print("\nAudit complete. No raw messages, events, credentials, or config contents were printed or saved.")


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        print("STOPPED:", str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("STOPPED: Local audit input is unavailable or has an unexpected format; keep raw files private.", file=sys.stderr)
        sys.exit(1)
