#!/usr/bin/env python3
"""Read-only context review of six draft rules against recorded corpora.

Retrieves a restricted field set from attack/public records only. Raw values
remain in memory; outputs contain counts, public sample labels, executable
basenames, access masks and fixed feature labels. Never retrieves live-host
event contents. Requires the previously installed validate-rules.py/probe.py.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import importlib.metadata
import json
from pathlib import Path
import re
import sys

SOURCE_FIELDS = [
    "tags", "fields.sample_tactic", "fields.sample_file", "fields.corpus",
    "fields.corpus_file", "event.code", "winlog.channel", "winlog.provider_name",
    "process.executable", "process.parent.executable", "process.command_line",
    "registry.path", "registry.data.strings", "winlog.event_data.SourceImage",
    "winlog.event_data.Image", "winlog.event_data.TargetImage",
    "winlog.event_data.GrantedAccess", "winlog.event_data.CommandLine",
    "winlog.event_data.TargetObject", "winlog.event_data.Details",
]
CAP = 5000


def field(source, name, default=None):
    if name in source:
        return source[name]
    value = source
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def text_value(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(item for item in value if isinstance(item, str))
    return ""


def executable(value):
    # No directory, username, argument, or arbitrary non-executable value.
    name = text_value(value).replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if re.fullmatch(r"[a-z0-9_ .()+&-]{1,100}\.(?:exe|com|dll)", name):
        return name
    return "(missing/withheld)"


def path_class(value):
    path = text_value(value).lower().replace("/", "\\")
    if not path:
        return "missing"
    for fragment, label in [("\\appdata\\", "AppData"), ("\\temp\\", "Temp"),
                            ("\\windows\\system32\\", "Windows/System32"),
                            ("\\windows\\syswow64\\", "Windows/SysWOW64"),
                            ("\\windows\\", "Windows/other"),
                            ("\\program files", "Program Files")]:
        if fragment in path:
            return label
    return "other"


def referenced_basenames(value):
    # Only filename-like executable references, without paths or arguments.
    candidates = re.findall(r'(?:^|[\\/\s"\x27])([a-z0-9_.()+&-]{1,100}\.(?:exe|com|dll))(?=$|[\s"\x27,;])', text_value(value).lower())
    return sorted({executable(item.strip()) for item in candidates} - {"(missing/withheld)"})


def features(stem, source):
    image = (field(source, "process.executable") or field(source, "winlog.event_data.SourceImage")
             or field(source, "winlog.event_data.Image"))
    cmd = text_value(field(source, "process.command_line") or field(source, "winlog.event_data.CommandLine")).lower()
    result = {"writer": executable(image), "writer_location": path_class(image)}
    if stem == "lsass_selected_read_access":
        mask = text_value(field(source, "winlog.event_data.GrantedAccess")).lower()
        result["access_mask"] = mask if re.fullmatch(r"0x[0-9a-f]{1,8}", mask) else "(missing/withheld)"
    elif stem == "powershell_encoded_command":
        selected = ["-e", "-ec", "-en", "-enc", "-enco", "-encodedcommand"]
        result["selected_spaced_flag"] = any(" " + flag + " " in cmd for flag in selected)
        result["encoded_switch_token"] = bool(re.search(
            r"(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?=\s|$)", cmd))
        result["command_present"] = bool(cmd)
    elif stem == "schtasks_create_task":
        for flag in ["create", "tr", "xml", "query", "delete", "change", "run"]:
            result["switch_" + flag] = bool(re.search(r"(?:^|\s)/" + flag + r"(?=\s|$)", cmd))
        result["literal_create_tr_spaces"] = " /create " in cmd and " /tr " in cmd
        result["parent"] = executable(field(source, "process.parent.executable"))
        result["referenced_executables"] = referenced_basenames(cmd)
    elif stem == "run_key_suspicious_value":
        target = text_value(field(source, "registry.path") or field(source, "winlog.event_data.TargetObject")).lower()
        data = text_value(field(source, "registry.data.strings") or field(source, "winlog.event_data.Details")).lower()
        result["key_class"] = "RunOnce" if "\\runonce\\" in target else "Run" if "\\run\\" in target else "other"
        indicators = ["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"]
        result["payload_indicators"] = [item for item in indicators if item in data]
        result["appdata_reference"] = "\\appdata\\" in data or "%appdata%" in data
        result["temp_reference"] = "\\temp\\" in data or "%temp%" in data
        result["value_present"] = bool(data)
        result["referenced_executables"] = referenced_basenames(data)
    elif stem == "windows_event_log_cleared":
        # Print only known provider/channel values; never arbitrary event strings.
        provider = field(source, "winlog.provider_name")
        result = {"channel": field(source, "winlog.channel") if field(source, "winlog.channel") in {"Security", "System"} else "other",
                  "event_code": str(field(source, "event.code")) if str(field(source, "event.code")) in {"104", "1102"} else "other",
                  "provider": provider if provider in {"Microsoft-Windows-Eventlog", "Microsoft-Windows-Security-Auditing"} else "other/missing"}
    elif stem == "wmi_consumer_filter_binding":
        result = {"event_code": "21" if str(field(source, "event.code")) == "21" else "other"}
    else:
        raise ValueError("Unsupported rule context classifier.")
    return result


def public_label(value, suffix=None):
    # All labels originate in public recorded datasets, never host telemetry.
    if (not isinstance(value, str) or len(value) > 300 or not value
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or (suffix and not value.lower().endswith(suffix))):
        return "(missing/withheld)"
    return value


def get_records(snapshot, query, expected_tag, v):
    expected_count = snapshot.count(query)
    if expected_count > CAP:
        raise v.ProbeError("Context review exceeds its 5,000-record cap; no truncated report accepted.")
    response = snapshot.search({"size": CAP, "query": query, "_source": SOURCE_FIELDS,
                                "sort": ["_shard_doc"], "track_total_hits": True})
    hits = response["hits"]["hits"]
    if len(hits) != expected_count:
        raise v.ProbeError("Context fetch/count mismatch; incomplete results rejected.")
    for hit in hits:
        tags = field(hit["_source"], "tags", [])
        if not isinstance(tags, list) or expected_tag not in tags or "baseline" in tags:
            raise v.ProbeError("Unexpected corpus label; raw event values withheld.")
    return hits


def review(v, suite):
    client = v.Rest()
    snapshot = v.Snapshot(client)
    started = datetime.now(timezone.utc)
    report = {"utc": started.isoformat(), "status": "in_progress",
              "method": "Single PIT; public/attack records only; fixed feature groups, no raw events",
              "interpretation": "Public matches require review; unmatched precursors are not technique-wide false negatives.",
              "rules": []}
    attack = {"term": {"tags": "attack-sample"}}
    public = v.both({"term": {"tags": "benign-corpus"}},
                    {"terms": {"fields.corpus": ["win10-client", "win11-client"]}})
    no_host = {"bool": {"must_not": [{"term": {"tags": "baseline"}}]}}
    try:
        # Reject contamination before retrieving any source fields.
        for corpus in [attack, public]:
            if snapshot.count(v.both(corpus, {"term": {"tags": "baseline"}})):
                raise v.ProbeError("Recorded corpus overlaps host labels; review stopped.")
        if snapshot.count(v.both(attack, public)):
            raise v.ProbeError("Attack/public labels overlap; review stopped.")
        print("Read-only rule-context review UTC:", started.isoformat())
        print("No live-host event contents are retrieved. Groups are context, not verdicts.\n", flush=True)
        for path, raw, spec, eql, query, scope, opportunity, eligible in suite:
            matched_ids = snapshot.ids(v.both(attack, query))
            union = {"bool": {"should": [opportunity, query], "minimum_should_match": 1}}
            attack_rows = get_records(snapshot, v.both(attack, no_host, union), "attack-sample", v)
            public_rows = get_records(snapshot, v.both(public, no_host, query), "benign-corpus", v)
            entry = {"rule": path.name, "id": raw["id"],
                     "rule_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                     "public_matches": len(public_rows), "public_groups": [], "attack_groups": []}
            counts = Counter()
            for hit in public_rows:
                source = hit["_source"]
                safe = {"corpus": public_label(field(source, "fields.corpus")),
                        "file": public_label(field(source, "fields.corpus_file"), ".evtx"),
                        **features(path.stem, source)}
                counts[json.dumps(safe, sort_keys=True)] += 1
            entry["public_groups"] = [dict(json.loads(key), events=count) for key, count in sorted(counts.items())]
            counts = Counter()
            for hit in attack_rows:
                source = hit["_source"]
                safe = {"tactic": public_label(field(source, "fields.sample_tactic")),
                        "file": public_label(field(source, "fields.sample_file"), ".evtx"),
                        "rule_matched": (hit["_index"], hit["_id"]) in matched_ids,
                        **features(path.stem, source)}
                counts[json.dumps(safe, sort_keys=True)] += 1
            entry["attack_groups"] = [dict(json.loads(key), events=count) for key, count in sorted(counts.items())]
            if sum(row["events"] for row in entry["attack_groups"] if row["rule_matched"]) != len(matched_ids):
                raise v.ProbeError("Attack match/context reconciliation failed.")
            report["rules"].append(entry)
            print(spec["label"] + ": public matches=" + str(len(public_rows)))
            for group in entry["public_groups"]:
                print("  Public:", json.dumps(group, sort_keys=True))
            if not public_rows:
                print("  No public matches; consult eligible telemetry counts before judging specificity.")
            unmatched = [group for group in entry["attack_groups"] if not group["rule_matched"]]
            for group in unmatched:
                print("  Recorded precursor outside rule:", json.dumps(group, sort_keys=True))
            print("  Matched attack context groups saved:", sum(group["rule_matched"] for group in entry["attack_groups"]))
            print(flush=True)
        report["status"] = "review_complete"
    finally:
        try:
            snapshot.close()
        except v.ProbeError:
            print("PIT cleanup unavailable; the read snapshot expires automatically.", file=sys.stderr)
    directory = v.ROOT / "coverage/reviews" / started.strftime("%Y%m%d-%H%M%S")
    directory.mkdir(parents=True, exist_ok=False)
    v.atomic_json(directory / "context.json", report)
    print("CONTEXT REVIEW COMPLETE. No rules or indexed documents changed.")
    print("Sanitized review:", directory / "context.json")
    print("No full paths, commands, registry values, event messages, credentials, or live-host contents printed/saved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-check", action="store_true")
    args = parser.parse_args()
    module_path = Path(__file__).with_name("validate-rules.py")
    if not module_path.is_file():
        raise RuntimeError("Install beside scripts/validate-rules.py in the project.")
    spec = importlib.util.spec_from_file_location("soc_validator", module_path)
    v = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v)
    for name, version in {"pySigma": "1.5.1", "pySigma-backend-elasticsearch": "2.1.1"}.items():
        if importlib.metadata.version(name) != version:
            raise v.ProbeError("Tool version differs from the tested version: " + name)
    suite = v.load_suite()
    if args.offline_check:
        print("Six rule queries compiled; context classifiers ready. No Elasticsearch connection opened.")
        return
    review(v, suite)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted; read-only review can be rerun.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("STOPPED: Dependency, label, query, or response check failed; raw details withheld.", file=sys.stderr)
        sys.exit(1)
