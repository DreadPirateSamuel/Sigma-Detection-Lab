#!/usr/bin/env python3
"""Confirm that the live positive controls were detected end to end.

Run in WSL after scripts/live-positive-controls.ps1. Read-only: it runs the
committed EQL queries in converted/ against the live-host corpus (tag
"baseline"), limited to a recent time window, and prints counts only. No event
contents are retrieved or printed.

A count of zero for a rule is a finding, not a script error: the event never
reached Elasticsearch in a form the rule can evaluate. Check the local Sysmon
log first; a later stage cannot detect an event that was never collected.

Usage
  ES_LOCAL_PASSWORD="$ES_LOCAL_PASSWORD" python3 scripts/check-live-controls.py \
      [--since 2026-10-05T19:44:08Z | --minutes 30]
"""
import argparse
import sys
from pathlib import Path

EXPECTED = [
    ("powershell_encoded_command", "PowerShell -EncodedCommand"),
    ("schtasks_create_task", "schtasks /create /tr"),
    ("run_key_suspicious_value", "Run value containing cmd.exe"),
    ("windows_event_log_cleared", "throwaway log cleared (System 104)"),
]
NOT_EXERCISED = ["lsass_selected_read_access", "wmi_consumer_filter_binding"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--since", help="UTC start time printed by live-positive-controls.ps1")
    parser.add_argument("--minutes", type=int, default=30, help="look-back window when --since is not given")
    args = parser.parse_args()
    release = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(release / "scripts"))
    from probe import Client, ProbeError  # the project's read-only localhost client

    start = args.since or f"now-{args.minutes}m"
    window = {"bool": {"filter": [{"term": {"tags": "baseline"}},
                                  {"range": {"@timestamp": {"gte": start}}}]}}
    try:
        client = Client()
        total = client.count(window)
        print(f"Live-host events since {start}: {total:,}")
        if total == 0:
            print("STOPPED: no live-host events in the window. Is Winlogbeat running and Elastic up?")
            sys.exit(1)
        print(f"\n{'Rule':30} {'Control':38} {'Hits':>5}  Result")
        missing = 0
        for stem, label in EXPECTED:
            query = (release / "converted" / (stem + ".eql")).read_text().strip()
            result = client.post("/winlogbeat-*/_eql/search?allow_partial_search_results=false"
                                 "&filter_path=hits.total,is_partial,is_running,timed_out,shard_failures,_shards",
                                 {"query": query, "filter": window, "size": 100})
            hits = result.get("hits", {}).get("total", {}).get("value", 0)
            verdict = "DETECTED" if hits >= 1 else "NOT SEEN"
            missing += hits < 1
            print(f"{stem:30} {label:38} {hits:>5}  {verdict}")
        print("\nNot exercised by design:", ", ".join(NOT_EXERCISED))
        if missing:
            print(f"\n{missing} control(s) NOT SEEN. Wait a minute and rerun once; if still missing, "
                  "that event type is not reaching Elasticsearch from this host.")
            sys.exit(1)
        print("\nALL FOUR LIVE CONTROLS DETECTED")
    except ProbeError as error:
        print("STOPPED:", error, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
