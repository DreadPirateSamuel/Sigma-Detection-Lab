#!/usr/bin/env python3
"""Offline check that the published tables equal the measured evidence.

Reads README.md and coverage/RESULTS.md and compares every result cell with
the final measurement JSON. Baseline cells use three notations, and each must
agree with the evidence:

  a number   hits, where the corpus contained the rule's precursor behavior
  0*         zero hits; eligible events existed but no precursor behavior
  n/a        zero hits; the corpus had no eligible events for the rule

Also checks corpus totals, the before/after tuning figures, and that no
document links to a file outside the release. No Elasticsearch access.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINAL = "coverage/runs/20261005-184548/results.json"
FIRST = "coverage/runs/20261005-183023/results.json"
DASH = "n/a"
LABELS = {"lsass": "lsass_selected_read_access", "powershell": "powershell_encoded_command",
          "run-key": "run_key_suspicious_value", "schtasks": "schtasks_create_task",
          "log clearing": "windows_event_log_cleared", "wmi": "wmi_consumer_filter_binding"}
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return condition


def stem_for(label):
    plain = re.sub(r"\[|\]\(.*?\)", "", label).lower()
    for key, stem in LABELS.items():
        if key in plain:
            return stem
    return None


def table_rows(text, heading):
    section = text.split(heading, 1)[1]
    rows = []
    for line in section.splitlines()[1:]:
        if line.startswith("## "):
            break
        if line.startswith("|") and not set(line) <= set("|-: "):
            rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows[1:]


def expected_cell(corpus, measured):
    hits = measured["hits"]
    if corpus == "attack":
        return str(hits)
    if measured["eligible_events"] == 0:
        return DASH
    if measured["opportunity_events"] == 0:
        return "0*"
    return str(hits)


def main():
    final = json.loads((ROOT / FINAL).read_text())
    first = json.loads((ROOT / FIRST).read_text())
    by_stem = {r["rule"][:-4]: r for r in final["rules"]}
    first_by_stem = {r["rule"][:-4]: r for r in first["rules"]}
    compared = 0
    kinds = {"number": 0, "0*": 0, DASH: 0}
    for name, heading in (("README.md", "## Final measured results"),
                          ("coverage/RESULTS.md", "## Matching events and observable-file coverage")):
        rows = table_rows((ROOT / name).read_text(), heading)
        check(len(rows) == 6, f"{name}: expected six result rows, found {len(rows)}")
        for row in rows:
            stem = stem_for(row[0])
            if not check(stem is not None, f"{name}: unrecognised rule label {row[0]}"):
                continue
            corpora = by_stem[stem]["corpora"]
            files = by_stem[stem]["attack_files"]
            for cell, corpus in zip(row[1:5], ("attack", "host", "win10", "win11")):
                want = expected_cell(corpus, corpora[corpus])
                check(cell.replace(",", "") == want,
                      f"{name}: {stem}/{corpus} shows '{cell}', evidence requires '{want}'")
                compared += 1
                if corpus != "attack" and name == "README.md":
                    kinds[want if want in kinds else "number"] += 1
            fraction = f"{files['covered_opportunity_files']}/{files['opportunity_files']}"
            check(row[5].replace(" ", "") == fraction, f"{name}: {stem} file fraction differs from evidence")
            compared += 1
    readme = " ".join((ROOT / "README.md").read_text().split())
    totals = final["corpus_totals"]
    for key in ("attack", "host", "win10", "win11"):
        check(f"{totals[key]:,}" in readme, f"README.md: corpus total for {key} not found")
        compared += 1
    check(f"{totals['win10'] + totals['win11']:,}" in readme, "README.md: public total not found")
    # The README's summary of how many baseline cells were actually exercised.
    exercised = kinds["number"]
    check(f"{exercised} of the 18 baseline cells" in readme,
          f"README.md: expected the statement '{exercised} of the 18 baseline cells'")
    check(f"{18 - exercised} of the 18 rule/baseline result cells" in readme,
          f"README.md: expected the statement '{18 - exercised} of the 18 rule/baseline result cells'")
    for stem in ("lsass_selected_read_access", "schtasks_create_task"):
        before, after = first_by_stem[stem]["corpora"], by_stem[stem]["corpora"]
        for corpus in ("attack", "win11"):
            wanted = f"{before[corpus]['hits']} \u2192 {after[corpus]['hits']}"
            check(wanted in readme, f"README.md: tuning figure '{wanted}' for {stem} not found")
            compared += 1
    listed = set(json.loads((ROOT / "release-files.json").read_text())["files"])
    links = 0
    for name in sorted(listed):
        if not name.endswith(".md"):
            continue
        text = (ROOT / name).read_text()
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("#"):
                continue
            resolved = (ROOT / name).parent.joinpath(target.split("#")[0]).resolve()
            relative = resolved.relative_to(ROOT).as_posix() if resolved.is_relative_to(ROOT) else None
            is_listed_dir = resolved.is_dir() and any(item.startswith(relative + "/") for item in listed)
            check(relative in listed or is_listed_dir, f"{name}: link to '{target}' is outside the release file list")
            links += 1
    if failures:
        print(f"FAILED: {len(failures)} check(s)", file=sys.stderr)
        for failure in failures:
            print("  -", failure, file=sys.stderr)
        sys.exit(1)
    print(f"Passed: {compared} published figures equal the final evidence "
          f"({kinds['number']} exercised baseline cells, {kinds['0*']} without precursor behavior, "
          f"{kinds[DASH]} without eligible events); {links} document links stay inside the release.")


if __name__ == "__main__":
    main()
