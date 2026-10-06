# First measurement and context review

Evidence: exact-count/EQL validation started at 2026-10-05T18:30:23Z;
read-only context review started at 2026-10-05T18:39:57Z. Metrics below are
from the original six rule hashes. They are pre-tuning numbers. The run after
the two changes below is reported in [RESULTS.md](../coverage/RESULTS.md).

## Original measured results

| Rule | Attack events | Live-host events | Win10 baseline events | Win11 baseline events | Attack files matched |
| --- | ---: | ---: | ---: | ---: | ---: |
| LSASS selected read masks | 24 | 0 | 0 | 86 | 12 |
| Encoded PowerShell | 1 | 0 | 0 | 0 | 1 |
| Run-key suspicious value | 4 | 0 | 0 | 2 | 4 |
| Schtasks creation | 5 | 0 | 0 | 1 | 4 |
| Windows log clearing | 26 | 0 | 1 | 0 | 26 |
| WMI consumer binding | 5 | 0 | 0 | 0 | 3 |

Corpus snapshot: 37,364 attack, 100,790 live-host, 34,719 Win10 and
1,758,047 Win11 events. All 24 rule/corpus EQL document-ID comparisons
matched the exact DSL result sets. Counts are events, not incidents.
The public baseline results assume the datasets represent benign activity;
individual event intent was not independently established.

## LSASS: two supported mask additions, no basename exclusions

The 86 public matches were associated with msiexec.exe (55),
dropboxupdate.exe (14), mrt.exe (9), dropbox.exe (2), csrss.exe (2),
wininit.exe (2), officeclicktorun.exe (1), and wmiprvse.exe (1).
Access masks were 0x1410 (32 events) and 0x1fffff (54 events).
These names and location classes suggest routine activity in this public
baseline, but do not authenticate the files or prove harmless execution.
No executable-name exclusions are introduced.

Two attack records were outside the original selected mask list:

- Credential Access / CA_sysmon_hashdump_cmd_meterpreter.evtx:
  voice_mail.msg.exe, mask 0x1f1fff, one event.
- Privilege Escalation / sysmon_privesc_from_admin_to_system_handle_inheritance.evtx:
  python.exe, mask 0x101ffb, one event.

Both masks include PROCESS_VM_READ (bit 0x0010), so both are added to the
selected list. Two ppldump.exe events with mask 0x1000 remain outside the
rule: this mask denotes PROCESS_QUERY_LIMITED_INFORMATION and lacks the
memory-read bit. The sample also has other events matching the original
rule. Requested/granted access is an indicator; no successful credential
dump is established by this rule.

This is enumeration tuned with observed recorded samples, not an exhaustive
bitwise test. The same attack dataset informed this change, so the rerun is
regression/coverage measurement, not an independent holdout evaluation.
Generalization to unseen masks or software remains untested.

## Schtasks: include XML-based creation

The public match was schtasks.exe launched with TeamViewer executable
context. That is compatible with legitimate remote-management installation
or maintenance, but context here does not independently establish intent.
Keep this match visible; it is a task-creation behavior rule.

Two recorded creation events used `/create` and `/xml` without `/tr`:

- AutomatedTestingTools / rundll32_cmd_schtask.evtx: one event.
- Privilege Escalation / sysmon_1_11_exec_as_system_via_schedtask.evtx: one event.

Microsoft documents XML-based task registration. Extend the condition to
`/create AND (/tr OR /xml)` using the same surrounding-space matching.
Task `/run`, `/delete`, `/change`, and `/query` remain outside this
creation rule. XML contents and the resulting task action are not parsed.
API-based creation and alternate command syntax can still be missed.

## Other rules: retain scope and document tradeoffs

Encoded PowerShell: all 15 unmatched recorded PowerShell process starts
lacked the recognized encoded-command switch tokens in this review. They
are outside the rule's intended behavior, rather than evidence that the
encoded-command predicate failed. This rule does not claim to detect all
malicious PowerShell execution. There were only eight PowerShell starts in
the public Win11 candidate set and none in Win10/live-host candidate sets;
zero matches is a limited specificity test.

Run-key suspicious value: the two public matches were RunOnce activity
with installer-like context (cmd.exe and a Python installer reference),
written by target.exe in AppData/Temp. This is plausible legitimate activity,
not verified benign intent. Keep both visible. Three unmatched recorded
writes referenced atomicredteam.exe, taskhost.exe, or tendyron.exe without
the selected script-host/user-writable-path indicators. Two additional
opportunity files had no rule match. These are documented coverage limits;
we do not broaden the rule into every Run-key write or exclude RunOnce.

Log clearing: the Win10 match was System event 104 from
Microsoft-Windows-Eventlog. Clearing a log can be administrative. Of the
26 matching attack files, only two are explicitly named for log clearing:
DE_104_system_log_cleared.evtx and DE_1102_security_log_cleared.evtx.
Other matches may reflect setup or adjacent activity. Filename context is
not a technique ground-truth review. Do not report 26 true malicious
log-clearing cases or 100% technique recall.

WMI binding: five recorded events in three files matched. None of the
baseline corpora had eligible Sysmon 21 events, so benign specificity is
untested. Absence of matches does not establish a zero-false-positive rule.

## Follow-up

Both changes were re-measured in the second run, and the before/after figures
are preserved in the results. Source-file technique labels have not been
independently reviewed, so no technique-coverage claim is made. All rules
remain experimental.

## Primary references

- Microsoft process access rights:
  https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
- Microsoft Schtasks syntax and XML registration:
  https://learn.microsoft.com/en-us/windows/win32/taskschd/schtasks
- MITRE ATT&CK LSASS Memory:
  https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK Scheduled Task:
  https://attack.mitre.org/techniques/T1053/005/

Current v19 log-clearing mapping is T1685.005 (Defense Impairment);
historical T1070.001 is a crosswalk, not the current mapping used by this
ruleset. Historical recorded lab simulations and two client baselines do
not establish enterprise or production readiness.
