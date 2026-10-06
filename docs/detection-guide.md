# Rule logic, telemetry, and investigation guide

All six rules are experimental behavior indicators. Counts below describe
the final 2026-10-05 snapshot. None alone proves compromise. Generic Sigma
fields use `ecs_windows` plus `lab/ecs-winlogbeat-local.yml` in this lab.

## LSASS selected memory-read masks — T1003.001

**Logic:** Sysmon 10, TargetImage ending in `\lsass.exe`, and one of nine
selected GrantedAccess values. Every selected mask includes bit 0x0010
(PROCESS_VM_READ). This is enumeration, not a general bitwise predicate.
Query-only 0x1000 is excluded.

**Required telemetry:** Sysmon ProcessAccess events with TargetImage and
GrantedAccess, scoped to Microsoft-Windows-Sysmon/Operational. Source process,
parent, call trace, signature/path provenance, and surrounding events can
help investigation but are not required by this predicate.

**Measured:** 26 attack events in 14/14 precursor files; Win11 86 hits among
60,743 eligible ProcessAccess events and 166 LSASS precursor events. Host and
Win10 had no eligible ProcessAccess telemetry. 14/14 is file-level observable
coverage, not credential-dumping recall or 28/28 event coverage.

**Tradeoff/limits:** two observed masks were added after review. Other masks,
alternative credential access, missing capture, and bypassed sensors remain
gaps. Granted access does not prove a memory read succeeded. Baseline sources
included installers, updates, and Windows components; no basename allowlist
was added.

**Severity and live evidence:** the rule file is labeled `high`, but 86 of
166 baseline LSASS-access events matched on one public host. Treat it as a
hunting signal until exclusions are added and re-measured. It was not
exercised live.

**Triage:** establish source executable provenance, user/session, parent
lineage, expected tooling/maintenance, and whether correlated dump-file or
suspicious process activity exists. Treat a familiar name as a clue rather
than authentication. Avoid blanket exclusion of injectable service processes.

## Encoded PowerShell process — T1059.001

**Logic:** Sysmon 1 with powershell.exe/pwsh.exe image suffix and one of
` -e `, ` -ec `, ` -en `, ` -enc `, ` -enco `, ` -encodedcommand ` in the
command line. Matching is case-insensitive but uses selected surrounding
spaces; it is not a complete parser of all accepted PowerShell syntax.

**Required telemetry:** process.executable and process.command_line on Sysmon
process creation. Security 4688 and PowerShell script-block events are not
part of this local rule evaluation.

**Measured:** one attack event/file; zero public/host matches. There were
16 recorded PowerShell starts, eight public Win11 starts, and no Win10 or
host precursor starts. Other observed attack PowerShell starts lacked the
recognized encoded-command tokens; 1/12 precursor files is not a statement
that the rule missed eleven encoded-command cases.

**Tradeoff/limits:** administrative deployment/management can encode commands.
Renamed binaries, alternate hosting, other abbreviation forms, tabs/spacing,
and missing process capture can evade this predicate. Small benign candidate
sets limit the specificity conclusion.

**Live evidence:** none. The live host recorded no PowerShell process starts,
so a harmless encoded-command control produced no event for this rule to
evaluate. See [live-controls.md](live-controls.md).

**Triage:** review expected automation, signer/path provenance, parent, user,
and surrounding execution/network activity. If decoding is needed, do so
locally without executing the decoded content or publishing private commands.

## Suspicious Run/RunOnce value — T1547.001

**Logic:** Sysmon 13 with a selected CurrentVersion Run/RunOnce path and
string data referencing a selected script host/execution utility, AppData,
Temp, or those environment variables. The local pipeline maps generic
TargetObject/Details to registry.path/registry.data.strings.

**Measured:** four attack events in four of six precursor files; two Win11
matches among 473,803 eligible string-value events and 16 Run/RunOnce
precursors. Live host had 10,723 eligible registry events but zero selected
Run/RunOnce precursors. Win10 had no eligible Sysmon 13 telemetry.

**Tradeoff/limits:** public RunOnce matches had installer-like context; they
remain visible. Three recorded writes referenced other executable names
without the selected data features. Binary data, other autostart locations,
different payload paths, and hidden-value tricks can be missed.

**Live evidence:** a harmless HKCU Run value containing `cmd.exe` was
detected end to end, then removed.

**Triage:** establish value ownership and installer/change context, data
target provenance, user scope, and subsequent logon execution. AppData is
a signal, not proof of malicious intent; legitimate per-user software uses it.

## Schtasks creation — T1053.005

**Logic:** Sysmon 1 schtasks.exe with `/create` and either `/tr` or `/xml`,
using selected surrounding-space syntax. XML task content is not inspected.
`/run`, `/delete`, `/query`, and `/change` alone are outside this creation rule.

**Measured:** seven attack events in six of eight precursor files; nine
Win11 matches among 2,245 eligible process events and 33 Schtasks precursors.
Live host had 13 Schtasks precursors but zero selected creation matches.

**Tradeoff/limits:** XML support added two attack events and eight baseline
events. Baseline parent context was integrator.exe (4), officeclicktorun.exe
(4), and teamviewer_.exe (1). This is task-creation visibility; using these
names as blanket exclusions is not justified. API creation, task updates,
alternate syntax, and missing process collection remain gaps.

**Live evidence:** a harmless `schtasks /create ... /tr` control was detected
end to end, then deleted.

**Triage:** inspect the registered task/action locally, schedule, principal,
privilege level, parent provenance, maintenance context, and later executions.
Correlate task audit/operational logs if available; this lab's measurements
do not assume those other sources were collected.

## WMI consumer-filter binding — T1546.003

**Logic:** Sysmon 21, a binding component of a permanent WMI event subscription.
Event 19 filter and event 20 consumer records are useful context but are not
the rule predicate. The rule does not require a process command line.

**Measured:** five events in three precursor files. Host/Win10/Win11 had
zero eligible event-21 telemetry, so zero baseline matches provides no test
of benign WMI subscription specificity.

**Tradeoff/limits:** authorized monitoring/management can use permanent WMI
subscriptions. Missing Sysmon configuration, collection, or existing
subscriptions created before observation can hide the behavior.

**Live evidence:** not exercised on a daily-use machine.

**Triage:** connect filter and consumer identities, inspect the configured
trigger/action and owner locally, compare with expected management tooling,
and correlate execution. A binding event alone is not a maliciousness verdict.

## Windows log clearing — T1685.005

**Logic:** Security channel with event 1102 OR System channel with event 104.
System 104 can describe clearing of another channel; do not assume the
cleared target is always System. The predicate uses channel/code rather than
a provider-name restriction; the reviewed matches came from Windows Eventlog.

**Measured:** 26 attack events/files and one Win10 baseline event. Two attack
file names explicitly describe clearing logs; other matches may be setup or
adjacent activity. 26/26 precursor files is not 100% technique recall or
26 confirmed malicious clears. Other baseline scopes had no eligible events.

**Tradeoff/limits:** legitimate administrators clear logs. Context and capture
gaps matter; this rule does not detect every tool or method that disables
logging. Current ATT&CK v19 maps clearing to T1685.005 (Defense Impairment);
historical T1070.001 is retained only as a documentation crosswalk.

**Live evidence:** clearing a throwaway event log produced System 104
events that were detected end to end. No real log was cleared.

**Triage:** identify the affected channel, authorized maintenance/change
context, associated user/session, and surrounding suspicious activity. Avoid
publishing private usernames, messages, or host command lines.
