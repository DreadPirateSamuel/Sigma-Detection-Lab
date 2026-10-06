# Detection engineering with separate attack and baseline corpora

## Objective and delivered behavior

Build a small Windows ruleset that can be explained, converted, and tested
with visible limitations. The lab ingests live Windows/Sysmon telemetry and
recorded lab simulations into Elasticsearch. Six generic Windows Sigma
rules are converted to EQL through ECS and a local compatibility pipeline.
The runner evaluates each rule against four separate corpora and preserves
exact event counts, source-file labels, and rule hashes.

These are search-based detections and validation tooling. Scheduled Elastic
alert deployment, notification delivery, and response automation are not
implemented by this release.

## Lab and data

The measured setup used Windows with Sysmon 15.22 and Winlogbeat 9.5.4;
Ubuntu 24.04.2 under WSL2 with Python 3.12.3; and Elasticsearch/Kibana 9.5.4
in Docker. The stack is local-testing only: HTTP localhost, with the exposed
9200/5601 ports bound to 127.0.0.1. Private replay configs and state stay
outside the public project.

The final snapshot contained 37,364 recorded attack events from 278 sample
files, 113,226 live-host events, 34,719 public Win10 events, and 1,758,047
public Win11 events. Tags and source labels distinguish the corpora. Dataset
details, hashes, warning counts, and completeness limits are documented in
[datasets.md](datasets.md). No exploit or malware sample was executed to
produce these measurements; recorded logs were replayed.

## Normalize before drawing conclusions

The public replay acknowledged 1,792,766 events with no observed output
drops, but public Sysmon process/registry events initially lacked ECS fields.
Raw fields remained available. Simulating the installed routing pipeline
on sampled records produced the missing ECS fields without simulated
failures. The lab then backed up 1,725,047 public Sysmon documents and
normalized the selected originals through that installed pipeline.

Reported verification showed zero repair failures/conflicts, unchanged
public totals, all 2,245 Sysmon process records with executable/command
fields, and all 473,878 registry records with registry.path. String registry
data existed on 473,803 records; other data types are outside the string
rule's eligibility. These repair observations come from the terminal audit,
not a claim that the full pipeline root cause was resolved. The original
routing bypass remains unexplained.

This mattered because a zero-hit query against absent normalized fields
would have looked quiet while measuring an ingestion gap. Eligibility
counts now make that limitation visible alongside every detection count.

## Conversion and measurement method

Generic Sigma rules use fields such as EventID, Image, CommandLine,
TargetObject, and Details. `ecs_windows` maps standard fields; the local
pipeline adds this lab's Sysmon channel scope, uses the actual executable
fields instead of absent `.caseless` fields, and maps registry Details to
registry.data.strings. This avoids rewriting query text with string hacks.

Exact-count DSL and EQL conversion are derived from the same processed
pySigma condition tree. The DSL adapter supports the types these rules
use and rejects unsupported conditions, including general negation whose
missing-field behavior could differ from EQL. Wildcard paths preserve
literal Windows separators and escaped wildcard characters.

All DSL measurements in a run share one Elasticsearch point-in-time
snapshot. EQL cannot share that snapshot; below 10,000 matches, the runner
compares complete index/document-ID sets rather than counts alone. Static
corpus mismatch stops validation; changing-host mismatch is flagged as
drift/mismatch. Partial results and truncated exact counts are rejected.
The final run had MATCH for all 24 rule/corpus comparisons.

## Tuning with explicit tradeoffs

The first LSASS rule matched 24 recorded attack events in 12 files and 86
Win11 baseline events. Context review identified two additional masks,
0x101ffb and 0x1f1fff, each including the PROCESS_VM_READ bit. Adding them
raised the attack result to 26 events in 14 files; Win11 stayed at 86.
Query-only 0x1000 stayed excluded. Access rights are an indicator, not proof
of successful memory reads or credential extraction.

The original Schtasks rule required `/create` and `/tr`. Two recorded task
creation events instead used `/create` and `/xml`. Extending to either
action form raised attack matches from five to seven, and files from four
to six. Win11 baseline matches also rose from one to nine: four integrator.exe
parent events, four officeclicktorun.exe parent events, and one TeamViewer
context event. XML creation broadened useful behavior coverage and noise.

No executable-basename allowlists were added. Names and coarse location
classes cannot authenticate a binary or establish benign intent; excluding
installer/service names could also hide abuse through those processes.
The attack dataset informed tuning, so the after run measures regression
on that dataset rather than independent holdout performance.

## Interpreting coverage and benign matches

The file denominators are observable precursor files, not all files labeled
for an ATT&CK technique. For example, 14/14 LSASS precursor files contain at
least one selected-mask match, but two query-only events remain outside the
rule. The encoded PowerShell rule covers one of 12 files containing any
PowerShell start; the other observed starts lack its recognized encoded
switch. That does not make ordinary PowerShell starts false negatives for
this narrower rule.

Log clearing matched 26 files, many named for other scenarios. Some clears
may be setup or adjacent activity. Only two sample names explicitly concern
clearing logs; the corpus is not independently adjudicated into 26 malicious
clearing cases. WMI binding has five recorded matches in three files, but
no baseline eligible binding events, so its benign specificity is untested.

Baseline match counts assume the public dataset is benign. They are useful
noise observations; they are not formal FP probabilities. The reported
hits-per-100,000 value normalizes against all corpus events and is neither
an alert-per-day rate nor a unique incident count. The live-host baseline
does not represent enterprise activity or every candidate behavior.

## Delivered evidence and next engineering work

[coverage/RESULTS.md](../coverage/RESULTS.md) links the count reports, initial
rule bytes, context review, per-file coverage index, and converted queries.
The per-rule guide documents requirements and investigation questions.
Offline checks verify those links, hashes, counts, rule semantics, and
publication file boundaries. Measurements were produced locally by Samuel Yoder.

## Live positive controls

Recorded data shows that a query matches stored events. It does not show that
the live host produces those events. After the snapshot, four harmless
controls were run on the live host and checked with the committed queries.
Scheduled-task creation, a Run-key value, and log clearing were detected end
to end. An encoded PowerShell start was not: reading the local Sysmon log
showed no process-creation event for `powershell.exe` at all, so the gap is in
collection, upstream of ingestion, field mapping, and the rule. Its cause is
unresolved, and [live-controls.md](live-controls.md) records what was tried.
The same finding shows that the live-host zero for that rule in the measured
results carried no information.

Future engineering includes independently labeled/held-out attack tests,
the PowerShell collection gap, exclusion support in the validation runner,
baseline WMI activity, fresh-lab ingest verification, root-cause analysis of
the routing bypass, field-aware production tuning, and scheduled alert
deployment with a separate operational evaluation.
