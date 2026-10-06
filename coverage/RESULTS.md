# Measured detection results

Source run: `runs/20261005-184548/results.json` (measurement_complete).
Context review: `reviews/20261005-184922/context.json` (review_complete).
Historical baseline run: `runs/20261005-183023/results.json`.
Current rule hashes reconcile with the final run and context review once
the measured `author` line is restored; that line was shortened afterwards.

## Snapshot event counts

| Corpus | Events | Source |
| --- | ---: | --- |
| Recorded lab simulations | 37,364 | 278 indexed EVTX sample identities |
| Live-host baseline | 113,226 | Windows host; changing corpus |
| Public Win10 baseline | 34,719 | evtx-baseline v0.8.5 |
| Public Win11 baseline | 1,758,047 | evtx-baseline v0.8.5 |

## Matching events and observable-file coverage

| Rule | Attack hits | Live-host hits | Win10 hits | Win11 hits | Matched/precursor files |
| --- | ---: | ---: | ---: | ---: | ---: |
| LSASS selected read masks | 26 | n/a | n/a | 86 | 14/14 |
| Encoded PowerShell | 1 | 0* | n/a | 0 | 1/12 |
| Run-key suspicious value | 4 | 0* | n/a | 2 | 4/6 |
| Schtasks creation | 7 | 0 | n/a | 9 | 6/8 |
| Windows log clearing | 26 | n/a | 1 | n/a | 26/26 |
| WMI consumer binding | 5 | n/a | n/a | n/a | 3/3 |

In the three baseline columns, `n/a` means the corpus had no eligible events
for the rule, and `0*` means eligible events existed but none showed the
precursor behavior. Both are zero hits in the evidence JSON, and neither is a
clean result. The eligibility table below gives the exact counts.

The denominator is a broader signal, not a set independently labeled for
an entire ATT&CK technique. File identity is tactic plus filename. A match
in a multi-technique file can concern adjacent activity or setup. No overall
recall, precision, specificity, or confirmed-malicious count is computed.

## Eligibility and precursor event counts

Eligible means the rule's event scope and required fields exist. Precursor
means the broader candidate condition matches. Eligibility alone does not
mean the relevant behavior occurred.

| Rule | Corpus | Eligible events | Precursor events | Hits per 100,000 corpus events |
| --- | --- | ---: | ---: | ---: |
| LSASS selected read masks | attack | 157 | 28 | 69.586 |
| LSASS selected read masks | host | 0 | 0 | 0.000 |
| LSASS selected read masks | win10 | 0 | 0 | 0.000 |
| LSASS selected read masks | win11 | 60,743 | 166 | 4.892 |
| Encoded PowerShell | attack | 1,491 | 16 | 2.676 |
| Encoded PowerShell | host | 220 | 0 | 0.000 |
| Encoded PowerShell | win10 | 0 | 0 | 0.000 |
| Encoded PowerShell | win11 | 2,245 | 8 | 0.000 |
| Run-key suspicious value | attack | 223 | 7 | 10.705 |
| Run-key suspicious value | host | 10,723 | 0 | 0.000 |
| Run-key suspicious value | win10 | 0 | 0 | 0.000 |
| Run-key suspicious value | win11 | 473,803 | 16 | 0.114 |
| Schtasks creation | attack | 1,491 | 11 | 18.735 |
| Schtasks creation | host | 220 | 13 | 0.000 |
| Schtasks creation | win10 | 0 | 0 | 0.000 |
| Schtasks creation | win11 | 2,245 | 33 | 0.512 |
| Windows log clearing | attack | 26 | 26 | 69.586 |
| Windows log clearing | host | 0 | 0 | 0.000 |
| Windows log clearing | win10 | 1 | 1 | 2.880 |
| Windows log clearing | win11 | 0 | 0 | 0.000 |
| WMI consumer binding | attack | 5 | 5 | 13.382 |
| WMI consumer binding | host | 0 | 0 | 0.000 |
| WMI consumer binding | win10 | 0 | 0 | 0.000 |
| WMI consumer binding | win11 | 0 | 0 | 0.000 |

Rates divide matching events by all corpus events, not by eligible events,
users, machines, days, or incidents. They are volume normalization only.
In particular, neither client baseline nor host baseline contains eligible
WMI binding events; the zero-hit result is inconclusive for benign WMI use.
Live-host PowerShell candidate count was zero despite 220 Sysmon process
starts overall; collection filters and behavior representation matter.

## Tuning comparison on static corpora

| Rule | Attack before → after | Win10 before → after | Win11 before → after | Matched files before → after |
| --- | ---: | ---: | ---: | ---: |
| LSASS selected read masks | 24 → 26 | 0 → 0 | 86 → 86 | 12 → 14 |
| Encoded PowerShell | 1 → 1 | 0 → 0 | 0 → 0 | 1 → 1 |
| Run-key suspicious value | 4 → 4 | 0 → 0 | 2 → 2 | 4 → 4 |
| Schtasks creation | 5 → 7 | 0 → 0 | 1 → 9 | 4 → 6 |
| Windows log clearing | 26 → 26 | 1 → 1 | 0 → 0 | 26 → 26 |
| WMI consumer binding | 5 → 5 | 0 → 0 | 0 → 0 | 3 → 3 |

Both snapshots passed all 24 EQL comparisons. Static attack/public totals
were unchanged. Host totals changed 100,790 → 113,226, so host counts are
reported separately and do not form a fixed holdout evaluation. The attack
data informed tuning; the after run is regression measurement on the same
data, not evidence of generalization to an unseen attack test set.

## Live positive controls

Four harmless live controls were run after this snapshot. Scheduled-task
creation, the Run-key value, and log clearing were detected end to end. The
encoded PowerShell control was not, because the live host recorded no
PowerShell process starts. See [live controls](../docs/live-controls.md).
These are separate from the counts above.

## Evidence files

The full reports preserve individual matching/precursor file labels and
rule hashes. `initial-rules/` preserves the first-run rules; only the `author` line differs
from the measured bytes.
`file-coverage.json` lists every indexed attack file and the matching rule
IDs, including files matching none. `summary.json` includes measured data
and evidence hashes. `converted/` contains current EQL and exact-count DSL;
conversion was regenerated offline from the unchanged measured rules and
provided pipeline using the pinned pySigma versions.
