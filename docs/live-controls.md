# Live positive controls and collection limits

The measured results in this repository come from recorded and public logs.
This page covers a separate question: does a behavior performed on the live
host travel all the way from Sysmon, through Winlogbeat and Elasticsearch, to
a match by the committed EQL query? It was tested after the measured snapshot
(2026-10-05 18:45:48 UTC) and is new evidence, not part of that snapshot.

## Controls

`scripts/live-positive-controls.ps1` performs four harmless administrative
actions and undoes each one immediately. No attack tool runs and no real log
is cleared. `scripts/check-live-controls.py` then runs the queries in
`converted/` against the live-host corpus for the same time window and prints
counts only.

| Control | Rule | Matching events per run |
| --- | --- | ---: |
| `schtasks /create ... /tr`, then delete the task | Schtasks creation | 1 |
| HKCU Run value containing `cmd.exe`, then delete it | Run-key suspicious value | 1 |
| Create a throwaway event log, clear it, remove it | Windows log clearing | 2 |
| `powershell.exe -EncodedCommand` that prints one word | Encoded PowerShell | 0 |

The controls ran twice, starting 2026-10-05 19:44:08 UTC and 19:45:33 UTC,
with the same result each time. Log clearing produced two System 104 events
per run. LSASS access and WMI event subscriptions were deliberately not
exercised: producing them on a daily-use machine means credential-access-like
or persistence-like activity.

Three of the four exercised rules therefore have end-to-end live evidence.
The control events remain in the live-host corpus from 19:44 UTC onward. Any
later live-host matches from those runs are positive controls, not baseline
noise. The measured snapshot predates them.

## The PowerShell collection gap

The encoded PowerShell control was not detected because the event never
existed. Reading the local Sysmon log directly, before any change:

- 105 process-creation events were recorded in the preceding 90 minutes.
- None had `powershell.exe` as its image, although PowerShell had been started
  several times in that window, including by the control itself.

A later local probe gave the same picture. Starts of `whoami.exe`, `cmd.exe`,
`where.exe`, and `schtasks.exe` were each recorded once, labeled by collection
rules from the Sysmon configuration. Three differently flagged
`powershell.exe` starts, and one `hostname.exe` start, were not recorded.

This is a collection gap on this host, upstream of Winlogbeat, Elasticsearch,
field mapping, and the Sigma rule. The rule's logic is supported by one
recorded sample and by offline tests, but it has no live evidence here. It
also means the live-host zero for this rule in the measured results says
nothing about noise: no PowerShell start was ever available to it.

### What was tried, and what is still unknown

- A lab copy of the Sysmon configuration with added include conditions for
  PowerShell starts was loaded twice (about 19:56 and 20:13 UTC, as reported
  by the script, not read from a Sysmon configuration-change event). PowerShell
  starts were still not recorded. `whoami.exe` was recorded before and after.
- Sysmon gives exclusions precedence over inclusions, so an exclusion that
  matches these starts is the leading explanation. None has been identified.
  A text search of the process-creation rules found no exclusion that names
  PowerShell, but an exclusion can match on other properties.
- Sysmon's printed configuration listed one include section and one exclude
  section for process creation, while the configuration file has 45 and 25
  blocks. Events were recorded under collection-rule names that the listing
  did not show, so that listing is not a complete inventory of active rules.
- After these tests the host was returned to the original configuration.
  The lab copy is not part of this release and was never the measured
  configuration.

### Limits of these checks

- The local probe matched events by executable name within a short window. It
  did not match the launched process ID, check child exit codes, or separate
  a query error from an empty result.
- Only process creation was probed. Nothing here establishes which other
  event types are complete on this host.
- The collection-rule names in Sysmon events are labels from the collector
  configuration. They are not Sigma rule IDs or alerts.

## Collector configuration

| Item | Value |
| --- | --- |
| Sysmon | 15.22 (Sysmon64), schema 4.91 |
| Configuration | sysmon-modular default `sysmonconfig.xml`, downloaded 2026-10-05 |
| SHA-256 of that file | `F115AAC5770DAE468E5CFB48C58A8B6E37588208A31F1B746812C534577A244B` |
| Installed | 2026-10-05, before the measured runs |

The hash was taken later the same day from the file used at installation.
The configuration decides which live events exist at all, so live-host
results in this repository describe this collector configuration only.

## Next steps

1. Review every process-creation exclusion in the configuration, including
   compound rules and their AND/OR relations, against a controlled PowerShell
   start.
2. Repeat the control with an explicit executable path and a retained process
   ID, and poll for its Sysmon event over a bounded interval.
3. Do broad collector comparisons in a disposable VM, not on a daily-use host.
4. Record any collector change and its measurements as new evidence, without
   altering the published snapshot.
