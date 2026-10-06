# Dataset provenance and collection observations

## Recorded lab simulations

- Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Pinned commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`.
- Indexed: 278 sample identities, 37,364 events; no missing sample labels
  reported by the audit. Identity is tactic plus filename.
- Tag: `attack-sample`; labels: `fields.sample_tactic`, `fields.sample_file`.
- Upstream license: GPL-3.0. Raw logs are not redistributed here.

Upstream folders describe broad tactics; they do not independently label
every event for every technique. Multi-technique files and setup events can
match several indicators. No technique-wide benchmark ground truth is
claimed. The original attack replay configuration/launcher is not included,
so recreating that ingest requires a verified importer with equivalent labels.

## Public client baselines

- Source: https://github.com/NextronSystems/evtx-baseline
- Release: `v0.8.5`; upstream license: Apache-2.0.
- `win10-client.tgz`: SHA-256
  `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`.
- `win11-client.tgz`: SHA-256
  `6caab8391ac3cf7135e2fd5f545c7b116a2b445ec061f83d05873f8081ff0202`.
- Prepared: 352 Win10 and 355 Win11 EVTX files; 707 total in 23 batches.
- Indexed: 34,719 Win10 and 1,758,047 Win11 events; 1,792,766 total.
- Tag: `benign-corpus`; fields: `corpus` (win10-client/win11-client),
  `corpus_file` (relative source filename), `dataset_release` (v0.8.5).

The source describes software installation and user interaction. Treat its
benign intent as an evaluation assumption, not independent adjudication of
each match. Historical clients and a few public machines are not an enterprise
production baseline. No public server/AD baseline was included in these runs.

## Private live-host baseline

Tag: `baseline`. Final snapshot: 113,226 events; the initial run had 100,790.
The corpus grows. Reports preserve counts only; host identifiers, commands,
raw events, and credentials are absent from the release. No malicious test
tools were executed on the live host as part of this evaluation.

Collector: Sysmon 15.22 with the sysmon-modular default configuration as
downloaded on 2026-10-05 (file SHA-256
`F115AAC5770DAE468E5CFB48C58A8B6E37588208A31F1B746812C534577A244B`). Under it
the host recorded no PowerShell process starts and no eligible LSASS-access
events, so live-host zeros for those rules are not noise measurements.
From 19:44 UTC the corpus also contains events from harmless positive
controls; see [live-controls.md](live-controls.md). The measured snapshot
predates them.

## Reported replay and normalization checks

These observations summarize the terminal audits during the lab session;
they are not a bundled copy of private replay logs or repair receipts.

- 23/23 latest public replay completion markers had exit 0.
- Shutdown totals: 1,792,766 output acknowledgements; zero observed output
  dropped/failed/dead-letter/failure-store counts. Missing metric keys were
  treated as zero by the audit, so this is not a universal loss proof.
- Indexed totals matched acknowledgements. Corpus/file/release label checks
  reported no missing/overlapping unexpected labels.
- Distinct indexed file labels were 96/352 Win10 and 101/355 Win11.
  Empty EVTX files create no documents. Nonempty-file completeness has not
  been independently verified, so do not claim that all 707 files produced
  events or that every source record arrived.
- 427 warnings: 202 publisher/metadata, 79 event-data/template-parameter
  mismatches, 146 initially unclassified (renderer event ID 6117).
  Observed warning IDs differ from the selected six rule signals, but full
  impact remains unverified; the warnings are not declared harmless.
- Installed pipelines were present. Public Sysmon raw fields initially
  survived while selected ECS fields were absent. A sampled simulation of
  the routing pipeline added expected fields without observed failures.
- A verified local backup preserved 1,725,047 original public Sysmon docs.
  Repair reported 1,725,047 updates, zero failures/conflicts, unchanged public
  totals, zero remaining pending normalization, and zero Sysmon error.message.
  Backup indices use `soc-lab-backup-*`, outside `winlogbeat-*` detection scope.
- Final repaired availability: Sysmon 1 executable and command line 2,245/2,245;
  Sysmon 13 registry.path 473,878/473,878; string data 473,803/473,878.
  Non-string registry data is outside this rule's required string fields.

## Remaining limits

The original public routing-bypass cause remains unresolved. Non-Sysmon
normalization gaps may persist; the selected rules use Sysmon or scoped log
clearing codes. The live collector configuration is identified above; why it
records no PowerShell process starts is unresolved. Full source-file completeness, warning
impact, production fidelity, and independent technique recall are unmeasured.
These limits bound the conclusions rather than being concealed by zero hits.
