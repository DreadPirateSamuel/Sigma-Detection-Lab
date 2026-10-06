# Reproduction guide

## Route 1: offline conversion and evidence checks

Use Python 3.12. From the release root, activate the existing lab virtualenv
or create a project virtualenv and install `requirements.txt`. The package
versions were tested as a set; do not silently substitute a newer backend.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 scripts/check-project.py
```

No datasets, real password, Elastic connection, or Windows changes are needed.
The first `sigma check` on a machine downloads MITRE ATT&CK and D3FEND
reference data; later runs use the local cache.
Synthetic fixtures stay offline; a request-handling test opens a temporary
localhost HTTP stub with dummy credentials. It does not contact port 9200.
The published measured numbers come from the evidence JSON, not fixtures.

## Route 2: rerun against the existing measured lab

The release folder can sit beside `home-soc-detections` and
`elastic-start-local`. In WSL Ubuntu, reuse the existing lab environment:

```bash
source ../home-soc-detections/.venv/bin/activate
source ../elastic-start-local/.env
ES="http://localhost:9200" ES_LOCAL_PASSWORD="$ES_LOCAL_PASSWORD" \
  python3 scripts/validate-rules.py
```

The password is passed through the environment; `.env` is outside this
repository. Do not print it or copy the Elastic config into the release.
Validation writes `coverage/runs/<UTC>/results.json` and converted queries.
Expected status: MEASUREMENT COMPLETE with 24 MATCH checks for these corpora.
Host counts may grow; drift is explicitly flagged if the EQL set differs.

To repeat the recorded-context review, use the same environment:

```bash
ES="http://localhost:9200" ES_LOCAL_PASSWORD="$ES_LOCAL_PASSWORD" \
  python3 scripts/review-rule-context.py
```

Only recorded attack/public source fields are retrieved, then reduced to
public file labels, basenames, masks, and fixed feature flags. Full values
remain in memory. No live-host event contents are retrieved. This is read-only
for indexed documents; timestamped local reports are written.

## Required ingest contract

All searches use `winlogbeat-*`; backup indices must stay outside it.
Corpuses must be disjoint by tag:

| Corpus | Tag | Required source labels |
| --- | --- | --- |
| Recorded attack | attack-sample | fields.sample_tactic, fields.sample_file |
| Private host | baseline | no public source labels required |
| Public Win10 | benign-corpus | fields.corpus=win10-client, fields.corpus_file, fields.dataset_release=v0.8.5 |
| Public Win11 | benign-corpus | fields.corpus=win11-client, fields.corpus_file, fields.dataset_release=v0.8.5 |

The runner checks required searchable keyword fields and label aggregation
compatibility. Expected fields include event.code, winlog.channel,
process.executable, process.command_line, registry.path, registry.data.strings,
winlog.event_data.TargetImage, and winlog.event_data.GrantedAccess. Required
field presence is measured per rule/corpus; a global mapping alone is not
evidence that every corpus has useful data.

## Fresh-lab preparation: partial automation, verify each stage

This release does not provision Windows, Docker, Sysmon, Winlogbeat, or
Elastic, nor reproduce the original attack replay launcher. A fresh lab needs
those components configured locally and an attack importer respecting the
contract above. Pin the dataset commit; ingest recorded logs rather than
executing the referenced attacks. Exact live-host counts/configuration will
differ. No full fresh-install equivalence claim is made.

Included public baseline helpers can reproduce the fetch/prepare/replay
workflow in an equivalent WSL/Windows layout:

1. `python3 scripts/fetch-benign.py` downloads and hash-verifies the pinned
   two archives, extracting only EVTX under `C:\soc-lab\benign-corpus`.
2. `python3 scripts/prepare-benign-replay.py` creates private batch configs
   under `C:\soc-lab\benign-replay`, reusing the existing localhost
   Winlogbeat output settings. It expects a literal local password in that
   private live config and stores it privately outside the repository.
3. Administrator PowerShell runs:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\soc-lab\benign-replay\replay-benign.ps1'`.
   This ingests recorded logs into the lab. It does not change the live service.
4. Run `audit-corpora.py` and `diagnose-normalization.py` with the same
   ES/password environment. They report counts/metadata and simulate
   normalization; indexed documents remain unchanged.

Do not rerun successful replays with fresh state directories: that can create
duplicates. Preparation retains an existing replay plan/state. Confirm the
configured routing pipeline actually ran by checking ECS field availability,
not merely pipeline existence or a config setting.

`repair-public-sysmon.py` defaults to simulation/checks. Its explicit `--apply`
mode backs up and changes selected public Sysmon documents, writing private
receipts under `C:\soc-lab\normalization`. Use it only when its verified
scope/plan matches a normalization problem; it is not an offline check or a
default step for an already repaired lab. The original routing bypass has
not been fixed at its source.

## Preservation and publication

Preserve initial/final evidence and current rule hashes. Fresh runs are new
snapshots, not replacements for the published measurement. Source datasets,
credentials, configs, replay state/logs, normalization receipts, and Elastic
backups stay local and outside Git.

## Live positive controls

On the monitored Windows host, Administrator PowerShell runs
`scripts\live-positive-controls.ps1`. It creates and removes a scheduled task,
a Run value, and a throwaway event log, and starts PowerShell once with an
encoded command that prints one word. After a minute, WSL runs
`scripts/check-live-controls.py --since <printed UTC start>` with the same
ES/password environment. It is read-only and prints counts.

In the measured lab three controls were detected and the encoded PowerShell
control was not; see [live-controls.md](live-controls.md). A different
collector configuration can give a different result. The control events stay
in the live-host corpus, so later live-host matches from those runs are
positive controls, not baseline noise.
