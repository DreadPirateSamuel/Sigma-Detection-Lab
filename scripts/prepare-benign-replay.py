#!/usr/bin/env python3
"""Prepare private Windows replay configs from existing local output settings.

Run in the project's WSL virtualenv (PyYAML). Public script contains no secret.
Generated configs, credentials, state and console logs stay outside the repo.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import urllib.parse
import yaml

CORPORA = {"win10-client": 352, "win11-client": 355}
BATCH_SIZE = 32
RELEASE = "v0.8.5"


def windows_path(path):
    parts = path.resolve().parts
    if len(parts) < 4 or parts[1:3] != ("mnt", "c"):
        raise RuntimeError("Expected paths on the Windows C: drive (/mnt/c).")
    return str(PureWindowsPath("C:/", *parts[3:]))


def write_json(path, data, private=False):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if private:
        os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/mnt/c/soc-lab/benign-corpus"))
    parser.add_argument("--replay-root", type=Path, default=Path("/mnt/c/soc-lab/benign-replay"))
    parser.add_argument("--live-config", type=Path, default=Path("/mnt/c/soc-lab/winlogbeat/winlogbeat.yml"))
    args = parser.parse_args()
    root, replay = args.root.resolve(), args.replay_root.resolve()
    live = yaml.safe_load(args.live_config.read_text(encoding="utf-8-sig"))
    output = live.get("output.elasticsearch")
    if not isinstance(output, dict):
        raise RuntimeError("Expected output.elasticsearch settings were not found.")
    output = dict(output)
    hosts = output.get("hosts", [])
    if not isinstance(hosts, list) or not hosts:
        raise RuntimeError("Expected a non-empty output.elasticsearch.hosts list.")
    for host in hosts:
        if urllib.parse.urlsplit(host).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise RuntimeError("Output must point to the localhost lab.")
    if not output.get("pipeline"):
        raise RuntimeError("Expected ECS routing pipeline setting was not found.")
    password = output.get("password")
    if not isinstance(password, str) or not password or "${" in password:
        raise RuntimeError("Expected a local literal password in the existing Winlogbeat output settings.")
    source = json.loads((root / "source-manifest.json").read_text())
    if source.get("source_release") != RELEASE:
        raise RuntimeError("Unexpected public dataset release.")
    collected = {}
    for corpus, expected in CORPORA.items():
        folder = root / corpus
        files = sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx")
        if len(files) != expected:
            raise RuntimeError(f"{corpus}: expected {expected} EVTX files; found {len(files)}.")
        collected[corpus] = files
    launcher_source = Path(__file__).with_name("replay-benign.ps1")
    if not launcher_source.is_file():
        raise RuntimeError("Companion replay-benign.ps1 is missing.")
    manifest_path = replay / "replay-manifest.json"
    if manifest_path.exists():
        print("Existing replay plan found. Retaining its configs, credentials and state.")
        print("Use the existing launcher; do not generate a fresh replay state path.")
        return
    replay.mkdir(parents=True, exist_ok=True)
    configs = replay / "configs"
    configs.mkdir(exist_ok=True)
    # Store the reused secret once, separately from all configs and public scripts.
    write_json(replay / "connection-secrets.json", {"password": password}, private=True)
    output["password"] = "${SOC_LAB_ES_PASSWORD}"
    output["bulk_max_size"] = 512
    output["worker"] = 1
    batches = []
    for corpus, files in collected.items():
        folder = root / corpus
        for offset in range(0, len(files), BATCH_SIZE):
            batch_id = f"{corpus}-{offset // BATCH_SIZE + 1:03d}"
            entries = []
            for path in files[offset:offset + BATCH_SIZE]:
                relative = path.relative_to(folder).as_posix()
                identity = hashlib.sha256((corpus + "/" + relative).encode()).hexdigest()[:24]
                entries.append({"name": windows_path(path), "id": "benign-" + identity,
                                "no_more_events": "stop", "batch_read_size": 128,
                                "fields": {"corpus": corpus, "corpus_file": relative,
                                           "dataset_source": "evtx-baseline", "dataset_release": RELEASE}})
            state = replay / "state" / batch_id
            logs = replay / "logs" / batch_id
            state.mkdir(parents=True, exist_ok=True)
            logs.mkdir(parents=True, exist_ok=True)
            config = {
                "winlogbeat.event_logs": entries,
                "winlogbeat.registry_file": windows_path(state / ".winlogbeat.yml"),
                "winlogbeat.registry_flush": "0s", "winlogbeat.shutdown_timeout": "120s",
                "tags": ["benign-corpus", corpus],
                "processors": [{"fingerprint": {
                    "fields": ["fields.corpus", "fields.corpus_file", "fields.dataset_release", "winlog.record_id"],
                    "target_field": "@metadata._id", "method": "sha256", "ignore_missing": False}}],
                "output.elasticsearch": output,
                "logging.level": "info", "logging.to_files": False,
                "logging.to_stderr": True, "logging.metrics.enabled": True,
                "logging.metrics.period": "30s", "monitoring.enabled": False,
            }
            config_path = configs / (batch_id + ".yml")
            config_path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding="utf-8")
            batches.append({"id": batch_id, "corpus": corpus, "files": len(entries),
                            "config": windows_path(config_path), "state": windows_path(state),
                            "logs": windows_path(logs)})
    (replay / "replay-benign.ps1").write_bytes(launcher_source.read_bytes())
    write_json(manifest_path, {"dataset_release": RELEASE, "batch_size": BATCH_SIZE,
                              "files": sum(len(v) for v in collected.values()), "batches": batches})
    for corpus, files in collected.items():
        print(f"{corpus}: {len(files)} files prepared")
    print(f"Batches prepared: {len(batches)} (at most {BATCH_SIZE} files each)")
    print("Replay launcher: C:\\soc-lab\\benign-replay\\replay-benign.ps1")
    print("Existing localhost connection settings reused; credentials were not printed.")
    print("PREPARATION COMPLETE. No replay has started.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, yaml.YAMLError):
        # Parsing errors could contain fragments of credential-bearing YAML.
        print("ERROR: Replay preparation failed. Check the expected files and output settings; do not paste config contents.", file=sys.stderr)
        sys.exit(1)
