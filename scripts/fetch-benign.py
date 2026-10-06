#!/usr/bin/env python3
"""Fetch pinned evtx-baseline archives and extract only recorded EVTX logs.

Run in WSL with Python 3.12. Does not run archive contents, alter services,
read credentials, or replay logs. Raw logs stay outside the project folder.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone


RELEASE = "v0.8.5"
SOURCE = "https://github.com/NextronSystems/evtx-baseline"
ASSETS = {
    "win10-client": "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e",
    "win11-client": "6caab8391ac3cf7135e2fd5f545c7b116a2b445ec061f83d05873f8081ff0202",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url, destination, expected):
    if destination.exists():
        if sha256(destination) == expected:
            print(f"Reusing verified archive: {destination.name}", flush=True)
            return
        raise RuntimeError(f"Existing archive has a different hash: {destination.name}; not overwritten.")
    partial = destination.with_name(destination.name + ".part")
    for attempt in range(1, 4):
        print(f"Downloading {destination.name} (attempt {attempt}/3)", flush=True)
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "soc-lab-benign-fetch/1.0"})
            received = 0
            last_report = 0
            with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    received += len(chunk)
                    if received - last_report >= 20 * 1024 * 1024:
                        print(f"  Received {received / 1024 / 1024:.0f} MiB", flush=True)
                        last_report = received
            if sha256(partial) != expected:
                raise RuntimeError(f"SHA-256 mismatch for {destination.name}; extraction refused.")
            partial.rename(destination)
            print(f"SHA-256 verified: {destination.name}", flush=True)
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            if attempt == 3:
                raise RuntimeError(f"Download failed for {destination.name}: {type(error).__name__}") from None
            print("  Network/download error; retrying.", flush=True)


def extract(archive, destination, expected):
    marker = destination / ".extraction-complete.json"
    if destination.exists():
        if marker.is_file() and json.loads(marker.read_text())["archive_sha256"] == expected:
            print(f"Reusing completed extraction: {destination.name}", flush=True)
            return
        raise RuntimeError(f"Existing folder lacks the expected completion marker: {destination.name}; not overwritten.")
    stage = destination.with_name(destination.name + ".extracting")
    if stage.exists():
        raise RuntimeError(f"Incomplete staging folder exists: {stage.name}; report this before continuing.")
    stage.mkdir()
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = [member for member in bundle.getmembers()
                       if member.isfile() and Path(member.name).suffix.lower() == ".evtx"]
            if not members:
                raise RuntimeError(f"No EVTX files in {archive.name}.")
            # Python's data filter rejects traversal and unsafe archive paths.
            bundle.extractall(stage, members=members, filter="data")
        files = sorted(p for p in stage.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx")
        if len(files) != len(members):
            raise RuntimeError(f"EVTX member/file count mismatch in {archive.name}.")
        marker_data = {"archive_sha256": expected, "evtx_files": len(files)}
        (stage / marker.name).write_text(json.dumps(marker_data, indent=2) + "\n")
        stage.rename(destination)
    except Exception:
        # Remove only this invocation's newly created temporary extraction tree.
        shutil.rmtree(stage)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/mnt/c/soc-lab/benign-corpus"))
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or later is required.")
    root = args.root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    archives = root / "archives"
    archives.mkdir(exist_ok=True)
    manifest = {"source_repository": SOURCE, "source_release": RELEASE,
                "upstream_repository_license": "Apache-2.0",
                "prepared_at_utc": datetime.now(timezone.utc).isoformat(), "corpora": []}
    for name, expected in ASSETS.items():
        url = f"{SOURCE}/releases/download/{RELEASE}/{name}.tgz"
        archive = archives / f"{name}.tgz"
        download(url, archive, expected)
        destination = root / name
        extract(archive, destination, expected)
        files = sorted(p for p in destination.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx")
        size = sum(p.stat().st_size for p in files)
        print(f"{name}: {len(files)} EVTX files | {size / 1024 / 1024:.1f} MiB extracted", flush=True)
        manifest["corpora"].append({"name": name, "archive": archive.name,
                                  "download_url": url, "archive_sha256": expected,
                                  "evtx_files": len(files), "evtx_bytes": size})
    manifest_path = root / "source-manifest.json"
    temp = root / "source-manifest.json.tmp"
    temp.write_text(json.dumps(manifest, indent=2) + "\n")
    os.replace(temp, manifest_path)
    print(f"\nSource metadata saved: {manifest_path}")
    print("PREPARATION COMPLETE: both archives verified; only EVTX data was extracted.")
    print("No log replay was performed. Elasticsearch public-corpus counts remain unchanged.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, tarfile.TarError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted. Completed archives are reusable; partial downloads will restart.", file=sys.stderr)
        sys.exit(130)
