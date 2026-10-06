#!/usr/bin/env python3
"""Validate draft Sigma rules using read-only localhost Elasticsearch queries.

Saves query text, counts, hashes, and recorded attack-file labels only. Exact
DSL counts share one PIT snapshot. EQL parity checks use only index/doc IDs,
never event contents. Unsupported Sigma features and partial results fail.
"""
import argparse
import copy
import hashlib
import importlib.metadata
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.processing.pipeline import ProcessingPipeline
from sigma.types import SigmaString, SigmaNumber, SigmaBool, SigmaNull, SigmaExists, SpecialChars

from probe import Client, ProbeError, both

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 10000


def pipeline():
    return ecs_windows() + ProcessingPipeline.from_yaml((ROOT / "lab/ecs-winlogbeat-local.yml").read_text())


def dsl(node):
    """Limited exact-count adapter for the parsed, pipeline-processed Sigma AST.

    Strings use case-insensitive wildcard queries, including literals, to
    match EQL colon/like~ semantics. Escaped wildcard literals stay literal.
    """
    if isinstance(node, ConditionAND):
        return both(*(dsl(arg) for arg in node.args))
    if isinstance(node, ConditionOR):
        return {"bool": {"should": [dsl(arg) for arg in node.args], "minimum_should_match": 1}}
    if isinstance(node, ConditionNOT):
        inner = node.args[0]
        if isinstance(inner, ConditionFieldEqualsValueExpression) and isinstance(inner.value, SigmaNull):
            return {"exists": {"field": inner.field}}
        # EQL's missing-field/null behavior differs from a general DSL NOT.
        # Reject general negation rather than silently changing its meaning.
        raise ProbeError("General Sigma negation is unsupported by the exact-count adapter.")
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise ProbeError("Unsupported Sigma condition in the exact-count adapter.")
    field, value = node.field, node.value
    if type(value) is SigmaString:
        parts = []
        for part in value.s:
            if isinstance(part, str):
                parts.append(part.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?"))
            elif part is SpecialChars.WILDCARD_MULTI:
                parts.append("*")
            elif part is SpecialChars.WILDCARD_SINGLE:
                parts.append("?")
            else:
                raise ProbeError("Unsupported Sigma string expansion.")
        return {"wildcard": {field: {"value": "".join(parts), "case_insensitive": True}}}
    if isinstance(value, (SigmaNumber, SigmaBool)):
        return {"term": {field: value.to_plain()}}
    if isinstance(value, SigmaExists):
        exists = {"exists": {"field": field}}
        return exists if value.exists else {"bool": {"must_not": [exists]}}
    if isinstance(value, SigmaNull):
        return {"bool": {"must_not": [{"exists": {"field": field}}]}}
    raise ProbeError("Unsupported Sigma value in the exact-count adapter.")


def compile_rule(raw, eql=True):
    rules = SigmaCollection.from_yaml(yaml.safe_dump(raw))
    if len(rules.rules) != 1:
        raise ProbeError("Expected one Sigma rule per file.")
    rule = rules.rules[0]
    if eql:
        queries = EqlBackend(processing_pipeline=pipeline()).convert(rules)
        if len(queries) != 1 or not queries[0].startswith("any where "):
            raise ProbeError("Only single-event EQL rules are supported.")
        query = queries[0]
    else:
        pipeline().apply(rule)
        query = None
    conditions = rule.detection.parsed_condition
    if len(conditions) != 1:
        raise ProbeError("Multiple Sigma conditions are unsupported.")
    return query, dsl(conditions[0].parsed)


def variant(raw, detection):
    data = copy.deepcopy(raw)
    data["detection"] = copy.deepcopy(detection)
    return compile_rule(data, eql=False)[1]


def field_names(query):
    names = set()
    if isinstance(query, dict):
        for kind, item in query.items():
            if kind in {"wildcard", "term", "terms"}:
                names.update(item)
            elif kind == "exists":
                names.add(item["field"])
            else:
                names.update(field_names(item))
    elif isinstance(query, list):
        for item in query:
            names.update(field_names(item))
    return names


class Rest(Client):
    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.url + path, data, self.headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            raise ProbeError(f"Elasticsearch HTTP {error.code}; raw response withheld.") from None
        except (urllib.error.URLError, OSError, ValueError):
            raise ProbeError("Local Elasticsearch request failed; raw details withheld.") from None
        if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
            raise ProbeError("Partial Elasticsearch results rejected.")
        return result


class Snapshot:
    def __init__(self, client):
        self.client = client
        self.id = client.request("POST", "/winlogbeat-*/_pit?keep_alive=5m&allow_partial_search_results=false")["id"]

    def search(self, body):
        request = dict(body, pit={"id": self.id, "keep_alive": "5m"})
        result = self.client.post("/_search?allow_partial_search_results=false", request)
        self.id = result.get("pit_id", self.id)
        return result

    def count(self, query):
        result = self.search({"size": 0, "query": query, "track_total_hits": True})
        total = result["hits"]["total"]
        if total["relation"] != "eq":
            raise ProbeError("A non-exact count was rejected.")
        return total["value"]

    def ids(self, query):
        result = self.search({"size": LIMIT, "query": query, "_source": False, "sort": ["_shard_doc"]})
        hits = result["hits"]["hits"]
        if len(hits) >= LIMIT:
            raise ProbeError("Document-ID check reached the cap.")
        return {(hit["_index"], hit["_id"]) for hit in hits}

    def files(self, query, file_field, tactic_field):
        sources = [{"tactic": {"terms": {"field": tactic_field, "missing_bucket": True}}},
                   {"file": {"terms": {"field": file_field}}}]
        composite = {"size": 500, "sources": sources}
        files = {}
        while True:
            result = self.search({"size": 0, "query": query, "aggs": {"files": {"composite": composite}}})
            page = result["aggregations"]["files"]
            for bucket in page["buckets"]:
                key = (bucket["key"].get("tactic"), bucket["key"]["file"])
                files[key] = bucket["doc_count"]
            if not page["buckets"] or "after_key" not in page:
                return files
            composite["after"] = page["after_key"]

    def close(self):
        self.client.request("DELETE", "/_pit", {"id": self.id})


def file_rows(files):
    return [{"tactic": key[0], "file": key[1], "events": count}
            for key, count in sorted(files.items(), key=lambda item: (item[0][0] or "", item[0][1]))]


def atomic_json(path, obj):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(obj, indent=2, default=str) + "\n")
    temporary.replace(path)


def eql_ids(client, query, scope):
    path = ("/winlogbeat-*/_eql/search?allow_partial_search_results=false"
            "&filter_path=hits.events._index,hits.events._id,hits.total,"
            "timed_out,is_partial,is_running,shard_failures,_shards")
    result = client.post(path, {"query": query, "filter": scope, "size": LIMIT})
    events = result.get("hits", {}).get("events", [])
    return {(event["_index"], event["_id"]) for event in events}, len(events)


def load_suite():
    tests = yaml.safe_load((ROOT / "lab/rule-tests.yml").read_text())
    suite = []
    for path in sorted((ROOT / "rules").glob("*.yml")):
        raw = yaml.safe_load(path.read_text())
        spec = tests.get(path.stem)
        if spec is None:
            raise ProbeError("Missing test definition for " + path.name)
        eql, query = compile_rule(raw)
        scope = variant(raw, spec["scope"])
        opportunity = variant(raw, spec["opportunity"])
        required = {name + "|exists": True for name in spec["required_fields"]}
        present = variant(raw, {"required": required, "condition": "required"})
        eligible = both(scope, present)
        suite.append((path, raw, spec, eql, query, scope, opportunity, eligible))
    if len(suite) != 6:
        raise ProbeError("Expected six draft rules; review the test manifest before changing suite size.")
    return suite


def validate(suite):
    client = Rest()
    caps = client.post("/winlogbeat-*/_field_caps", {"fields": ["*"]})["fields"]
    required = {"tags", "fields.corpus", "fields.sample_file", "fields.sample_tactic"}
    for _, _, _, _, query, scope, opportunity, eligible in suite:
        required |= field_names(query) | field_names(scope) | field_names(opportunity) | field_names(eligible)
    for name in sorted(required):
        types = {k: v for k, v in caps.get(name, {}).items() if k != "unmapped"}
        if (not types or not set(types) <= {"keyword", "constant_keyword", "wildcard"}
                or not all(v.get("searchable") and not v.get("non_searchable_indices") for v in types.values())):
            raise ProbeError("Required searchable keyword field missing/incompatible: " + name)
        if name in {"fields.sample_file", "fields.sample_tactic"} and not all(
            v.get("aggregatable") and not v.get("non_aggregatable_indices") for v in types.values()
        ):
            raise ProbeError("Attack-file labels are not aggregatable.")
    scopes = {
        "attack": {"term": {"tags": "attack-sample"}},
        "host": {"term": {"tags": "baseline"}},
        "win10": both({"term": {"tags": "benign-corpus"}}, {"term": {"fields.corpus": "win10-client"}}),
        "win11": both({"term": {"tags": "benign-corpus"}}, {"term": {"fields.corpus": "win11-client"}})
    }
    started = datetime.now(timezone.utc)
    directory = ROOT / "coverage/runs" / started.strftime("%Y%m%d-%H%M%S")
    directory.mkdir(parents=True, exist_ok=False)
    converted = ROOT / "converted"
    converted.mkdir(exist_ok=True)
    report = {"status": "in_progress", "utc_started": started.isoformat(),
              "method": "PIT exact DSL counts; EQL document-ID parity below 10000",
              "attack_coverage": "candidate-opportunity file coverage; technique-wide recall unreviewed",
              "versions": {name: importlib.metadata.version(name) for name in ("pySigma", "pySigma-backend-elasticsearch")},
              "sources": {"attack_commit": "4ceed2f4706daf601c212a8f91c113dd85349a2c", "public_release": "v0.8.5"},
              "rules": []}
    snapshot = Snapshot(client)
    try:
        totals = {name: snapshot.count(scope) for name, scope in scopes.items()}
        report["corpus_totals"] = totals
        if not totals["attack"] or not totals["win10"] or not totals["win11"]:
            raise ProbeError("Required attack/public corpus is empty.")
        for a, scope in scopes.items():
            for b, other in scopes.items():
                if a < b and snapshot.count(both(scope, other)):
                    raise ProbeError("Corpus labels overlap; validation stopped.")
        all_files = snapshot.files(scopes["attack"], "fields.sample_file", "fields.sample_tactic")
        atomic_json(directory / "attack-file-inventory.json", file_rows(all_files))
        print("Validation UTC:", started.isoformat())
        print("Snapshot corpus totals:", " | ".join(f"{name}={count:,}" for name, count in totals.items()))
        print("Counts only; draft detections, no technique-wide recall claim.\n", flush=True)
        for path, raw, spec, eql, query, scope, opportunity, eligible in suite:
            (converted / (path.stem + ".eql")).write_text(eql + "\n")
            atomic_json(converted / (path.stem + ".dsl.json"), query)
            entry = {"rule": path.name, "id": raw["id"], "title": raw["title"],
                     "rule_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                     "techniques": [tag for tag in raw["tags"] if re.fullmatch(r"attack\.t\d+(?:\.\d+)?", tag)],
                     "corpora": {}}
            report["rules"].append(entry)
            print(spec["label"])
            print(f"{'Corpus':8} {'Hits':>8} {'Eligible':>10} {'Opportunity':>12} {'Hits/100k':>11}  EQL check")
            for name, corpus in scopes.items():
                match = both(corpus, query)
                hits = snapshot.count(match)
                available = snapshot.count(both(corpus, eligible))
                opportunities = snapshot.count(both(corpus, opportunity))
                returned, count = eql_ids(client, eql, corpus)
                if hits >= LIMIT or count >= LIMIT:
                    parity = "CAPPED / UNVERIFIED"
                else:
                    expected = snapshot.ids(match)
                    if len(expected) != hits:
                        raise ProbeError("Snapshot document-ID/count mismatch.")
                    parity = "MATCH" if returned == expected else ("LIVE DRIFT / MISMATCH" if name == "host" else "MISMATCH")
                rate = hits * 100000 / totals[name] if totals[name] else None
                entry["corpora"][name] = {"hits": hits, "corpus_events": totals[name],
                    "eligible_events": available, "opportunity_events": opportunities,
                    "hits_per_100k_corpus_events": rate, "eql_check": parity,
                    "eql_returned": count, "no_eligible_telemetry": available == 0}
                print(f"{name:8} {hits:8,} {available:10,} {opportunities:12,} {rate if rate is not None else 0:11.3f}  {parity}", flush=True)
                atomic_json(directory / "results.json", report)
                if parity == "MISMATCH":
                    raise ProbeError("Static-corpus EQL/DSL document sets differ; results remain incomplete.")
            matched = snapshot.files(both(scopes["attack"], query), "fields.sample_file", "fields.sample_tactic")
            opportunity_files = snapshot.files(both(scopes["attack"], opportunity), "fields.sample_file", "fields.sample_tactic")
            intersection = set(matched) & set(opportunity_files)
            entry["attack_files"] = {"matched": file_rows(matched), "opportunities": file_rows(opportunity_files),
                "covered_opportunity_files": len(intersection), "opportunity_files": len(opportunity_files),
                "matched_outside_opportunity": len(set(matched) - set(opportunity_files))}
            print(f"Attack files matched: {len(matched)}; candidate-opportunity coverage: {len(intersection)}/{len(opportunity_files)}")
            for key in sorted(matched, key=lambda item: (item[0] or "", item[1])):
                print(f"  Recorded sample: {key[0] or '(root)'} / {key[1]}")
            if not matched:
                print("  NO ATTACK MATCH: investigate rule scope/logic before acceptance.")
            print()
            atomic_json(directory / "results.json", report)
        report["status"] = "measurement_complete"
        report["utc_finished"] = datetime.now(timezone.utc).isoformat()
        atomic_json(directory / "results.json", report)
        print("MEASUREMENT COMPLETE. Review hits, misses, telemetry gaps, and coverage labels before accepting rules.")
        print("Sanitized report:", directory / "results.json")
        print("No raw event values, host command lines, or credentials were printed or saved.")
    except ProbeError as error:
        report["status"] = "incomplete"
        report["reason"] = str(error)
        atomic_json(directory / "results.json", report)
        raise
    finally:
        try:
            snapshot.close()
        except ProbeError:
            print("PIT cleanup unavailable; the read snapshot expires automatically.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-check", action="store_true")
    args = parser.parse_args()
    expected = {"pySigma": "1.5.1", "pySigma-backend-elasticsearch": "2.1.1"}
    for name, version in expected.items():
        if importlib.metadata.version(name) != version:
            raise ProbeError("Tool version differs from the tested version: " + name)
    suite = load_suite()
    if args.offline_check:
        print("Six Sigma rules, EQL queries, scope/opportunity/eligibility definitions, and exact-count adapters compiled successfully.")
        return
    validate(suite)


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        print("STOPPED:", str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; read-only validation can be rerun.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("STOPPED: Unexpected rule, dependency, or response format; raw details withheld.", file=sys.stderr)
        sys.exit(1)
