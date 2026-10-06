#!/usr/bin/env python3
"""Release checks; no real Elasticsearch connection or mutations.

Checks pinned dependencies, measured evidence/hashes, converted queries,
Sigma rules, regression fixtures, published tables, Markdown links, and
publication boundaries. Synthetic request testing uses a dummy temporary
localhost HTTP server only. The first "sigma check" on a machine downloads
MITRE ATT&CK and D3FEND reference data; everything else is offline.
"""
from collections import Counter
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


MEASURED_AUTHOR_LINE = b'author: Samuel Yoder, with AI-assisted drafting'


def measured_sha(path):
    """Hash of a rule file as it was measured.

    The author line was shortened after measurement. Nothing else may differ:
    putting the measured author line back must reproduce the measured hash.
    """
    lines = path.read_bytes().split(b'\n')
    require(sum(line.startswith(b'author:') for line in lines) == 1, 'Expected one author line: ' + path.name)
    restored = [MEASURED_AUTHOR_LINE if line.startswith(b'author:') else line for line in lines]
    return hashlib.sha256(b'\n'.join(restored)).hexdigest()


def load(path):
    return json.loads((ROOT / path).read_text())


def file_ids(rows):
    return {(row['tactic'], row['file']) for row in rows}


def recorded_evidence():
    before = load('coverage/runs/20261005-183023/results.json')
    after = load('coverage/runs/20261005-184548/results.json')
    context = load('coverage/reviews/20261005-184922/context.json')
    inventory = load('coverage/runs/20261005-184548/attack-file-inventory.json')
    index = load('coverage/file-coverage.json')
    summary = load('coverage/summary.json')
    require(before['status'] == after['status'] == 'measurement_complete', 'Incomplete measured evidence.')
    require(context['status'] == 'review_complete', 'Incomplete context evidence.')
    require(summary['measurement'] == after and summary['comparison'] == before and summary['context'] == context,
            'Summary differs from recorded evidence.')
    require(len(before['rules']) == len(after['rules']) == len(context['rules']) == 6, 'Expected six rules.')
    require(len(inventory) == len(file_ids(inventory)) == len(index) == 278, 'Attack file inventory mismatch.')
    require(sum(row['events'] for row in inventory) == after['corpus_totals']['attack'], 'Inventory event total mismatch.')
    require(file_ids(index) == file_ids(inventory), 'Coverage index changed source labels.')
    indexed = {(row['tactic'], row['file']): row for row in index}
    for path, expected in summary['evidence_sha256'].items():
        require(sha(ROOT / path) == expected, 'Evidence file hash changed: ' + path)
    for result in after['rules']:
        name = result['rule']
        require(measured_sha(ROOT / 'rules' / name) == result['rule_sha256'], 'Measured rule changed: ' + name)
        initial = next(row for row in before['rules'] if row['rule'] == name)
        require(measured_sha(ROOT / 'coverage/initial-rules' / name) == initial['rule_sha256'], 'Initial rule bytes mismatch: ' + name)
        reviewed = next(row for row in context['rules'] if row['rule'] == name)
        require(reviewed['rule_sha256'] == result['rule_sha256'], 'Context rule hash mismatch: ' + name)
        for run in [before, after]:
            measured = next(row for row in run['rules'] if row['rule'] == name)
            for corpus, c in measured['corpora'].items():
                require(c['eql_check'] == 'MATCH' and c['eql_returned'] == c['hits'], 'Unverified EQL evidence: ' + name)
                require(c['corpus_events'] == run['corpus_totals'][corpus], 'Corpus denominator mismatch.')
                require(0 <= c['hits'] <= c['eligible_events'] <= c['corpus_events'], 'Inconsistent eligibility counts.')
                require(0 <= c['opportunity_events'] <= c['corpus_events'], 'Invalid precursor count.')
                rate = c['hits'] * 100000 / c['corpus_events']
                require(abs(c['hits_per_100k_corpus_events'] - rate) < 1e-8, 'Rate mismatch.')
        require(sum(g['events'] for g in reviewed['attack_groups'] if g['rule_matched']) == result['corpora']['attack']['hits'],
                'Attack context total mismatch: ' + name)
        groups = Counter()
        for g in reviewed['attack_groups']:
            if g['rule_matched']:
                groups[(g['tactic'], g['file'])] += g['events']
        require(dict(groups) == {(g['tactic'], g['file']): g['events'] for g in result['attack_files']['matched']},
                'Attack context/file reconciliation failed: ' + name)
        public = sum(result['corpora'][corpus]['hits'] for corpus in ['win10', 'win11'])
        require(public == reviewed['public_matches'] == sum(g['events'] for g in reviewed['public_groups']), 'Public context mismatch.')
        for corpus in ['win10-client', 'win11-client']:
            require(sum(g['events'] for g in reviewed['public_groups'] if g['corpus'] == corpus) == result['corpora'][corpus.split('-')[0]]['hits'],
                    'Public per-corpus context mismatch.')
        f = result['attack_files']
        require(len(file_ids(f['opportunities'])) == f['opportunity_files'], 'Precursor file count mismatch.')
        require(len(file_ids(f['matched']) & file_ids(f['opportunities'])) == f['covered_opportunity_files'], 'File coverage mismatch.')
        for identity, row in indexed.items():
            require((result['id'] in row['matched_rule_ids']) == (identity in file_ids(f['matched'])), 'File index match labels differ.')
            require((result['id'] in row['precursor_rule_ids']) == (identity in file_ids(f['opportunities'])), 'File index precursor labels differ.')
    print('PASS: both measured runs, 24 final EQL checks, six rule hashes, context counts, and 278-file index.')


def publication_files():
    allowed = load('release-files.json')['files']
    require(len(allowed) == len(set(allowed)), 'Duplicate release paths.')
    for name in allowed:
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe release path.')
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(ROOT), 'Missing/linked release file: ' + name)
        require(path.suffix.lower() not in {'.evtx', '.tgz', '.zip', '.log', '.out', '.err'}, 'Raw/private artifact in release.')
        require(not any(part in {'.venv', '.git', 'private', 'logs', 'state', 'data'} for part in relative.parts), 'Private directory in release.')
        require(not path.name.startswith('.env') and path.name != 'connection-secrets.json', 'Credential config in release.')
        content = path.read_text()
        require(not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', content), 'Private key marker in release.')
        require(not re.search(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})', content), 'Possible credential token in release.')
        if path.suffix == '.md':
            for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', content):
                if '://' in target or target.startswith('#'):
                    continue
                target = target.split('#')[0]
                require((path.parent / target).exists(), 'Broken Markdown file link in ' + name)
    # Local ignored files are not candidates; other extras require deliberate review.
    extra = []
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in {'.venv', '.git', '__pycache__', 'private'} for part in relative.parts) or path.suffix == '.pyc':
            continue
        if relative.as_posix() not in allowed:
            extra.append(relative.as_posix())
    require(not extra, 'Unreviewed extra release files: ' + ', '.join(sorted(extra)[:10]))
    print('PASS: explicit release file set, raw/private artifact exclusions, credential-pattern scan, and Markdown file links.')


def conversion():
    spec = importlib.util.spec_from_file_location('validation', ROOT / 'scripts/validate-rules.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path, raw, definition, eql, dsl, scope, opportunity, eligible in module.load_suite():
        require((ROOT / 'converted' / (path.stem + '.eql')).read_text().strip() == eql, 'EQL conversion differs: ' + path.name)
        require(load('converted/' + path.stem + '.dsl.json') == dsl, 'DSL conversion differs: ' + path.name)
    print('PASS: six current EQL/DSL conversions using the pinned pipeline.')


def run_checks():
    versions = {'sigma-cli': '3.1.0', 'pySigma': '1.5.1', 'pySigma-backend-elasticsearch': '2.1.1', 'PyYAML': '6.0.3'}
    for name, expected in versions.items():
        require(importlib.metadata.version(name) == expected, 'Pinned dependency differs: ' + name)
    print('PASS: pinned tool versions.')
    recorded_evidence()
    publication_files()
    conversion()
    sigma = shutil.which('sigma')
    require(sigma is not None, 'Activate the lab virtualenv so sigma is on PATH.')
    tasks = [[sigma, 'check', str(ROOT / 'rules')]]
    tasks += [[sys.executable, str(ROOT / 'tests' / name)] for name in
              ['test_rules.py', 'test_known_gaps.py', 'test_docs.py', 'test_http.py', 'test_context.py']]
    for command in tasks:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        hint = ''
        if command[1] == 'check':
            hint = ' The first sigma check needs internet access to download ATT&CK/D3FEND reference data.'
        require(result.returncode == 0, 'Check failed: ' + Path(command[-1]).name + '; raw diagnostics withheld.' + hint)
        print(result.stdout.strip())
    print('PROJECT CHECKS PASSED. No real lab queries or service/settings changes performed.')


if __name__ == '__main__':
    try:
        run_checks()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else 'Unexpected dependency, file, or response format; raw details withheld.'
        print('STOPPED:', message, file=sys.stderr)
        sys.exit(1)
