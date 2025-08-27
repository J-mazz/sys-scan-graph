#!/usr/bin/env python3
"""Lightweight release validation helper.

Checks:
 1. Canonical fleet report schema hash (sha256) recorded in manifest.
 2. Rule pack (.rule) files hashed; emits deterministic manifest for attestation.
 3. Ensures repository build version matches optional --expected-version.
 4. Optionally verifies reproducible build flag present in CMake cache if --repro-required.

Usage:
  python scripts/release_validate.py --expected-version 0.1.0 --schema schema/fleet_report.schema.json \
      --rules-dir rules --output artifacts/release-manifest.json --repro-required

Exit codes:
 0 success; non-zero on any failed invariant.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def detect_version(cmake_lists: Path) -> str | None:
    m = re.search(r'project\(\s*sys-scan\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)', cmake_lists.read_text())
    return m.group(1) if m else None


def git_commit() -> str:
    try:
        return subprocess.check_output(['git', 'rev-parse', '--short=12', 'HEAD'], text=True).strip()
    except Exception:
        return 'unknown'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--schema', default='schema/fleet_report.schema.json')
    ap.add_argument('--rules-dir', default='rules')
    ap.add_argument('--expected-version')
    ap.add_argument('--repro-required', action='store_true')
    ap.add_argument('--output', default='artifacts/release-manifest.json')
    args = ap.parse_args()

    failures = []
    schema_path = Path(args.schema)
    if not schema_path.is_file():
        failures.append(f'Schema not found: {schema_path}')
    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        failures.append(f'Rules directory missing: {rules_dir}')

    cmake_version = detect_version(Path('CMakeLists.txt'))
    if args.expected_version and cmake_version != args.expected_version:
        failures.append(f'Version mismatch: expected {args.expected_version} got {cmake_version}')

    repro_flag = False
    cache = Path('CMakeCache.txt')
    if args.repro_required and cache.is_file():
        for line in cache.read_text().splitlines():
            if 'SYS_SCAN_REPRO_BUILD:BOOL=ON' in line:
                repro_flag = True
                break
        if not repro_flag:
            failures.append('Repro build required but SYS_SCAN_REPRO_BUILD not enabled in CMakeCache.txt')

    manifest = {
        'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'git_commit': git_commit(),
        'version': cmake_version,
        'schema': None,
        'rules': [],
    }

    if schema_path.is_file():
        manifest['schema'] = {
            'path': str(schema_path),
            'sha256': sha256_file(schema_path),
            'size': schema_path.stat().st_size,
        }

    if rules_dir.is_dir():
        for rule_file in sorted(rules_dir.glob('**/*.rule')):
            if rule_file.is_file():
                manifest['rules'].append({
                    'path': str(rule_file),
                    'sha256': sha256_file(rule_file),
                    'size': rule_file.stat().st_size,
                })

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2))

    if failures:
        print('FAILED invariants:', file=sys.stderr)
        for f in failures:
            print(' -', f, file=sys.stderr)
        print('Manifest written (for inspection):', out_path, file=sys.stderr)
        sys.exit(1)
    else:
        print('All release validation checks passed.')
        print('Manifest:', out_path)

if __name__ == '__main__':
    main()
