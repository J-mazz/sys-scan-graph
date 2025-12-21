# CI integration (artifacts-first)

This guide shows how to run sys-scan-graph in CI and publish the **JSON artifacts** (`report.json` and `enriched_report.json`) for review.

> Note: the C++ core in this repository emits **JSON**; SARIF/NDJSON switches are not currently implemented in `src/main.cpp`.

## Prerequisites

- A built `sys-scan` binary available to the workflow (either download from Releases or build from source).

## Example: GitHub Actions (Ubuntu)

```yaml
name: Security Scan (sys-scan-graph)

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
  push:
    branches: [ main ]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-22.04
    steps:
      - name: Checkout repo (if relevant)
        uses: actions/checkout@v4

      - name: Download sys-scan-graph binary
        uses: robinraju/release-downloader@v1
        with:
          repository: J-mazz/sys-scan-graph
          latest: true
          fileName: "sys-scan-graph-*-linux-x86_64.tar.gz"
          extract: true

      - name: Run core scan (JSON)
        run: |
          chmod +x sys-scan
          ./sys-scan --canonical --output report.json

      - name: Enrich (optional)
        run: |
          python3 -m venv .venv
          source .venv/bin/activate
          pip install -U pip
          pip install sys-scan-agent
          sys-scan-graph analyze --report report.json --out enriched_report.json

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sys-scan-graph-results
          path: |
            report.json
            enriched_report.json
```

## Notes

- For deterministic artifacts, prefer `--canonical` for core JSON output.
- If you need GitHub Code Scanning integration, you can treat the JSON output as a build artifact, or add a JSON→SARIF conversion step (not shipped in this repository today).

## Alternative: build from source

```yaml
- name: Setup dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y build-essential cmake ninja-build

- name: Build sys-scan
  run: |
    cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j$(nproc)

- name: Run scan
  run: ./build/sys-scan --canonical --output report.json
```