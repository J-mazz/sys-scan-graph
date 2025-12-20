# Metrics export (agent)

The optional Python intelligence layer can export **node telemetry metrics** as a file during `sys-scan-graph analyze`.

This page documents *what exists in this repository today* and how to use it.

## Export formats

The output format is selected by the `--metrics-out` file extension:

- `.json` (structured summary)
- `.csv` (spreadsheet-friendly)
- `.prom` (Prometheus text format)

Example:

```bash
sys-scan-graph analyze --report report.json --out enriched_report.json --metrics-out metrics.json
```

Implementation:

- CLI flag handling: `agent/sys_scan_agent/cli.py`
- Export logic: `agent/sys_scan_agent/metrics_exporter.py`

## Notes

- The exporter writes a snapshot of whatever metrics are present in the final workflow state.
- If you want to ingest `.prom` into Prometheus, use a file-based collector appropriate for your environment.
