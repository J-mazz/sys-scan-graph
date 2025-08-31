# LangGraph Node Telemetry Dashboard

This document provides guidance for setting up monitoring dashboards for the LangGraph node telemetry system implemented in Phase 2.

## Overview

The telemetry system collects comprehensive metrics about node execution including:
- Per-node execution times and call counts
- Cache hit rates and performance statistics
- Error rates and success/failure patterns
- Resource utilization trends

## Supported Export Formats

### JSON Format
Comprehensive structured data for custom analysis:
```json
{
  "total_nodes_executed": 12,
  "total_calls": 15,
  "node_breakdown": {
    "enhanced_enrich_findings": {
      "calls": 1,
      "total_duration": 0.45,
      "avg_duration": 0.45,
      "min_duration": 0.45,
      "max_duration": 0.45,
      "last_invocation_id": "enhanced_enrich_findings_1703123456_abc123"
    }
  },
  "performance_stats": {
    "total_execution_time": 3.2,
    "avg_node_duration": 0.267,
    "slowest_node": "enhanced_summarize_host_state"
  }
}
```

### CSV Format
Spreadsheet-compatible format for Excel/Google Sheets analysis:
```csv
Node,Calls,Total_Duration,Avg_Duration,Min_Duration,Max_Duration,Last_Invocation_ID
enhanced_enrich_findings,1,0.45,0.45,0.45,0.45,enhanced_enrich_findings_1703123456_abc123
enhanced_summarize_host_state,1,1.2,1.2,1.2,1.2,enhanced_summarize_host_state_1703123456_def456
```

### Prometheus Format
Metrics format for time-series monitoring:
```prometheus
# HELP sys_scan_graph_node_calls_total Total number of times each node was called
# TYPE sys_scan_graph_node_calls_total counter
sys_scan_graph_node_calls_total{node="enhanced_enrich_findings"} 1
sys_scan_graph_node_calls_total{node="enhanced_summarize_host_state"} 1

# HELP sys_scan_graph_node_duration_seconds Time spent in each node
# TYPE sys_scan_graph_node_duration_seconds histogram
sys_scan_graph_node_duration_seconds_count{node="enhanced_enrich_findings"} 1
sys_scan_graph_node_duration_seconds_sum{node="enhanced_enrich_findings"} 0.45
```

## Dashboard Setup

### Grafana Dashboard

1. **Data Source**: Configure Prometheus as data source
2. **Import Dashboard**: Use the provided dashboard JSON
3. **Key Panels**:
   - Node execution time trends
   - Call frequency by node
   - Cache hit rate over time
   - Error rate monitoring
   - Performance regression alerts

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sys-scan-graph'
    static_configs:
      - targets: ['localhost:9090']  # Adjust as needed
    file_sd_configs:
      - files:
        - '/path/to/metrics/*.prom'
```

### Custom Dashboard Panels

#### Node Performance Overview
```
Panel Type: Table
Query: sys_scan_graph_node_duration_seconds{quantile="0.95"}
```

#### Execution Time Trends
```
Panel Type: Graph
Query: rate(sys_scan_graph_node_duration_seconds_sum[5m]) / rate(sys_scan_graph_node_duration_seconds_count[5m])
```

#### Cache Performance
```
Panel Type: Singlestat
Query: sys_scan_graph_cache_hit_rate
```

## CLI Usage

Export metrics during analysis:
```bash
# Export to JSON
python -m agent.cli analyze report.json --metrics-out metrics.json

# Export to CSV
python -m agent.cli analyze report.json --metrics-out metrics.csv

# Export to Prometheus format
python -m agent.cli analyze report.json --metrics-out metrics.prom
```

## Performance Regression Detection

The system includes automatic performance regression detection:

1. **Baseline Management**: Maintains expected performance baselines
2. **Regression Alerts**: Detects when performance exceeds thresholds
3. **CI Integration**: Can be integrated into CI/CD pipelines

### Example CI Check
```yaml
# .github/workflows/ci.yml
- name: Performance Check
  run: |
    python -m agent.cli analyze test_report.json --metrics-out current_metrics.json
    python -c "
    from agent.performance_baseline import check_performance_regression
    from agent.metrics_exporter import write_metrics_json
    import json

    with open('current_metrics.json') as f:
        current = json.load(f)

    results = check_performance_regression(current)
    if results['regression_detected']:
        print('Performance regression detected!')
        for violation in results['violations']:
            print(f'- {violation}')
        exit(1)
    else:
        print('Performance check passed')
    "
```

## Alerting Rules

### Prometheus Alerting Rules
```yaml
# alerting_rules.yml
groups:
  - name: sys_scan_graph
    rules:
      - alert: NodeExecutionTimeout
        expr: sys_scan_graph_node_duration_seconds > 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Node execution timeout"
          description: "Node {{ $labels.node }} took more than 30 seconds"

      - alert: CacheHitRateLow
        expr: sys_scan_graph_cache_hit_rate < 0.1
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "Low cache hit rate"
          description: "Cache hit rate dropped below 10%"
```

## Troubleshooting

### Common Issues

1. **Missing Metrics**: Ensure `--metrics-out` flag is used with analyze command
2. **Empty Reports**: Check that the graph execution completed successfully
3. **Performance Spikes**: Review node implementations for optimization opportunities

### Debug Commands
```bash
# View current metrics summary
python -c "from agent.metrics_exporter import print_metrics_summary; print_metrics_summary({})"

# Check baseline status
python -c "from agent.performance_baseline import load_baseline; print(load_baseline())"
```

## Future Enhancements

- Real-time metrics streaming
- Custom alerting webhooks
- Historical trend analysis
- Anomaly detection integration
- Resource utilization monitoring