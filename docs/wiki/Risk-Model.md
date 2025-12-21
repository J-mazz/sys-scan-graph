# Risk model

This page describes the **implemented** risk scoring and probability calibration used by the Python intelligence layer (`sys-scan-agent`).

Source of truth:

- Risk scoring: `agent/sys_scan_agent/risk.py`
- Probability calibration: `agent/sys_scan_agent/calibration.py`
- CLI controls: `agent/sys_scan_agent/cli.py`

## What the system computes

The risk system produces two related quantities:

1. **`risk_score`**: an integer $0..100$ (bounded and comparable across runs)
2. **`probability_actionable`**: a calibrated probability $0..1$ derived from the raw weighted sum

## Risk scoring (0–100)

### Formula (implemented)

```text
risk_total_raw = impact * W_impact + exposure * W_exposure + anomaly * W_anomaly
risk_score     = clamp_0_100( (risk_total_raw / max_possible_raw) * 100 * confidence )
```

The implementation normalizes by a theoretical maximum so scores remain comparable even if weights change.

### Expected input ranges (implemented caps)

`risk.py` uses these caps for normalization:

- `impact <= 10`
- `exposure <= 3`
- `anomaly <= 2`

`confidence` is treated as a multiplier (typically $0..1$).

## Probability calibration (logistic)

`probability_actionable` is derived from the raw weighted sum using a logistic curve:

```text
p = 1 / (1 + exp(-(a + b * risk_total_raw)))
```

Defaults (as shipped):

- `a = -3.0`
- `b = 0.15`

## Where weights and calibration live

Both are persisted in the **current working directory**:

- `agent_risk_weights.json` (weights)
- `agent_risk_calibration.json` (calibration)

### Weight defaults

If no file/env overrides are present:

```json
{
  "impact": 5.0,
  "exposure": 3.0,
  "anomaly": 2.0
}
```

### Environment overrides

You can override weights without touching the JSON file:

- `RISK_W_IMPACT`
- `RISK_W_EXPOSURE`
- `RISK_W_ANOMALY`

## CLI controls

### View or set weights

```bash
sys-scan-graph risk-weights --show
sys-scan-graph risk-weights --impact 5 --exposure 3 --anomaly 2
```

To reset to defaults, delete `agent_risk_weights.json`.

### View or set calibration

```bash
sys-scan-graph risk-calibration --show
sys-scan-graph risk-calibration --a -3.0 --b 0.15
```

To reset to defaults, delete `agent_risk_calibration.json`.

## Operational mapping (team policy)

`sys-scan-graph` does **not** perform automated remediation actions by default.
Teams typically map score bands to response actions in downstream tooling.

Example (policy suggestion):

- 90–100: immediate triage
- 70–89: priority remediation
- 50–69: plan remediation
- <50: monitor

## Troubleshooting

- If risk values look “off” after tuning weights, remember normalization uses caps; very large weights still normalize to 0–100.
- If probability values feel too “flat” or too “spiky”, adjust calibration `a`/`b` and re-run analysis.
- For performance debugging, export node telemetry with `--metrics-out` and inspect bottlenecks.
