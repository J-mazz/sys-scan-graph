# Risk Model

This page describes the risk scoring and probability modeling system used by the Intelligence Layer to prioritize security findings.

## Overview

The risk model combines multiple factors to produce actionable risk scores:

- **Impact**: Potential damage from exploitation
- **Exposure**: How easily the vulnerability can be reached
- **Anomaly**: How unusual the finding is in the environment
- **Confidence**: Certainty in the assessment

## Risk Score Calculation

### Base Formula

```
Risk Score = (Impact × W_i + Exposure × W_e + Anomaly × W_a) × Confidence
```

Where:
- **Impact**: 1-10 scale (1 = minimal, 10 = critical system compromise)
- **Exposure**: 1-10 scale (1 = internal only, 10 = internet-exposed)
- **Anomaly**: 1-10 scale (1 = common, 10 = never seen before)
- **Confidence**: 0.1-1.0 scale (0.1 = uncertain, 1.0 = certain)

### Weight Configuration

Default weights (configurable):

```json
{
  "impact_weight": 6,
  "exposure_weight": 7,
  "anomaly_weight": 5
}
```

### Final Score Scaling

```
Scaled Score = (Raw Score / Max Possible) × 100
Final Score = min(100, max(0, Scaled Score))
```

## Risk Categories

### Severity Levels

| Score Range | Severity | Description | Action Required |
|-------------|----------|-------------|----------------|
| 90-100 | Critical | Immediate threat to security | Immediate remediation |
| 70-89 | High | Significant security risk | Priority remediation |
| 50-69 | Medium | Moderate security concern | Plan remediation |
| 30-49 | Low | Minor security issue | Monitor and assess |
| 0-29 | Info | Potential security note | Log for awareness |

### Risk Factors

#### Impact Assessment

**Critical (9-10):**
- Privilege escalation to root
- Remote code execution
- System compromise
- Data exfiltration

**High (7-8):**
- Service disruption
- Unauthorized access
- Configuration bypass
- Sensitive data exposure

**Medium (5-6):**
- Information disclosure
- Local privilege escalation
- Service degradation

**Low (3-4):**
- Potential attack vectors
- Weak configurations
- Unusual but non-threatening findings

**Info (1-2):**
- Security best practices
- Informational findings
- Baseline deviations

#### Exposure Assessment

**Internet-Exposed (9-10):**
- Public-facing services
- Internet-accessible ports
- Web applications
- API endpoints

**Network-Exposed (7-8):**
- Internal network services
- Database servers
- Application servers
- Shared services

**Host-Exposed (5-6):**
- Local services
- File system permissions
- User-accessible resources

**Restricted (3-4):**
- Internal tools
- Administrative interfaces
- Development systems

**Isolated (1-2):**
- Sandboxed environments
- Air-gapped systems
- Development containers

#### Anomaly Assessment

**Never Seen (9-10):**
- First occurrence in environment
- Unknown process or file
- Unusual network connection
- Unexpected system change

**Rare (7-8):**
- Occurs infrequently
- Baseline deviation
- Unusual pattern
- Sporadic occurrence

**Uncommon (5-6):**
- Below average frequency
- Mild baseline deviation
- Slightly unusual

**Common (3-4):**
- Normal frequency
- Within baseline
- Expected variation

**Standard (1-2):**
- Regular occurrence
- Well-known pattern
- Expected behavior

## Confidence Scoring

### Evidence Types

**High Confidence (0.9-1.0):**
- Direct evidence of vulnerability
- Confirmed exploitation
- Known attack patterns
- Verified security issues

**Medium Confidence (0.7-0.8):**
- Strong indicators
- Correlated findings
- Pattern matching
- Heuristic detection

**Low Confidence (0.4-0.6):**
- Weak indicators
- Partial evidence
- Inconclusive data
- Potential false positives

**Very Low Confidence (0.1-0.3):**
- Anomalous behavior
- Suspicious patterns
- Unconfirmed indicators
- Requires investigation

## Risk Calibration

### Logistic Regression Model

The system uses logistic regression to calibrate risk scores:

```
Probability = 1 / (1 + e^-(a + b × Raw Score))
```

Where:
- **a**: Intercept parameter (default: -2.5)
- **b**: Slope parameter (default: 0.18)

### Calibration Training

Risk calibration can be trained using analyst feedback:

```bash
# View current calibration
python -m agent.cli risk-calibration --show

# Update calibration parameters
python -m agent.cli risk-calibration --a -2.5 --b 0.18

# Train from feedback data
python -m agent.cli risk-calibration --train feedback.json
```

## Dynamic Risk Adjustment

### Baseline Integration

Risk scores are adjusted based on baseline data:

- **New findings**: Increased anomaly score
- **Common findings**: Decreased anomaly score
- **Rare findings**: Moderate anomaly increase

### Temporal Factors

- **Recent occurrences**: Higher risk weight
- **Historical patterns**: Adjusted based on frequency
- **Trend analysis**: Increasing frequency increases risk

### Contextual Factors

- **Environment type**: Production vs development
- **Asset value**: Critical systems vs utility servers
- **Compliance requirements**: Regulatory impact

## Risk Aggregation

### Finding-Level Aggregation

Multiple findings can be aggregated:

```json
{
  "finding_id": "kernel_module_unusual",
  "risk_score": 75,
  "contributing_factors": [
    {"type": "impact", "value": 8, "weight": 6},
    {"type": "exposure", "value": 6, "weight": 7},
    {"type": "anomaly", "value": 9, "weight": 5}
  ],
  "confidence": 0.85
}
```

### Report-Level Aggregation

Overall report risk assessment:

```json
{
  "summary": {
    "total_findings": 47,
    "high_severity": 3,
    "medium_severity": 12,
    "low_severity": 22,
    "info_findings": 10,
    "risk_distribution": {
      "critical": 0,
      "high": 3,
      "medium": 12,
      "low": 22,
      "info": 10
    },
    "average_risk_score": 45.2,
    "max_risk_score": 89
  }
}
```

## Risk Weight Management

### CLI Commands

```bash
# Display current weights
python -m agent.cli risk-weights --show

# Update individual weights
python -m agent.cli risk-weights --impact 7 --exposure 8 --anomaly 5

# Reset to defaults
python -m agent.cli risk-weights --reset

# Export weights
python -m agent.cli risk-weights --export weights.json

# Import weights
python -m agent.cli risk-weights --import weights.json
```

### Configuration File

```json
{
  "risk_weights": {
    "impact": 6,
    "exposure": 7,
    "anomaly": 5,
    "confidence_base": 0.8
  },
  "calibration": {
    "intercept": -2.5,
    "slope": 0.18,
    "training_data": "feedback.json"
  }
}
```

## Risk Decision Engine

### Automated Actions

Based on risk scores, the system can trigger:

- **Critical**: Immediate alerts, automated remediation
- **High**: Priority notifications, scheduled remediation
- **Medium**: Standard notifications, planned remediation
- **Low**: Logged notifications, monitoring
- **Info**: Informational logging

### Threshold Configuration

```json
{
  "risk_thresholds": {
    "critical_min": 90,
    "high_min": 70,
    "medium_min": 50,
    "low_min": 30,
    "auto_remediate_max": 95
  }
}
```

## Performance Considerations

### Computational Efficiency

- **O(n)** complexity for individual findings
- **Batch processing** for multiple findings
- **Caching** of baseline data
- **Incremental updates** for temporal analysis

### Memory Usage

- **Minimal overhead** for risk calculations
- **Efficient data structures** for baseline storage
- **Streaming processing** for large datasets

## Validation and Testing

### Unit Tests

```bash
# Run risk model tests
python -m pytest agent/tests/test_risk_model.py -v

# Run calibration tests
python -m pytest agent/tests/test_risk_calibration.py -v
```

### Validation Metrics

- **Accuracy**: Correct classification rate
- **Precision**: True positive rate
- **Recall**: False negative rate
- **F1 Score**: Harmonic mean of precision and recall

### Benchmarking

```bash
# Performance benchmarking
python -m agent.cli benchmark-risk-model --iterations 1000 --concurrency 4
```

## Troubleshooting

### Common Issues

**Inconsistent risk scores:**
- Check weight configuration
- Verify baseline data integrity
- Review calibration parameters

**False positives/negatives:**
- Adjust anomaly thresholds
- Update baseline data
- Refine confidence scoring

**Performance issues:**
- Enable caching
- Use batch processing
- Optimize baseline queries

### Debug Commands

```bash
# Debug risk calculation
python -m agent.cli analyze --debug-risk --report scan.json

# Show risk factors
python -m agent.cli risk-factors --finding-id kernel_module_unusual

# Validate calibration
python -m agent.cli risk-calibration --validate
```

## Future Enhancements

### Planned Features

- **Machine learning models** for risk prediction
- **Integration with threat intelligence** feeds
- **Custom risk rules** and policies
- **Real-time risk adjustment** based on events
- **Multi-dimensional risk visualization**

### Research Areas

- **Advanced anomaly detection** algorithms
- **Temporal risk modeling** with time series
- **Cross-system risk correlation**
- **Automated risk mitigation** strategies