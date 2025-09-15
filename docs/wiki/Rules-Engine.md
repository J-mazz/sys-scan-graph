# Rules Engine

This page details the Rules Engine component of sys-scan-graph, including rule file formats, correlation logic, MITRE ATT&CK integration, and severity management.

## Overview

The Rules Engine is the correlation and analysis framework that processes raw scanner findings through declarative rules to identify security patterns, relationships, and potential threats. It combines YAML/JSON rule definitions with sophisticated matching logic to transform individual findings into actionable security insights.

## Rule File Formats

### YAML Rule Format

Rules are defined in YAML files with the following structure:

```yaml
# Example rule file: rules/critical-kernel-modules.yaml
rules:
  - name: "Critical Kernel Module Exposure"
    description: "Detection of critical kernel modules with world-writable permissions"
    severity: "high"
    tags: ["kernel", "permissions", "exposure"]

    # Matching criteria
    match:
      scanner: "kernel_modules"
      conditions:
        - field: "permissions"
          op: "contains"
          value: "world-writable"
        - field: "module_name"
          op: "in"
          values: ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"]

    # Correlation logic
    correlation:
      exposure_bonus: 2.0
      related_findings:
        - scanner: "processes"
          field: "cmdline"
          op: "contains"
          value: "modprobe"

    # Actions and recommendations
    actions:
      - "Audit kernel module loading"
      - "Review module permissions"
      - "Consider kernel hardening"

  - name: "SUID Binary Network Exposure"
    description: "SUID binaries that can bind to network ports"
    severity: "critical"
    tags: ["suid", "network", "privilege-escalation"]

    match:
      scanner: "suid"
      conditions:
        - field: "capabilities"
          op: "contains"
          value: "net_bind_service"
        - field: "binary_path"
          op: "not_in"
          values: ["/bin/ping", "/usr/bin/traceroute"]

    correlation:
      exposure_bonus: 3.0
      temporal_window: "1h"
      sequence:
        - scanner: "network"
          field: "listening_ports"
          op: "intersects"
          value: "privileged_ports"

    actions:
      - "Immediate SUID removal or permission correction"
      - "Investigate network service requirements"
      - "Implement network segmentation"
```

### JSON Rule Format

Rules can also be defined in JSON format:

```json
{
  "rules": [
    {
      "name": "World Writable System Binary",
      "description": "System binaries with world-writable permissions",
      "severity": "high",
      "tags": ["permissions", "integrity"],
      "match": {
        "scanner": "world_writable",
        "conditions": [
          {
            "field": "file_path",
            "op": "regex",
            "value": "^/bin/|^/sbin/|^/usr/bin/|^/usr/sbin/"
          },
          {
            "field": "file_type",
            "op": "eq",
            "value": "regular"
          }
        ]
      },
      "correlation": {
        "exposure_bonus": 2.5,
        "related_findings": [
          {
            "scanner": "integrity",
            "field": "hash_mismatch",
            "op": "eq",
            "value": true
          }
        ]
      },
      "actions": [
        "Verify file integrity",
        "Check for unauthorized modifications",
        "Restore from trusted backup"
      ]
    }
  ]
}
```

## Rule Matching Logic

### Condition Operators

The Rules Engine supports various matching operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Exact equality | `"field": "value"` |
| `neq` | Not equal | `"field": "value"` |
| `contains` | String contains substring | `"field": "substring"` |
| `not_contains` | String does not contain | `"field": "substring"` |
| `starts_with` | String prefix match | `"field": "prefix"` |
| `ends_with` | String suffix match | `"field": "suffix"` |
| `regex` | Regular expression match | `"field": "pattern"` |
| `in` | Value in array | `"field": ["val1", "val2"]` |
| `not_in` | Value not in array | `"field": ["val1", "val2"]` |
| `gt` | Greater than (numeric) | `"field": 100` |
| `lt` | Less than (numeric) | `"field": 100` |
| `gte` | Greater than or equal | `"field": 100` |
| `lte` | Less than or equal | `"field": 100` |
| `intersects` | Array intersection | `"field": ["a", "b"]` |
| `exists` | Field exists | `true` |
| `not_exists` | Field does not exist | `true` |

### Logical Combinations

Rules support complex logical combinations:

```yaml
match:
  scanner: "processes"
  logic: "AND"  # AND, OR, NOT
  conditions:
    - field: "user"
      op: "eq"
      value: "root"
    - logic: "OR"
      conditions:
        - field: "cmdline"
          op: "contains"
          value: "nc"
        - field: "cmdline"
          op: "contains"
          value: "netcat"

correlation:
  logic: "OR"
  related_findings:
    - scanner: "network"
      field: "connections"
      op: "exists"
    - scanner: "files"
      field: "suspicious_paths"
      op: "contains"
      value: "/tmp"
```

## Correlation Engine

### Rule-Based Correlations

The correlation engine processes findings through multiple stages:

1. **Individual Rule Matching**: Each finding is tested against all rules
2. **Cross-Finding Relationships**: Related findings are linked based on rule definitions
3. **Temporal Analysis**: Time-based correlations within configurable windows
4. **Exposure Calculation**: Risk exposure bonuses applied based on finding relationships

### Exposure Bonus System

Rules can apply exposure bonuses to increase risk scores:

```yaml
correlation:
  exposure_bonus: 2.0  # Multiplier for risk exposure
  max_exposure: 5.0    # Maximum exposure cap
  related_findings:
    - scanner: "network"
      field: "open_ports"
      op: "contains"
      value: 22
      exposure_bonus: 1.5  # Additional bonus for SSH exposure
```

### Temporal Correlations

Rules can define time-based relationships:

```yaml
correlation:
  temporal_window: "30m"  # 30 minutes window
  sequence:
    - scanner: "processes"
      field: "cmdline"
      op: "contains"
      value: "wget"
      order: 1
    - scanner: "files"
      field: "file_path"
      op: "regex"
      value: "\\.sh$"
      order: 2
      max_delay: "5m"  # Maximum delay between events
```

## MITRE ATT&CK Integration

### ATT&CK Mapping

Rules can be mapped to MITRE ATT&CK techniques:

```yaml
attack_mapping:
  techniques:
    - id: "T1548.001"
      name: "Abuse Elevation Control Mechanism: Setuid and Setgid"
      tactics: ["Privilege Escalation"]
      confidence: 0.9
    - id: "T1095"
      name: "Non-Application Layer Protocol"
      tactics: ["Command and Control"]
      confidence: 0.7

  subtechniques:
    - id: "T1548.001"
      name: "Setuid and Setgid"
      confidence: 0.95

  mitigations:
    - id: "M1026"
      name: "Privileged Account Management"
    - id: "M1038"
      name: "Execution Prevention"
```

### Coverage Tracking

The system tracks ATT&CK coverage across all rules:

```yaml
# Coverage statistics
attack_coverage:
  total_techniques: 156
  covered_techniques: 89
  coverage_percentage: 57.1
  tactics_coverage:
    "Initial Access": 0.45
    "Execution": 0.67
    "Persistence": 0.72
    "Privilege Escalation": 0.83
    "Defense Evasion": 0.51
    "Credential Access": 0.38
    "Discovery": 0.61
    "Lateral Movement": 0.29
    "Collection": 0.34
    "Command and Control": 0.56
    "Exfiltration": 0.23
    "Impact": 0.41
```

### ATT&CK Hypotheses

The engine generates causal hypotheses based on ATT&CK patterns:

```yaml
hypotheses:
  - technique: "T1059.004"
    name: "Command and Scripting Interpreter: Unix Shell"
    confidence: 0.85
    evidence:
      - "SUID shell binary found"
      - "Unusual shell execution pattern"
      - "Network connection from shell process"
    chain:
      - "Initial compromise via web application"
      - "Privilege escalation through SUID binary"
      - "Shell access establishment"
      - "Lateral movement to other systems"
```

## Severity Management

### Severity Levels

Rules define severity levels with specific thresholds:

```yaml
severity_levels:
  - name: "info"
    threshold: 0-10
    color: "#17a2b8"
    description: "Informational findings"

  - name: "low"
    threshold: 11-30
    color: "#28a745"
    description: "Low risk findings"

  - name: "medium"
    threshold: 31-60
    color: "#ffc107"
    description: "Medium risk findings"

  - name: "high"
    threshold: 61-80
    color: "#fd7e14"
    description: "High risk findings"

  - name: "critical"
    threshold: 81-100
    color: "#dc3545"
    description: "Critical risk findings"
```

### Severity Overrides

Rules can override severity based on conditions:

```yaml
severity_overrides:
  - condition:
      field: "user"
      op: "eq"
      value: "root"
    severity: "critical"
    reason: "Root user involvement escalates severity"

  - condition:
      field: "network_exposure"
      op: "eq"
      value: true
    severity: "+2"  # Increase by 2 levels
    reason: "Network exposure increases risk"

  - condition:
      field: "trusted_binary"
      op: "eq"
      value: true
    severity: "-1"  # Decrease by 1 level
    reason: "Trusted binary reduces risk"
```

### Dynamic Severity Calculation

Severity is calculated based on multiple factors:

```python
def calculate_severity(finding, rule):
    base_severity = rule.severity

    # Apply exposure bonuses
    exposure_multiplier = 1.0
    for correlation in finding.correlations:
        exposure_multiplier *= correlation.exposure_bonus

    # Apply overrides
    for override in rule.severity_overrides:
        if matches_condition(finding, override.condition):
            if override.severity.startswith('+'):
                base_severity = min(5, base_severity + int(override.severity[1:]))
            elif override.severity.startswith('-'):
                base_severity = max(1, base_severity - int(override.severity[1:]))
            else:
                base_severity = severity_name_to_level(override.severity)

    # Calculate final severity
    final_severity = min(100, base_severity * exposure_multiplier)

    return final_severity
```

## Rule Validation

### Schema Validation

Rules are validated against a JSON schema:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "rules": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "match"],
        "properties": {
          "name": {"type": "string"},
          "description": {"type": "string"},
          "severity": {"enum": ["info", "low", "medium", "high", "critical"]},
          "tags": {"type": "array", "items": {"type": "string"}},
          "match": {
            "type": "object",
            "properties": {
              "scanner": {"type": "string"},
              "logic": {"enum": ["AND", "OR", "NOT"]},
              "conditions": {"type": "array"}
            }
          },
          "correlation": {
            "type": "object",
            "properties": {
              "exposure_bonus": {"type": "number"},
              "related_findings": {"type": "array"}
            }
          }
        }
      }
    }
  }
}
```

### Rule Testing

Rules can be tested against sample data:

```bash
# Test a rule file against sample findings
python -m agent.cli rule-test \
    --rule-file rules/critical-kernel-modules.yaml \
    --test-data test/findings.json \
    --verbose

# Validate rule syntax
python -m agent.cli rule-validate \
    --rule-file rules/*.yaml \
    --strict
```

## Rule Management

### Rule Organization

Rules are organized in the `rules/` directory:

```bash
rules/
├── compliance/
│   ├── cis-benchmarks.yaml
│   ├── nist-frameworks.yaml
│   └── pci-dss.yaml
├── attack/
│   ├── initial-access.yaml
│   ├── privilege-escalation.yaml
│   └── persistence.yaml
├── custom/
│   ├── organization-specific.yaml
│   └── environment-specific.yaml
└── templates/
    ├── rule-template.yaml
    └── validation-examples.yaml
```

### Rule Loading

Rules are loaded and cached at startup:

```python
def load_rules(rule_directory):
    rules = []
    for rule_file in glob.glob(f"{rule_directory}/**/*.yaml"):
        with open(rule_file, 'r') as f:
            rule_data = yaml.safe_load(f)
            for rule in rule_data.get('rules', []):
                # Validate rule schema
                validate_rule(rule)
                rules.append(rule)

    # Build rule index for efficient matching
    rule_index = build_rule_index(rules)

    return rules, rule_index
```

### Rule Dependencies

Rules can reference other rules:

```yaml
depends_on:
  - "base-network-exposure"
  - "system-integrity-check"

extends:
  - rule: "base-privilege-escalation"
    overrides:
      severity: "critical"
      conditions:
        - field: "user"
          op: "eq"
          value: "root"
```

## Performance Optimization

### Rule Indexing

Rules are indexed for efficient matching:

```python
def build_rule_index(rules):
    index = defaultdict(list)

    for rule in rules:
        scanner = rule['match']['scanner']
        index[scanner].append(rule)

        # Index by tags
        for tag in rule.get('tags', []):
            index[f"tag:{tag}"].append(rule)

        # Index by severity
        severity = rule.get('severity', 'medium')
        index[f"severity:{severity}"].append(rule)

    return index
```

### Caching Strategies

Rule matching results are cached:

```python
@lru_cache(maxsize=10000)
def match_rule_cached(finding_hash, rule_hash):
    # Cache key based on finding and rule content hashes
    return match_rule(findings_cache[finding_hash],
                     rules_cache[rule_hash])
```

### Parallel Processing

Rules can be processed in parallel:

```python
def process_rules_parallel(findings, rules):
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for finding in findings:
            future = executor.submit(match_finding_rules,
                                   finding, rules)
            futures.append(future)

        results = []
        for future in as_completed(futures):
            results.extend(future.result())

    return results
```

## Integration Examples

### Basic Rule Processing

```bash
# Process findings with rules
python -m agent.cli analyze \
    --report report.json \
    --rules rules/ \
    --out correlated.json
```

### Custom Rule Development

```bash
# Create a new rule template
python -m agent.cli rule-template \
    --scanner processes \
    --name "Suspicious Process Pattern" \
    --output rules/custom/suspicious-processes.yaml

# Test the new rule
python -m agent.cli rule-test \
    --rule-file rules/custom/suspicious-processes.yaml \
    --interactive
```

### Rule Performance Analysis

```bash
# Analyze rule matching performance
python -m agent.cli rule-profile \
    --report report.json \
    --rules rules/ \
    --output performance.json
```

## Related Documentation

- **[Architecture](Architecture.md)** - System architecture overview
- **[Intelligence Layer](Intelligence-Layer.md)** - Analysis pipeline details
- **[Risk Model](Risk-Model.md)** - Risk assessment and calibration
- **[CLI Guide](CLI-Guide.md)** - Command-line interface usage
- **[Extensibility](Extensibility.md)** - Adding custom rules and scanners

---

*For questions about the Rules Engine implementation or rule development, see the [Contributing Guide](../../CONTRIBUTING.md) or open a [GitHub Discussion](https://github.com/Mazzlabs/sys-scan-graph/discussions).*