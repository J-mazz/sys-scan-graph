# CLI Guide

This guide provides comprehensive documentation for the command-line interfaces of both the core scanner and intelligence layer.

## Core Scanner Commands

The core scanner (`sys-scan`) is the high-performance C++ engine that performs the actual security scanning.

### Basic Usage

```bash
# Run a basic scan with default settings
./build/sys-scan

# Run with canonical output (deterministic, stable hashes)
./build/sys-scan --canonical

# Scan with specific severity threshold
./build/sys-scan --min-severity medium

# Fail on high-severity findings
./build/sys-scan --fail-on high
```

### Output Formats

```bash
# JSON output (default)
./build/sys-scan --canonical --output report.json

# NDJSON streaming output
./build/sys-scan --ndjson

# SARIF format for CI/CD integration
./build/sys-scan --sarif

# HTML report generation
./build/sys-scan --html --output report.html
```

### Scanner Selection

```bash
# Run all scanners (default)
./build/sys-scan

# Run specific scanners only
./build/sys-scan --scanners process,network,kernel

# Exclude specific scanners
./build/sys-scan --exclude-scanners compliance
```

### Advanced Options

```bash
# Enable parallel scanning
./build/sys-scan --parallel --parallel-threads 4

# Set custom module summary threshold
./build/sys-scan --modules-summary

# Enable debug output
./build/sys-scan --debug

# Suppress collection warnings
./build/sys-scan --quiet
```

### Configuration

```bash
# Use custom configuration file
./build/sys-scan --config /path/to/config.yaml

# Override specific config values
./build/sys-scan --set-config scanner.kernel.enabled=false
```

## Intelligence Layer Commands

The intelligence layer (`agent/cli`) provides advanced analysis, enrichment, and reporting capabilities.

### Environment Setup

```bash
# Create and activate virtual environment
python -m venv agent/.venv
source agent/.venv/bin/activate

# Install dependencies
pip install -r agent/requirements.txt
```

### Basic Analysis

```bash
# Analyze a core scanner report
python -m agent.cli analyze --report report.json --out enriched.json

# Generate HTML dashboard
python -m agent.cli analyze --report report.json --html --out dashboard.html

# Compare with previous scan
python -m agent.cli analyze --report report.json --prev previous.json --out diff.json
```

### Risk Management

```bash
# Display current risk weights
python -m agent.cli risk-weights --show

# Update risk weights
python -m agent.cli risk-weights --impact 7 --exposure 8 --anomaly 6

# Show risk calibration
python -m agent.cli risk-calibration --show

# Update calibration parameters
python -m agent.cli risk-calibration --a -2.5 --b 0.18
```

### Fleet and Rarity Analysis

```bash
# Generate fleet report
python -m agent.cli fleet-report --out fleet.json

# Generate rarity file
python -m agent.cli rarity-generate-cmd

# Analyze process novelty
python -m agent.cli process-novelty --report report.json
```

### Rule Management

```bash
# List available rules
python -m agent.cli rules --list

# Validate rule files
python -m agent.cli rules --validate /path/to/rules/

# Generate rule gap analysis
python -m agent.cli rule-gap-mine --dir history/ --refine
```

### Data Management

```bash
# Export baseline data
python -m agent.cli baseline --export baseline.json

# Import baseline data
python -m agent.cli baseline --import baseline.json

# Clean old baseline entries
python -m agent.cli baseline --cleanup --days 30
```

### Performance and Debugging

```bash
# Enable checkpointing for debugging
python -m agent.cli analyze --checkpoint-dir checkpoints/ --report report.json

# Set performance regression threshold
python -m agent.cli analyze --perf-threshold 50 --report report.json

# Enable verbose logging
python -m agent.cli analyze --verbose --report report.json
```

## Configuration Files

### Core Scanner Configuration

The core scanner uses YAML configuration files:

```yaml
# config.yaml
scanner:
  process:
    enabled: true
    max_depth: 10
  network:
    enabled: true
    timeout: 30
  kernel:
    enabled: true
    check_modules: true

output:
  format: json
  canonical: true
  include_metadata: true

logging:
  level: info
  file: /var/log/sys-scan.log
```

### Intelligence Layer Configuration

The intelligence layer uses JSON configuration:

```json
{
  "baseline_db": "./baseline.db",
  "llm_provider": "openai",
  "risk_weights": {
    "impact": 6,
    "exposure": 7,
    "anomaly": 5
  },
  "performance": {
    "regression_threshold": 30,
    "baseline_retention_days": 90
  }
}
```

## Environment Variables

### Core Scanner

```bash
# Provenance overrides
SYS_SCAN_PROV_GIT_COMMIT=abc123
SYS_SCAN_PROV_COMPILER_ID=GNU
SYS_SCAN_PROV_BUILD_TYPE=Release

# Runtime configuration
SYS_SCAN_CONFIG_FILE=/path/to/config.yaml
SYS_SCAN_DEBUG=1
SYS_SCAN_QUIET=1

# Output control
SYS_SCAN_CANON_TIME_ZERO=1
SYS_SCAN_OUTPUT_FORMAT=json
```

### Intelligence Layer

```bash
# Database and storage
AGENT_BASELINE_DB=./baseline.db
AGENT_INDEX_DIR=./indices/
AGENT_CHECKPOINT_DIR=./checkpoints/

# LLM configuration
AGENT_LLM_PROVIDER=openai
AGENT_OPENAI_API_KEY=your_key_here
AGENT_MAX_TOKENS=4096

# Performance and limits
AGENT_MAX_REPORT_MB=5
AGENT_PERF_REGRESSION_PCT=30
AGENT_MAX_SUMMARY_ITERS=3

# Feature flags
AGENT_LOAD_HF_CORPUS=1
AGENT_ENABLE_HTML=1
```

## Common Workflows

### Development Testing

```bash
# Build and test core scanner
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure

# Test intelligence layer
cd agent && python -m pytest tests/ -v
```

### CI/CD Integration

```bash
# Run scan with SARIF output for GitHub Security tab
./build/sys-scan --sarif --output security-results.sarif

# Generate comprehensive report
./build/sys-scan --canonical --output scan.json
python -m agent.cli analyze --report scan.json --html --out security-report.html

# Check for high-severity issues
./build/sys-scan --fail-on high --min-severity medium
```

### Performance Monitoring

```bash
# Run with performance tracking
SYS_SCAN_PERF_TRACKING=1 ./build/sys-scan --canonical --output perf.json

# Analyze performance regression
python -m agent.cli analyze --report perf.json --perf-baseline baseline.json
```

### Compliance Auditing

```bash
# Run compliance-focused scan
./build/sys-scan --scanners compliance --canonical --output compliance.json

# Generate compliance report
python -m agent.cli analyze --report compliance.json --compliance-focus --out compliance-report.html
```

## Troubleshooting

### Common Issues

**Core scanner won't start:**
```bash
# Check permissions
ls -la ./build/sys-scan

# Check dependencies
ldd ./build/sys-scan

# Run with debug output
./build/sys-scan --debug
```

**Intelligence layer import errors:**
```bash
# Check Python environment
python --version
pip list | grep -E "(langgraph|langchain|openai)"

# Reinstall dependencies
pip install -r agent/requirements.txt --force-reinstall
```

**Memory issues:**
```bash
# Limit report size
python -m agent.cli analyze --max-size 10MB --report large.json

# Use streaming for large datasets
./build/sys-scan --ndjson | python -m agent.cli analyze --stream
```

### Debug Commands

```bash
# Core scanner debug
./build/sys-scan --debug --verbose --log-file debug.log

# Intelligence layer debug
python -m agent.cli analyze --debug --checkpoint-dir debug_checkpoints/ --report report.json

# Environment info
python -c "import sys; print(sys.version, sys.platform)"
./build/sys-scan --version
```

## Command Reference

### Core Scanner Options

| Option | Description |
|--------|-------------|
| `--canonical` | Generate deterministic output |
| `--ndjson` | Stream NDJSON output |
| `--sarif` | Generate SARIF format |
| `--html` | Generate HTML report |
| `--parallel` | Enable parallel scanning |
| `--min-severity` | Set minimum severity threshold |
| `--fail-on` | Fail on specified severity |
| `--scanners` | Specify scanners to run |
| `--exclude-scanners` | Exclude specific scanners |
| `--config` | Use custom config file |
| `--debug` | Enable debug output |
| `--quiet` | Suppress warnings |

### Intelligence Layer Commands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze and enrich scan reports |
| `risk-weights` | Manage risk scoring weights |
| `risk-calibration` | Manage risk calibration |
| `fleet-report` | Generate fleet analytics |
| `rarity-generate-cmd` | Generate rarity analysis |
| `rule-gap-mine` | Analyze rule coverage gaps |
| `baseline` | Manage baseline data |
| `rules` | Manage security rules |

For more detailed help, use `--help` with any command:

```bash
./build/sys-scan --help
python -m agent.cli analyze --help
```