# Rules engine

This page documents the **implemented** rule support in the Python intelligence layer.

Source of truth:

- Rule loading and linting: `agent/sys_scan_agent/rules.py`
- Correlation integration: `agent/sys_scan_agent/correlator.py`
- CLI helpers: `agent/sys_scan_agent/cli.py`

Rules operate over findings and can contribute lightweight correlation output.

## What rule files are supported

The correlator can load rules from directories containing:

- `.json`
- `.yml`
- `.yaml`

Each file may contain either:

- a single rule object (dict)
- a list of rule objects

Note: the repository root `rules/` directory also contains legacy/demo `.rule` files and YARA content. The Python rule loader described here loads only `.json/.yml/.yaml`.

## Rule shape (implemented)

Rules are dictionaries with a small, intentionally simple shape. Common keys include:

- `id` (string, required): unique identifier
- `title` (string): correlation title
- `rationale` (string): human-readable explanation
- `conditions` (list, required): condition objects
- `logic` ("all"|"any", default: "all"): match policy across conditions
- `risk_score_delta` (number, default: 0): score adjustment when rule matches
- `tags` (list[string], default: []): classification tags

Each condition supports keys like:

- `field`: a `Finding` attribute name (for example `id`, `title`, `severity`)
- `contains`: substring match
- `equals`: exact string match
- `metadata_key`: look up `Finding.metadata[metadata_key]`
- `metadata_contains`: substring match against the metadata value

## Example rule (YAML)

```yaml
id: ip_forward_enabled
title: IP forwarding enabled
rationale: Host has net.ipv4.ip_forward=1 which increases routing capability.
logic: all
risk_score_delta: 5
tags: [routing, surface]
conditions:
  - metadata_key: sysctl_key
    equals: net.ipv4.ip_forward
    metadata_contains: "1"
```

## CLI helpers

### Lint rules

```bash
sys-scan-graph rule-lint --rules-dir rules/
```

This command returns a non-zero exit code when issues are found (useful in CI).

### Dry-run matching

```bash
sys-scan-graph rule-dry-run --rules-dir rules/ --findings-json findings.json
```

`findings.json` must be a JSON array where each element resembles:

```json
{
  "id": "example_finding_id",
  "title": "(optional title)",
  "severity": "info",
  "risk_score": 0,
  "metadata": {}
}
```

## Configure rule directories for analysis

`sys-scan-graph analyze` reads configuration from `./config.yaml` (current working directory).

Example:

```yaml
paths:
  rule_dirs:
    - rules/
    - rules/custom/
```

## Related documentation

- **[Architecture](Architecture.md)**
- **[Intelligence Layer](Intelligence-Layer.md)**
- **[CLI Guide](CLI-Guide.md)**
- **[Extensibility](Extensibility.md)**
