# Extensibility

This page documents the supported extension points in `sys-scan-graph` and its optional Python intelligence layer.

The goal is to make customization **safe, reviewable, and reproducible**:

- Prefer data-driven configuration (rules and config) over code changes.
- Keep the C++ core deterministic.
- Keep the intelligence layer local-first by default (no outbound LLM APIs unless explicitly opted in).

## Extend with correlation rules (recommended)

The lowest-friction customization mechanism is the rules engine. Rules live under `rules/` and are loaded from directories listed in `config.yaml`.

### 1) Add or edit a rule file

Create a new `.yml`, `.yaml`, or `.json` file under `rules/` (for example `rules/custom/my_org_rules.yaml`).

### 2) Point the agent at your rules

`sys-scan-graph` reads `./config.yaml` from the current working directory.

Example:

```yaml
paths:
  rule_dirs:
    - rules/
    - rules/custom/
```

### 3) Validate your rules

Use the built-in linter:

```bash
sys-scan-graph rule-lint --rules-dir rules/
```

### 4) Dry-run matching against sample findings

The dry-run command applies a rules directory to a JSON array of findings:

```bash
sys-scan-graph rule-dry-run --rules-dir rules/ --findings-json findings.json
```

This is useful for rapid iteration without running a full scan.

## Extend the C++ core with a new scanner (advanced)

The core scanner is implemented as C++20 module units under `src/scanners/modules/`.

### Suggested workflow

1. **Find the closest existing scanner** in `src/scanners/modules/` and copy its structure.
2. Implement a new module unit (for example, `src/scanners/modules/my_scanner.ixx`).
3. Register the scanner in the registry/composition root.
   - Registry code lives under `src/core/modules/` (see `src/core/modules/registry.ixx`).
   - The composition root is in `src/main.cpp`.
4. Ensure output conforms to the report schema (`schema/v4.json`).
5. Add tests under `tests/` (C++), and validate deterministic output ordering using `--canonical`.

Notes:

- Keep scanner output stable: avoid embedding timestamps or non-deterministic identifiers in finding IDs.
- Prefer explicit feature flags (`--enable/--disable`) consistent with existing scanners.

## Extending the Intelligence Layer — Adding an LLM provider

Providers live under `agent/sys_scan_agent/providers/` and are discovered by the factory in `agent/sys_scan_agent/llm_provider.py`.

Minimal steps:

1. Add a new provider module implementing the `ILLMProvider` Protocol (see `agent/sys_scan_agent/llm_provider.py` for the required methods and telemetry (`ProviderMetadata`)).
2. Add the new provider to the factory mapping or update `_maybe_init_from_env()` to include alias names and fallback logic. Handle opt-in for networked providers using `AGENT_EXTERNAL_LLM_ENABLED`.
3. Add tests under `agent/tests/` that mock the provider and validate behavior and telemetry.
4. Document the provider in `docs/wiki/Intelligence-Layer.md` and `docs/wiki/Extensibility.md` (what data may leave the host, required credentials, how to disable).

Security note: If the provider requires external network access, gate it behind `AGENT_EXTERNAL_LLM_ENABLED=1` and document clearly what is sent to the external service.

## Extend the Python intelligence workflow (advanced)

The intelligence workflow consumes `report.json` and produces `enriched_report.json`.

### Where to look

- Workflow orchestration: `agent/sys_scan_agent/graph/`
- CLI entry points: `agent/sys_scan_agent/cli.py` (`sys-scan-graph`)
- Correlation: `agent/sys_scan_agent/correlator.py`
- Canonicalization: `agent/sys_scan_agent/canonicalize.py`

### Adding a new enrichment step

1. Add your node/function under `agent/sys_scan_agent/graph/`.
2. Wire it into the workflow (graph app when enabled, or scaffold workflow fallback).
3. Add tests under `agent/tests/`.
4. Keep outputs deterministic (stable ordering, stable IDs).

## Add a new LLM provider (advanced)

Providers live under `agent/sys_scan_agent/providers/`.

- Default provider selection is implemented in `agent/sys_scan_agent/llm_provider.py`.
- Provider implementations include `local_llm_provider.py` (heuristic), `local_qwen_provider.py` (offline model), and `langchain_api_provider.py` (opt-in external inference).

To add a new provider:

1. Create a provider module under `agent/sys_scan_agent/providers/`.
2. Update the provider factory to recognize a new `AGENT_LLM_PROVIDER` value.
3. Prefer local/offline providers.
  If you add an external provider, require an explicit opt-in gate (similar to `AGENT_EXTERNAL_LLM_ENABLED`) and document:
  - what data may leave the host
  - what credentials users must supply (the project must not ship keys)
  - any costs/quotas and how to disable the provider.

## Related documentation

- **[Architecture](Architecture.md)** — system structure and data contracts
- **[CLI Guide](CLI-Guide.md)** — commands and environment variables
- **[Rules Engine](Rules-Engine.md)** — rule formats and validation
- **[Contributing](../../CONTRIBUTING.md)** — development workflow
