# sys-scan Intelligence Layer (Agent MVP)

This directory contains a Python prototype for the analysis / correlation / summarization layer built on top of the core `sys-scan` C++ collector.

Goals (Phase 1 MVP):
- Load a sys-scan JSON report (schema v2)
- Validate & parse into typed Pydantic models
- Apply baseline diffing (SQLite) for new/changed findings
- Apply deterministic correlation rules (YAML/JSON) to build enriched correlations
- Reduce large arrays into compact, model-friendly summaries
- Produce structured summaries (executive, analyst JSON) using a pluggable LLM interface (stub by default)
- Derive an ordered action plan deterministically
- Emit a consolidated enriched JSON artifact with all intermediate state for reproducibility

## Quick Start

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m agent.cli analyze --report ../report.json --out enriched_report.json
```

If you don't have a `report.json`, run the C++ scanner first:
```
./build/sys-scan -o report.json
```

## Components
- models.py: Pydantic models & schema extensions (host_id, scan_id, risk_subscores, tags...)
- baseline.py: SQLite-backed baseline store (host_id + finding identity hash)
- rules.py: Deterministic correlation rule engine (separate from C++ emission rules)
- reduction.py: Token/cost reduction transforms
- llm.py: LLM abstraction + stub implementation (returns deterministic templates)
- pipeline.py: Orchestrates nodes (validate -> baseline -> correlate -> reduce -> summarize -> actions -> output)
- cli.py: Typer-based CLI wrapper

## Roadmap
See top-level project discussion for multi-phase evolution. This MVP keeps external dependencies minimal.

## Security Notes
- All LLM-bound content uses reduced summaries (no raw large arrays)
- Redaction hooks present (not yet enforcing username/IP hashing)

## License
Follows repository root license.
