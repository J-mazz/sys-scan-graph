# Architecture (Technical Details)

This page dives into the **current, code-backed implementation**.

If you’re looking for “what runs where,” start with:

- `CMakeLists.txt` (targets + module file sets)
- `src/main.cpp` (C++ composition root)
- `src/core/modules/*.ixx` (core module APIs)
- `src/scanners/modules/*.ixx` (scanner implementations)
- `agent/sys_scan_agent/cli.py` (Python CLI entrypoints)

## C++ core layout

### Targets and module structure

The build defines a module library (`sys_scan_modules`) and an executable (`sys-scan`). The module library is made from `.ixx` sources under:

- `src/core/modules/`
- `src/scanners/modules/`

In this repository snapshot, `src/main.cpp` is intentionally small and acts as a composition root.

### Core types and interfaces

At a high level, the C++ core revolves around three concepts:

1. **A common finding model** (`sys_scan.types`)
2. **A scanner interface that yields findings** (`sys_scan.scanner`)
3. **A registry/executor that runs scanners and aggregates results** (`sys_scan.registry` + `sys_scan.report`)

#### Findings

The core finding object contains:

- severity (enum)
- title/description
- an identifier (often a file path, module name, or other stable key)
- optional metadata for machine parsing

Severity mapping helpers live in `sys_scan.types` (e.g., `severity_to_string`).

#### Coroutines: streaming findings

Scanners return a coroutine-backed `Generator<Finding>` (exported by `sys_scan.coro`). This supports a streaming-style implementation where scanners can `co_yield` findings as they’re discovered.

The report uses a consumption pattern:

- `Report::consume(scanner_name, generator)` iterates the generator and captures its results into a per-scanner `ScanResult` (see `sys_scan.report`).

### Dependency injection (DI) and system services

Instead of calling the OS directly everywhere, scanners can depend on abstract interfaces.

Key abstractions live in `sys_scan.interfaces`:

- filesystem access (`IFileSystem`)
- command execution (`IProcessRunner`)
- system information (`ISystemInfo`)
- sleep/time (`ISleeper`)

Concrete implementations like `RealFileSystem` and `RealProcessRunner` live in `sys_scan.system_services`.

This DI approach makes it practical to unit-test scanners by swapping in fakes.

### Execution orchestration

`ScannerRegistry` owns scanner instances and runs them into a shared `Report` (see `sys_scan.registry`).

Important behaviors:

- Supports **sequential** execution.
- Supports **parallel** execution when enabled via `Config`.
	- Concurrency is bounded by a semaphore and `parallel_max_threads`.

The configuration type (`sys_scan.config`) also includes toggles for enabling/disabling families of scanners and for output formatting preferences.

## Scanner modules

Scanner implementations are C++ modules under `src/scanners/modules/*.ixx`. Each scanner is responsible for a specific signal source or domain.

Examples you can trace end-to-end:

- `ProcessScanner` reads process information from `/proc` (and emits collection warnings when process metadata can’t be read).
- `KernelScanner` checks kernel parameters under `/proc/sys/...`.
- `ModuleScanner` enumerates loaded kernel modules.
- `MACScanner` inspects SELinux/AppArmor state.
- `IntegrityScanner` can call out to package managers (e.g., `dpkg -V` / `rpm -Va`) via `IProcessRunner`.

For a scanner-by-scanner index, see **[Core Scanners](Core-Scanners.md)**.

## JSON schemas and report formats

The repository includes a single active JSON schema in `schema/` (`schema/v4.json`). The Python intelligence layer expects the raw scan report to conform to that schema.

The repository root also includes a sample `report.json` showing the v2 shape.

### Current limitation

In this workspace snapshot:

- The core emits the v4 ground-truth-compatible JSON when requested by CLI flags.

The schema and sample report are still useful as a stable contract and for testing the Python analysis pipeline with fixtures.

## Python intelligence layer

The Python layer is packaged under `agent/` and implements a Typer CLI in `agent/sys_scan_agent/cli.py`.

Key capabilities implemented in code:

- report validation against `schema/v4.json` (`validate-report`)
- enrichment workflow (`analyze`) producing `enriched_report.json`
- canonicalization of output for stable diffs
- optional metrics export (`--metrics-out`) and optional HTML/diff artifacts

## If you’re extending the system

### Add a new C++ scanner

1. Create a new module in `src/scanners/modules/` implementing the scanner interface.
2. Register it in `src/main.cpp` (current composition root) and/or in a future CLI entrypoint.
3. Add tests for the scanner using DI-friendly fake services.

### Add a new Python enrichment step

1. Add a node/function under `agent/sys_scan_agent/`.
2. Wire it into the workflow called by `run_intelligence_workflow()`.
3. Add a fixture report and a pytest validating the new behavior.
