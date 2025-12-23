# Developer Guide — short and practical

This page collects the most common developer tasks and where to look in the code when you need to make changes, run tests, or debug behavior.

## Quick dev setup

1. Clone and enter repo:

```bash
git clone https://github.com/J-mazz/sys-scan-graph.git
cd sys-scan-graph
```

2. Tools (recommended):
- Linux with Clang (modules support required for C++ build)
- Ninja build
- Python >= 3.10 (for the agent and tests)

3. Build core scanner (C++):

```bash
export CC=clang
export CXX=clang++
cmake -B build -S . -G Ninja -DCMAKE_CXX_STANDARD=23
cmake --build build -j$(nproc)
```

4. Python agent (optional):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ./agent[dev]
# Run agent tests: cd agent; pytest -q
```

## Run a specific scanner locally (use test fixtures)

- Use `--test-root` to make a local folder appear as `/` to the scanner:

```bash
./build/sys-scan --canonical --output report.json --test-root ./tests/fixtures/simple-root
```

- To run a single scanner, use `--disable` for others or `--enable` to pick the one you want:

```bash
./build/sys-scan --enable processes --disable network --output report.json
```

## Running tests

- C++ unit tests (CTest target `sys-scan-tests`):

```bash
cmake -B build -S . -DBUILD_TESTING=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

- Python tests (agent):

```bash
cd agent
python -m pytest -v
```

## Coverage

- C++ (use `SYS_SCAN_ENABLE_COVERAGE=ON` in configure and the `coverage` custom target — see `docs/TEST_COVERAGE.md`).
- Python (pytest-cov, see `docs/TEST_COVERAGE.md` for the exact commands used in CI).

## Debugging & common tricks

- Use `LOGLEVEL=DEBUG` (or set logger level in tests) to see more detail from the agent.
- To debug the registry, run the core with `--verbose` (if available) or add temporary logging in `src/core/modules/registry.ixx`.
- Many scanners are implemented to be testable via DI (see `tests/test_core.cpp` and `FakeFileSystem` / `FakeProcessRunner` usage).

## Adding or changing a scanner

1. Implement a new scanner module under `src/scanners/modules/` following existing examples (e.g., `process_scanner.ixx`).
2. Register it in the composition root (`src/main.cpp`) or add dynamic registration as appropriate.
3. Add C++ unit tests under `tests/` using the `FakeFileSystem` harness.
4. Ensure outputs conform to `schema/v4.json` and are deterministic (use `--canonical` in tests when validating JSON ordering).

## Adding / changing LLM providers and agent nodes

- LLM provider discovery and default selection lives in `agent/sys_scan_agent/llm_provider.py`.
- Provider implementations belong in `agent/sys_scan_agent/providers/` (see `local_qwen_provider.py`, `local_llm_provider.py`, `langchain_api_provider.py`).
- Update tests under `agent/tests/` to mock provider behaviour (do not ship model weights in repo).

## Files & shortcuts (where to look)

- `src/main.cpp` — CLI parsing and composition root
- `src/core/modules/registry.ixx` — scanner registration & orchestration
- `src/core/modules/report.ixx` — `Report::consume()` and ScanResult
- `src/scanners/modules/*` — scanner implementations
- `agent/sys_scan_agent/cli.py` — agent CLI entrypoints
- `agent/sys_scan_agent/graph.py` — workflow assembly (LangGraph)
- `agent/sys_scan_agent/llm_provider.py` — provider selection logic

## Coding standards and tests

- Python formatting: `black` / `isort` enforced by pre-commit in `agent/` dev env (see `pyproject.toml`).
- C++ static analysis: CI runs `clang-tidy` and `codeql` periodically.

---

If you'd like, I can add an automated link checker and a small pytest that validates `agent/sys_scan_agent/cli.py` default schema path to prevent future regressions. Would you like that added next?