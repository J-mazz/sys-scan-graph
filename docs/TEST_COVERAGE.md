# Test coverage

This document explains how to run tests and coverage for **sys-scan-graph**.

## C++ core tests

The C++ test runner is built as `sys-scan-tests` (CTest target: `sys-scan-tests`).

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

## C++ coverage (gcovr + llvm-cov)

Coverage is generated via the `coverage` build target when `SYS_SCAN_ENABLE_COVERAGE=ON`.

```bash
cmake -B build-coverage -S . \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON \
  -DSYS_SCAN_ENABLE_COVERAGE=ON

cmake --build build-coverage -j$(nproc)
cmake --build build-coverage --target coverage
```

Artifacts (written to the build directory):

- `build-coverage/coverage.html` (HTML details) — add `--html=coverage.html` to the gcovr invocation if missing
- `build-coverage/coverage.xml` (XML)

### Measured results (this run, 2025-12-21)
- lines: **87.7%** (810 / 924)
- functions: **93.1%** (108 / 116)
- branches: **45.7%** (1246 / 2728)

Note: branch coverage is reported but not enforced; improving branch coverage requires adding tests that exercise alternate code paths and error handling in low-coverage components.

### Quality gate

The build enforces a **minimum line coverage** threshold (default: **85%**) via:

- `SYS_SCAN_COVERAGE_MIN` (CMake cache variable)

Function/branch/region coverage is still *reported* in the summary output, but it is not used to fail the `coverage` target.

### What is (and is not) counted

Coverage is intentionally scoped to `src/` and excludes build directories and test sources. Some infrastructure/entrypoint and thin module shim files are excluded as well.

The authoritative list of filters/excludes lives in `CMakeLists.txt` under the `coverage` custom target.

## Python agent tests and coverage

The Python package is in `agent/`.

Run tests normally:

```bash
cd agent
python -m pytest -v
```

Run tests with coverage (requires `pytest-cov`):

```bash
# activate your environment where pytest-cov is installed (example: .venv-312)
source .venv-312/bin/activate
cd agent
python -m pytest --disable-warnings --maxfail=1 --cov=agent --cov-report=term --cov-report=xml:../build-cov/agent-coverage.xml
```

### Measured results (this run, 2025-12-21)
- **Python agent overall coverage**: **88%** (17748 statements, 2195 missed)
- Coverage XML written to: `build-cov/agent-coverage.xml`

### Notes & next steps
- Several modules have low coverage (see per-file output). Prioritize tests for:
  - providers with external dependencies (e.g., `providers/*` implementations)
  - complex pipeline transforms (`graph/`, `summarization.py`) to improve branch and behavior coverage
- Consider adding a gated CI job that fails on drop of overall agent coverage below a chosen threshold (e.g., 85%).
