# Test coverage

### Measured results (2025-12-21)

C++ (src/ layer)
- statements/lines: **924** total, **810** covered → **87.7%** (810 / 924)
- functions: **116** total, **108** covered → **93.1%** (108 / 116)
- branches: **2728** total, **1246** covered → **45.7%** (1246 / 2728)

Python (agent)
- statements: **17748** total, **2195** missed → **85%** overall coverage 
- branches: **2794** total, **410** partial branches reported 

**Notes & recommendations:**
- Branch coverage is low (45.7%). Focus on adding tests that exercise alternate branches and error-handling paths in scanner modules and registry logic to raise this metric.
- The generated HTML reports live in `build-cov/` (`coverage.html`, `coverage-details.html`) and can be reviewed locally or uploaded as CI artifacts for easy browsing.

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
- **Python agent overall coverage**: **85%** (17748 statements, 2195 missed)
- Coverage XML written to: `build-cov/agent-coverage.xml`


This section explains how to run tests and coverage for **sys-scan-graph**.

## Summary of measured coverage (2025-12-21)

| Component | Metric | Value |
|---|---:|---:|
| C++ (`src/` layer) | lines | **87.7%** (810 / 924) |
| C++ (`src/` layer) | functions | **93.1%** (108 / 116) |
| C++ (`src/` layer) | branches | **45.7%** (1246 / 2728) |
| Python (agent) | overall (statements) | **85%** (17748 stmts, 2195 missed) |

Artifacts:
- C++ HTML report: `build-cov/coverage.html` and `build-cov/coverage-details.html`
- C++ XML: `build-cov/coverage.xml`
- Python agent XML: `build-cov/agent-coverage.xml`

Commands used in this run:

- C++ (gcovr via coverage target):

```bash
cmake -B build-cov -S . -DSYS_SCAN_ENABLE_COVERAGE=ON
cmake --build build-cov -j$(nproc)
cmake --build build-cov --target coverage
# or direct gcovr (focused on src/):
cd build-cov
gcovr -r .. --filter ../src --html --html-details -o coverage.html --xml -o coverage.xml --fail-under-line 85
```

- Python (agent):

```bash
# activate a venv with pytest-cov installed (example: .venv-312)
source .venv-312/bin/activate
cd agent
python -m pytest --disable-warnings --maxfail=1 --cov=agent --cov-report=term --cov-report=xml:../build-cov/agent-coverage.xml
```

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

- `build-coverage/coverage.html` (HTML summary)
- `build-coverage/coverage-details.html` (per-file HTML details)
- `build-coverage/coverage.xml` (XML)

If you prefer running gcovr directly for a focused src-layer report, example command used here:

```bash
# from repo root, after running tests in build-cov
cd build-cov
gcovr -r .. --filter ../src --html --html-details -o coverage.html --xml -o coverage.xml --fail-under-line 85
```
