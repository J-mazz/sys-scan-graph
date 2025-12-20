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

- `build-coverage/coverage.html` (HTML details)
- `build-coverage/coverage.xml` (XML)

### Quality gate

The build enforces a **minimum line coverage** threshold (default: **85%**) via:

- `SYS_SCAN_COVERAGE_MIN` (CMake cache variable)

Function/branch/region coverage is still *reported* in the summary output, but it is not used to fail the `coverage` target.

### What is (and is not) counted

Coverage is intentionally scoped to `src/` and excludes build directories and test sources. Some infrastructure/entrypoint and thin module shim files are excluded as well.

The authoritative list of filters/excludes lives in `CMakeLists.txt` under the `coverage` custom target.

## Python agent tests (optional)

The Python package is in `agent/`.

```bash
cd agent
python -m pytest -v
```
