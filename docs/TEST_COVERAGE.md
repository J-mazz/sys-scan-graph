# Test Coverage Report

**Last Updated:** October 1, 2025  
**Project:** sys-scan-graph v6.0

---

## Executive Summary

| Metric | C++ Core | Python Agent | Combined |
|--------|----------|--------------|----------|
| **Test Suites** | 56 suites | 249 tests | 305 total |
| **Pass Rate** | 100% | 83.1% | 85.6% |
| **Code Coverage** | ~85%* | 57% | — |
| **Test LOC** | 15,761 lines | ~6,240 lines | ~22,000 lines |

\* Estimated from GTest/GMock coverage patterns  
— Combined coverage not computed (different toolchains)

---

## C++ Core Scanner Tests

**Status:** ✅ All tests passing  
**Framework:** GoogleTest + GoogleMock  
**Total Test Suites:** 56  
**Test Lines of Code:** 15,761

### Test Distribution

```text
Core Infrastructure:     12 suites (ArgumentParser, Config, JSONWriter, etc.)
Security Scanners:       18 suites (Integrity, SUID/SGID, Processes, etc.)
File System Scanners:     8 suites (WorldWritable, Mounts, Kernel Params)
Container/Hardening:      6 suites (Containers, MAC, Auditd, Hardening)
Extended Scenarios:      12 suites (Privilege, Canonical, Compliance)
```

### Notable Test Categories

- **Memory Safety:** Validated with AddressSanitizer, UndefinedBehaviorSanitizer
- **Fuzzing:** Smoke tests with libFuzzer (config + rule parsing)
- **Cross-Build:** Debug and Release builds tested independently
- **Integration:** Comprehensive system tests with real scanners

### Recent Fixes (v6.0)

- ✅ Fixed heap-use-after-free in ArgumentParser test (vector reallocation)
- ✅ Resolved Debug build metadata differences in canonical tests
- ✅ Eliminated implementation-defined alignment assumptions

---

## Python Intelligence Layer Tests

**Status:** ⚠️ 6 failures, 36 skipped  
**Framework:** pytest + pytest-cov  
**Total Tests:** 249  
**Pass Rate:** 83.1% (207 passed / 6 failed / 36 skipped)  
**Code Coverage:** 57% (6,240 / 10,856 statements)

### Coverage Breakdown by Module

| Module | Coverage | Status |
|--------|----------|--------|
| **Core Pipeline** | 75-85% | ✅ Good |
| Graph Analysis | 82% | ✅ Good |
| Knowledge Enrichment | 78% | ✅ Good |
| LLM Provider | 71% | ⚠️ Moderate |
| Metrics/Baseline | 57% | ⚠️ Needs Work |
| CLI/Config | 45-60% | ⚠️ Needs Work |

### Test Categories

```text
Unit Tests:           ~180 tests (core logic, transformations)
Integration Tests:    ~40 tests (pipeline, graph, agent)
Mocking Tests:        ~25 tests (LLM, tool servers)
Skipped Tests:        36 (missing dependencies, slow integration)
```

### Known Issues

1. **6 Failures:** Mostly related to:
   - LLM mock server timing issues
   - Test fixture cleanup ordering
   - External dependency availability

2. **36 Skipped:** Tests requiring:
   - Mistral model files (not in CI)
   - GPU availability
   - External API credentials

---

## Coverage Analysis

### Python Module Coverage (Top 10)

```text
sys_scan_graph_agent/
├── __init__.py                        100%
├── graph_nodes_enhanced.py             95%
├── graph_state.py                      92%
├── knowledge.py                        88%
├── canonicalize.py                     85%
├── graph_analysis.py                   82%
├── pipeline.py                         78%
├── llm_provider.py                     71%
├── metrics.py                          57%
└── cli.py                              45%
```

### Uncovered Critical Paths

- Edge case error handling in LLM retry logic
- Rare attack pattern detection branches
- Performance degradation scenarios (not yet automated)
- Multi-tenant isolation edge cases

---

## Test Execution

### C++ Tests

```bash
# Build all test targets
cmake --build build --target all -j8

# Run with CTest
ctest --test-dir build --output-on-failure

# Run with sanitizers
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON ..
make && ctest
```

### Python Tests

```bash
cd agent/

# Run all tests
python3 -m pytest -v

# Run with coverage
python3 -m pytest --cov=sys_scan_graph_agent --cov-report=html

# View coverage report
open htmlcov/index.html
```

---

## Continuous Integration

**GitHub Actions Workflows:**

- ✅ `ci.yml`: Build + test (Release/Debug matrix)
- ✅ `sanitize`: ASan + UBSan builds
- ✅ `python-test`: Python test suite + coverage
- ✅ `fuzz-smoke`: Fuzzer smoke tests
- ✅ `codeql`: Static analysis

**Test Execution Time:**

- C++ tests: ~2-3 minutes
- Python tests: ~6 seconds (excluding skipped)
- Full CI matrix: ~8-12 minutes

---

## Quality Gates

### Current Standards

| Gate | Threshold | Current | Status |
|------|-----------|---------|--------|
| C++ Pass Rate | 100% | 100% | ✅ |
| Python Pass Rate | ≥85% | 83.1% | ⚠️ |
| Python Coverage | ≥60% | 57% | ⚠️ |
| Memory Leaks | 0 | 0 | ✅ |
| Sanitizer Errors | 0 | 0 | ✅ |

### Improvement Targets (v6.1)

- [ ] Increase Python pass rate to 90% (fix 6 failures)
- [ ] Increase Python coverage to 65% (add integration tests)
- [ ] Reduce skipped tests to <20 (mock external dependencies)
- [ ] Add performance regression tests (benchmark suite)

---

## Contributing

When adding new features, ensure:

1. **C++ Code:** Add corresponding GoogleTest suite
2. **Python Code:** Add pytest tests with ≥70% coverage
3. **Integration:** Add end-to-end test if touching pipeline
4. **Documentation:** Update this report with new test counts

**Test Naming Convention:**

```cpp
// C++
TEST_F(ScannerNameTest, BehaviorDescription) { ... }

// Python
def test_module_function_behavior():
    """Test that function handles edge case X."""
```

---

## References

- **C++ Coverage:** Generated via CMake + gcov/lcov (not included in this report)
- **Python Coverage:** `agent/htmlcov/index.html` (generated by pytest-cov)
- **Test Files:**
  - C++: `tests/test_*.cpp`
  - Python: `agent/tests/test_*.py`
