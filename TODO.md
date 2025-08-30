# Local TODO (not committed)

## eBPF Implementation Status: COMPLETED

**Status Update (2025-08-30)**: eBPF implementation is now working in the current environment. All basic events (exec.trace and net.connect) are captured successfully with proper metadata.

### eBPF Resume Plan

1. Ensure per-kernel bpftool binary available:
   - Packages (Ubuntu): `linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)`
   - Verify: `/usr/lib/linux-tools-$(uname -r)/bpftool` exists; wrapper warning gone.
2. Confirm BTF file present: `/sys/kernel/btf/vmlinux` (already true previously).
3. Reconfigure strict build:
   - `rm -rf build`
   - `cmake -S . -B build -DWITH_EBPF=ON -DWITH_EBPF_STRICT=ON -DCMAKE_BUILD_TYPE=Release`
   - `cmake --build build -j` (no fallback message expected)
4. Run test capture:
   - `sudo ./build/sys-scan --ioc-exec-trace 5` in one terminal.
   - During window: run a few processes (`/bin/true`, `ls`) and an outbound connect (`curl https://example.com`).
5. Verify findings contain types: `exec.trace` (or equivalent) and `net.connect` with metadata (pid, comm, dst_ip, dst_port).

## Current State Snapshot

- Kernel: 6.14.0-28-generic
- BTF: present
- bpftool: wrapper found; kernel-specific binary required (install step pending at time of snapshot)
- Code: `process_exec.bpf.c` emits EXEC + CONNECT via tracepoints (sched_process_exec & sys_enter_connect) -> ring buffer typed events.
- User space: `EbpfScanner.cpp` now uses RAII for skeleton & ring buffer; detailed logging on failure paths; still operates with stub behavior if skeleton generation fails (bpftool missing).

## Nice-to-Haves (After Basic Events Work)

Completed:
- [x] RAII + detailed error logging in `EbpfScanner.cpp` (skeleton + ring buffer) – leak paths removed, easier diagnosis on permission/kernel issues.

Pending / Proposed:
- Add IPv6 connect capture (sys_enter_connect handles sockaddr length; add AF_INET6 parsing).
- Add event version / size field for forward compatibility.
- Rate limiting / max event cap to avoid high CPU if flood.
- Unit test: Inject synthetic ring buffer records to validate parsing.
- Raw object loader fallback (no skeleton) for environments lacking bpftool.
- Expand risk scoring for suspicious outbound connections (e.g. rare ports / external IP heuristics).
- Structured metrics: counts for exec events, connect events, poll errors, dropped events (expose via JSON meta).
- Optional early abort if zero events after N polls (fast fail path).

## Raw Object Loader (If Needed Instead of Skeleton)
Steps (not yet implemented):
- Compile BPF object unconditionally to `generated/ebpf/process_exec.bpf.o`.
- Add loader utility to open object with `bpf_object__open_file` / `bpf_object__load` and attach programs by section name.
- Gate with CMake option `WITH_EBPF_RAW_LOADER` (mutually exclusive with skeleton path).

## Troubleshooting Checklist
- If build still warns "bpftool not found for kernel": ensure `linux-tools-$(uname -r)` installed and PATH includes `/usr/lib/linux-tools-$(uname -r)` or symlink binary to `/usr/local/bin/bpftool`.
- If skeleton compiles but no events: confirm running as root and tracepoints exist (`bpftool prog show | grep sched_process_exec`).
- If connect events missing but exec present: validate syscall tracepoint enabled (`ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect`). Enable ftrace subsystem if needed.

## Deferred Ideas
- Capture exec argv / sha256 of first mapped file (needs careful size limit & copy_from_user safety).
- Add per-event monotonic timestamp for sequencing.
- Correlate connect events to preceding exec event (short-lived processes) for basic lineage.

## Current Focus: Non-eBPF Improvements

### Phase 2: Refactoring & Cohesion (The Consolidation Quarter)

Goal: Address medium-severity findings by refactoring complex components, modernizing code, and improving the contracts between system layers.

1. Refactor the Monolithic ModuleScanner
   - Action: Break down the large ModuleScanner function into smaller, testable components. Create distinct helper classes or functions for CompressionUtils, ElfModuleHeuristics, and SignatureAnalyzer. (Ref: Medium 1, Sec 10.2)
   - Why: Improves maintainability, testability, and ease of future extension for module analysis.
2. Modernize C++ Codebase
   - Action: Replace all hand-rolled IP address and port conversion logic with standard, portable library calls (ntohs, inet_ntop). (Ref: Medium 2)
   - Action: Consolidate duplicated utility functions like trim into a shared utility library. (Ref: Low/Style)
   - Why: Increases portability, readability, and reduces maintenance burden.
3. Strengthen Security Posture & Privilege Handling
   - Action: Audit `main.cpp` privilege drop lifecycle: initialize resources (eBPF, rules), then drop capabilities, then apply seccomp filters last. Add logging for capability state before and after drop. (Ref: High 8)
   - Action: Implement enforcement points for PII suppression flags (no_user_meta, etc.) within each scanner and add unit tests to verify redaction. (Ref: High 7)
   - Why: Hardens scanner and ensures privacy controls function as intended.
4. Improve Schema and API Contracts
   - Action: Create `SCHEMA_MIGRATION.md` detailing plan and timeline for moving from v2 to v3 FactPack schema. (Ref: Medium 5)
   - Action: Add distinct status field (e.g., `baseline_db_missing`) to baseline query output to differentiate first run from genuinely new finding. (Ref: Medium 7)
   - Why: Provides clarity for developers and API consumers, improving integration reliability.

## Phase 3: Strategic Enhancements & Future-Proofing (The Long-Term Vision)

Goal: Implement architectural improvements and strategic features that enhance performance, extensibility, and overall platform value.

1. Enhance the Event Pipeline
   - Action: Implement streaming NDJSON output mode (`--ndjson`) enabling incremental processing from long-running scanners like eBPF. (Ref: Sec 5)
   - Why: Moves toward near-real-time analysis capability.
2. Improve Performance and Determinism
   - Action: Add per-scanner timing metrics to `ScanResult` metadata.
   - Action: Create a "fast mode" flag (`--fast-scan`) disabling resource-intensive scanners (full module analysis, eBPF) for quick triage. (Ref: Sec 7)
   - Why: Gives users control over performance/thoroughness trade-offs.
3. Expand and Document Extensibility
   - Action: Fill documentation gaps in `README.md` (rule engine schema, risk model, build flags). (Ref: Sec 12)
   - Action: Investigate pluggable architecture for scanners (e.g., `dlopen`) for dynamic loading, reducing core binary footprint. (Ref: Sec 14)
   - Why: Lowers contributor barrier and enables flexible deployments.

## Implementation Priority and Timeline

### Phase 1: Critical Security (Weeks 1-2) ✅ COMPLETED
- ✅ **Fix shell injection vulnerability in IntegrityScanner**: Replaced insecure `popen()` with secure `fork/execvp` implementation
- ✅ **Verify ModuleScanner security**: Confirmed native liblzma/zlib decompression with bounded size limits (already secure)
- ✅ **Verify main.cpp GPG signing**: Confirmed secure fork/execvp pattern (already secure)
- Add input validation framework
- Add memory sanitizer testing

### Phase 2: Code Quality (Weeks 3-4)
- Refactor main.cpp into smaller components
- Standardize error handling
- Add comprehensive unit tests
- Implement common scanner utilities

### Phase 3: Performance (Weeks 5-6)
- Implement file caching
- Add parallel scanner execution
- Optimize memory usage
- Add performance monitoring

### Phase 4: Intelligence Layer (Weeks 7-8)
- Enhance LLM provider reliability
- Add pipeline checkpointing
- Implement comprehensive metrics
- Add alerting system

### Phase 5: Documentation (Weeks 9-10)
- Complete API documentation
- Create developer onboarding guide
- Add usage examples
- Create deployment guides

## Validation and Testing Strategy

### Integration Testing
- Add comprehensive integration tests
- Create test scenarios for end-to-end, performance, and security

### Performance Benchmarking  
- Add benchmarking suite for scanner performance and memory usage

### Security Testing
- Add security testing for input validation and privilege escalation

