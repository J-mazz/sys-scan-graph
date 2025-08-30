# Local TODO (not committed)

Purpose: Scratchpad for resuming eBPF implementation after kernel / toolchain work.

## eBPF Resume Plan
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
- User space: `EbpfScanner.cpp` parses heterogeneous events; currently operates with stub skeleton when generation fails.

## Nice-to-Haves (After Basic Events Work)
- Add IPv6 connect capture (sys_enter_connect handles sockaddr length; add AF_INET6 parsing).
- Add event version / size field for forward compatibility.
- Rate limiting / max event cap to avoid high CPU if flood.
- Unit test: Inject synthetic ring buffer records to validate parsing.
- Raw object loader fallback (no skeleton) for environments lacking bpftool.
- Expand risk scoring for suspicious outbound connections (e.g. rare ports / external IP heuristics).

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

(End of local TODO)

## Phase 3: Advanced eBPF Roadmap (Planned)

### 1. In-Kernel Exec Path Filtering
Goal: Reduce ring buffer volume; drop uninteresting exec events before user space.
Implementation Plan:
1. Add `BPF_MAP_TYPE_HASH` named `trusted_exec` keyed by 64-bit FNV-1a hash of path prefix or full path (value: u8 1).
2. User space (EbpfScanner init) populates map (e.g. `/usr/bin/`, `/bin/`, `/usr/sbin/`).
3. In `sched_process_exec` handler: derive executable path (future: `bpf_d_path`). Interim: approximate using `task->comm` OR pathname if accessible; hash and lookup.
4. If present -> return (drop event). Else emit event.
5. Expose counter map for dropped vs emitted.
Verification: Filter `/usr/bin/`; running `ls` yields no exec event; running `/tmp/test.sh` yields event.

### 2. Kernel-Validated PID Metadata Map
Goal: Anti-masquerade by comparing /proc vs kernel snapshot.
Implementation Plan:
1. Map `pid_meta` (key: u32 pid, value struct { u64 start_ns; u32 uid; char comm[16]; }).
2. Populate on exec (overwrite).
3. ProcessScanner: for each PID read map; compare comm and start time (convert /proc stat start). Differences -> finding.
4. Cleanup: optional LRU map or user sweep after scan.
Verification: Synthetic test or controlled rename trick to create mismatch.

### 3. File Integrity Monitoring (FIM)
Goal: Real-time detection of writes to critical files (e.g. `/etc/passwd`).
Implementation Plan:
1. Map `fim_watch` (key: 64-bit hash of canonical path, value: flags (e.g. required perms)).
2. Attach to `security_file_open` (preferred) or `sys_enter_openat` + track flags.
3. On open with write flags and hash match -> emit FIM event (store hash, pid, comm, flags).
4. User space maps hash -> cleartext path list.
Verification: Append to `/etc/passwd` triggers event; read-only open does not.

### Shared Enhancements
- Add versioned header to all events (u16 ver, u16 type, u32 size).
- Hashing: Implement 64-bit FNV-1a in user space; kernel only consumes provided hashes.
- Metrics map: counters for filtering, pid_meta writes, fim hits.
- Feature detection: attempt to load each program; if load fails (missing LSM helpers) gracefully disable feature.

### Delivery Order
1. Exec filtering
2. PID metadata correlation
3. FIM
4. Event versioning & hashing refactor

### Open Questions
- Path acquisition robustness (fallback strategies).
- Map eviction policy for pid_meta under high churn.

-- End Phase 3 Plan --
 analysis based on the architecture document plus the exposed source (main.cpp & Config.h). I focus on correctness, security, determinism, performance, extensibility, and latent technical debt. Actionable recommendations are prioritized.

================================================================
A. Argument / Configuration Layer
================================================================
Observations
1. Manual flag parsing: Repetitive if/else chain; risk of silent drift between help text, Config fields, and implementation.
2. Missing flag handling: --seccomp-strict is advertised in help (line 76) but never parsed (no branch sets cfg.seccomp_strict=true). This is a correctness & security gap (users think strict mode is enforced but it never is).
3. Partially exposed Config fields:
   - integrity_pkg_rehash, integrity_pkg_rehash_limit exist in Config but no CLI flags in help or parsing.
   - fs_world_writable_limit exists but no flag; mismatch between design and operational control.
4. Default semantics ambiguity:
   - ioc_exec_trace_seconds defaults to 0 in Config (comment: 0=default 3s). main.cpp sets seconds only if a numeric follows; if absent it remains 0. Downstream code must normalize to 3; any missed normalization yields a 0-second trace (effectively disabled). This is fragile.
5. Duplicate or conflicting formatting logic: flags pretty, compact, canonical, ndjson, sarif can combine in undefined ways (e.g. --sarif + --ndjson). No conflict resolution logic.
6. Global singleton config() encourages hidden coupling and complicates testing & parallelization. Hard to run multiple scan contexts in-process (e.g., library embedding).
7. Severity filtering & fail-on logic occurs only after full scan generation (lines 218–225) rather than streaming; memory and latency could be improved by early filtering.

Recommendations
- Introduce a declarative flag specification table (name, target field pointer / setter, expects value, validator, conflicts, default). Generate help text from this table to eliminate drift.
- Add validation phase: detect unknown combinations (e.g., NDJSON + SARIF simultaneously) and missing required values (e.g., --sign-gpg without --output).
- Normalize defaults right after parse (e.g., if ioc_exec_trace && ioc_exec_trace_seconds==0 -> 3).
- Enforce explicit severity enumeration now (internally) while maintaining string CLI compatibility via bidirectional mapping.
- Remove silent non-implemented flags (or implement them) before a release: seccomp_strict, integrity_pkg_rehash* etc.
- Consider layered config: (a) compile-time defaults, (b) file-based config, (c) env overrides, (d) CLI; produce an emitted “effective config” block in JSON meta for transparency.

================================================================
B. Security Surfaces & Hardening
================================================================
Observations
1. system() invocation for GPG signing (lines 211–214):
   - Command constructed via string concatenation with user-provided key id and output path.
   - Shell injection risk if output_file or key contain spaces or metacharacters; even if typical usage is benign, defense-in-depth suggests a safer invocation strategy.
2. External decompression utilities for modules (architecture doc) rely on trusted root-owned paths but still expand the attack surface (PATH confusion, potential future path traversal).
3. Two seccomp applications: early (line 174) and again at line 203. Second apply is redundant; if the profile forbids re-applying certain syscalls, it might fail unexpectedly (currently logged as continue).
4. Capability drop occurs before rule directory reading? Actually: set_config then file reading (allowlist) then capability drop (line 172). If future scanners or rule loading require CAP_DAC_READ_SEARCH for deeper reads, dropping earlier may cause subtle privilege failures (document this ordering).
5. No sandboxing around rule parsing: if future rule engine evolves (regex, JIT, dynamic modules) this becomes a risk.
6. Potential TOCTOU windows if scanners open files after enumerations without revalidating.
7. Lack of explicit path sanitization/logging for user-supplied directories (rules_dir, world_writable_dirs).
8. Integrity signing: optional; no verification path in core (integrity handled by outside layer?). Potential for user to rely erroneously on a non-existent verify path.

Recommendations
- Replace system() with fork/exec (build argv vector) or use GPGME; quote and validate key id against expected regex.
- Add explicit seccomp_strict parsing and ensure only a single application (move second call behind a conditional or remove).
- Integrate embedded decompression (roadmap item) with bounded memory windows and size limits.
- Provide a security invariants document describing which scanners require which privileges to help users decide on --drop-priv.
- Add rule directory ownership & permission checks (refuse if writable by non-root).
- Add path normalization + canonicalization before external tool calls (e.g., realpath).
- Introduce a separate warnings array for partial failures (already on roadmap) to surface permission denials explicitly instead of silent omission.

================================================================
C. Determinism & Reproducibility
================================================================
Observations
1. Deterministic ordering reliant on registration order; parallel mode (cfg.parallel) is advertised, but we do not see concurrency orchestration in main.cpp. If implemented in ScannerRegistry, lock ordering & stable output merging are critical.
2. Canonical and pretty flags interplay unclear; code comments say naive pretty printing but actual pretty block (lines 188–190) is empty (placeholder) -> mismatch between expectation and implementation.
3. NDJSON & SARIF modes: main.cpp never branches for special formatting; rely on JSONWriter detecting cfg flags? Potential hidden logic. If not implemented, flags produce confusing output or invalid SARIF schema.
4. Severity filtering after scanning ensures consistent global counts, but if memory pressure occurs, streaming canonical NDJSON could be beneficial.

Recommendations
- Add a post-write audit: Re-parse output and re-serialize canonical; assert equality in debug builds to prevent accidental nondeterminism (especially after metadata additions).
- Document precedence: If --sarif is set, ignore pretty/compact/canonical (or define canonical only affects inner arrays).
- Expand JSONWriter to return structured multi-part (meta, findings, summary) so NDJSON emission becomes explicit & testable.
- Provide a determinism test harness: run scan twice with deterministic fixtures (mock /proc) and compare SHA256 of canonical output.

================================================================
D. Performance & Scalability
================================================================
Observations
1. All scanning occurs before any filtering; large process inventories or network socket enumerations may consume memory if process_inventory or network_advanced are on.
2. ioc_exec_trace eBPF short-lived trace adds overhead; if default seconds normalization is incorrect (0), either overhead is lost (no trace) or repeated by misconfiguration.
3. Single-thread execution for potentially independent I/O-bound scanners (process enumeration, /proc/net parsing, module reading).
4. Potential duplication of hashing (module hashes, process hashes) if same path inspected by multiple scanners—no central digest cache.

Recommendations
- Introduce a bounded LRU hash cache keyed by inode+mtime+size to avoid duplicate SHA256 computations (process and module scanners).
- Implement optional streaming writer: flush findings as soon as each scanner completes (especially for NDJSON). Keep a light-weight aggregate structure for summary recomputation.
- Add per-scanner timing & count metrics to the final JSON meta (architecture mentions some meta but ensure all scanners measured). Already partially captured by Report start/end, but expose it explicitly.
- Provide a “cost budget” (config or internal constants) to early terminate or degrade data collection if resource usage surpasses thresholds (e.g., >X seconds or >Y MB RSS).

================================================================
E. Concurrency (Future Parallelization)
================================================================
Observations
1. Report is mutex-protected; good precursor. Need deterministic merge ordering (e.g., stable index tokens capturing registration order).
2. CLI exposes --parallel and --parallel-threads, but main.cpp does not validate that parallel_max_threads >0 if --parallel; no fallback warnings.
3. No visible mechanism to prevent excessive thread creation (scanners may spawn their own internal threads later).

Recommendations
- In ScannerRegistry: store original registration index and when merging parallel results, sort by that index to reconstruct deterministic sequence.
- Validate thread count: if user passes 0 or negative, normalize to hardware_concurrency.
- Provide a concurrency invariants test: run with and without --parallel; ensure canonical outputs identical (hash compare).
- Mark scanners that are NOT thread-safe (if any) with a trait; skip them from parallel pool.

================================================================
F. API & Modularity
================================================================
Observations
1. main.cpp performs both CLI parsing and runtime orchestrations; large but still linear. Future growth may reduce clarity (e.g., more integrity/compliance flags).
2. Singleton config & global rule_engine() hamper embedding as a library.
3. Missing separation for output formatting concerns (writer write() returns string; raising performance cost for large outputs before writing to file/stdout).

Recommendations
- Refactor main pipeline into phases:
  - parse_cli(argc, argv) -> Config
  - validate_config(Config&)
  - initialize_security_measures(Config&)
  - load_rules(Config&)
  - run_scanners(Config&) -> Report
  - emit_outputs(Config&, Report&)
  - post_actions(Config&, Report&)
- Provide a public C++ API (library) entrypoint: run_scan(const Config&, IWriter&). This facilitates integration into orchestrators and tests.
- Abstract JSONWriter interface for alternate formats (NDJSONWriter, SarifWriter) implementing a common IReportSerializer interface.

================================================================
G. Error Handling & Observability
================================================================
Observations
1. Mixed output streams: diagnostics go to std::cerr but no structured logging for machine parsing (except final JSON). Hard for automated systems to attribute errors to scanners.
2. Warnings from rule_engine loaded (line 176) rely on Logger global; if logging level changes or destination not set, warnings may be lost.
3. Fail-fast criteria limited to unsupported rule versions unless --rules-allow-legacy, seccomp failure (strict), or severity/finding counts. No threshold for partial read failures.

Recommendations
- Introduce structured warnings array inside the JSON meta with fields: code, message, scanner, severity, timestamp.
- Add a verbose diagnostics (debug) mode to emit intermediate counts and memory usage.
- Add a --fail-on-warning-pattern option for CI gating particular warning codes.

================================================================
H. Rule Engine Integration
================================================================
Observations
1. CLI toggles rules_enable and rules_dir but no explicit version compatibility logic except warning scanning; future expansions will need version gating.
2. Absence of rule listing or summary in output might hinder validation of what logic executed (unless included downstream).
3. Potential for rule file explosion → load_dir should implement size limits, file count limits, and timeouts.

Recommendations
- Emit a rule_summary block: count_loaded, count_skipped, incompatible_versions, duplicate_ids.
- Provide a dry-run (--rules-dry-run) mode listing matched rules per synthetic test finding, improving author feedback.
- Introduce hashing of rule directory content (aggregate SHA256) into meta for reproducibility.

================================================================
I. Output Formats & Interoperability
================================================================
Observations
1. SARIF mode present as a flag; mapping from findings to SARIF results not shown—careful about required fields (tool, runs, version). If writer converts generically, ok; verify severity mapping.
2. NDJSON streaming unimplemented in main: currently collects full JSON string first. For large envs, could become memory-heavy.
3. Canonical mode aims at RFC 8785; ensure stable representation of numeric types, booleans, and null. If custom writer lacks strict type normalization, subtle drift may happen (e.g., integer vs string severity rank later).

Recommendations
- Provide a schema JSON file with json_schema_version—publish alongside releases.
- Offer a --validate-only flag: parse existing file, validate against embedded schema, exit.
- Add integration tests generating output in each format and verifying either schema compliance (SARIF) and canonical stability (hash match).

================================================================
J. Security Testing & Fuzzing
================================================================
Observations
1. fuzz/ directory exists; architecture mentions rule parser and scanners could be targets.
2. Manual argument parsing is a prime fuzz target (discover unknown interactions, overflow risk if future code adds unsafe conversions).
3. External file ingestion: /proc parsing, modules.dep lines, rule files, allowlist. All should have fuzz corpora.

Recommendations
- Add a fuzz harness for:
  - Flag parsing (simulate argv array).
  - Rule file loader (arbitrary bytes).
  - Module list parser (simulated modules.dep lines).
  - Network entry parser (lines from /proc/net/*).
- Maintain minimized corpus & integrate crash triage CI job.
- Add sanitizers (ASan/UBSan) in CI for fuzz configs.

================================================================
K. Memory & Resource Management
================================================================
Observations
1. Potential large vectors of findings (process_inventory). No early cap except max_processes after scanning.
2. Hashing large executables limited to first 1MB (good performance trade-off) but ensure that truncated hashing is clearly labeled (e.g., hash_truncated: true) to avoid misinterpretation.

Recommendations
- Add explicit memory accounting instrumentation (approx object sizes * counts) to meta. Threshold-based warnings if exceeding expected range.
- Provide streaming filter: apply severity and quantity limits immediately per scanner to reduce retained vectors.

================================================================
L. Consistency & Drift Risks
================================================================
Observations
1. Divergence between help text and actual option behavior (seccomp_strict missing; pretty placeholder).
2. Comments in Config describing features not yet surfaced as flags will confuse contributors.

Recommendations
- Implement a generation step: Config.schema.json derived from struct fields, used to verify help text coverage.
- Add unit test verifying every help line corresponds to either a parsed flag or an intentionally documented future flag (with a tag like [planned]).

================================================================
M. Prioritized Action Plan (Top 10)
1. Fix security-critical mismatches:
   - Implement --seccomp-strict parsing.
   - Quote or replace system() usage for GPG signing.
2. Reconcile Config & CLI: audit for missing/unused fields (integrity_pkg_rehash*, fs_world_writable_limit) and either implement or remove.
3. Implement or remove placeholder pretty logic; clarify precedence among pretty/compact/canonical.
4. Add validation & conflict detection post-parse; emit structured errors.
5. Provide determinism regression test harness (run twice, hash compare).
6. Add structured warnings collection & emission in JSON meta.
7. Implement rule_summary output and rules directory integrity hash.
8. Normalize ioc_exec_trace_seconds default (assign 3 if trace enabled and zero).
9. Add concurrency safety & determinism test if --parallel is used; otherwise hide flag until implemented.
10. Harden external tool interactions (module decompression, rule_dir permission checks).

================================================================
N. Forward-Looking Enhancements
- Introduce a plugin ABI version for scanners (if dynamic loading planned).
- Provide a C API facade for embedding in other languages.
- Offer incremental scan mode (reuse previous baseline to only emit deltas).
- Add provenance block with build-time supply chain metadata (compiler hash, dependency digests).
- Integrate a “policy pack” concept (bundle of config + rule pack + expected SUID baseline) with a single hash.

================================================================
O. Metrics to Track (for continuous improvement)
- scan_duration_total, per_scanner_duration
- findings_count_total, per_severity_counts
- memory_peak_rss (if accessible via /proc/self/status)
- rule_load_time, rule_count_loaded, rule_count_skipped
- hash_cache_hits/misses (post introduction)
- warnings_count (by code)
- parallel_speedup_ratio (sequential_time / parallel_time)
- canonical_hash (string) for artifact reproducibility

================================================================
P. Test Strategy Additions
- Golden output tests for each format (JSON canonical, NDJSON, SARIF).
- Fuzz-driven differential test: random flag sets vs reference parser implementation (if refactor).
- Negative tests: invalid severity, mutually exclusive flags, missing values.
- Mock scanner injection tests: ensures registration ordering invariants hold.
- Security tests: attempt GPG signing with odd key IDs (spaces, special chars) to verify sanitization.

================================================================
Q. Quick Code Smells / Micro Issues
- Duplicate namespace using (line 85 extraneous).
- Pretty printer stub (lines 188–190) promises behavior not implemented.
- Potential truncated lines (split_csv, suid_expected_file load CUT in snippet) – verify robust EOF handling & trailing whitespace trimming.
- Two seccomp apply calls (lines 174 & 203) – unify.

================================================================
R. Threat Modeling Snapshot (Abbreviated)
Assets: Accurate scan findings, integrity of output, absence of false trust signals, stable deterministic artifacts.
Attack Vectors:
- Malicious rule file → attempt to cause crash / DoS.
- Shell injection via system() for GPG.
- Path tampering (module files) if trust assumptions break (e.g., compromised root context).
- Resource exhaustion via vast /proc entries (container explosion) → memory blow-up.
Mitigations Proposed: rule directory permission checks, no system(), size/time guards, streaming output, structured warnings.

================================================================
Closing
The core is conceptually solid (deterministic sequence, modular scanners, explicit config). The most pressing fixes are: security hygiene around system(), parity between advertised and implemented flags, determinism validation for emerging parallel mode, and structured warning/error surfaces for operational clarity. Addressing those yields a sturdier foundation for expanding the intelligence layer and advanced correlation capabilities.

If you want focused implementation plans (e.g., for determinism harness or rule engine hardening), let me know the target area and I can produce concrete design snippets.