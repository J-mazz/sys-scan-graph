# Security Invariants & Privilege Requirements

This document enumerates the core security assumptions ("invariants") and the minimum privileges each scanner or subsystem requires. Operators can use this to make informed decisions about running `sys-scan` with `--drop-priv`, containerization, or additional sandboxing.

> Goal: Principle of Least Privilege. If a capability / privilege is *not* needed for your use-case, drop it before scanning.

## Legend
- Priv Columns:
  - R: requires read access
  - C: may create / open (non-destructive)
  - CAP: Linux capability dependency (best-effort)
  - Root*: effectively requires UID 0 for reliable / full fidelity
- Severity Impact: Reduction in finding fidelity if missing privilege.

## Global Invariants
1. Scanner execution must never perform writes outside ephemeral in-memory structures except the designated output file (and optional signature / env file).
2. No scanner should execute external binaries except explicitly documented cases (GPG signing with `--sign-gpg`).
3. All file reads are treated as untrusted; parsers must bound memory and handle malformed input gracefully.
4. Failure to access a resource MUST NOT crash the process; it should emit a structured warning (future: unified warnings array) or degrade gracefully.
5. Deterministic output ordering regardless of privilege level (absence of data => missing findings, not reordering).

## Capability / Privilege Matrix (Summary)
| Scanner / Subsystem | Needs Root? | Needs CAP_DAC_READ_SEARCH | Other Caps | Notes on Degradation |
|---------------------|------------|---------------------------|------------|----------------------|
| ProcessScanner | Recommended | Yes (for full /proc/<pid>/exe & cmdline of other users) |  | Without: some processes hidden / limited cmdline |
| NetworkScanner | Recommended | No (mostly /proc/net) | CAP_NET_RAW (optional for future raw socket metrics) | Without root: still works but some inode->process mapping may degrade |
| KernelParamScanner | Yes (for certain /proc/sys) | Yes |  | Non-root cannot read some sysctl entries; findings reduced |
| ModuleScanner | Yes | Yes |  | Without: cannot read module files for signature / anomaly checks |
| WorldWritableScanner | No (root improves coverage) | CAP_DAC_READ_SEARCH |  | Non-root skips unreadable paths (risk of false negatives) |
| SuidScanner | Yes (for exhaustive ownership / permission checks) | Yes |  | Non-root may miss restricted directories |
| IOCScanner (env trust) | Recommended | CAP_DAC_READ_SEARCH |  | Missing capability reduces trust correlation scope |
| MACScanner / IntegrityScanner | Yes | Yes | CAP_SYS_ADMIN (sometimes required for IMA) | IMA stats may be unavailable |
| ContainerScanner | Recommended | No |  | Namespace introspection limited non-root |
| AuditdScanner | Yes | Yes | CAP_AUDIT_READ (future) | Without: cannot query audit status |
| YaraScanner (if enabled) | Yes (memory scan) | Yes | CAP_SYS_PTRACE (future) | Degraded to file-only scan |
| Integrity (pkg verify) | Yes | Yes |  | Non-root cannot read package DB fully |
| eBPF Exec Trace | Yes | No | CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN (depending on kernel) | Without: feature disabled |
| Rule Engine | No | No |  | Only reads rules directory |
| GPG Signing | No | No |  | Uses fork/exec gpg; keyring must be accessible |

## Detailed Notes
### Process Enumeration
- Requires `procfs` readability. If running inside a container, host processes outside namespace will be invisible (expected isolation).
- Without CAP_DAC_READ_SEARCH, some `/proc/<pid>/exe` symlinks or cmdlines may read as empty -> severity logic should not misclassify.

### Network Enumeration
- Reads `/proc/net/{tcp,udp,...}`. Root not strictly required. Socket inode to PID mapping can miss short-lived connections without elevated privileges.

### Module Analysis
- Reads `/lib/modules/<kernel>/modules.dep`, module binaries, and sysfs `/sys/module`. Many module files require root to read; signature / anomaly heuristics degrade otherwise.
- Decompression uses bounded in-process streaming (caps in `ModuleScanner.cpp`), no external decompressors.

### Filesystem Hygiene (world-writable, SUID)
- Traverses common system paths. Without CAP_DAC_READ_SEARCH some directories are skipped (permission denied). Future: emit structured warnings per skipped root path.

### Integrity & Compliance (IMA / pkg verify)
- IMA requires kernel support and generally root or CAP_SYS_ADMIN to read securityfs entries.
- Package verification invokes dpkg/rpm queries; requires root for complete metadata in some distributions.

### eBPF Exec Trace
- Attaching to tracepoints requires recent kernels and capabilities (`CAP_BPF` and `CAP_PERFMON`, or root). Fallback: feature silently disabled (future improvement: explicit warning).

## Privilege Recommendation Levels
| Deployment Scenario | Recommended Flags |
|---------------------|-------------------|
| Full host audit (root) | `--drop-priv` (after initial module & rule load) only if capability retention not required; otherwise run as root without dropping |
| Minimal container introspection | Run as container root inside namespace (isolated), disable module & integrity scanners |
| Developer workstation quick scan | Non-root; accept reduced module / integrity coverage |
| CI pipeline (build artifact verification) | Non-root + `--sign-gpg` + disable network & eBPF features |

## Interaction With `--drop-priv`
- Capability drop currently removes all unless `--keep-cap-dac` specified.
- If you need full filesystem traversal but want to minimize privilege, combine: `--drop-priv --keep-cap-dac`.
- After drop: eBPF, IMA, some integrity, and module hashing may be partially or fully disabled.

## Planned Structured Warnings
Future unified warnings array (JSON meta) will include codes such as:
- `perm_denied:path` – scanner skipped path
- `ebpf_attach_failed:tracepoint` – eBPF feature unavailable
- `module_read_failed:path` – module file unreadable
- `integrity_pkg_db_inaccessible` – package DB read issue

## Defensive Defaults
- Bounded decompression (2MB limit) prevents resource abuse by anomalous module files.
- GPG signing uses fork/exec and argument vector (no shell interpolation).
- Seccomp profile (if enabled) applied early; `--seccomp-strict` enforces failure-as-error.

## Verification Checklist (Operators)
1. Run once with high privileges and record summary metrics (module counts, integrity stats).
2. Re-run with `--drop-priv` (and optional `--keep-cap-dac`) and compare high-level counts.
3. Investigate large discrepancies (could indicate missing privileges or genuine anomalies).

## Contributions
When adding a new scanner:
1. Document its privilege needs here.
2. Ensure graceful degradation without required privilege.
3. Add bounds to all external input parsing.
4. Emit warnings instead of silent skips.

---
This document will evolve; suggestions welcome via normal issue tracker (non-sensitive) or security advisory if you believe a missing invariant exposes risk.
