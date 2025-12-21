# Security invariants & privilege requirements

This document enumerates the core security assumptions ("invariants") and the **minimum privileges** each scanner or subsystem typically requires.

> Goal: Principle of Least Privilege. If a privilege is not needed for your use-case, don’t grant it.

> Note: the current `sys-scan` CLI in this repository does **not** implement privilege dropping or seccomp sandbox flags. If you want containment, use your OS/container runtime (user namespaces, containers, seccomp profiles, etc.).

## Global invariants

1. Scanner execution must never perform writes outside ephemeral in-memory structures except the designated output file.
2. External commands (when used) must be invoked without shell interpolation and treated as untrusted output.
3. All file reads are treated as untrusted; parsers must bound memory and handle malformed input gracefully.
4. Failure to access a resource must not crash the process; emit warnings and degrade gracefully.
5. Deterministic output ordering regardless of privilege level (absence of data => missing findings, not reordering).

## Capability / privilege matrix (summary)

Scanner names below match what is wired in `src/main.cpp`.

| Scanner | Needs root? (typical) | Why | Degradation when unprivileged |
|--------|------------------------|-----|------------------------------|
| `ProcessScanner` | Recommended | full `/proc/<pid>/...` visibility | reduced process metadata for other users / namespaces |
| `NetworkScanner` | Recommended | full socket/process correlation | partial visibility; still reads `/proc/net/*` |
| `KernelScanner` | Sometimes | some kernel tunables and procfs/sysfs details | fewer kernel parameter findings |
| `ModuleScanner` | Recommended | module file probing under `/lib/modules/...` | reduced module anomaly checks |
| `FsPermsScanner` | Recommended | filesystem traversal across protected paths | permission-denied skips (risk of false negatives) |
| `MountScanner` | No (usually) | mount table inspection | typically minimal impact |
| `MACScanner` | No (usually) | SELinux/AppArmor state checks | minimal impact |
| `IntegrityScanner` | Recommended | package DB and verification commands | reduced package verification coverage |
| `IOCScanner` | Recommended | deeper filesystem inspection | reduced scope |
| `AuditdScanner` | Recommended | audit subsystem visibility | reduced fidelity |
| `SystemdUnitScanner` | No (usually) | unit state inspection | minimal impact |
| `ContainerScanner` | Recommended | namespace/container introspection | reduced container visibility |
| `YaraScanner` | Depends | scanning more paths / protected locations | reduced scan scope |
| `EbpfScanner` | Yes | attaching to tracepoints requires elevated privilege | feature disabled or degraded |

## Operational guidance

- For the highest fidelity, run as root (or with equivalent privileges in a container namespace).
- For lower risk, run in a container with read-only mounts and minimal capabilities, accepting reduced coverage.
- If you run non-root, expect fewer findings in protected areas; treat that as reduced visibility, not a clean bill of health.

## Planned hardening (future)

The project may add optional hardening features over time (e.g., structured warnings, privilege dropping, seccomp profiles). Until then, prefer external sandboxing.
