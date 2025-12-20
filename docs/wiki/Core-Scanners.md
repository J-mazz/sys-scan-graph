# Core Scanners (C++)

This page documents the scanners that exist **right now** under `src/scanners/modules/` and how they behave.

The scanners are registered (in this repository snapshot) in `src/main.cpp` and executed through `ScannerRegistry` (`sys_scan.registry`).

## Quick index

| Scanner name | Module | What it inspects | Gated by `Config` |
|---|---|---|---|
| `processes` | `process_scanner.ixx` | `/proc/<pid>` inventory | `process_inventory` or `all_processes` |
| `network` | `network_scanner.ixx` | `/proc/net/{tcp,tcp6,udp,udp6}` | disabled by `fast_scan` |
| `kernel` | `kernel_scanner.ixx` | `/proc/sys/...` hardening params | `hardening` |
| `mounts` | `mount_scanner.ixx` | `/proc/mounts` (tmpfs hardening) | always on |
| `fs_perms` | `fs_perms_scanner.ixx` | targeted world-writable + SUID checks | disabled by `fast_scan` |
| `auditd` | `auditd_scanner.ixx` | `/etc/audit/*` audit rules coverage | `hardening` |
| `systemd_units` | `systemd_scanner.ixx` | systemd unit hardening knobs | `hardening` |
| `integrity` | `integrity_scanner.ixx` | `dpkg -V` / `rpm -Va` verification | `integrity` |
| `ioc` | `ioc_scanner.ixx` | /proc heuristics (patterns, LD_PRELOAD, deleted exe) | always on |
| `modules` | `module_scanner.ixx` | `/proc/modules` + module heuristics | `hardening` or `modules_summary_only` |
| `containers` | `container_scanner.ixx` | container environment detection | `containers` |
| `yara` | `yara_scanner.ixx` | placeholder wiring for YARA scanning | `rules_enable` + `yara_scan_roots` |
| `ebpf_trace` | `ebpf_scanner.ixx` | exec/connect trace (eBPF or /proc fallback) | `ioc_exec_trace` |

Notes:

- Many scanners honor `test_root` via `sys_scan::utils::in_root(...)` so they can be tested against a fixture directory.
- Some `Config` fields exist but are not currently used by these scanners in this snapshot. This page only documents behavior present in the implementations.

## Scanner details

### `processes` (ProcessScanner)

Source: `src/scanners/modules/process_scanner.ixx`

Purpose: emits an informational finding per process.

Signal sources:

- `/proc/<pid>/cmdline` (nulls replaced with spaces)
- `/proc/<pid>/status` is read, but parsing is currently stubbed (no UID/GID extraction yet)

Gating:

- Does nothing unless `Config.process_inventory` **or** `Config.all_processes` is enabled.
- If `all_processes` is **false**, kernel threads / empty cmdlines are skipped.
- If `no_user_meta` is **true**, `/proc/<pid>/status` is not read.

Example IDs:

- `<pid>` (the PID directory name)

### `network` (NetworkScanner)

Source: `src/scanners/modules/network_scanner.ixx`

Purpose: emits an informational finding per socket table row in `/proc/net/*`.

Signal sources:

- `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`

Gating:

- If `fast_scan` is enabled, the scanner returns immediately.
- If `network_listen_only` is enabled, only TCP rows with state `0A` (LISTEN) are emitted.

Notes:

- Current implementation yields `Severity::Info` for all rows and does not join sockets to owning processes.

### `kernel` (KernelScanner)

Source: `src/scanners/modules/kernel_scanner.ixx`

Purpose: checks a small, fixed set of `/proc/sys` parameters when hardening mode is enabled.

Gating:

- Runs only when `hardening` is enabled.

Checked parameters (expected values):

- `kernel.kptr_restrict=2`
- `kernel.dmesg_restrict=1`
- `kernel.yama.ptrace_scope=1`
- `fs.protected_symlinks=1`
- `fs.protected_hardlinks=1`
- `net.ipv4.conf.all.accept_redirects=0`
- `net.ipv4.conf.default.accept_redirects=0`

### `mounts` (MountScanner)

Source: `src/scanners/modules/mount_scanner.ixx`

Purpose: flags insecure mount options for tmp-like paths.

Signal sources:

- `/proc/mounts`

Behavior:

- For `/tmp`, `/var/tmp`, `/dev/shm`, emits a `low` severity finding if any of `noexec`, `nosuid`, or `nodev` are missing.

### `fs_perms` (FsPermsScanner)

Source: `src/scanners/modules/fs_perms_scanner.ixx`

Purpose: small, targeted filesystem permission checks (not a full filesystem crawl).

Gating:

- Skips entirely when `fast_scan` is enabled.

Behavior:

- Flags world-writable **critical files** (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/fstab`, `/boot/grub/grub.cfg`) as `high` severity.
- Scans a focused set of directories (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`) for SUID files in a **non-recursive** directory listing and emits a `medium` severity finding per SUID binary.

### `auditd` (AuditdScanner)

Source: `src/scanners/modules/auditd_scanner.ixx`

Purpose: heuristically checks whether common syscall audit patterns appear in audit rules.

Gating:

- Runs only when `hardening` is enabled.

Signal sources:

- `/etc/audit/audit.rules`
- `/etc/audit/rules.d/*.rules`

Behavior:

- Emits `info` findings when patterns are present and `medium`/`high` findings when patterns are missing.

### `systemd_units` (SystemdUnitScanner)

Source: `src/scanners/modules/systemd_scanner.ixx`

Purpose: checks a small set of systemd hardening knobs on services with `ExecStart`.

Gating:

- Runs only when `hardening` is enabled.

Signal sources (searched):

- `/etc/systemd/system`
- `/usr/lib/systemd/system`
- `/lib/systemd/system`

Checks:

- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `ProtectSystem=strict` (explicitly treats `full` as not OK)
- `ProtectHome=read-only`

### `integrity` (IntegrityScanner)

Source: `src/scanners/modules/integrity_scanner.ixx`

Purpose: runs the host package manager verification command and reports mismatches.

Gating:

- Runs only when `integrity` is enabled.

Behavior:

- On Debian-like systems: `dpkg -V`
- On RPM-based systems: `rpm -Va`
- Emits up to 10 `medium` mismatch findings and a `high` summary finding if any mismatches are found.

Limitation:

- When `test_root` is set to a non-root snapshot, the scanner emits an `info` finding indicating offline snapshots are not supported.

### `ioc` (IOCScanner)

Source: `src/scanners/modules/ioc_scanner.ixx`

Purpose: simple IOC heuristics over `/proc`.

Signal sources:

- `/proc/<pid>/cmdline` string matching (patterns: `cryptominer`, `xmrig`, `minerd`, `malware`)
- `/proc/<pid>/environ` for `LD_PRELOAD`
- `/proc/<pid>/exe` symlink for `(deleted)` executables

### `modules` (ModuleScanner)

Source: `src/scanners/modules/module_scanner.ixx` and helper `module_utils.ixx`

Purpose: summary-level kernel module anomaly detection.

Gating:

- Runs if `hardening` is enabled or `modules_summary_only` is enabled.

Signal sources:

- `/proc/modules`
- module file probing under `/lib/modules/<release>/...`

Behavior:

- Counts (a) unsigned modules, (b) out-of-tree / tainted indicators (heuristic), and (c) modules with W+X sections.
- Emits a single `Kernel Module Summary` finding if any count is non-zero.

### `containers` (ContainerScanner)

Source: `src/scanners/modules/container_scanner.ixx`

Purpose: detects whether the host appears to be running inside a container.

Gating:

- Runs only when `containers` is enabled.

Evidence sources:

- `/.dockerenv`
- `/proc/1/cgroup` substring matching (`docker`, `kubepods`, `lxc`)
- `/proc/1/environ` for `KUBERNETES_SERVICE_HOST`

### `yara` (YaraScanner)

Source: `src/scanners/modules/yara_scanner.ixx`

Status: currently a **wiring placeholder**.

Gating:

- Requires `rules_enable` and at least one entry in `yara_scan_roots`.

Behavior:

- If built with libyara headers available, emits an informational “YARA Scan” placeholder finding.
- Otherwise emits an `error` severity finding indicating YARA support wasn’t present at compile time.

### `ebpf_trace` (EbpfScanner)

Source: `src/scanners/modules/ebpf_scanner.ixx`

Purpose: traces process execution and outbound connections.

Gating:

- Runs only when `ioc_exec_trace` is enabled.

Behavior:

- If compiled with `SYS_SCAN_HAVE_EBPF`, attempts to attach an eBPF program and read events.
- If eBPF is unavailable or fails, falls back to a `/proc` polling method that snapshots PIDs, sleeps for `ioc_exec_trace_seconds` (default ~2s), then reports newly observed PIDs.

## Relationship to JSON schemas

The scanner implementations emit `Finding` objects in-memory. The repository includes the v4 JSON schema (`schema/v4.json`) that describes the structured report format consumed by the intelligence layer.

If you’re working on wiring JSON output, this page provides the authoritative list of scanners and their current behavior.