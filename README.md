# sys-scan

Lightweight Linux (Debian/Ubuntu focused) system security/environment scanner written in modern C++20.

## Features (initial)
- Process enumeration (/proc)
- Listening TCP sockets (/proc/net)
- Kernel parameter checks (basic hardening set)
- Loaded kernel modules
- World-writable file discovery in critical directories
- SUID/SGID binary enumeration
- JSON report output (stdout)

## Build (Debian/Ubuntu)
# sys-scan

Lightweight Linux (Debian/Ubuntu focused) system security & hygiene scanner in modern C++20. Produces a structured JSON report with aggregated, noise‑reduced findings across several scanners.

## Current Feature Set

Core Scanners:
- Processes: Enumerates userland processes (optionally kernel threads) with basic heuristic IOC detection.
- Network: TCP/UDP socket inventory with state / protocol filters, listener focus, severity heuristics for exposure & privileged/uncommon ports.
- Kernel Params: Basic hardening-related sysctl snapshot.
- Kernel Modules: Full list or single summary (out‑of‑tree & unsigned heuristic detection, compressed module signature scanning).
- World‑Writable: Detects world‑writable files in selected critical directories (configurable includes/excludes).
- SUID/SGID: Enumerates privileged binaries with inode de‑duplication and alternate path aggregation.
- IOC: Heuristic Indicators of Compromise (process path patterns, deleted executables, execution from world‑writable dirs, suspicious LD_* env usage, preload anomalies, SUID in home, executables dropped in temp). Aggregated env & process findings reduce noise.

Output & Reporting:
- Deterministic JSON with summary block (counts, durations, severities, slowest scanner).
- Pretty or compact output modes.
- Severity filtering & fail-on threshold for CI gating.
- Aggregated findings (env/process IOC, SUID alt paths, module summary) to reduce repeated noise.

Noise Reduction Enhancements:
- IOC environment findings aggregated per executable with pid counts and allowlist downgrade (e.g. snap/flatpak paths).
- Process IOC findings merged per exe with severity escalation (deleted -> critical, world-writable exec -> high, pattern -> high).
- SUID binaries deduped by inode; alternate hardlink paths captured in metadata.
- Module summary mode collapses 100s of module entries into one finding with counts of out‑of‑tree, unsigned, and compressed modules.

Security Heuristics Highlights:
- Network severity lift for exposed listeners and privileged or uncommon ports.
- IOC detection of ld.so.preload anomalies (missing / world‑writable entries).
- Unsigned kernel module heuristic via signature marker scan (handles compressed .ko.{xz,gz}).

## Build (Debian/Ubuntu)
{
  "results": [
    {
      "scanner": "processes",
      "start_time": "2025-08-25T12:00:00Z",
      "end_time": "2025-08-25T12:00:01Z",
      "findings": [ { "id": "123", "title": "Process 123", "severity": "info", ... } ]
    }
(xz/gzip used for optional compressed module signature inspection.)

## CLI Overview
```
--enable name[,name...]       Only run specified scanners
--disable name[,name...]      Disable specified scanners
--output FILE                 Write JSON to FILE (default stdout)
--min-severity SEV            Filter out findings below SEV
--fail-on SEV                 Exit non-zero if any finding >= SEV
--pretty                      Pretty-print JSON
--compact                     Force minimal JSON (overrides pretty)
--all-processes               Include kernel/thread processes lacking cmdline
--world-writable-dirs dirs    Extra comma-separated directories to scan
--world-writable-exclude pats Comma-separated substrings to ignore
--max-processes N             Cap process findings after filtering
--max-sockets N               Cap network socket findings
--network-debug               Include raw /proc/net lines in findings
--network-listen-only         Limit to listening TCP (and bound UDP) sockets
--network-proto tcp|udp       Protocol filter
--network-states list         Comma-separated TCP states (LISTEN,ESTABLISHED,...)
--ioc-allow list              Comma-separated substrings to downgrade env IOC
--modules-summary             Collapse module list into single summary finding
--help                        Show usage
```

## JSON Output Structure (abridged)
  ]
}
```

## Extending
Implement a new `Scanner` subclass in `src/scanners`, add to `CMakeLists.txt` and register it inside `ScannerRegistry::register_all_default()`.

## Testing
Minimal smoke test provided (`test_basic`). Build with `-DBUILD_TESTS=ON` (default) then:
```bash
ctest --output-on-failure
```

## Extending
Create a new `Scanner` subclass in `src/scanners/`, implement `scan`, and register it in `ScannerRegistry::register_all_default()`. Provide concise, stable `Finding.id` values to enable future suppression / correlation.

## Testing
Minimal smoke test (`test_basic`). Build & run:
## Roadmap Ideas
- Add hashing of binaries (optional OpenSSL/Blake3)
- Add package integrity checks (dpkg --verify)

## Operational Tips
- Use `--modules-summary` to shrink report size in continuous runs.
- Combine `--min-severity medium` with `--fail-on high` in CI to gate only on stronger signals.
- Add benign path substrings to `--ioc-allow` (e.g. `/snap/,/flatpak/`) to reduce env IOC noise further.

## Roadmap (Short-Term)
- Taint flag extraction for modules (/sys/module/*/taint)
- Risk scoring (numeric) alongside severity
- Allowlist file support (`--ioc-allow-file`)
- Additional process correlation (env + process IOC merged)
- Package integrity & systemd hardening checks

## License
MIT (proposed) – add LICENSE file.
- SELinux/AppArmor status
## Prior (Long-Term) Roadmap Ideas
- Binary hashing (BLAKE3) & file reputation
- Package integrity checks (dpkg --verify)
- SELinux/AppArmor status
- Systemd hardening option evaluation
- Container / virtualization detection
- User & group anomaly detection
- CVE matching via local feed (deferred)
