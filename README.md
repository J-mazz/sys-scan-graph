# sys-scan

![CI](https://github.com/J-mazz/sys-scan/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Lightweight Linux (Debian/Ubuntu focused) system security/environment scanner written in modern C++20.

## Overview
Lightweight Linux (Debian/Ubuntu focused) system security & hygiene scanner in modern C++20. Produces a structured JSON report with aggregated, noise‑reduced findings across several scanners.

### Core Scanners
Processes, Network, Kernel Params, Kernel Modules (summary / unsigned & out‑of‑tree heuristics incl. compressed .ko scanning), World‑Writable, SUID/SGID (inode de‑dup), IOC (deleted execs, temp execution, LD_* env anomalies, preload issues, SUID in home), MAC (SELinux/AppArmor status & anomalies).

### Output & Reporting
Deterministic JSON (pretty / compact) with summary (counts, durations, severities, slowest). Severity filtering & fail-on threshold; aggregated findings reduce noise (env/process IOC, SUID alt paths, module summary).

### Noise Reduction
Env IOC aggregation with allowlist downgrade, process IOC merging per exe, SUID inode dedupe, module summary mode.

### Example Use
```
./sys-scan --pretty --modules-summary --min-severity info
```

### Security Heuristic Highlights
Network exposed listener severity lift; ld.so.preload anomaly detection; unsigned/out‑of‑tree kernel module markers (includes .ko.xz/.gz scan).

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

## Build (Debian/Ubuntu)
```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
./build/sys-scan --help
```

## Testing
```
cd build
ctest --output-on-failure
```
## Roadmap Ideas
- Add hashing of binaries (optional OpenSSL/Blake3)
- Add package integrity checks (dpkg --verify)

## Operational Tips
- Use `--modules-summary` to shrink report size in continuous runs.
- Combine `--min-severity medium` with `--fail-on high` in CI to gate only on stronger signals.
- Add benign path substrings to `--ioc-allow` (e.g. `/snap/,/flatpak/`) to reduce env IOC noise further.

## Roadmap (Short-Term)
Taint flags, numeric risk scoring, allowlist file (`--ioc-allow-file`), package integrity & systemd hardening checks, advanced MAC profiling.

## License
Licensed under the MIT License. See `LICENSE` for full text.
