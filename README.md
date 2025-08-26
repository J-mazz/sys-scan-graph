# sys-scan

![CI](https://github.com/J-mazz/sys-scan/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Lightweight Linux (Debian/Ubuntu focused) system security/environment scanner written in modern C++20.

## Overview
Lightweight Linux (Debian/Ubuntu focused) system security & hygiene scanner in modern C++20. Produces a structured JSON report with aggregated, noise‑reduced findings across several scanners.

### Core Scanners
Processes, Network, Kernel Params, Kernel Modules (summary / unsigned & out‑of‑tree heuristics incl. compressed .ko scanning), World‑Writable, SUID/SGID (inode de‑dup), IOC (deleted execs, temp execution, LD_* env anomalies, preload issues, SUID in home), MAC (SELinux/AppArmor status & anomalies).

### Output & Reporting
Deterministic JSON (pretty / compact) with summary (counts, durations, severities, slowest) plus optional canonical RFC8785 mode (`--canonical`) for stable hashing, NDJSON streaming (`--ndjson`) and SARIF (`--sarif`) for pipeline / code‑scanning integrations. Severity filtering & fail-on threshold; aggregated findings reduce noise (env/process IOC, SUID alt paths, module summary).

### Rule Engine
Optional enrichment rules (`--rules-enable --rules-dir rules/`) provide:
* Multi-condition AND / OR logic with scoped fields (id, title, description, metadata.*)
* Regex conditions (pre‑compiled & length/ count guardrails)
* Severity override & additive MITRE technique tagging (order‑preserving de‑dup)
* Structured warnings surfaced for unsupported versions, excessive rules / conditions, invalid regex.

Rule file example:
```
rule_version = 1

rule "Upgrade suspicious finding" {
	when {
		id ~= "proc_.*deleted"
		metadata.mitre_missing = "true"  # exact match example
	}
	severity = "high"
	mitre_techniques = ["T1055","T1105"]
	notes = "Escalate deleted executable with missing MITRE mapping"
}
```

### Privacy & Metadata Suppression
Flags to drop potentially sensitive host data from `meta`:
* `--no-user-meta` (removes user, uid/gid/euid/egid)
* `--no-cmdline-meta` (removes process invocation cmdline)
* `--no-hostname-meta` (removes hostname)

Test coverage (`meta_suppression`) ensures these fields are absent when flags set.

### Noise Reduction
Env IOC aggregation with allowlist downgrade (via `--ioc-allow` / `--ioc-allow-file`), process IOC merging per exe, SUID inode dedupe (with expected baseline downgrade), module summary mode and anomalies-only options.

### Example Use
```
./sys-scan --pretty --modules-summary --min-severity info
```

### Security Heuristic Highlights
Network exposed listener severity lift; ld.so.preload anomaly detection; unsigned/out‑of‑tree kernel module markers (includes .ko.xz/.gz scan); SUID expected baseline downgrades common utilities; IOC findings include `rule` metadata explaining trigger.

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
--modules-anomalies-only      Only emit unsigned/out-of-tree module entries (no summary)
--process-hash                Include SHA256 hash of process executable (first 1MB) if OpenSSL available
--process-inventory           Emit all processes (otherwise only IOC/anomalies)
--ioc-allow-file FILE         Newline-delimited additional env allowlist patterns
--fail-on-count N             Exit non-zero if total finding count >= N
--suid-expected list          Extra expected SUID paths (comma list)
--suid-expected-file FILE     Newline-delimited expected SUID paths
--canonical                   Emit RFC8785 canonical JSON (stable ordering & formatting)
--ndjson                      Emit newline-delimited meta/summary/finding lines (stream friendly)
--sarif                       Emit SARIF 2.1.0 run with findings as results
--rules-enable                Enable rule enrichment engine
--rules-dir DIR               Directory containing .rule files
--rules-allow-legacy          Allow loading legacy rule_version without hard fail
--no-user-meta                Suppress user/uid/gid/euid/egid in meta
--no-cmdline-meta             Suppress cmdline in meta
--no-hostname-meta            Suppress hostname in meta
--drop-priv                   Drop Linux capabilities early (best-effort; requires libcap)
--keep-cap-dac                Retain CAP_DAC_READ_SEARCH when using --drop-priv
--seccomp                     Apply restrictive seccomp-bpf profile after initialization (libseccomp)
* `--seccomp` – installs a minimal allowlist seccomp-bpf program early, before scanning.
* `--seccomp-strict` – treat failure to apply seccomp as fatal (exit code 4).
--sign-gpg KEYID              Detached ASCII armored signature (requires --output)
--write-env FILE              Emit .env file with version, git commit (if available), binary SHA256
--slsa-level N                Declare SLSA build level (meta.provenance)
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
Key tests:
* `canonical_golden` – regression guard for canonical stable hash
* `ndjson_mitre` – MITRE technique formatting in NDJSON
* `rules_*` – rule engine multi-condition, version, warnings, MITRE de‑dup
* `meta_suppression` – metadata privacy flags honor suppression
* `canonical_golden` – also guards provenance field stability (hash updates only on intentional schema or provenance additions)

## Result Integrity & Provenance

Canonical JSON (`--canonical`) plus deterministic ordering (& optional `SYS_SCAN_CANON_TIME_ZERO=1`) enables stable hashing of reports. To attest integrity you can:
Provenance override environment variables (if set, override embedded build constants): `SYS_SCAN_PROV_GIT_COMMIT`, `SYS_SCAN_PROV_COMPILER_ID`, `SYS_SCAN_PROV_COMPILER_VERSION`, `SYS_SCAN_PROV_CXX_STANDARD`, `SYS_SCAN_PROV_CXX_FLAGS`, `SYS_SCAN_PROV_SLSA_LEVEL`, `SYS_SCAN_PROV_BUILD_TYPE`.

1. Produce report: `./sys-scan --canonical --output report.json`
2. (Optional) Zero timestamps for fully reproducible hash: `SYS_SCAN_CANON_TIME_ZERO=1 ./sys-scan --canonical --output report.json`
3. Sign with GPG: `./sys-scan --canonical --output report.json --sign-gpg <KEYID>` (emits `report.json.asc` detached signature)

The `meta.provenance` object embeds build metadata for supply‑chain transparency:
```
"provenance": {
	"git_commit": "<short-hash>",
	"compiler_id": "GNU|Clang|...",
	"compiler_version": "<ver>",
	"cxx_standard": "20",
	"cxx_flags": "<merged flags>",
	"slsa_level": "<declared level>",
	"build_type": "Release|Debug"
}
```
Runtime override: `--slsa-level` (or env `SYS_SCAN_SLSA_LEVEL_RUNTIME`) if you want to declare an attested SLSA build level at execution time.

### Reproducible Builds

The project avoids embedding volatile timestamps (unless you rely on external libraries that do so). For stricter reproducibility:

Recommended invocation:
```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
	-DSYS_SCAN_REPRO_BUILD=ON -DSYS_SCAN_SLSA_LEVEL=1 \
	-DCMAKE_CXX_FLAGS_RELEASE="-O2 -g0 -ffile-prefix-map=$(pwd)=. -fdebug-prefix-map=$(pwd)=."
cmake --build build -j$(nproc)
SOURCE_DATE_EPOCH=1700000000 SYS_SCAN_CANON_TIME_ZERO=1 ./build/sys-scan --canonical --output report.json
sha256sum report.json
```
Notes:
* `SYS_SCAN_REPRO_BUILD=ON` scrubs `__DATE__/__TIME__` and marks build reproducible.
* `SYS_SCAN_CANON_TIME_ZERO=1` normalizes all timestamps to epoch and sets `meta.normalized_time=true`.
* Use toolchain packaged compilers for determinism; ensure locale + TZ stable (e.g. `LC_ALL=C TZ=UTC`).
* Provide `--sign-gpg` to generate a detached signature after writing the file.

Future options may add cosign / age signing modes; current implementation focuses on ubiquitous GPG.
## Roadmap Ideas
- Add hashing of binaries (optional OpenSSL/Blake3)
- Add package integrity checks (dpkg --verify)
 - Extract canonical IR structs (CanonVal) into shared header for potential external tooling
 - Additional SARIF properties (locations, partial fingerprints)

## Operational Tips
- Use `--modules-summary` to shrink report size in continuous runs.
- Combine `--min-severity medium` with `--fail-on high` in CI to gate only on stronger signals.
- Add benign path substrings to `--ioc-allow` (e.g. `/snap/,/flatpak/`) to reduce env IOC noise further.

## Roadmap (Short-Term)
Taint flags, numeric risk scoring, allowlist file (`--ioc-allow-file`), package integrity & systemd hardening checks, advanced MAC profiling.

## License
Licensed under the MIT License. See `LICENSE` for full text.
