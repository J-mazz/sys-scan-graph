# sys-scan

![CI](https://github.com/J-mazz/sys-scan/actions/workflows/ci.yml/badge.svg) ![License: Hybrid](https://img.shields.io/badge/License-Hybrid-blue.svg)

I started sys-scan as a way to refine my C++ skills and practice prompt engineering while creating something genuinely useful for myself as a Linux user and for the small network of machines I administer. I initially used GitHub Copilot in agent mode to scaffold the project, then manually refactored and extended it with new features, relying on Copilot only as an assistant rather than the driver for most of the development. I’m still learning C++, and this project has been a hands-on way to grow while building a tool I hope others will also find valuable. I plan to keep expanding sys-scan, and I welcome contributions from anyone interested in practical, free security utilities.

Modern C++20 Linux system security & hygiene scanner (Debian/Ubuntu oriented, broadly portable). Focus: high‑signal, low‑noise findings + deterministic, attestable artifacts.

---
## Table of Contents
1. Quick Start
2. Feature Highlights
3. Core Scanners
4. Output & Formats
5. Rules Engine
6. Privacy & Noise Reduction
7. Security Hardening Model
8. Determinism, Reproducibility & Provenance
9. Risk & Severity Model
10. Schema & Versioning
11. Build & Install
12. Usage Scenarios & Recipes
13. CI / Pipeline Integration
14. Examples (JSON / NDJSON / SARIF snippets)
15. Advanced Flags Reference
16. Roadmap & Ideas
17. License & Usage

---
## 1. Quick Start
```bash
git clone https://github.com/J-mazz/sys-scan.git
cd sys-scan
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/sys-scan --pretty --modules-summary --min-severity info > report.json
```
View compact canonical (stable hash) report:
```bash
SYS_SCAN_CANON_TIME_ZERO=1 ./build/sys-scan --canonical > canon.json
sha256sum canon.json
```

Minimal pipelines (stdout):
```bash
./build/sys-scan --ndjson | grep '"type":"finding"'
```

---
## 2. Feature Highlights
* High‑level summary + per‑scanner grouping reduces alert fatigue.
* Dual metrics: total vs emitted (post filter) counts & risk scores.
* Deterministic canonical JSON for hashing/signing / SBOM-like workflows.
* Optional NDJSON streaming & SARIF 2.1.0 export.
* Extensible rule engine (regex + structured conditions) for enrichment & MITRE tagging.
* Security hardening: capability drop, optional seccomp sandbox.
* Provenance block (compiler, commit, flags, SLSA level) with runtime overrides.
* Reproducibility toggles & timestamp zeroing (`SYS_SCAN_CANON_TIME_ZERO=1`).
* Optional multi-standard compliance assessment (PCI DSS 4.0, HIPAA Security Rule, NIST CSF 2.0) with summarized pass/fail/score metrics (Core emits structured compliance_summary).
* Gap analysis mode producing focused `compliance_gaps` with remediation hints & normalized severities (Core + Intelligence Layer enrichment).
* Fast: avoids expensive full file reads (bounded hashing window, selective parsing).

---
## 3. Core Scanners
| Scanner | Focus | Notable Signals |
|---------|-------|-----------------|
| Process | Userland processes | Deleted executables, temp exec, env LD anomalies, executable hashing (opt) |
| Network | TCP/UDP sockets | Listening exposure, high fan‑out heuristics (planned) |
| Kernel Params | sysctl / /proc | Insecure kernel tunables (planned extensions) |
| Kernel Modules | Loaded & filesystem state | Unsigned, out‑of‑tree, missing file, hidden vs sysfs, compressed .ko scan |
| World Writable | Directories & files | Writable risk surfaces & path hijack potential |
| SUID/SGID | Privileged binaries | Unexpected SUID set, baseline expected set downgrade |
| IOC | Execution context | ld.so.preload abuse, deleted binaries, env risk aggregation |
| MAC | SELinux/AppArmor status | Missing MAC, downgrade logic if one present |
| Compliance (opt) | PCI / HIPAA / NIST CSF controls | Pass/fail aggregation + gap analysis (when enabled) |
| Integrity (opt) | Future pkg/IMA | Placeholders for package & IMA measurement stats |
| Rules | Post-processing layer | MITRE tagging, severity escalation |

---
## 4. Output & Formats
Base JSON always contains:
* `meta` – environment + provenance.
* `summary` – dual counts, severities, timings, slowest scanner.
* `results[]` – per-scanner groups.
* `collection_warnings[]` & `scanner_errors[]` – non-fatal diagnostics.
* `summary_extension` – extended scoring (total & emitted risk).

Optional:
* `--canonical` enforces deterministic ordering & minimal whitespace (RFC8785 style stabilization).
* `--ndjson` streams: meta, summary_extension, each finding (easy piping).
* `--sarif` produces SARIF for code scanning ingestion.

---
## 5. Rules Engine
Capabilities:
* Declarative rule files (`.rule`) with `rule_version` guard.
* AND/OR logic; equality, regex (`~=`), substring future extension.
* MITRE technique aggregation (order‑preserving de‑dup).
* Severity override & notes.
* Structured warnings on invalid/legacy versions (non‑fatal unless gated).

Example:
```
rule_version = 1

rule "Escalate deleted suspicious binary" {
	when {
Runtime overrides via env (`SYS_SCAN_PROV_*`) or `--slsa-level`. Deterministic canonical mode + optional timestamp zeroing yields stable hashes for attestations or artifact promotion.

SYS_SCAN_CANON_TIME_ZERO=1 ./b/sys-scan --canonical > r.json
sha256sum r.json
```
Generate provenance env file:
```bash
./b/sys-scan --write-env build.env --output report.json --canonical
cat build.env
```

---
## 9. Risk & Severity Model
Each finding has:
* `severity`: info, low, medium, high, critical, error
* `risk_score`: integer 0‑100 (heuristic weighting per scanner)

`summary_extension.total_risk_score` sums all scores; `emitted_risk_score` reflects active filter (`--min-severity`). This enables gating on both signal density and threshold severity simultaneously.

Filtering examples:
```bash
# Only medium+ and fail pipeline if any high+
./sys-scan --min-severity medium --fail-on high

# Gate on volume (after filtering)
./sys-scan --min-severity low --fail-on-count 150
```

---
## 10. Schema & Versioning
Current schema: `v2` (`meta.json_schema_version = "2"`). Additive fields keep same major; breaking semantic shifts bump major.

File: `schema/v2.json` – validated via tests. Dual metrics & emitted risk score are enumerated. Additional properties intentionally permitted for forward flexibility (attestation/deployment contexts).

---
## 11. Build & Install
### Standard Build
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
./build/sys-scan --version
```

### Options (CMake)
| Option | Default | Effect |
|--------|---------|--------|
| `BUILD_TESTS` | ON | Build test binaries & enable ctest targets |
| `ENABLE_OPENSSL` | ON | Use OpenSSL for hashing (graceful fallback) |
| `ENABLE_SECCOMP` | ON | Discover & enable seccomp support |
| `ENABLE_CAPABILITIES` | ON | Enable capability dropping |
| `SYS_SCAN_REPRO_BUILD` | OFF | Repro build defines; strip volatile macros |
| `BUILD_FUZZERS` | OFF | Build libFuzzer harnesses (clang) |

### Package Artifacts
Debian packaging skeleton under `debian/` (invoke standard `dpkg-buildpackage` flow) – future refinement may add signed packages / provenance embedding.

---
## 12. Usage Scenarios & Recipes
| Scenario | Command |
|----------|---------|
| Quick hygiene sweep | `./sys-scan --modules-summary --min-severity medium` |
| Attestable artifact | `SYS_SCAN_CANON_TIME_ZERO=1 ./sys-scan --canonical --output rep.json` |
| Signed report | `./sys-scan --canonical --output rep.json --sign-gpg <KEY>` |
| Stream to SIEM | `./sys-scan --ndjson | jq -c 'select(.type=="finding")'` |
| Rule enrichment | `./sys-scan --rules-enable --rules-dir rules/` |
| Tight CI gate | `./sys-scan --min-severity low --fail-on high --fail-on-count 250` |
| Max transparency | `./sys-scan --process-inventory --modules-summary --process-hash` |

---
## 13. CI / Pipeline Integration
Suggested stages:
3. Optional signing (`--sign-gpg`).
4. Policy gate: severity & count thresholds.
5. Upload artifacts (report.json + report.json.asc + build.env).

	echo "Gate failed" >&2; exit 1; }
```

Streaming to SARIF‑aware platforms:
```bash
./sys-scan --sarif > results.sarif
```
<<<<<<< HEAD

### Release Validation Helper
The script `scripts/release_validate.py` provides lightweight invariants before tagging or publishing a build:
* Verifies fleet report schema exists & records its sha256.
* Hashes every `*.rule` under `rules/` into a deterministic manifest.
* Optionally enforces an expected semantic version (matches `project(... VERSION X.Y.Z)` in `CMakeLists.txt`).
* Can assert reproducible build flag was enabled (`--repro-required`).

Example:
```bash
python scripts/release_validate.py \
	--expected-version 0.1.0 \
	--schema schema/fleet_report.schema.json \
	--rules-dir rules \
	--output artifacts/release-manifest.json \
	--repro-required
```
Exit code non‑zero if any invariant fails; manifest always written for inspection.

An automated GitHub Actions workflow (`.github/workflows/release-validate.yml`) runs the validator on every push to `main` and on tags (`v*`). On tag pushes it also generates and uploads an SPDX SBOM plus the manifest to the GitHub Release.

=======
>>>>>>> 7616f75 (docs: hybrid licensing, compliance integration tests, HTML compliance section, remediation enrichment)
---
## 14. Examples
### Canonical JSON (excerpt)
```json
{
	"meta":{"hostname":"host","tool_version":"0.1.0","json_schema_version":"2"},

### NDJSON (first lines)
```json
{"type":"meta","tool_version":"0.1.0","schema":"2"}
{"type":"summary_extension","total_risk_score":880,"emitted_risk_score":310}
{"type":"finding","scanner":"process","id":"1234",...}
```

### SARIF (excerpt)
```json
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"sys-scan"}},"results":[{"ruleId":"proc_deleted","level":"high",...}]}]}
```

---
## 15. Advanced Flags Reference
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
--modules-hash                Include SHA256 of module file (if OpenSSL available)
--process-hash                Include SHA256 hash of process executable (first 1MB) if OpenSSL available
--process-inventory           Emit all processes (otherwise only IOC/anomalies)
--ioc-allow-file FILE         Newline-delimited additional env allowlist patterns
--fail-on-count N             Exit non-zero if total finding count >= N
--suid-expected list          Extra expected SUID paths (comma list)
--suid-expected-file FILE     Newline-delimited expected SUID paths
--canonical                   Emit canonical JSON (stable ordering & formatting)
--ndjson                      Emit newline-delimited meta/summary/finding lines
--sarif                       Emit SARIF 2.1.0 run
--rules-enable                Enable rule enrichment engine
--rules-dir DIR               Directory containing .rule files
--rules-allow-legacy          Allow loading legacy rule_version without hard fail
--no-user-meta                Suppress user/uid/gid/euid/egid in meta
--no-cmdline-meta             Suppress cmdline in meta
--no-hostname-meta            Suppress hostname in meta
--drop-priv                   Drop Linux capabilities early (best-effort; requires libcap)
--keep-cap-dac                Retain CAP_DAC_READ_SEARCH when using --drop-priv
--seccomp                     Apply restrictive seccomp-bpf profile after initialization
--seccomp-strict              Treat seccomp apply failure as fatal (exit code 4)
--sign-gpg KEYID              Detached ASCII armored signature (requires --output)
--write-env FILE              Emit .env file with version & binary hash
--slsa-level N                Declare SLSA build level (meta.provenance)
--version                     Print version & provenance summary
--help                        Show usage
```

> Placeholder for future screenshot: (Report summary terminal capture)
> Placeholder for future screenshot: (SARIF ingestion view)

---
## 16. Roadmap & Ideas
See also inline comments / issues. Near‑term concepts:
* Extended risk scoring calibrations.
* Package integrity (dpkg/rpm verify) & mismatch aggregation.
* Landlock / chroot sandbox addition.
* eBPF exec short‑lived process tracing (`--ioc-exec-trace`).
* Enhanced network exposure heuristics & fan‑out thresholds.
* Additional output signing backends (cosign, age).

### Intelligence Layer (Agent MVP – Proprietary)

An experimental Python intelligence layer prototype now lives under `agent/` providing:
* Schema validation & typed parsing (Pydantic subset + extensions: host_id, scan_id, tags, risk_subscores)
* Deterministic correlation (Phase 1 simple rules distinct from C++ emission-time rules)
* Baseline-ready design (SQLite store scaffold in `baseline.py`)
* Cost / token reduction (module, SUID, network summarizers) prior to any LLM usage
* Stub LLM summarizer (deterministic) with pluggable future LangGraph integration
* Structured enriched artifact (correlations, reductions, actions, summaries)

Quick start:
```bash
python -m venv agent/.venv
source agent/.venv/bin/activate
pip install -r agent/requirements.txt
./build/sys-scan --pretty --output report.json
python -m agent.cli analyze --report report.json --out enriched_report.json
jq '.summaries.executive_summary' enriched_report.json
```

Planned next phases:
1. Integrate LangGraph stateful nodes (stream partial reductions as scanners finish)
2. Baseline diff persistence (host_id + finding identity hash) feeding rarity scoring
3. Expanded deterministic correlations (multi-finding joins, exposure scoring)
4. Allowlist & rarity-driven risk_subscores feeding revised composite risk formula
5. Multi-format outputs (analyst markdown, slack snippet, remediation playbook YAML)
6. Action planner triggering optional secondary collection tasks

This layer stays optional and out-of-path for the core C++ scanner; it consumes the existing stable JSON. It is distributed under a proprietary license (see `LICENSE`) while the Core scanner remains MIT.

---
## 17. License & Usage
Hybrid model:
* Core scanner (C++ code under `src/`, schemas, rules) – MIT License.
* Intelligence Layer (`agent/`) – Proprietary (internal evaluation use only unless separately licensed).

See `LICENSE` for full hybrid terms and SPDX identifiers.


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

### Schema

The JSON Schema (`schema/v2.json`) explicitly enumerates dual metrics: `finding_count_total` vs `finding_count_emitted`, `severity_counts` vs `severity_counts_emitted`, and includes `emitted_risk_score` in `summary_extension` alongside `total_risk_score`. Additional properties remain open for forward compatibility; provenance and normalization flags (`meta.provenance`, `meta.normalized_time`) are permitted via `additionalProperties`.
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

---
### Phase 10 Productization Demo
A quick end-to-end demonstration (two scans, enrichment, HTML generation, diff, manifest, timing):
```bash
./scripts/demo_phase10.sh
```
Outputs:
- report_demo_1.json / report_demo_2.json (raw C++ scanner outputs)
- enriched_demo_1.json / enriched_demo_2.json (Python agent enriched)
- enriched_report.html (static dashboard)
- enriched_diff.md (risk movement & new/removed findings)
- manifest.json (version, rule pack SHA, embedding model hash, weights)

The script prints total wall time for two enrichment runs; single-run latency should target <1.5s on a modern laptop for typical host sizes.
