# Changelog

All notable changes will be documented in this file.

## [Unreleased]
### Added
- `--process-hash` optional SHA256 hashing of process executables (OpenSSL-enabled builds).
- `json_schema_version` field in JSON meta (currently `1`).
- Noise reduction flags: `--process-inventory` (off by default) and `--modules-anomalies-only`.
- IOC rule metadata (`rule` key) indicating trigger: cmd_path_pattern, deleted_executable, exec_from_world_writable, ld_env_temp, executable_in_temp, suid_in_home, preload_world_writable, preload_missing.
- SUID expected baseline with downgrade: `--suid-expected`, `--suid-expected-file` plus builtin list (sudo/passwd/...);
- Allowlist configuration: `--ioc-allow-file` for newline-delimited IOC environment allowlist additions.
- Failure threshold: `--fail-on-count` for gating on total finding count.

### Changed
- SELinux absence severity downgraded to low when AppArmor enabled (still high if neither MAC active).
- Modules summary: unsigned/out-of-tree detection supports anomalies-only mode.

### Removed
- (None)

### Fixed
- Added missing include for unordered_set in SUID scanner after baseline logic.

## [0.1.0] - Initial Release
- Core scanners (processes, network, kernel params, modules, world_writable, suid_sgid, ioc, mac)
- JSON summary & severity filtering
- Module summary mode & IOC aggregation
