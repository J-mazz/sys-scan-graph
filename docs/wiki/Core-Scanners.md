# Core Scanners

This page details the core security scanners implemented in the C++ scanner engine, including their capabilities, output formats, and configuration options.

## Overview

The core scanner includes multiple specialized scanners that enumerate different aspects of host security. Each scanner produces structured findings with consistent metadata and severity classification.

## Scanner Registry

Scanners are registered in a deterministic order to ensure stable JSON output:

```cpp
ScannerRegistry::register_all_default()
```

This fixed ordering enables reliable diffing and caching of scan results.

## Available Scanners

### Process Scanner (`processes`)
Enumerates running processes and their characteristics.

**Capabilities:**
- Reads `/proc/*/status` and `/proc/*/cmdline`
- Optional SHA256 hashing of process executables (first 1MB)
- Captures process metadata (PID, PPID, UID, GID, state)

**Configuration:**
- `--process-hash`: Enable executable hashing using OpenSSL
- `--max-processes`: Limit number of processes to scan (default: unlimited)

**Example Output:**
```json
{
  "id": "process.unusual.parent",
  "title": "Process with unusual parent",
  "severity": "medium",
  "description": "Process has parent that is not a standard system process",
  "metadata": {
    "pid": "1234",
    "ppid": "1",
    "cmdline": "/usr/bin/suspicious",
    "parent_cmdline": "/bin/bash"
  }
}
```

### Network Scanner (`network`)
Analyzes network socket information and listening services.

**Capabilities:**
- Parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- Identifies listening sockets and established connections
- Applies severity heuristics for exposed services

**Configuration:**
- `--max-sockets`: Limit number of sockets to scan (default: 1000)
- State filters: `listen`, `established`, `time_wait`
- Protocol filters: `tcp`, `udp`, `tcp6`, `udp6`

**Example Output:**
```json
{
  "id": "network.exposed.service",
  "title": "Exposed network service",
  "severity": "high",
  "description": "Service listening on external interface",
  "metadata": {
    "local_address": "0.0.0.0:8080",
    "remote_address": "0.0.0.0:0",
    "state": "listen",
    "inode": "12345"
  }
}
```

### Kernel Parameters Scanner (`kernel_params`)
Snapshots kernel security parameters and hardening settings.

**Capabilities:**
- Reads `/proc/sys/kernel/*` and `/proc/sys/net/*` parameters
- Compares against security best practices
- Identifies misconfigured kernel parameters

**Configuration:**
- Custom parameter allowlists and denylists
- Severity mapping for different parameter categories

**Example Output:**
```json
{
  "id": "kernel.hardening.disabled",
  "title": "Kernel hardening parameter disabled",
  "severity": "medium",
  "description": "Security-relevant kernel parameter is not set",
  "metadata": {
    "parameter": "kernel.kptr_restrict",
    "expected": "1",
    "actual": "0"
  }
}
```

### Module Scanner (`modules`)
Analyzes loaded kernel modules for security and compliance.

**Capabilities:**
- Enumerates `/proc/modules` and module files
- Detects out-of-tree and unsigned modules
- Handles compressed module files (`.ko.gz`, `.ko.xz`)

**Configuration:**
- `--modules-summary`: Generate summary statistics instead of individual findings
- Compression support: `gzip`, `xz` (external utilities)

**Example Output:**
```json
{
  "id": "module.unsigned",
  "title": "Unsigned kernel module",
  "severity": "low",
  "description": "Kernel module is not signed",
  "metadata": {
    "module": "suspicious_module",
    "size": "45056",
    "used_by": "2"
  }
}
```

### World Writable Files Scanner (`world_writable`)
Identifies files with overly permissive permissions.

**Capabilities:**
- Walks configured directory trees
- Reports world-writable files and directories
- Applies exclusion patterns for known safe paths

**Configuration:**
- Directory allowlists and denylists
- File extension exclusions
- Path pattern exclusions

**Example Output:**
```json
{
  "id": "file.world_writable",
  "title": "World-writable file",
  "severity": "medium",
  "description": "File has world write permissions",
  "metadata": {
    "path": "/tmp/suspicious_file",
    "permissions": "0777",
    "owner": "root",
    "size": "1024"
  }
}
```

### SUID/SGID Scanner (`suid`)
Analyzes setuid/setgid binaries for security risks.

**Capabilities:**
- Aggregates SUID/SGID files by inode (handles hardlinks)
- Identifies unusual or suspicious locations
- Cross-references with known safe binaries

**Configuration:**
- Path allowlists for trusted SUID binaries
- Severity escalation for unusual locations

**Example Output:**
```json
{
  "id": "suid.unusual.location",
  "title": "SUID binary in unusual location",
  "severity": "high",
  "description": "SUID binary found outside standard system directories",
  "metadata": {
    "path": "/home/user/suid_binary",
    "permissions": "4755",
    "owner": "user",
    "inode": "123456"
  }
}
```

### Indicators of Compromise Scanner (`ioc`)
Heuristic detection of compromise indicators.

**Capabilities:**
- Deleted executable detection
- Execution from temporary directories
- Suspicious environment variable usage
- SUID binaries in user directories

**Configuration:**
- `--ioc-allow` / `--ioc-allow-file`: Allowlist for false positives
- Configurable severity thresholds

**Example Output:**
```json
{
  "id": "ioc.temp.execution",
  "title": "Execution from temporary directory",
  "severity": "medium",
  "description": "Process executed from temporary directory",
  "metadata": {
    "pid": "1234",
    "cmdline": "/tmp/malicious_binary",
    "parent_pid": "5678"
  }
}
```

### Mandatory Access Control Scanner (`mac`)
Assesses SELinux/AppArmor configuration and enforcement.

**Capabilities:**
- Captures MAC system status
- Counts policy violations and complain mode entries
- Identifies unconfined critical processes

**Configuration:**
- MAC system detection (SELinux, AppArmor, or none)
- Violation threshold configuration

**Example Output:**
```json
{
  "id": "mac.unconfined.process",
  "title": "Unconfined critical process",
  "severity": "low",
  "description": "Critical system process running unconfined",
  "metadata": {
    "pid": "1234",
    "cmdline": "/usr/sbin/critical_service",
    "mac_context": "unconfined"
  }
}
```

### Compliance Scanner (`compliance`)
Evaluates compliance against industry standards.

**Capabilities:**
- PCI DSS 4.0 control assessment
- HIPAA Security Rule evaluation
- NIST CSF 2.0 framework compliance
- Per-standard scoring and gap analysis

**Configuration:**
- `--compliance-enable`: Enable compliance scanning
- `--compliance-standards`: Specify standards to evaluate
- `--compliance-gap-analysis`: Enable remediation gap reporting

**Example Output:**
```json
{
  "id": "compliance.pci.fail",
  "title": "PCI DSS Control Failure",
  "severity": "high",
  "description": "Failed PCI DSS 4.0 control requirement",
  "metadata": {
    "standard": "PCI DSS 4.0",
    "control": "2.2.4",
    "requirement": "Implement automated audit trails",
    "status": "fail"
  }
}
```

## Output Schema

### Finding Structure
All scanners produce findings with a consistent structure:

```json
{
  "id": "string",           // Unique, stable identifier
  "title": "string",        // Human-readable title
  "severity": "string",     // info|low|medium|high|critical
  "description": "string",  // Detailed description
  "metadata": {             // Sorted key-value pairs
    "key1": "value1",
    "key2": "value2"
  }
}
```

### JSON Schema Versioning
- **Current Version**: 2
- **Compatibility**: Backward compatible within major versions
- **Breaking Changes**: Increment major version
- **Additive Changes**: Increment minor version

## Scanner Execution

### Sequential Processing
Scanners run in deterministic order to ensure stable output:

1. `processes` - Process enumeration
2. `network` - Network socket analysis
3. `kernel_params` - Kernel parameter checks
4. `modules` - Module security assessment
5. `world_writable` - File permission analysis
6. `suid` - Setuid binary analysis
7. `ioc` - Compromise indicator detection
8. `mac` - MAC system evaluation
9. `compliance` - Standards compliance (conditional)

### Performance Characteristics
- **Memory Usage**: Streaming processing with minimal memory footprint
- **I/O Patterns**: Sequential file reads with early termination options
- **Threading**: Single-threaded with mutex-protected data structures
- **Limits**: Configurable caps prevent resource exhaustion

## Configuration Options

### Global Options
- `--min-severity`: Filter findings below specified severity
- `--output-format`: json|json-pretty|sarif
- `--canonical`: Enable canonical output ordering

### Scanner-Specific Options
- `--process-hash`: Enable process executable hashing
- `--modules-summary`: Generate module summary statistics
- `--ioc-allow-file`: Specify IOC allowlist file
- `--compliance-enable`: Enable compliance scanning

## Error Handling

### Non-Fatal Errors
- Permission denied on `/proc` entries: Silently skip
- File read failures: Omit data, continue scanning
- Module decompression failures: Skip problematic modules

### Future Enhancements
- Structured warning channel for non-fatal errors
- Detailed error reporting with context
- Recovery mechanisms for partial failures

## Integration Examples

### Basic Scan
```bash
sys-scan --output-format json-pretty
```

### Compliance-Focused Scan
```bash
sys-scan --compliance-enable --min-severity medium --canonical
```

### Development/Debug Scan
```bash
sys-scan --process-hash --modules-summary --ioc-allow-file allowlist.txt
```

## Related Documentation

- **[Architecture](Architecture.md)** - System architecture overview
- **[CLI Guide](CLI-Guide.md)** - Command-line usage and options
- **[Extensibility](Extensibility.md)** - Adding new scanners
- **[Testing](Testing-and-CI.md)** - Scanner testing and validation

---

*For questions about specific scanners or their implementation, see the [Contributing Guide](../../CONTRIBUTING.md) or open a [GitHub Issue](https://github.com/Mazzlabs/sys-scan-graph/issues).*"