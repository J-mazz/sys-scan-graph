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
```bash
sudo apt update
sudo apt install -y build-essential cmake
# optional: libssl-dev (if you plan to use OpenSSL features later)
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --parallel
./sys-scan > report.json
```

## JSON Output Structure
```json
{
  "results": [
    {
      "scanner": "processes",
      "start_time": "2025-08-25T12:00:00Z",
      "end_time": "2025-08-25T12:00:01Z",
      "findings": [ { "id": "123", "title": "Process 123", "severity": "info", ... } ]
    }
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

## Roadmap Ideas
- Add hashing of binaries (optional OpenSSL/Blake3)
- Add package integrity checks (dpkg --verify)
- SELinux/AppArmor status
- Systemd service security options (NoNewPrivileges, ProtectSystem, etc.)
- Container detection
- User/Group enumeration anomalies
- CVE matching via local database (deferred)

## License
(Choose and add appropriate license.)
