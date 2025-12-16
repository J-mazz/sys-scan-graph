import sys_scan.types;
import sys_scan.report;
import sys_scan.scanner;
import sys_scan.interfaces;
import sys_scan.system_services;
import sys_scan.config;
import sys_scan.registry;

// Import Converted Scanners
import sys_scan.scanners.auditd;
import sys_scan.scanners.systemd;
import sys_scan.scanners.process;
import sys_scan.scanners.network;
import sys_scan.scanners.kernel;
import sys_scan.scanners.mount;
import sys_scan.scanners.fs_perms;
import sys_scan.scanners.mac;
import sys_scan.scanners.integrity;
import sys_scan.scanners.ioc;
import sys_scan.scanners.container;
import sys_scan.scanners.yara;
import sys_scan.scanners.modules;
import sys_scan.scanners.ebpf;

#include <iostream>
#include <vector>
#include <memory>

using namespace sys_scan;

int main(int argc, char** argv) {
    // 1. Composition Root: Instantiate Services
    RealFileSystem fs;
    RealProcessRunner runner;
    RealSystemInfo sysinfo;
    RealSleeper sleeper;
    
    // 2. Instantiate Config
    Config cfg;
    // Argument parsing would populate 'cfg' here (using sys_scan.utils or similar)
    // cfg.hardening = true; // Example default

    // 3. Register Scanners with Dependency Injection
    ScannerRegistry registry;
    registry.register_scanner(std::make_unique<AuditdScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<SystemdUnitScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<ProcessScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<NetworkScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<KernelScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<MountScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<FsPermsScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<MACScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<IntegrityScanner>(cfg, fs, runner));
    registry.register_scanner(std::make_unique<IOCScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<ModuleScanner>(cfg, fs, sysinfo));
        registry.register_scanner(std::make_unique<ContainerScanner>(cfg, fs));
        registry.register_scanner(std::make_unique<YaraScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<EbpfScanner>(cfg, fs, sleeper));

    // 4. Run Scanners
    Report report;
    registry.run_all(report, cfg);

    // 5. Output Results
    std::cout << "Scan complete. Found " << report.results().size() << " scanner results." << std::endl;
    for(const auto& res : report.results()) {
        for(const auto& f : res.findings) {
            std::cout << "[" << severity_to_string(f.severity) << "] " 
                      << f.title << ": " << f.description << std::endl;
        }
    }
    
    return 0;
}
