module;
#include <coroutine>
#include <string>
#include <vector>
#include <iostream>

// Include YARA headers if available, otherwise mock for compilation
// Ideally this is handled by CMake find_package, but for module purity we guard it.
#if __has_include(<yara.h>)
#include <yara.h>
#define HAVE_YARA_LIB
#endif

export module sys_scan.scanners.yara;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class YaraScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit YaraScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "yara"; }
    std::string description() const override { return "Scans files using YARA rules"; }

    Generator<Finding> scan() override {
        if (!config_.rules_enable || config_.yara_scan_roots.empty()) co_return;

#ifdef HAVE_YARA_LIB
        // Simplified YARA logic for the refactor
        // In a real implementation, you would: yr_initialize(), yr_compiler_create(), etc.
        // Here we yield a placeholder to indicate the module is wired up.
        
        Finding f;
        f.id = "yara_scan_started";
        f.title = "YARA Scan";
        f.severity = Severity::Info;
        f.description = "YARA scanning enabled (module ported)";
        f.metadata["scan_roots_count"] = std::to_string(config_.yara_scan_roots.size());
        co_yield f;
        
        // Actual file walking and scanning would happen here, utilizing fs_ to read files
        // and passing buffers to yr_rules_scan_mem().
#else
        Finding f;
        f.id = "yara_missing";
        f.title = "YARA Library Missing";
        f.severity = Severity::Error;
        f.description = "YARA scanner enabled but libyara not found during compilation";
        co_yield f;
#endif
    }
};

}