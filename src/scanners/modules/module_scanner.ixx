module;
#include <coroutine>
#include <string>
#include <vector>
#include <sstream>
#include <sys/utsname.h>

export module sys_scan.scanners.modules;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;
import sys_scan.scanners.module_utils;

export namespace sys_scan {

class ModuleScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit ModuleScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "modules"; }
    std::string description() const override { return "Scans kernel modules for signatures and taint"; }

    Generator<Finding> scan() override {
        if (!config_.modules_summary_only && !config_.hardening) co_return;

        struct utsname un;
        uname(&un);
        std::string kernel_release = un.release;
        std::string lib_base = "/lib/modules/" + kernel_release + "/";

        std::string modules = fs_.read_file("/proc/modules");
        auto lines = sys_scan::utils::read_lines_from_string(modules);
        
        size_t unsigned_count = 0;
        size_t oot_count = 0;
        size_t wx_sections = 0;

        for (const auto& line : lines) {
            std::stringstream ss(line);
            std::string name;
            ss >> name;
            if (name.empty()) continue;

            if (line.find("O") != std::string::npos || line.find("E") != std::string::npos) {
                 oot_count++;
            }
            
            std::string path = lib_base + "kernel/drivers/" + name + ".ko";
            if (!fs_.exists(path)) continue;

            if (SignatureAnalyzer::is_unsigned_module(path)) {
                unsigned_count++;
            }

            auto sections = ElfModuleHeuristics::parse_sections(path);
            if (ElfModuleHeuristics::has_wx_section(sections)) wx_sections++;
        }

        if (unsigned_count > 0 || oot_count > 0 || wx_sections > 0) {
            Finding f;
            f.id = "module_summary";
            f.title = "Kernel Module Summary";
            f.severity = Severity::Medium;
            f.description = "Unsigned:" + std::to_string(unsigned_count) + " OOT:" + std::to_string(oot_count) + " WX:" + std::to_string(wx_sections);
            co_yield f;
        }
    }
};

}
