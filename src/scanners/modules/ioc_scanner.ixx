module;
#include <coroutine>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

export module sys_scan.scanners.ioc;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class IOCScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit IOCScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "ioc"; }
    std::string description() const override { return "Scans for Indicators of Compromise"; }

    Generator<Finding> scan() override {
        std::vector<std::string> suspicious = {"cryptominer", "xmrig", "minerd", "malware"};

        const std::string proc_root = sys_scan::utils::in_root(config_.test_root, "/proc");
        auto entries = fs_.list_directory(proc_root);
        for (const auto& entry : entries) {
            if (!entry.is_directory || !std::all_of(entry.name.begin(), entry.name.end(), ::isdigit)) continue;

            std::string cmdline = fs_.read_file(proc_root + "/" + entry.name + "/cmdline");
            std::string environ = fs_.read_file(proc_root + "/" + entry.name + "/environ");

            // Check Command Lines
            for (const auto& s : suspicious) {
                if (cmdline.find(s) != std::string::npos) {
                    Finding f;
                    f.id = "ioc:suspicious:" + entry.name;
                    f.title = "Suspicious Process";
                    f.severity = Severity::Critical;
                    f.description = "Process matches suspicious pattern: " + s;
                    f.metadata["pid"] = entry.name;
                    co_yield f;
                }
            }

            // Check Environment
            if (environ.find("LD_PRELOAD") != std::string::npos) {
                Finding f;
                f.id = "ioc:ld_preload:" + entry.name;
                f.title = "LD_PRELOAD Detected";
                f.severity = Severity::High;
                f.description = "Process has LD_PRELOAD set";
                f.metadata["pid"] = entry.name;
                co_yield f;
            }
            
            // Check deleted executable
              std::string exe = fs_.read_symlink(proc_root + "/" + entry.name + "/exe");
            if (exe.find("(deleted)") != std::string::npos) {
                 Finding f;
                 f.id = "ioc:deleted_exe:" + entry.name;
                 f.title = "Deleted Executable Running";
                 f.severity = Severity::High;
                 f.description = "Process running from deleted file: " + exe;
                 f.metadata["pid"] = entry.name;
                 co_yield f;
            }
        }
    }
};

}