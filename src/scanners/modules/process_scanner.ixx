module;
#include <coroutine>
#include <string>
#include <vector>
#include <charconv>
#include <system_error>

export module sys_scan.scanners.process;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class ProcessScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit ProcessScanner(const Config& cfg, const IFileSystem& fs) 
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "processes"; }
    std::string description() const override { return "Enumerate running processes"; }

    Generator<Finding> scan() override {
        if(!config_.process_inventory && !config_.all_processes) co_return;

        std::string proc_root = sys_scan::utils::in_root(config_.test_root, "/proc");
        auto entries = fs_.list_directory(proc_root);
        
        for(const auto& entry : entries) {
            if(!entry.is_directory) continue;
            // Check if PID
            int pid = 0;
            auto [ptr, ec] = std::from_chars(entry.name.data(), entry.name.data() + entry.name.size(), pid);
            if(ec != std::errc()) continue;

            std::string pid_dir = proc_root + "/" + entry.name;
            std::string cmdline = fs_.read_file(pid_dir + "/cmdline");
            // Replace nulls with spaces for display
            for(char& c : cmdline) { if(c == '\0') c = ' '; }
            cmdline = sys_scan::utils::trim(cmdline);

            if(cmdline.empty() && !config_.all_processes) continue;

            Finding f;
            f.id = entry.name;
            f.title = "Process " + entry.name;
            f.severity = Severity::Info;
            f.description = cmdline.empty() ? "(kernel thread or hidden)" : cmdline;
            
            // Read status for UID/GID if needed
            if(!config_.no_user_meta) {
                std::string status = fs_.read_file(pid_dir + "/status");
                // Simple parsing logic would go here, simplified for this example
                // f.metadata["uid"] = parse_uid(status);
            }
            
            co_yield f;
        }
    }
};

}