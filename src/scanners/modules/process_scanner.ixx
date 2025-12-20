module;
#include <coroutine>
#include <string>
#include <vector>
#include <string_view>
#include <charconv>
#include <system_error>
#include <cctype>
#include <algorithm>

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

            // Parse status for uid/gid and process name (lightweight, non-allocating)
            std::string status = fs_.read_file(pid_dir + "/status");
            std::string_view status_view{status};
            auto parse_first_int = [](std::string_view line) -> std::string {
                // after the key, fields are whitespace separated integers
                size_t pos = line.find_first_not_of("\t ");
                if (pos == std::string_view::npos) return {};
                line.remove_prefix(pos);
                // read until next space
                size_t end = line.find_first_of(" \t");
                std::string_view token = line.substr(0, end == std::string_view::npos ? line.size() : end);
                return std::string(token);
            };

            auto find_line = [&](std::string_view key)->std::string {
                size_t start = 0;
                while (start < status_view.size()) {
                    size_t nl = status_view.find('\n', start);
                    std::string_view line = status_view.substr(start, nl == std::string_view::npos ? status_view.size() - start : nl - start);
                    if (line.compare(0, key.size(), key) == 0) {
                        line.remove_prefix(key.size());
                        return parse_first_int(line);
                    }
                    if (nl == std::string_view::npos) break;
                    start = nl + 1;
                }
                return {};
            };

            std::string uid = config_.no_user_meta ? std::string{} : find_line("Uid:");
            std::string gid = config_.no_user_meta ? std::string{} : find_line("Gid:");
            std::string name_line = find_line("Name:");

            Finding f;
            f.id = entry.name;
            f.title = "Process " + entry.name;
            f.severity = Severity::Info;
            f.description = cmdline.empty() ? "(kernel thread or hidden)" : cmdline;
            f.metadata["pid"] = entry.name;
            if(!uid.empty()) f.metadata["uid"] = uid;
            if(!gid.empty()) f.metadata["gid"] = gid;
            if(!name_line.empty()) f.metadata["comm"] = name_line;
            
            co_yield f;
        }
    }
};

}