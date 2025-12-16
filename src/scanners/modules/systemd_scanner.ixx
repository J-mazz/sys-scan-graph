module;
#include <coroutine>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

export module sys_scan.scanners.systemd;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class SystemdUnitScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

    struct UnitData {
        std::string name;
        std::map<std::string, std::string> properties;
    };

    UnitData parse_unit(const std::string& name, const std::string& content) const {
        UnitData data; 
        data.name = name;
        auto lines = sys_scan::utils::read_lines_from_string(content);
        for(const auto& line : lines) {
            auto trim_line = sys_scan::utils::trim(line);
            if(trim_line.empty() || trim_line[0] == '#' || trim_line[0] == ';') continue;
            auto pos = trim_line.find('=');
            if(pos != std::string::npos) {
                std::string key = sys_scan::utils::trim(trim_line.substr(0, pos));
                std::string val = sys_scan::utils::trim(trim_line.substr(pos + 1));
                data.properties[key] = val;
            }
        }
        return data;
    }

public:
    explicit SystemdUnitScanner(const Config& cfg, const IFileSystem& fs) 
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "systemd_units"; }
    std::string description() const override { return "Evaluates systemd service unit hardening"; }

    Generator<Finding> scan() override {
        if(!config_.hardening) co_return;

        std::string root = config_.test_root;
        std::vector<std::string> search_paths = {
            root + "/etc/systemd/system",
            root + "/usr/lib/systemd/system",
            root + "/lib/systemd/system"
        };

        for(const auto& dir : search_paths) {
            if(!fs_.is_directory(dir)) continue;
            
            auto files = fs_.list_directory(dir);
            for(const auto& entry : files) {
                if(!entry.name.ends_with(".service")) continue;
                
                std::string content = fs_.read_file(dir + "/" + entry.name);
                if(content.empty()) continue;

                UnitData unit = parse_unit(entry.name, content);
                
                // Only analyze services (must have ExecStart)
                if(!unit.properties.count("ExecStart")) continue;

                // Check Hardening
                static const struct { const char* k; const char* exp; Severity s; } checks[] = {
                    {"NoNewPrivileges", "yes", Severity::Medium},
                    {"PrivateTmp", "yes", Severity::Low},
                    {"ProtectSystem", "strict", Severity::Medium},
                    {"ProtectHome", "read-only", Severity::Low},
                };

                for(const auto& c : checks) {
                    bool present = unit.properties.count(c.k);
                    std::string val = present ? unit.properties.at(c.k) : "";
                    bool ok = present && (std::string(c.exp).empty() || val == c.exp);
                    
                    // Special case for ProtectSystem=full vs strict
                    if(std::string(c.k) == "ProtectSystem" && val == "full") ok = false;

                    Finding f;
                    f.id = "systemd:" + std::string(c.k) + ":" + unit.name;
                    f.title = unit.name + " " + c.k;
                    f.metadata["unit"] = unit.name;
                    f.metadata["key"] = c.k;
                    if(present) f.metadata["value"] = val;
                    
                    if(ok) {
                        f.severity = Severity::Info;
                        f.description = std::string(c.k) + " enforced";
                    } else {
                        f.severity = c.s;
                        f.description = std::string(c.k) + " not set to " + c.exp;
                    }
                    co_yield f;
                }
            }
        }
    }
};

}