module;
#include <coroutine>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <utility>

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
        bool has_execstart{false};
        std::string no_new_priv;
        std::string private_tmp;
        std::string protect_system;
        std::string protect_home;
    };

    UnitData parse_unit(const std::string& name, const std::string& content) const {
        UnitData data;
        data.name = name;

        auto trim_sv = [](std::string_view sv) {
            const char* ws = " \t\n\r";
            auto start = sv.find_first_not_of(ws);
            if (start == std::string_view::npos) return std::string_view{};
            auto end = sv.find_last_not_of(ws);
            return sv.substr(start, end - start + 1);
        };

        for (auto line : sys_scan::utils::split_lines_sv(content)) {
            line = trim_sv(line);
            if (line.empty() || line.front() == '#' || line.front() == ';') continue;
            auto pos = line.find('=');
            if (pos == std::string_view::npos) continue;

            std::string_view key_sv = trim_sv(line.substr(0, pos));
            std::string_view val_sv = trim_sv(line.substr(pos + 1));
            if (key_sv.empty()) continue;

            if (key_sv == "ExecStart") {
                data.has_execstart = true;
                continue;
            }
            if (key_sv == "NoNewPrivileges") {
                data.no_new_priv.assign(val_sv.begin(), val_sv.end());
            } else if (key_sv == "PrivateTmp") {
                data.private_tmp.assign(val_sv.begin(), val_sv.end());
            } else if (key_sv == "ProtectSystem") {
                data.protect_system.assign(val_sv.begin(), val_sv.end());
            } else if (key_sv == "ProtectHome") {
                data.protect_home.assign(val_sv.begin(), val_sv.end());
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

        std::string root = sys_scan::utils::in_root(config_.test_root, "");
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
                if(!unit.has_execstart) continue;

                // Check Hardening
                static constexpr std::array checks {
                    std::pair{std::string_view{"NoNewPrivileges"}, std::string_view{"yes"}},
                    std::pair{std::string_view{"PrivateTmp"}, std::string_view{"yes"}},
                    std::pair{std::string_view{"ProtectSystem"}, std::string_view{"strict"}},
                    std::pair{std::string_view{"ProtectHome"}, std::string_view{"read-only"}}
                };

                for(const auto& c : checks) {
                    const std::string* val_ptr = nullptr;
                    if (c.first == "NoNewPrivileges") val_ptr = &unit.no_new_priv;
                    else if (c.first == "PrivateTmp") val_ptr = &unit.private_tmp;
                    else if (c.first == "ProtectSystem") val_ptr = &unit.protect_system;
                    else if (c.first == "ProtectHome") val_ptr = &unit.protect_home;

                    bool present = val_ptr && !val_ptr->empty();
                    std::string val = present ? *val_ptr : std::string{};
                    bool ok = present && val == c.second;

                    // Special case for ProtectSystem=full vs strict
                    if(c.first == "ProtectSystem" && val == "full") ok = false;

                    Finding f;
                    f.id = "systemd:" + std::string(c.first) + ":" + unit.name;
                    f.title = unit.name + " " + std::string(c.first);
                    f.metadata["unit"] = unit.name;
                    f.metadata["key"] = std::string(c.first);
                    if(present) f.metadata["value"] = val;

                    if(ok) {
                        f.severity = Severity::Info;
                        f.description = std::string(c.first) + " enforced";
                    } else {
                        f.severity = (c.first == "NoNewPrivileges" || c.first == "ProtectSystem") ? Severity::Medium : Severity::Low;
                        f.description = std::string(c.first) + " not set to " + std::string(c.second);
                    }
                    co_yield f;
                }
            }
        }
    }
};

}