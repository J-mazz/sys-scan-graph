module;
#include <coroutine>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cctype>

export module sys_scan.scanners.mac;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class MACScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit MACScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "mac"; }
    std::string description() const override { return "Checks AppArmor and SELinux status"; }

    Generator<Finding> scan() override {
        bool selinux_present = false;
        bool apparmor_enabled = false;
        std::string test_root = sys_scan::utils::in_root(config_.test_root, "");

        // SELinux
        if (fs_.exists(sys_scan::utils::in_root(test_root, "/sys/fs/selinux"))) {
            selinux_present = true;
            std::string enforce = sys_scan::utils::trim(fs_.read_file(sys_scan::utils::in_root(test_root, "/sys/fs/selinux/enforce")));
            bool enforcing = (enforce == "1");

            Finding f;
            f.id = "selinux";
            f.title = "SELinux Status";
            f.severity = enforcing ? Severity::Info : Severity::Medium;
            f.description = enforcing ? "SELinux is enforcing" : "SELinux is permissive/disabled";
            f.metadata["present"] = "true";
            f.metadata["enforcing"] = enforce;
            co_yield f;
        } else {
            Finding f;
            f.id = "selinux";
            f.title = "SELinux Status";
            f.severity = Severity::Info;
            f.metadata["present"] = "false";
            co_yield f;
        }

        // AppArmor
        if (fs_.exists(sys_scan::utils::in_root(test_root, "/sys/module/apparmor/parameters/enabled"))) {
            std::string val = sys_scan::utils::trim(fs_.read_file(sys_scan::utils::in_root(test_root, "/sys/module/apparmor/parameters/enabled")));
            if (val == "Y") {
                apparmor_enabled = true;
                Finding f;
                f.id = "apparmor";
                f.title = "AppArmor Status";
                f.severity = Severity::Info;
                f.metadata["enabled"] = "true";
                co_yield f;
            }
        }

        // Unconfined critical processes (heuristic)
        size_t unconfined = 0;
        auto procs = fs_.list_directory(sys_scan::utils::in_root(test_root, "/proc"));
        for (const auto& p : procs) {
            if (!p.is_directory || !std::all_of(p.name.begin(), p.name.end(), ::isdigit)) continue;
            std::string attr = fs_.read_file(sys_scan::utils::in_root(test_root, "/proc/" + p.name + "/attr/current"));
            if (attr.find("unconfined") != std::string::npos) {
                std::string exe = fs_.read_symlink(sys_scan::utils::in_root(test_root, "/proc/" + p.name + "/exe"));
                if (exe == "/usr/sbin/sshd" || exe == "/usr/bin/dockerd") unconfined++;
            }
        }

        if (unconfined > 0) {
            Finding f;
            f.id = "apparmor_unconfined";
            f.title = "Unconfined Critical Processes";
            f.severity = Severity::Medium;
            f.description = "Found " + std::to_string(unconfined) + " critical processes unconfined";
            co_yield f;
        }
    }
};

}
