module;
#include <coroutine>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <algorithm>
#include <charconv>

export module sys_scan.scanners.kernel;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

// Combined module for Kernel Params and Hardening
class KernelScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit KernelScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "kernel"; }
    std::string description() const override { return "Checks kernel parameters and hardening configuration"; }

    Generator<Finding> scan() override {
        if (!config_.hardening) co_return;

        // Map of param -> expected value
        std::map<std::string, std::string_view> hardening_params = {
            {"kernel.kptr_restrict", "2"},
            {"kernel.dmesg_restrict", "1"},
            {"kernel.yama.ptrace_scope", "1"},
            {"fs.protected_symlinks", "1"},
            {"fs.protected_hardlinks", "1"},
            {"net.ipv4.conf.all.accept_redirects", "0"},
            {"net.ipv4.conf.default.accept_redirects", "0"}
        };

        for (const auto& [param, expected] : hardening_params) {
             std::string path = "/proc/sys/" + param;
             size_t start_pos = 10; // len("/proc/sys/")
             for (size_t i = start_pos; i < path.length(); ++i) {
                 if (path[i] == '.') path[i] = '/';
             }

                 std::string raw = fs_.read_file(sys_scan::utils::in_root(config_.test_root, path));
                 std::string value = sys_scan::utils::trim(raw);
             
                 // If missing, arguably a finding, but maybe module not loaded
                 if (value.empty()) continue;

                 if (value != expected) {
                     Finding f;
                     f.id = "kernel:" + param;
                     f.title = "Weak Kernel Parameter: " + param;
                     f.severity = Severity::Medium;
                     f.description = "Value is " + value + ", expected " + std::string(expected);
                     f.metadata["param"] = param;
                     f.metadata["actual"] = value;
                     f.metadata["expected"] = expected;
                     co_yield f;
                 }
        }

            // Additional fast checks: taint flag and lockdown status
            auto parse_int = [](std::string_view sv, int& out)->bool {
                auto [p, ec] = std::from_chars(sv.data(), sv.data()+sv.size(), out);
                return ec == std::errc();
            };

            std::string taint_raw = fs_.read_file(sys_scan::utils::in_root(config_.test_root, "/proc/sys/kernel/tainted"));
            if (!taint_raw.empty()) {
                std::string_view tv = sys_scan::utils::trim(taint_raw);
                int taint = 0;
                if (parse_int(tv, taint) && taint != 0) {
                    Finding f;
                    f.id = "kernel_taint";
                    f.title = "Kernel is tainted";
                    f.severity = Severity::Medium;
                    f.description = "Kernel taint flag: " + std::to_string(taint);
                    f.metadata["taint"] = std::to_string(taint);
                    co_yield f;
                }
            }

            std::string lockdown_raw = fs_.read_file(sys_scan::utils::in_root(config_.test_root, "/sys/kernel/security/lockdown"));
            if (!lockdown_raw.empty()) {
                std::string trimmed = sys_scan::utils::trim(lockdown_raw);
                if (trimmed != "none") {
                    Finding f;
                    f.id = "kernel_lockdown";
                    f.title = "Kernel lockdown";
                    f.severity = Severity::Info;
                    f.description = "Lockdown mode: " + trimmed;
                    f.metadata["mode"] = trimmed;
                    co_yield f;
                }
            }
    }
};

}
