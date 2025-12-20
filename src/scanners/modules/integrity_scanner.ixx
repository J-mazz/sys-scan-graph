module;
#include <coroutine>
#include <string>
#include <string_view>

export module sys_scan.scanners.integrity;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class IntegrityScanner : public Scanner {
    const IFileSystem& fs_;
    const IProcessRunner& runner_;
    const Config& config_;

public:
    explicit IntegrityScanner(const Config& cfg, const IFileSystem& fs, const IProcessRunner& runner)
        : config_(cfg), fs_(fs), runner_(runner) {}

    std::string name() const override { return "integrity"; }
    std::string description() const override { return "Verifies system package integrity"; }

    Generator<Finding> scan() override {
        if (!config_.integrity) co_return;

        // This scanner relies on invoking the host package manager (dpkg/rpm) via IProcessRunner.
        // That does not reliably support offline snapshot roots without chroot/containerization.
        if (!config_.test_root.empty() && config_.test_root != "/") {
            Finding f;
            f.id = "integrity:offline_unsupported";
            f.title = "Offline integrity check not supported";
            f.severity = Severity::Info;
            f.description = "IntegrityScanner requires executing the system package manager and does not support --test-root snapshots.";
            f.metadata["test_root"] = config_.test_root;
            co_yield f;
            co_return;
        }

        std::string output;
        bool used_dpkg = false;
        bool command_failed = false;
        int exit_code = 0;
        bool found_pm = false;

        if (fs_.exists("/usr/bin/dpkg")) {
            found_pm = true;
            if (auto res = runner_.exec("dpkg", {"-V"}); res) {
                output = *res;
                used_dpkg = true;
            } else {
                command_failed = true;
                exit_code = res.error();
            }
        } else if (fs_.exists("/usr/bin/rpm")) {
            found_pm = true;
            if (auto res = runner_.exec("rpm", {"-Va"}); res) {
                output = *res;
            } else {
                command_failed = true;
                exit_code = res.error();
            }
        }

        if (!found_pm) co_return;

        if (command_failed) {
            Finding f;
            f.id = "integrity:command_failed";
            f.title = "Integrity check command failed";
            f.severity = Severity::Info;
            f.description = "Package manager integrity command did not complete successfully";
            f.metadata["tool"] = used_dpkg ? "dpkg" : "rpm";
            f.metadata["exit_code"] = std::to_string(exit_code);
            co_yield f;
            co_return;
        }

        if (output.empty()) co_return;

        auto lines = sys_scan::utils::split_lines_sv(output);
        int mismatches = 0;

        for (auto line : lines) {
            if (line.empty()) continue;
            // Ignore config files (c) or missing (?)
            if (line.find(" c ") != std::string_view::npos || line.front() == '?') continue;

            mismatches++;
            if (mismatches <= 10) {
                Finding f;
                f.id = "pkg_mismatch_" + std::to_string(mismatches);
                f.title = "Package Integrity Mismatch";
                f.severity = Severity::Medium;
                f.description = std::string(line);
                f.metadata["tool"] = used_dpkg ? "dpkg" : "rpm";
                co_yield f;
            }
        }

        if (mismatches > 0) {
            Finding f;
            f.id = "integrity_summary";
            f.title = "Integrity Check Summary";
            f.severity = Severity::High;
            f.description = "Found " + std::to_string(mismatches) + " file mismatches";
            co_yield f;
        }
    }
};

}
