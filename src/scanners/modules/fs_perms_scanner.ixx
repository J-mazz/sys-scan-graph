module;
#include <coroutine>
#include <string>
#include <vector>
#include <filesystem>
#include <stack>
#include <string_view>
#include <charconv>

export module sys_scan.scanners.fs_perms;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

namespace fs = std::filesystem;

export namespace sys_scan {

class FsPermsScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

    static bool is_world_writable(const std::filesystem::perms p) {
        using fs_perms = std::filesystem::perms;
        return (p & fs_perms::others_write) != fs_perms::none;
    }

    static bool is_suid(const std::filesystem::perms p) {
        using fs_perms = std::filesystem::perms;
        return (p & fs_perms::set_uid) != fs_perms::none;
    }

public:
    explicit FsPermsScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "fs_perms"; }
    std::string description() const override { return "Scans for world-writable files and SUID binaries"; }

    Generator<Finding> scan() override {
        if (config_.fast_scan) co_return;

        const std::string root = config_.test_root;

        // Targets for SUID/WW checks – focused set for least-permission principle without full FS crawl
        std::vector<std::string> suid_roots = {
            "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"
        };

        std::vector<std::string> world_writable_paths = {
            "/tmp", "/var/tmp", "/dev/shm"
        };

        // Check critical files for world-writable
        std::vector<std::string> critical_files = {
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/fstab", "/boot/grub/grub.cfg"
        };

        for (const auto& path : critical_files) {
            const std::string scan_path = sys_scan::utils::in_root(root, path);
            if (!fs_.exists(scan_path)) continue;
            auto perms = fs_.permissions(scan_path);
            if (perms == fs::perms::unknown) continue;
            if (is_world_writable(perms)) {
                Finding f;
                f.id = "fs:world_writable:" + path;
                f.title = "World-writable critical file";
                f.severity = Severity::High;
                f.description = path + " is world-writable";
                f.metadata["path"] = path;
                if (!root.empty()) f.metadata["scan_path"] = scan_path;
                co_yield f;
            }
        }

        // Check temp-like mounts for missing protections already handled in MountScanner, but enforce world-writable visibility here too
        for (const auto& path : world_writable_paths) {
            const std::string scan_path = sys_scan::utils::in_root(root, path);
            if (!fs_.exists(scan_path)) continue;
            auto perms = fs_.permissions(scan_path);
            if (perms == fs::perms::unknown) continue;
            if (!is_world_writable(perms)) continue; // we expect ww on tmp, but flag if not? skip
        }

        // SUID scan over targeted roots (non-recursive shallow walk per directory)
        for (const auto& suid_root : suid_roots) {
            const std::string scan_root = sys_scan::utils::in_root(root, suid_root);
            if (!fs_.is_directory(scan_root)) continue;
            auto entries = fs_.list_directory(scan_root);
            for (const auto& e : entries) {
                const std::string logical_path = suid_root + "/" + e.name;
                const std::string scan_path = scan_root + "/" + e.name;
                if (!e.is_regular) continue;
                auto perms = fs_.permissions(scan_path);
                if (perms == fs::perms::unknown) continue;
                if (is_suid(perms)) {
                    Finding f;
                    f.id = "fs:suid:" + logical_path;
                    f.title = "SUID binary";
                    f.severity = Severity::Medium;
                    f.description = logical_path + " has setuid bit";
                    f.metadata["path"] = logical_path;
                    if (!root.empty()) f.metadata["scan_path"] = scan_path;
                    co_yield f;
                }
            }
        }
    }
};

}
