module;
#include <coroutine>
#include <string>
#include <vector>
#include <sstream>

export module sys_scan.scanners.mount;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class MountScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit MountScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "mounts"; }
    std::string description() const override { return "Checks mount points for security options (nodev, noexec, nosuid)"; }

    Generator<Finding> scan() override {
        std::string mounts = fs_.read_file(sys_scan::utils::in_root(config_.test_root, "/proc/mounts"));
        if (mounts.empty()) co_return;

        auto lines = sys_scan::utils::read_lines_from_string(mounts);
        for (const auto& line : lines) {
            std::stringstream ss(line);
            std::string device, path, type, options;
            ss >> device >> path >> type >> options;

            // Check for insecure mounts on sensitive paths
            bool is_tmp = (path == "/tmp" || path == "/var/tmp" || path == "/dev/shm");
            
            if (is_tmp) {
                bool has_noexec = (options.find("noexec") != std::string::npos);
                bool has_nosuid = (options.find("nosuid") != std::string::npos);
                bool has_nodev  = (options.find("nodev")  != std::string::npos);

                if (!has_noexec || !has_nosuid || !has_nodev) {
                    Finding f;
                    f.id = "mount:insecure:" + path;
                    f.title = "Insecure Mount Options: " + path;
                    f.severity = Severity::Low;
                    f.description = "Mount " + path + " missing hardening options (noexec, nosuid, nodev)";
                    f.metadata["path"] = path;
                    f.metadata["options"] = options;
                    co_yield f;
                }
            }
        }
    }
};

}
