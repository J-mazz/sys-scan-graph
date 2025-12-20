module;
#include <coroutine>
#include <string>
#include <string_view>

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
        if (!config_.hardening && !config_.containers) co_return;

        std::string mounts = fs_.read_file(sys_scan::utils::in_root(config_.test_root, "/proc/mounts"));
        if (mounts.empty()) co_return;

        auto lines = sys_scan::utils::split_lines_sv(mounts);
        for (auto line : lines) {
            // Format: device mountpoint fstype options ...
            std::string_view device, path, type, options;
            {
                size_t start = 0; int field = 0;
                while (start < line.size() && field < 4) {
                    size_t p = line.find_first_not_of(' ', start);
                    if (p == std::string_view::npos) break;
                    size_t e = line.find_first_of(' ', p);
                    std::string_view tok = line.substr(p, e == std::string_view::npos ? line.size() - p : e - p);
                    if (field == 0) device = tok;
                    else if (field == 1) path = tok;
                    else if (field == 2) type = tok;
                    else if (field == 3) options = tok;
                    ++field;
                    if (e == std::string_view::npos) break;
                    start = e;
                }
            }

            if (path.empty()) continue;

            auto flag_contains = [&](std::string_view key){ return options.find(key) != std::string_view::npos; };

            // Containers: detect overlay mounts typical for container filesystems
            if (config_.containers && type == "overlay") {
                Finding f;
                f.id = "mount:overlay:" + std::string(path);
                f.title = "Container overlay mount detected";
                f.severity = Severity::Info;
                f.description = "Overlay at " + std::string(path);
                f.metadata["mountpoint"] = std::string(path);
                f.metadata["device"] = std::string(device);
                co_yield f;
            }

            // Hardening checks: noexec,nodev,nosuid on tmp-like mounts
            bool is_tmp = (path == "/tmp" || path == "/var/tmp" || path == "/dev/shm");
            if (config_.hardening && is_tmp) {
                bool has_noexec = flag_contains("noexec");
                bool has_nosuid = flag_contains("nosuid");
                bool has_nodev  = flag_contains("nodev");

                if (!(has_noexec && has_nosuid && has_nodev)) {
                    Finding f;
                    f.id = "mount:insecure:" + std::string(path);
                    f.title = "Insecure Mount Options: " + std::string(path);
                    f.severity = Severity::Low;
                    f.description = "Mount " + std::string(path) + " missing hardening options (noexec, nosuid, nodev)";
                    f.metadata["path"] = std::string(path);
                    f.metadata["options"] = std::string(options);
                    co_yield f;
                }
            }
        }
    }
};

}
