module;
#include <coroutine>
#include <string>
#include <vector>
#include <sstream>
#include <map>

export module sys_scan.scanners.network;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class NetworkScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit NetworkScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "network"; }
    std::string description() const override { return "Scans open network sockets (TCP/UDP)"; }

    Generator<Finding> scan() override {
        if (config_.fast_scan) co_return;

        // Files to scan: /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
        const std::vector<std::string> net_files = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
        
        for (const auto& path : net_files) {
            std::string content = fs_.read_file(sys_scan::utils::in_root(config_.test_root, path));
            if (content.empty()) continue;

            auto lines = sys_scan::utils::read_lines_from_string(content);
            bool first = true;
            for (const auto& line : lines) {
                if (first) { first = false; continue; } // Skip header
                
                // Simple parser for /proc/net/tcp format:
                // sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                std::stringstream ss(line);
                std::string sl, local_addr, remote_addr, state;
                ss >> sl >> local_addr >> remote_addr >> state;

                // Filter for LISTEN (0A) if requested
                if (config_.network_listen_only && state != "0A") continue;

                Finding f;
                f.id = "net:" + local_addr;
                f.title = "Open Socket " + local_addr;
                f.description = "State: " + state + " (Path: " + path + ")";
                f.severity = Severity::Info;
                f.metadata["local"] = local_addr;
                f.metadata["remote"] = remote_addr;
                f.metadata["state"] = state;
                f.metadata["protocol"] = (path.find("tcp") != std::string::npos) ? "TCP" : "UDP";
                
                co_yield f;
            }
        }
    }
};

}
