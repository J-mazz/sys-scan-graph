module;
#include <coroutine>
#include <string>
#include <vector>
#include <string_view>
#include <charconv>
#include <array>
#include <algorithm>
#include <cstdint>

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

                // Tokenize by whitespace (no iostreams for speed)
                std::vector<std::string_view> tokens;
                tokens.reserve(12);
                size_t start = 0;
                std::string_view sv(line);
                while (start < sv.size()) {
                    size_t pos = sv.find_first_not_of(' ', start);
                    if (pos == std::string_view::npos) break;
                    size_t end = sv.find_first_of(' ', pos);
                    tokens.push_back(sv.substr(pos, end == std::string_view::npos ? sv.size() - pos : end - pos));
                    if (end == std::string_view::npos) break;
                    start = end;
                }
                if (tokens.size() < 4) continue;

                auto protocol = (path.find("tcp") != std::string::npos) ? "TCP" : "UDP";
                std::string_view local_hex = tokens[1];
                std::string_view remote_hex = tokens[2];
                std::string_view state = tokens[3];

                if (config_.network_listen_only && state != "0A") continue;

                auto parse_ipv4 = [](std::string_view hex)->std::string {
                    if (hex.size() < 9) return {};
                    unsigned int ip_raw = 0;
                    auto [p, ec] = std::from_chars(hex.data(), hex.data()+8, ip_raw, 16);
                    if (ec != std::errc()) return {};
                    unsigned int port = 0;
                    std::from_chars(hex.data()+9, hex.data()+hex.size(), port, 16);
                    std::array<unsigned int,4> octets{
                        (ip_raw      ) & 0xFF,
                        (ip_raw >> 8 ) & 0xFF,
                        (ip_raw >> 16) & 0xFF,
                        (ip_raw >> 24) & 0xFF
                    };
                    return std::to_string(octets[0]) + "." + std::to_string(octets[1]) + "." + std::to_string(octets[2]) + "." + std::to_string(octets[3]) + ":" + std::to_string(port);
                };

                auto parse_ipv6 = [](std::string_view hex)->std::string {
                    if (hex.size() < 33) return {};
                    // last 4 bytes after ':' are port
                    unsigned int port = 0;
                    auto colon = hex.find(':');
                    if (colon == std::string_view::npos) return {};
                    std::from_chars(hex.data()+colon+1, hex.data()+hex.size(), port, 16);
                    auto to_hex4 = [](uint16_t v){
                        std::array<char,4> buf{};
                        const char* digits = "0123456789abcdef";
                        buf[0]=digits[(v>>12)&0xF];
                        buf[1]=digits[(v>>8)&0xF];
                        buf[2]=digits[(v>>4)&0xF];
                        buf[3]=digits[v&0xF];
                        return std::string(buf.data(), buf.size());
                    };
                    std::array<uint16_t,8> parts{};
                    for(int i=0;i<8;i++) {
                        std::string_view seg = hex.substr(i*4, 4);
                        unsigned int v=0; std::from_chars(seg.data(), seg.data()+seg.size(), v, 16);
                        parts[i] = static_cast<uint16_t>(v);
                    }
                    // Compress zeros lightly for readability
                    std::string out;
                    for(int i=0;i<8;i++) {
                        out += (i==0?"":":") + to_hex4(parts[i]);
                    }
                    return out + ":" + std::to_string(port);
                };

                auto parse_addr = [&](std::string_view hex)->std::string {
                    return hex.size() > 25 ? parse_ipv6(hex) : parse_ipv4(hex);
                };

                std::string local = parse_addr(local_hex);
                std::string remote = parse_addr(remote_hex);
                if (local.empty()) local = std::string(local_hex);
                if (remote.empty()) remote = std::string(remote_hex);

                Finding f;
                f.id = "net:" + std::string(state) + ":" + local;
                f.title = "Open Socket " + local;
                f.description = "State: " + std::string(state) + " (" + protocol + ")";
                f.severity = Severity::Info;
                f.metadata["local"] = local;
                f.metadata["remote"] = remote;
                f.metadata["state"] = std::string(state);
                f.metadata["protocol"] = protocol;
                f.metadata["path"] = path;
                co_yield f;
            }
        }
    }
};

}
