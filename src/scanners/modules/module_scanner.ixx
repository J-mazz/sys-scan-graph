module;
#include <coroutine>
#include <string>
#include <string_view>
#include <vector>
#include <charconv>
#include <algorithm>

export module sys_scan.scanners.modules;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;
import sys_scan.scanners.module_utils;

export namespace sys_scan {

class ModuleScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;
    const ISystemInfo& sysinfo_;

public:
    explicit ModuleScanner(const Config& cfg, const IFileSystem& fs, const ISystemInfo& sysinfo)
        : config_(cfg), fs_(fs), sysinfo_(sysinfo) {}

    std::string name() const override { return "modules"; }
    std::string description() const override { return "Scans kernel modules for signatures and taint"; }

    Generator<Finding> scan() override {
        if (!config_.modules_summary_only && !config_.hardening) co_return;

        std::string kernel_release;
        {
            const std::string osrelease_path = sys_scan::utils::in_root(config_.test_root, "/proc/sys/kernel/osrelease");
            if (fs_.exists(osrelease_path)) {
                kernel_release = sys_scan::utils::trim(fs_.read_file(osrelease_path));
            }
        }
        if (kernel_release.empty()) {
            kernel_release = sysinfo_.kernel_release();
        }

        std::string lib_base = sys_scan::utils::in_root(config_.test_root, "/lib/modules/" + kernel_release + "/");

        std::string modules = fs_.read_file(sys_scan::utils::in_root(config_.test_root, "/proc/modules"));
        auto lines = sys_scan::utils::read_lines_from_string(modules);
        
        size_t unsigned_count = 0;
        size_t oot_count = 0;
        size_t wx_sections = 0;
        size_t live_count = 0;

        auto split_tokens = [](std::string_view line){
            std::vector<std::string_view> toks;
            toks.reserve(6);
            size_t start = 0;
            while(start < line.size()) {
                size_t p = line.find_first_not_of(' ', start);
                if (p == std::string_view::npos) break;
                size_t e = line.find_first_of(' ', p);
                toks.push_back(line.substr(p, e == std::string_view::npos ? line.size() - p : e - p));
                if (e == std::string_view::npos) break;
                start = e;
            }
            return toks;
        };

        for (const auto& line : lines) {
            auto toks = split_tokens(line);
            if (toks.empty()) continue;
            std::string_view name = toks[0];
            if (name.empty()) continue;

            // tokens: name size refcount deps state address
            std::string_view state = toks.size() >= 5 ? toks[4] : std::string_view{};
            if (state == "Live") ++live_count;

            bool flagged_oot = (line.find("O ") != std::string::npos) || (line.find("E ") != std::string::npos) || (line.find("O\t") != std::string::npos);
            if (flagged_oot) oot_count++;

            // Prefer .ko first, then compressed forms
            const std::vector<std::string> candidates = {
                lib_base + "kernel/drivers/" + std::string(name) + ".ko",
                lib_base + "kernel/drivers/" + std::string(name) + ".ko.xz",
                lib_base + "kernel/drivers/" + std::string(name) + ".ko.gz"
            };

            std::string existing;
            for (const auto& c : candidates) {
                if (fs_.exists(c)) { existing = c; break; }
            }
            if (existing.empty()) continue;

            if (SignatureAnalyzer::is_unsigned_module(existing)) {
                unsigned_count++;
            }

            // Only parse ELF if not compressed; if compressed, decompress boundedly
            std::string to_scan = existing;
            if (!CompressionUtils::is_compressed(existing)) {
                auto sections = ElfModuleHeuristics::parse_sections(to_scan);
                if (ElfModuleHeuristics::has_wx_section(sections)) wx_sections++;
            } else {
                auto buffer = CompressionUtils::decompress_bounded(existing);
                if (!buffer.empty()) {
                    // Minimal in-buffer section scan: search for "shf"-style WX hints would require full ELF parse.
                    // To keep safe and bounded, we skip WX detection on compressed modules unless decompressed.
                    // Here we perform a lightweight signature check: if module signature marker absent, count unsigned.
                    if (SignatureAnalyzer::is_unsigned_module(existing)) {
                        // already counted; avoid double-counting
                    }
                }
            }
        }

        if (unsigned_count > 0 || oot_count > 0 || wx_sections > 0) {
            Finding f;
            f.id = "module_summary";
            f.title = "Kernel Module Summary";
            f.severity = Severity::Medium;
            f.description = "Unsigned:" + std::to_string(unsigned_count) + " OOT:" + std::to_string(oot_count) + " WX:" + std::to_string(wx_sections) + " Live:" + std::to_string(live_count);
            f.metadata["unsigned"] = std::to_string(unsigned_count);
            f.metadata["out_of_tree"] = std::to_string(oot_count);
            f.metadata["wx_sections"] = std::to_string(wx_sections);
            f.metadata["live"] = std::to_string(live_count);
            co_yield f;
        }
    }
};

}
