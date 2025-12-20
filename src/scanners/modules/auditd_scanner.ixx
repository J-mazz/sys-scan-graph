module;
#include <coroutine>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <algorithm>
#include <cctype>

export module sys_scan.scanners.auditd;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class AuditdScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit AuditdScanner(const Config& cfg, const IFileSystem& fs) 
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "auditd"; }
    std::string description() const override { return "Checks auditd rules coverage"; }

    Generator<Finding> scan() override {
        std::string root = sys_scan::utils::in_root(config_.test_root, "");
        std::vector<std::string> paths;
        
        std::string audit_rules = sys_scan::utils::in_root(root, "/etc/audit/audit.rules");
        if(fs_.exists(audit_rules)) paths.push_back(audit_rules);

        std::string rules_dir = sys_scan::utils::in_root(root, "/etc/audit/rules.d");
        if(fs_.is_directory(rules_dir)) {
            auto entries = fs_.list_directory(rules_dir);
            for(const auto& e : entries) {
                if(e.name.ends_with(".rules")) {
                    paths.push_back(rules_dir + "/" + e.name);
                }
            }
        }

        std::string combined;
        for(const auto& p : paths) { 
            combined += fs_.read_file(p); 
            combined += "\n"; 
        }

        if(combined.empty()) {
            Finding f;
            f.id="auditd:rules:missing";
            f.title="No auditd rules detected";
            f.severity=Severity::Medium;
            f.description="Could not read auditd rules files";
            co_yield f;
            co_return;
        }

        std::string lowered = combined;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

        auto contains = [&](std::string_view needle) {
            return lowered.find(needle) != std::string::npos;
        };

        struct Pattern {
            std::string_view id;
            std::string_view title;
            std::string_view desc;
            Severity sev;
            std::array<std::string_view, 3> needles; // up to 3; unused entries may be empty
        };

        constexpr std::array<Pattern, 7> pats {{
            {"execve", "Audit execve present", "Execve syscall auditing present", Severity::Info, {"-s execve", "", ""}},
            {"setuid", "Audit setuid present", "setuid syscall auditing present", Severity::Info, {"-s setuid", "", ""}},
            {"setgid", "Audit setgid present", "setgid syscall auditing present", Severity::Info, {"-s setgid", "", ""}},
            {"chmod", "Audit chmod present", "chmod syscall auditing present", Severity::Info, {"-s chmod", "", ""}},
            {"chown", "Audit chown present", "chown syscall auditing present", Severity::Info, {"-s chown", "", ""}},
            {"capset", "Audit capset present", "capset syscall auditing present", Severity::Info, {"-s capset", "", ""}},
            {"insmod", "Module load auditing", "Module load operations likely audited", Severity::Info, {"-k modules", "insmod", "modprobe"}},
        }};

        std::array<bool, pats.size()> matched{};
        for (std::size_t i = 0; i < pats.size(); ++i) {
            bool ok = false;
            for (auto needle : pats[i].needles) {
                if (needle.empty()) continue;
                if (contains(needle)) { ok = true; break; }
            }
            matched[i] = ok;
        }

        for (std::size_t i = 0; i < pats.size(); ++i) {
            const auto& p = pats[i];
            bool ok = matched[i];
            Finding f;
            f.id = std::string("auditd:") + std::string(p.id);
            f.title = std::string(p.title);
            f.description = ok ? std::string(p.desc) : (std::string(p.title) + " missing");
            f.severity = ok ? Severity::Info : Severity::Medium;
            co_yield f;
        }

        if(!matched[0]){
            Finding f;
            f.id="auditd:execve:absent";
            f.title="Execve auditing missing";
            f.severity=Severity::High;
            f.description="Audit rules lack -S execve; process execution coverage incomplete";
            co_yield f;
        }
    }
};

}