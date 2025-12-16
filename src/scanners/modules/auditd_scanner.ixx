module;
#include <coroutine>
#include <string>
#include <vector>
#include <regex>
#include <unordered_set>

export module sys_scan.scanners.auditd;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;

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
        if(!config_.hardening) co_return;

        std::string root = config_.test_root;
        std::vector<std::string> paths;
        
        std::string audit_rules = root + "/etc/audit/audit.rules";
        if(fs_.exists(audit_rules)) paths.push_back(audit_rules);

        std::string rules_dir = root + "/etc/audit/rules.d";
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

        struct Pattern { const char* id; const char* regex_str; const char* title; const char* desc; Severity sev; };
        std::vector<Pattern> pats = {
            {"execve", "-S\\s+execve", "Audit execve present", "Execve syscall auditing present", Severity::Info},
            {"setuid", "-S\\s+setuid", "Audit setuid present", "setuid syscall auditing present", Severity::Info},
            {"setgid", "-S\\s+setgid", "Audit setgid present", "setgid syscall auditing present", Severity::Info},
            {"chmod", "-S\\s+chmod", "Audit chmod present", "chmod syscall auditing present", Severity::Info},
            {"chown", "-S\\s+chown", "Audit chown present", "chown syscall auditing present", Severity::Info},
            {"capset", "-S\\s+capset", "Audit capset present", "capset syscall auditing present", Severity::Info},
            {"insmod", "-k\\s*modules|/s?bin/(insmod|modprobe)", "Module load auditing", "Module load operations likely audited", Severity::Info},
        };

        std::unordered_set<std::string> matched;
        for(const auto& p : pats){
            try {
                std::regex rgx(p.regex_str, std::regex::icase);
                if(std::regex_search(combined, rgx)) matched.insert(p.id);
            } catch(...) {}
        }

        for(const auto& p : pats){
            bool ok = matched.count(p.id);
            Finding f;
            f.id = std::string("auditd:") + p.id;
            f.title = p.title;
            f.description = ok ? p.desc : (std::string(p.title) + " missing");
            f.severity = ok ? Severity::Info : Severity::Medium;
            co_yield f;
        }

        if(!matched.count("execve")){
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