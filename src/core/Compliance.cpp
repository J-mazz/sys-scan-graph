#include "Compliance.h"
#include "ScanContext.h"
#include "Report.h"
#include "Logging.h"
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace sys_scan {

static bool file_has_min_perms(const std::string& path, mode_t mask){
    struct stat st{}; if(::stat(path.c_str(), &st)!=0) return false; return (st.st_mode & mask) == mask; }

void ComplianceScanner::scan(ScanContext& context) {
    if(checks_.empty()) register_checks();
    std::vector<Finding> findings;
    findings.reserve(checks_.size());
    std::map<std::string, ComplianceStandardSummary> by_standard; // local aggregation
    for(const auto& c : checks_) {
        bool applicable = true;
        if(c.applicable) { try { applicable = c.applicable(); } catch(...) { applicable = true; } }
        bool passed = false;
        std::string rationale;
        if(!applicable){ rationale = "not_applicable"; }
        else {
            try { passed = c.test(); } catch(...) { passed = false; rationale = "test_exception"; }
        }
        Finding f;
        f.id = c.standard + ":" + c.control_id;
        f.title = c.standard + " control " + c.control_id;
        f.severity = c.severity;
        f.description = c.requirement;
        f.metadata["standard"] = c.standard;
        f.metadata["control_id"] = c.control_id;
        f.metadata["requirement"] = c.requirement;
        f.metadata["passed"] = passed ? "true" : "false";
        if(!rationale.empty()) f.metadata["rationale"] = rationale;
        if(!applicable) {
            f.metadata["not_applicable"] = "true";
        }
        findings.push_back(std::move(f));
        auto& sum = by_standard[c.standard];
        sum.total_controls++;
        if(!applicable) sum.not_applicable++; else if(passed) sum.passed++; else sum.failed++;
    }
    // push scan result
    if(!findings.empty()) {
        ScanResult sr; sr.scanner_name = name(); sr.start_time = std::chrono::system_clock::now(); sr.end_time = sr.start_time; sr.findings = std::move(findings); context.report.add_result(std::move(sr));
    }
    // store summary into report meta extension for now (future: dedicated structure)
    for(const auto& kv : by_standard){
        const auto& std_name = kv.first; const auto& sum = kv.second;
        context.report.set_compliance_metric(std_name, "total_controls", std::to_string(sum.total_controls));
        context.report.set_compliance_metric(std_name, "passed", std::to_string(sum.passed));
        context.report.set_compliance_metric(std_name, "failed", std::to_string(sum.failed));
        context.report.set_compliance_metric(std_name, "not_applicable", std::to_string(sum.not_applicable));
        int denom = (sum.passed + sum.failed) > 0 ? (sum.passed + sum.failed) : 1;
        double score = static_cast<double>(sum.passed)/denom;
        context.report.set_compliance_metric(std_name, "score", std::to_string(score));
    }
}

// --- PCI Implementation (skeleton) ---
void PCIComplianceScanner::register_checks() {
    // 3.4 Render PAN unreadable anywhere stored -> approximate by checking presence & permissions of /etc/ssl and /etc/crypttab
    checks_.push_back({
        "pci_dss_4_0", "3.4", "Sensitive data encryption configurations present (approximation)", Severity::Medium,
        [](){ return fs::exists("/etc/ssl") || fs::exists("/etc/crypttab"); },
        [](){ return true; }
    });
    // 7.1 Access control: presence of /etc/passwd and /etc/shadow with restrictive perms
    checks_.push_back({
        "pci_dss_4_0", "7.1", "Access control files have expected permissions (/etc/passwd, /etc/shadow)", Severity::High,
        [](){ struct stat stp{}, sts{}; if(::stat("/etc/passwd", &stp)!=0) return false; if(::stat("/etc/shadow", &sts)!=0) return false; return (stp.st_mode & 0777) <= 0644 && (sts.st_mode & 0777) <= 0640; },
        [](){ return true; }
    });
    // 10.2 Logging configuration: syslog config exists
    checks_.push_back({
        "pci_dss_4_0", "10.2", "Logging configuration present (/etc/rsyslog.conf or /etc/syslog.conf)", Severity::Medium,
        [](){ return fs::exists("/etc/rsyslog.conf") || fs::exists("/etc/syslog.conf"); },
        [](){ return true; }
    });
    // 2.2.4 File system permissions on critical system files (simplified subset)
    checks_.push_back({
        "pci_dss_4_0", "2.2.4", "Critical system file permissions restrictive (/etc/ssh/sshd_config)", Severity::Medium,
        [](){ struct stat st{}; if(::stat("/etc/ssh/sshd_config", &st)!=0) return false; return (st.st_mode & 0777) <= 0644; },
        [](){ return true; }
    });
}

} // namespace sys_scan
