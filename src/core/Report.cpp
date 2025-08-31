#include "Report.h"
#include <algorithm>
#include "RuleEngine.h"
#include "Config.h"

namespace sys_scan {

void Report::start_scanner(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    ScanResult sr;
    sr.scanner_name = name;
    sr.start_time = std::chrono::system_clock::now();
    results_.push_back(std::move(sr));
}

void Report::add_finding(const std::string& scanner, Finding finding) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(results_.begin(), results_.end(), [&](auto& r){ return r.scanner_name == scanner; });
    if(it != results_.end()) {
        // Apply rules if enabled in attached config
        if (cfg_ && cfg_->rules_enable) {
            rule_engine().apply(scanner, finding);
        }
        // Early severity filter (operational errors are kept; only security findings are filtered)
        int minRank = cfg_ ? severity_rank(cfg_->min_severity) : 0;
        if(!finding.operational_error && severity_rank_enum(finding.severity) < minRank){ return; }
        // Derive risk unless operational error (kept out of security risk totals)
        finding.base_severity_score = finding.operational_error ? 0 : severity_risk_score(finding.severity);
        it->findings.push_back(std::move(finding));
    }
}

void Report::add_result(ScanResult result){
    std::lock_guard<std::mutex> lock(mutex_);
    results_.push_back(std::move(result));
}

void Report::end_scanner(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(results_.begin(), results_.end(), [&](auto& r){ return r.scanner_name == name; });
    if(it != results_.end()) {
        it->end_time = std::chrono::system_clock::now();
    }
}

static std::string warn_code_string(WarnCode c){
    switch(c){
        case WarnCode::DecompressFail: return "decompress_fail";
        case WarnCode::ParamUnreadable: return "param_unreadable";
        case WarnCode::ProcUnreadableStatus: return "proc_unreadable_status";
        case WarnCode::ProcUnreadableCmdline: return "proc_unreadable_cmdline";
        case WarnCode::ProcExeSymlinkUnreadable: return "proc_exe_symlink_unreadable";
        case WarnCode::NetFileUnreadable: return "net_file_unreadable";
        case WarnCode::WalkError: return "walk_error";
        case WarnCode::MountsUnreadable: return "mounts_unreadable";
        case WarnCode::Generic: default: return "generic";
    }
}

void Report::add_warning(const std::string& scanner, WarnCode code, const std::string& detail){
    std::lock_guard<std::mutex> lock(mutex_);
    // encode as simple json-ish key=value pairs for downstream writer (avoid pulling full JSON lib here)
    std::string payload = warn_code_string(code);
    if(!detail.empty()) payload += ":" + detail; // detail may contain path; caller responsible for sanitization
    warnings_.emplace_back(scanner, payload);
}

void Report::add_error(const std::string& scanner, const std::string& message){
    std::lock_guard<std::mutex> lock(mutex_);
    errors_.emplace_back(scanner, message);
}

size_t Report::total_findings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for(const auto& r : results_) total += r.findings.size();
    return total;
}

}
