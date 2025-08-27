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
    if(config().rules_enable){ rule_engine().apply(scanner, finding); }
    finding.risk_score = severity_risk_score(finding.severity);
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

void Report::add_warning(const std::string& scanner, const std::string& message){
    std::lock_guard<std::mutex> lock(mutex_);
    warnings_.emplace_back(scanner, message);
}

void Report::add_error(const std::string& scanner, const std::string& message){
    std::lock_guard<std::mutex> lock(mutex_);
    errors_.emplace_back(scanner, message);
}

}
