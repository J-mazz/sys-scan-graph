#include "Report.h"
#include <algorithm>

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
        it->findings.push_back(std::move(finding));
    }
}

void Report::end_scanner(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(results_.begin(), results_.end(), [&](auto& r){ return r.scanner_name == name; });
    if(it != results_.end()) {
        it->end_time = std::chrono::system_clock::now();
    }
}

}
