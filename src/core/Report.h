#pragma once
#include "Scanner.h"
#include <mutex>

namespace sys_scan {

class Report {
public:
    void start_scanner(const std::string& name);
    void add_finding(const std::string& scanner, Finding finding);
    void end_scanner(const std::string& name);

    const std::vector<ScanResult>& results() const { return results_; }
private:
    std::vector<ScanResult> results_;
    std::mutex mutex_;
};

}
