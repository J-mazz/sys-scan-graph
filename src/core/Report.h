#pragma once
#include "Scanner.h"
#include <mutex>

namespace sys_scan {

class Report {
public:
    void start_scanner(const std::string& name);
    void add_finding(const std::string& scanner, Finding finding);
    void end_scanner(const std::string& name);
    // Warning / error side channels (non-security collection issues)
    void add_warning(const std::string& scanner, const std::string& message);
    void add_error(const std::string& scanner, const std::string& message);

    const std::vector<ScanResult>& results() const { return results_; }
    const std::vector<std::pair<std::string,std::string>>& warnings() const { return warnings_; }
    const std::vector<std::pair<std::string,std::string>>& errors() const { return errors_; }
private:
    std::vector<ScanResult> results_;
    std::vector<std::pair<std::string,std::string>> warnings_; // (scanner, message)
    std::vector<std::pair<std::string,std::string>> errors_;
    std::mutex mutex_;
};

}
