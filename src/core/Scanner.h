#pragma once
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <optional>
#include <map>
#include "Severity.h"

namespace sys_scan {

struct Finding {
    std::string id;
    std::string title;
    Severity severity = Severity::Info;
    std::string description;
    std::map<std::string, std::string> metadata; // flexible key/value pairs
    int risk_score = 0; // derived from severity mapping at emit time
};

struct ScanResult {
    std::string scanner_name;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::vector<Finding> findings;
};

class Report; // fwd

class Scanner {
public:
    virtual ~Scanner() = default;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;
    virtual void scan(Report& report) = 0;
};

using ScannerPtr = std::unique_ptr<Scanner>; 

}
