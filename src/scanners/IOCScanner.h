#pragma once
#include "../core/Scanner.h"
#include <vector>
#include <string>

namespace sys_scan {
class IOCScanner : public Scanner {
public:
    std::string name() const override { return "ioc"; }
    std::string description() const override { return "Heuristic & rule-based indicators of compromise"; }
    void scan(Report& report) override;
};
}
