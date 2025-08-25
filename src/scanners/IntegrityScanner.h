#pragma once
#include "../core/Scanner.h"

namespace sys_scan {
class IntegrityScanner : public Scanner {
public:
    std::string name() const override { return "integrity"; }
    std::string description() const override { return "Package & system integrity verification"; }
    void scan(Report& report) override;
};
}
