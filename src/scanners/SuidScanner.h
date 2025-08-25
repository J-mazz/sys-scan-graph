#pragma once
#include "../core/Scanner.h"

namespace sys_scan {
class SuidScanner : public Scanner {
public:
    std::string name() const override { return "suid_sgid"; }
    std::string description() const override { return "Find SUID/SGID binaries"; }
    void scan(Report& report) override;
};
}
