#pragma once
#include "../core/Scanner.h"

namespace sys_scan {

class AuditdScanner : public Scanner {
public:
    std::string name() const override { return "auditd"; }
    std::string description() const override { return "Checks auditd rules coverage for execve and privilege-escalation events"; }
    void scan(Report& report) override;
};

}
