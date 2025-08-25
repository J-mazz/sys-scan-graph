#pragma once
#include "../core/Scanner.h"

namespace sys_scan {

class SystemdUnitScanner : public Scanner {
public:
    std::string name() const override { return "systemd_units"; }
    std::string description() const override { return "Evaluates systemd service unit hardening directives"; }
    void scan(Report& report) override;
};

}
