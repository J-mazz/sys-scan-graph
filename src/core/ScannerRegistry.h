#pragma once
#include "Scanner.h"
#include <vector>

namespace sys_scan {

class ScannerRegistry {
public:
    void register_scanner(ScannerPtr scanner);
    void register_all_default();
    void run_all(Report& report);
private:
    std::vector<ScannerPtr> scanners_;
};

}
