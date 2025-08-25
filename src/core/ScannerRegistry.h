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
    void run_all_sequential(Report& report);
    void run_all_parallel(Report& report);
private:
    std::vector<ScannerPtr> scanners_;
};

}
