#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include <cassert>
#include <iostream>

int main(){
    sys_scan::Config cfg;
    sys_scan::ScannerRegistry reg; reg.register_all_default(cfg); sys_scan::Report rpt; sys_scan::ScanContext context(cfg, rpt); reg.run_all(context); auto& res = rpt.results(); std::cout << "Scanners run: " << res.size() << "\n"; assert(!res.empty()); return 0; }
