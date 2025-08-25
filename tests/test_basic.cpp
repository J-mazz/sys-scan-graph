#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include <cassert>
#include <iostream>

int main(){
    sys_scan::ScannerRegistry reg; reg.register_all_default(); sys_scan::Report rpt; reg.run_all(rpt); auto& res = rpt.results(); std::cout << "Scanners run: " << res.size() << "\n"; assert(!res.empty()); return 0; }
