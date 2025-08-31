#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <iostream>

int main(){
    using namespace sys_scan;
    Config cfg; cfg.sarif = true; cfg.min_severity = "medium"; set_config(cfg);
    ScannerRegistry reg; reg.register_all_default();
    Report rpt; reg.run_all(rpt);
    JSONWriter w; auto out = w.write(rpt, cfg);
    assert(out.find("\"version\":\"2.1.0\"") != std::string::npos);
    assert(out.find("\"runs\"") != std::string::npos);
    std::cout << "SARIF smoke passed\n";
    return 0;
}