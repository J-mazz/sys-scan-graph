#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include <cassert>
#include <iostream>
#include "core/Config.h"

// Simple test: run SUID scanner only and ensure expected baseline downgrades some common utilities to low.
int main(){
    using namespace sys_scan;
    Config cfg; cfg.enable_scanners = {"suid_sgid"}; set_config(cfg);
    ScannerRegistry reg; reg.register_all_default();
    Report rpt; reg.run_all(rpt);
    const auto& res = rpt.results();
    bool saw = false; bool downgraded=false;
    for(const auto& sr: res){ if(sr.scanner_name=="suid_sgid"){ for(const auto& f: sr.findings){ if(f.id.find("/passwd")!=std::string::npos || f.id.find("/sudo")!=std::string::npos){ saw=true; if(severity_to_string(f.severity)=="low") downgraded=true; } } } }
    assert(saw); // ensure we saw at least one baseline item
    assert(downgraded); // ensure severity was downgraded to low
    std::cout << "SUID expected baseline test passed\n";
    return 0;
}
