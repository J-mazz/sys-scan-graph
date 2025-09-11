#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include <cassert>
#include <iostream>

// Simple test: run SUID scanner only and ensure expected baseline downgrades some common utilities to low.
int main(){
    using namespace sys_scan;
    Config cfg; cfg.enable_scanners = {"suid_sgid"};
    ScannerRegistry reg; reg.register_all_default(cfg);
    Report rpt; ScanContext context(cfg, rpt); reg.run_all(context);
    const auto& res = rpt.results();
    bool saw = false; bool downgraded=false;
    for(const auto& sr: res){ if(sr.scanner_name=="suid_sgid"){ for(const auto& f: sr.findings){ if(f.id.find("/passwd")!=std::string::npos || f.id.find("/sudo")!=std::string::npos){ saw=true; if(severity_to_string(f.severity) == std::string("low")) downgraded=true; } } } }
    assert(saw); // ensure we saw at least one baseline item
    assert(downgraded); // ensure severity was downgraded to low
    std::cout << "SUID expected baseline test passed\n";
    return 0;
}
