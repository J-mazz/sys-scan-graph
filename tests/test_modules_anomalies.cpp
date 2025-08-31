#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include <cassert>
#include <iostream>

// Test modules anomalies-only mode yields zero or only anomaly findings (no summary id 'module_summary').
int main(){
    using namespace sys_scan;
    Config cfg; cfg.enable_scanners = {"modules"}; cfg.modules_anomalies_only = true;
    ScannerRegistry reg; reg.register_all_default(cfg);
    Report rpt; ScanContext context(cfg, rpt); reg.run_all(context);
    const auto& res = rpt.results();
    bool any=false; bool has_summary=false; bool any_non_anomaly=false;
    for(const auto& sr: res){ if(sr.scanner_name=="modules"){ for(const auto& f: sr.findings){ any=true; if(f.id=="module_summary") has_summary=true; if(f.title.rfind("Module anomaly",0)!=0) any_non_anomaly=true; } } }
    assert(!has_summary); // summary suppressed
    assert(!any_non_anomaly); // no plain module listings
    std::cout << "Modules anomalies-only test passed (anomalies count=" << (any?"some":"none") << ")\n";
    return 0;
}
