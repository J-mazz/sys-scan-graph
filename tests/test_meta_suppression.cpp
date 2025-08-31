#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <iostream>

int main(){
    using namespace sys_scan;
    // Use isolated Config to avoid cross-test races (tests may run in parallel)
    Config cfg; cfg.no_user_meta = true; cfg.no_cmdline_meta = true; cfg.no_hostname_meta = true; cfg.pretty = false; set_config(cfg);
    ScannerRegistry reg; reg.register_all_default();
    Report rpt; reg.run_all(rpt);
    JSONWriter writer; std::string out = writer.write(rpt, cfg);
    // Assert suppressed fields not present
    assert(out.find("\"hostname\"") == std::string::npos);
    assert(out.find("\"uid\"") == std::string::npos);
    assert(out.find("\"user\"") == std::string::npos);
    assert(out.find("\"cmdline\"") == std::string::npos);
    std::cout << "Meta suppression test passed" << std::endl;
    return 0;
}
