#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <iostream>

int main(){
    using namespace sys_scan;
    // Enable min config and suppression flags
    auto &cfg = config();
    cfg.no_user_meta = true;
    cfg.no_cmdline_meta = true;
    cfg.no_hostname_meta = true;
    cfg.pretty = false; // compact deterministic
    ScannerRegistry reg; reg.register_all_default();
    Report rpt; reg.run_all(rpt);
    JSONWriter writer; std::string out = writer.write(rpt);
    // Assert suppressed fields not present
    assert(out.find("\"hostname\"") == std::string::npos);
    assert(out.find("\"uid\"") == std::string::npos);
    assert(out.find("\"user\"") == std::string::npos);
    assert(out.find("\"cmdline\"") == std::string::npos);
    std::cout << "Meta suppression test passed" << std::endl;
    return 0;
}
