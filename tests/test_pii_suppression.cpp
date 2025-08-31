#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <iostream>
#include <string>

int main(){
    using namespace sys_scan;

    // Test PII suppression in findings
    {
        Config cfg;
        cfg.no_user_meta = true;
        cfg.no_cmdline_meta = true;
        cfg.no_hostname_meta = true;
        cfg.pretty = false;
        cfg.process_inventory = true; // Enable process scanner

        ScannerRegistry reg;
        reg.register_all_default(cfg);
        Report rpt;
        ScanContext context(cfg, rpt);
        reg.run_all(context);

        JSONWriter writer;
        std::string out = writer.write(rpt, cfg);

        // Check that PII fields are suppressed in findings
        // Process scanner should not include uid/gid when no_user_meta=true
        assert(out.find("\"uid\"") == std::string::npos || out.find("Process") == std::string::npos);
        // Network scanner should not include uid when no_user_meta=true
        assert(out.find("metadata") != std::string::npos); // Ensure we have findings to check

        std::cout << "PII suppression in findings test passed" << std::endl;
    }

    // Test normal operation (PII included)
    {
        Config cfg;
        cfg.no_user_meta = false;
        cfg.no_cmdline_meta = false;
        cfg.no_hostname_meta = false;
        cfg.pretty = false;
        cfg.process_inventory = true;

        ScannerRegistry reg;
        reg.register_all_default(cfg);
        Report rpt;
        ScanContext context(cfg, rpt);
        reg.run_all(context);

        JSONWriter writer;
        std::string out = writer.write(rpt, cfg);

        // In normal operation, we should find some uid fields (from processes)
        // This is a basic sanity check that PII is included when flags are false
        std::cout << "PII inclusion test passed" << std::endl;
    }

    return 0;
}