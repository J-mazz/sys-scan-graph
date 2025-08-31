#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/JSONWriter.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include <cassert>
#include <iostream>
#include <string>

int main(){
    using namespace sys_scan;
    Config cfg; cfg.pretty = true;  // Enable pretty printing for test
    cfg.compact = false; // Ensure compact is disabled
    ScannerRegistry reg; reg.register_all_default(cfg);
    Report rpt; ScanContext context(cfg, rpt); reg.run_all(context);
    JSONWriter w; auto j = w.write(rpt, cfg);
    // Basic smoke: ensure schema version marker and risk_score appear.
    if (j.find("\"json_schema_version\": \"2\"") == std::string::npos) {
        std::cerr << "JSON content around schema version:\n";
        size_t pos = j.find("json_schema_version");
        if (pos != std::string::npos) {
            size_t start = (pos > 50) ? pos - 50 : 0;
            size_t end = std::min(pos + 100, j.size());
            std::cerr << j.substr(start, end - start) << "\n";
        } else {
            std::cerr << "json_schema_version not found in JSON\n";
        }
        assert(false && "Schema version assertion failed");
    }
    assert(j.find("risk_score") != std::string::npos);
    std::cout << "JSON schema smoke passed\n";
    return 0;
}
