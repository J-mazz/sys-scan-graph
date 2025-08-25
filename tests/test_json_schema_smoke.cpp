#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/JSONWriter.h"
#include "core/Config.h"
#include <cassert>
#include <iostream>
#include <string>

int main(){
    using namespace sys_scan;
    Config cfg; set_config(cfg);
    ScannerRegistry reg; reg.register_all_default();
    Report rpt; reg.run_all(rpt);
    JSONWriter w; auto j = w.write(rpt);
    // Basic smoke: ensure schema version marker and risk_score appear.
    assert(j.find("\"json_schema_version\": \"2\"") != std::string::npos);
    assert(j.find("risk_score") != std::string::npos);
    std::cout << "JSON schema smoke passed\n";
    return 0;
}
