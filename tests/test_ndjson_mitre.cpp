#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include "core/RuleEngine.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

using namespace sys_scan;

int main(){
    // Create temp rules directory with a rule that tags a common finding title substring to produce mitre_techniques
    namespace fs = std::filesystem; const char* td = getenv("TMPDIR"); std::string tmp = std::string(td?td:"/tmp") + "/sys_scan_ndjson_rules";
    std::error_code ec; fs::create_directories(tmp, ec);
    std::ofstream r(tmp+"/t.rule");
    r << "id=t_rule\nfield=title\ncontains=World-writable\nmitre=T9999\n"; r.close();

    Config cfg; cfg.enable_scanners = {"world_writable"}; cfg.rules_enable = true; cfg.rules_dir = tmp; cfg.ndjson = true;
    // Load rules manually (mirrors main)
    std::string warn; rule_engine().load_dir(cfg.rules_dir, warn);

    ScannerRegistry reg; reg.register_all_default(cfg);
    Report rpt; ScanContext context(cfg, rpt); reg.run_all(context);
    JSONWriter w; std::string out = w.write(rpt, cfg);

    // Find at least one finding line containing mitre_techniques":"T9999
    bool seen=false; std::istringstream is(out); std::string line; while(std::getline(is,line)){
        if(line.find("\"type\":\"finding\"")!=std::string::npos && line.find("T9999")!=std::string::npos){
            // Basic JSON structure check: ensure ",\"mitre_techniques\":\" appears not escaped incorrectly
            assert(line.find("\\\"mitre_techniques\\\"")==std::string::npos); // should not be double escaped
            assert(line.find("\"mitre_techniques\":\"T9999\"")!=std::string::npos);
            seen=true; break;
        }
    }
    assert(seen);
    std::cout << "NDJSON mitre field formatting test passed\n";
    return 0;
}
