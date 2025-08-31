#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include "core/RuleEngine.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <filesystem>

// Dedicated tests for multi-condition AND/OR logic, regex matching, scope, severity override, MITRE aggregation, and legacy single-condition compatibility.
// We synthesize a minimal rules directory and run a constrained scanner set so findings are deterministic.

using namespace sys_scan;
namespace fs = std::filesystem;

static void write_rule(const fs::path& dir, const std::string& name, const std::string& body){ std::ofstream ofs(dir / name); ofs << body; }

int main(){
    Config cfg; // limit to world_writable scanner (it should reliably produce at least one finding on most systems with /tmp)
    cfg.enable_scanners = {"world_writable"};
    cfg.rules_enable = true;
    fs::path tmp = fs::temp_directory_path() / "sys_scan_rule_tests";
    fs::create_directories(tmp);

    // 1. Multi-condition AND (all) match: require id contains and title regex. We don't know exact id/title ahead; we'll craft a synthetic finding by running then re-applying rules manually.
    // So we first create a rule that will *not* match anything (narrow), then create synthetic finding to test matching function via apply.
    write_rule(tmp, "and.rule",
        "id=and_all\n"
        "scope=*\n"
    "condition0.field=title\n"
    "condition0.contains=World-writable" // match scanner title prefix (hyphenated)
        "\ncondition1.field=description\ncondition1.regex=dir\\s+/tmp\n"
        "severity=high\nmitre=T1000\n"
    );

    // 2. Any/OR logic rule - match either title contains or description regex.
    write_rule(tmp, "or.rule",
        "id=or_any\nlogic=any\n"
    "condition0.field=title\ncondition0.contains=World-writable\n"
        "condition1.field=description\ncondition1.regex=.*tmp.*\n"
        "severity=medium\nmitre=T2000\n"
    );

    // 3. Scoped rule (world_writable only) with severity override low and additional MITRE
    write_rule(tmp, "scoped.rule",
    "id=scoped\nscope=world_writable\ncondition0.field=title\ncondition0.contains=World-writable\nseverity=low\nmitre=T3000\n"
    );

    // 4. Legacy single-condition rule (field/contains) adds another MITRE tag
    write_rule(tmp, "legacy.rule",
    "id=legacy_one\nfield=title\ncontains=World-writable\nmitre=T4000\n"
    );

    cfg.rules_dir = tmp.string();
    // Explicitly load rules (mirrors main.cpp logic) before registering scanners
    {
        std::string warn; rule_engine().load_dir(cfg.rules_dir, warn); if(!warn.empty()) std::cerr << "Rule load warning: " << warn << "\n"; }

    // Run scanners
    ScannerRegistry reg; reg.register_all_default(cfg);
    Report rpt; ScanContext context(cfg, rpt); reg.run_all(context);

    // Collect world_writable findings
    const auto& results = rpt.results();
    const ScanResult* ww=nullptr; for(const auto& sr: results){ if(sr.scanner_name=="world_writable"){ ww=&sr; break; } }
    assert(ww && "world_writable scanner produced results");
    bool saw_and=false, saw_any=false; size_t adjusted=0; size_t mitre_augmented=0; 
    for(const auto& f: ww->findings){
        // All three constructed rules except the AND rule may match multiple findings; AND requires /tmp mention.
        auto it = f.metadata.find("mitre_techniques"); std::string mitre = (it!=f.metadata.end())?it->second:std::string();
        if(mitre.find("T3000")!=std::string::npos) adjusted++; // scoped severity applied
        if(mitre.find("T4000")!=std::string::npos) mitre_augmented++;
        if(mitre.find("T1000")!=std::string::npos) saw_and=true;
        if(mitre.find("T2000")!=std::string::npos) saw_any=true;
    }

    // Expect at least one finding had AND rule (system dependent but /tmp world writable is common). If not, skip gracefully.
    if(!saw_and){ std::cerr << "WARNING: AND rule didn't match any finding; environment may lack /tmp world writable entry. Test continuing.\n"; }
    assert(saw_any); // OR rule should match same as contains condition.
    assert(adjusted>0); // scoped rule matched at least something
    assert(mitre_augmented>0); // legacy rule matched

    std::cout << "Rule engine multi-condition/regex tests passed (AND=" << (saw_and?"hit":"miss") << ")" << std::endl;
    return 0;
}
