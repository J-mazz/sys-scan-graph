#include "core/RuleEngine.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace sys_scan; namespace fs = std::filesystem;

static void write_rule(const fs::path& dir, const std::string& name, const std::string& body){ std::ofstream ofs(dir / name); ofs << body; }

int main(){
    fs::path td = fs::temp_directory_path() / "sys_scan_rule_warn_struct"; fs::create_directories(td);
    write_rule(td, "badver.rule", "id=badver\nrule_version=9\ncondition0.field=title\ncondition0.contains=Foo\n");
    write_rule(td, "badregex.rule", "id=badregex\ncondition0.field=title\ncondition0.regex=([oops\n");
    write_rule(td, "nocond.rule", "id=nocond\nseverity=low\n");

    std::string legacy; rule_engine().load_dir(td.string(), legacy);
    const auto & ws = rule_engine().warnings();
    bool sawUnsupported=false, sawBadRegex=false, sawNoCond=false;
    for(const auto& w: ws){
        if(w.rule_id=="badver" && w.code=="unsupported_version") sawUnsupported=true;
        if(w.rule_id=="badregex" && w.code=="bad_regex" && !w.detail.empty()) sawBadRegex=true;
        if(w.rule_id=="nocond" && w.code=="no_conditions") sawNoCond=true;
    }
    assert(sawUnsupported && sawBadRegex && sawNoCond);
    // Aggregated helper should include the same codes
    auto agg = rule_engine().warnings_aggregated();
    assert(agg.find("badver:unsupported_version")!=std::string::npos);
    assert(agg.find("badregex:bad_regex")!=std::string::npos);
    assert(agg.find("nocond:no_conditions")!=std::string::npos);
    std::cout << "Structured warnings test passed\n";
    return 0;
}
