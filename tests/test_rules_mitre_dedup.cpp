#include "core/RuleEngine.h"
#include "core/Scanner.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace sys_scan; namespace fs = std::filesystem;

static void write_rule(const fs::path& dir, const std::string& name, const std::string& body){ std::ofstream ofs(dir / name); ofs << body; }

int main(){
    fs::path td = fs::temp_directory_path() / "sys_scan_rule_dedup"; fs::create_directories(td);
    write_rule(td, "a.rule", "id=a\nfield=title\ncontains=Match\nmitre=T1000,T2000\n");
    write_rule(td, "b.rule", "id=b\nfield=title\ncontains=Match\nmitre=T2000,T3000\n");
    write_rule(td, "c.rule", "id=c\nfield=title\ncontains=Match\nmitre=T1000 , T4000\n");
    std::string warn; rule_engine().load_dir(td.string(), warn);

    Finding f; f.title="Match example"; f.description=""; f.id="X"; f.severity=Severity::Info;
    rule_engine().apply("any", f);
    auto it = f.metadata.find("mitre_techniques"); assert(it!=f.metadata.end());
    std::string mt = it->second; // preserve order: first list T1000,T2000 then new unique T3000 then T4000
    assert(mt == "T1000,T2000,T3000,T4000");
    std::cout << "MITRE de-dup test passed: " << mt << "\n";
    return 0;
}
