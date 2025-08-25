#include "core/RuleEngine.h"
#include "core/Scanner.h"
#include "core/Severity.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace sys_scan;
namespace fs = std::filesystem;

static void write_rule(const fs::path& dir, const std::string& name, const std::string& body){ std::ofstream ofs(dir / name); ofs << body; }

int main(){
    fs::path td = fs::temp_directory_path() / "sys_scan_rule_unit"; fs::create_directories(td);

    // Rule A: AND logic (default) must match id equals & title contains
    write_rule(td, "a.rule",
        "id=rule_a\nrule_version=1\ncondition0.field=id\ncondition0.equals=F1\ncondition1.field=title\ncondition1.contains=Alpha\nseverity=high\nmitre=T1000\n");
    // Rule B: OR logic overrides severity again to medium if title contains Alpha OR description regex Beta
    write_rule(td, "b.rule",
        "id=rule_b\nlogic=any\ncondition0.field=title\ncondition0.contains=Alpha\ncondition1.field=description\ncondition1.regex=Beta.*Trail\nseverity=medium\nmitre=T2000\n");
    // Rule C: Scoped rule that won't apply (scope=other_scanner)
    write_rule(td, "c.rule",
        "id=rule_c\nscope=other_scanner\ncondition0.field=title\ncondition0.contains=Alpha\nseverity=critical\nmitre=T3000\n");
    // Rule D: Legacy single-condition adds extra MITRE
    write_rule(td, "d.rule",
        "id=rule_d\nfield=title\ncontains=Alpha\nmitre=T4000\n");
    // Rule E: Bad regex + unsupported version -> warnings
    write_rule(td, "e.rule",
        "id=rule_e\nrule_version=2\ncondition0.field=title\ncondition0.regex=([unclosed\nmitre=T5000\n");
    // Rule F: No conditions -> warning
    write_rule(td, "f.rule","id=rule_f\nrule_version=1\nseverity=low\n");

    std::string warnings; rule_engine().load_dir(td.string(), warnings);
    // Expect warnings to mention unsupported_version, bad_regex, no_conditions
    assert(warnings.find("rule_e:unsupported_version")!=std::string::npos);
    assert(warnings.find("rule_e:bad_regex")!=std::string::npos);
    assert(warnings.find("rule_f:no_conditions")!=std::string::npos);

    Finding f; f.id="F1"; f.title="Alpha Title"; f.description="Beta data Trail"; f.severity=Severity::Info;

    rule_engine().apply("sample_scanner", f); // scanner name should exclude rule_c

    // Severity: rule_a sets high, rule_b later sets medium (last match wins), rule_c skipped, legacy rule does not change severity.
    assert(f.severity == Severity::Medium);

    auto it = f.metadata.find("mitre_techniques"); assert(it!=f.metadata.end());
    std::string mitre = it->second;
    // Order should follow rule file ordering after sorting by filename: a,b,c,d,e,... so T1000 then T2000 then T4000 then T5000 (even though bad regex rule matched? it should still evaluate; but rule_e has bad regex which prevented its condition compile and thus won't match). T5000 should NOT appear.
    assert(mitre.find("T1000")!=std::string::npos);
    assert(mitre.find("T2000")!=std::string::npos);
    assert(mitre.find("T4000")!=std::string::npos);
    assert(mitre.find("T5000")==std::string::npos);

    std::cout << "Rule engine unit test passed (warnings and precedence)\n";
    return 0;
}
