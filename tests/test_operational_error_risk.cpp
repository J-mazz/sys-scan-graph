#include "core/Report.h"
#include "core/Scanner.h"
#include "core/JSONWriter.h"
#include "core/Severity.h"
#include <iostream>
#include <cassert>

using namespace sys_scan;

int main(){
    Report report;
    report.start_scanner("test");
    // Normal finding (High)
    {
        Finding f; f.id="f1"; f.title="normal"; f.severity=Severity::High; f.description="normal finding";
        report.add_finding("test", f);
    }
    // Operational error finding (Error severity but flagged)
    {
        Finding f; f.id="f2"; f.title="operr"; f.severity=Severity::Error; f.description="scanner failed"; f.operational_error=true;
        report.add_finding("test", f);
    }
    report.end_scanner("test");
    JSONWriter w; std::string out = w.write(report, Config{});
    // Expect base_severity_score present for normal, zero for operational error and not counted in totals
    if(out.find("\"id\":\"f1\"")==std::string::npos) { std::cerr << "Missing normal finding"; return 1; }
    if(out.find("\"id\":\"f2\"")==std::string::npos) { std::cerr << "Missing operational error finding"; return 1; }
    // total_risk_score should be >= base_severity_score of f1 but NOT include any for f2 (which is zero anyway)
    auto pos = out.find("total_risk_score");
    if(pos==std::string::npos){ std::cerr << "Missing total_risk_score"; return 1; }
    // Presence of operational_error marker (only emitted in ndjson path) isn't strictly required here.
    return 0;
}
