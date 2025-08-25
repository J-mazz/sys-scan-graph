#include "IntegrityScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <cstdio>
#include <array>
#include <optional>
#include <cstring>
#include <sys/stat.h>

namespace fs = std::filesystem;
namespace sys_scan {

static std::string run_cmd_capture(const char* cmd){
    std::array<char,256> buf{}; std::string out; FILE* f=popen(cmd,"r"); if(!f) return out; while(fgets(buf.data(), buf.size(), f)){ out += buf.data(); if(out.size()>1*1024*1024) break; } pclose(f); return out; }

void IntegrityScanner::scan(Report& report){
    auto& cfg = config();
    if(!cfg.integrity) return; // gated entirely

    size_t pkg_mismatch_count=0; size_t pkg_checked=0; size_t pkg_detail_emitted=0; std::vector<std::string> mismatch_sample; mismatch_sample.reserve(20);
    bool used_dpkg=false; bool used_rpm=false;
    if(cfg.integrity_pkg_verify){
        // Prefer dpkg -V (Debian) else rpm -Va (RPM-based)
        if(fs::exists("/usr/bin/dpkg")){
            used_dpkg=true; std::string out = run_cmd_capture("dpkg -V 2>/dev/null"); std::istringstream iss(out); std::string line; // Lines: status flags then space then package or file
            while(std::getline(iss,line)){
                if(line.empty()) continue; // lines starting with '??' or similar indicate mismatches
                if(line.size()>0 && (line[0]==' ' || line[0]=='?')) continue; // skip blank prefix lines
                // dpkg -V format: conffile mismatches lines start with '??' or multiple flag chars (MD5 sum mismatch => '5')
                if(line[0] != ' '){ // mismatch line
                    ++pkg_mismatch_count; if(mismatch_sample.size()<10) mismatch_sample.push_back(line.substr(0,40));
                    if(pkg_detail_emitted < (size_t)cfg.integrity_pkg_limit){ Finding f; f.id = std::string("pkg_mismatch:")+std::to_string(pkg_detail_emitted); f.title="Package file mismatch"; f.severity=Severity::Medium; f.description="dpkg verification mismatch"; f.metadata["raw"] = line; report.add_finding(this->name(), std::move(f)); ++pkg_detail_emitted; }
                }
            }
        } else if(fs::exists("/usr/bin/rpm")) {
            used_rpm=true; std::string out = run_cmd_capture("rpm -Va 2>/dev/null"); std::istringstream iss(out); std::string line; while(std::getline(iss,line)){
                if(line.empty()) continue; // rpm verification lines: 8 chars of flags, space, path or package
                if(line.size() < 2) continue; bool mismatch=false; for(char c: line.substr(0,8)){ if(c!='.' && c!=' '){ mismatch=true; break; } }
                if(!mismatch) continue; ++pkg_mismatch_count; if(mismatch_sample.size()<10) mismatch_sample.push_back(line.substr(0,40)); if(pkg_detail_emitted < (size_t)cfg.integrity_pkg_limit){ Finding f; f.id = std::string("pkg_mismatch:")+std::to_string(pkg_detail_emitted); f.title="Package file mismatch"; f.severity=Severity::Medium; f.description="rpm verification mismatch"; f.metadata["raw"] = line; report.add_finding(this->name(), std::move(f)); ++pkg_detail_emitted; }
            }
        }
    }
    // IMA measurement stats
    size_t ima_entries=0; size_t ima_fail=0; if(cfg.integrity_ima){
        if(fs::exists("/sys/kernel/security/ima/ascii_runtime_measurements")){
            std::ifstream ifs("/sys/kernel/security/ima/ascii_runtime_measurements"); std::string line; while(std::getline(ifs,line)){ if(line.empty()) continue; ++ima_entries; // columns: PCR template-hash algo digest path
                // simple heuristic: look for 'fail' or 'measure' anomalies not typical - placeholder
                if(line.find("fail")!=std::string::npos) ++ima_fail; if(ima_entries>500000) break; }
        }
    }

    // Summary finding
    Finding summary; summary.id = "integrity_summary"; summary.title = "Integrity summary"; summary.severity = Severity::Info; summary.description = "Package / integrity verification";
    if(pkg_mismatch_count>0) summary.severity = Severity::Medium; if(ima_fail>0) summary.severity = Severity::High;
    if(used_dpkg) summary.metadata["pkg_tool"] = "dpkg"; else if(used_rpm) summary.metadata["pkg_tool"]="rpm"; else if(cfg.integrity_pkg_verify) summary.metadata["pkg_tool"]="none";
    summary.metadata["pkg_mismatch_count"] = std::to_string(pkg_mismatch_count);
    if(!mismatch_sample.empty()){ std::string s; for(size_t i=0;i<mismatch_sample.size(); ++i){ if(i) s+=","; s+=mismatch_sample[i]; } summary.metadata["pkg_mismatch_sample"] = s; }
    if(cfg.integrity_ima){ summary.metadata["ima_entries"] = std::to_string(ima_entries); if(ima_fail>0) summary.metadata["ima_fail"] = std::to_string(ima_fail); }
    report.add_finding(this->name(), std::move(summary));
}

}
