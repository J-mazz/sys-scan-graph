#include "SystemdUnitScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <sstream>

namespace fs = std::filesystem;
namespace sys_scan {

struct UnitData { std::string name; std::unordered_map<std::string,std::string> kv; };

static void parse_unit(const fs::path& p, UnitData& out){
    std::ifstream f(p); if(!f.is_open()) return; std::string line;
    while(std::getline(f,line)){
        if(line.empty() || line[0]=='#' || line[0]==';') continue;
        auto pos = line.find('='); if(pos==std::string::npos) continue;
        std::string key = line.substr(0,pos); std::string val = line.substr(pos+1);
        // strip whitespace
        auto strip=[&](std::string& s){ while(!s.empty() && (s.back()==' '||s.back()=='\r'||s.back()=='\n')) s.pop_back(); size_t i=0; while(i<s.size() && s[i]==' ') ++i; if(i) s.erase(0,i); };
        strip(key); strip(val);
        out.kv[key]=val;
    }
}

void SystemdUnitScanner::scan(Report& report){
    if(!config().hardening) return;
    // We read *.service in typical paths. We avoid invoking systemctl. Pure file parse, may miss generated units.
    std::vector<fs::path> roots = {
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system"
    };
    std::unordered_set<std::string> seen; // unique unit names

    std::vector<UnitData> units;
    for(const auto& root: roots){
        std::error_code ec; if(!fs::exists(root, ec)) continue;
        for(auto& entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, ec)){
            if(ec) break; if(!entry.is_regular_file()) continue;
            auto p = entry.path(); if(p.extension() != ".service") continue; auto name = p.filename().string();
            if(seen.count(name)) continue; seen.insert(name);
            UnitData ud; ud.name = name; parse_unit(p, ud); units.push_back(std::move(ud));
        }
    }

    // Hardening directives of interest and their recommended states
    struct Rec { const char* key; const char* expect; Severity sev; const char* bad_desc; const char* good_desc; };
    std::vector<Rec> recs = {
        {"NoNewPrivileges", "yes", Severity::Medium, "NoNewPrivileges not set to yes", "NoNewPrivileges enforced"},
        {"PrivateTmp", "yes", Severity::Low, "PrivateTmp not enabled", "PrivateTmp enabled"},
        {"ProtectSystem", "strict", Severity::Medium, "ProtectSystem not strict", "ProtectSystem strict"},
        {"ProtectHome", "read-only", Severity::Low, "ProtectHome not read-only", "ProtectHome read-only"},
        {"CapabilityBoundingSet", "", Severity::Low, "CapabilityBoundingSet not present (no reduction)", "CapabilityBoundingSet present"},
        {"RestrictNamespaces", "yes", Severity::Low, "RestrictNamespaces not enabled", "RestrictNamespaces enabled"},
        {"RestrictSUIDSGID", "yes", Severity::Low, "RestrictSUIDSGID not enabled", "RestrictSUIDSGID enabled"},
        {"ProtectKernelModules", "yes", Severity::Low, "ProtectKernelModules not enabled", "ProtectKernelModules enabled"},
        {"ProtectKernelTunables", "yes", Severity::Low, "ProtectKernelTunables not enabled", "ProtectKernelTunables enabled"},
        {"ProtectControlGroups", "yes", Severity::Low, "ProtectControlGroups not enabled", "ProtectControlGroups enabled"},
        {"MemoryDenyWriteExecute", "yes", Severity::Low, "MemoryDenyWriteExecute not enabled", "MemoryDenyWriteExecute enabled"},
        {"RestrictRealtime", "yes", Severity::Low, "RestrictRealtime not enabled", "RestrictRealtime enabled"},
        {"LockPersonality", "yes", Severity::Low, "LockPersonality not enabled", "LockPersonality enabled"},
    };

    for(const auto& u : units){
        bool is_service = u.kv.count("ExecStart")>0; // approximate
        if(!is_service) continue;
        for(const auto& r : recs){
            auto it = u.kv.find(r.key);
            bool present = (it != u.kv.end());
            bool good = false;
            if(present){
                if(std::string(r.expect).empty()) good = true; // presence only requirement
                else if(it->second == r.expect) good = true;
                else if(std::string(r.key)=="ProtectSystem" && it->second=="full") { // degrade severity for full vs strict
                    good = false; // still report
                }
            }
            Finding f; f.id = std::string("systemd:") + r.key + ":" + u.name; f.title = std::string(u.name) + " " + r.key; f.metadata["unit"] = u.name; f.metadata["key"] = r.key; if(present) f.metadata["value"] = it->second; f.metadata["expected"] = r.expect;
            if(good){ f.severity = Severity::Info; f.description = r.good_desc; }
            else { f.severity = r.sev; f.description = present? r.bad_desc : std::string(r.bad_desc) + " (missing)"; }
            report.add_finding(name(), std::move(f));
        }
    }
}

}
