#include "ContainerScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <regex>

namespace fs = std::filesystem;
namespace sys_scan {

std::string ContainerScanner::derive_container_id(const std::string& cg){
    // Attempt to extract 64 or 32 hex id. Common patterns: /docker/<id>, /kubepods.slice/.../<id>, /containers/<id>
    static std::regex re("([0-9a-f]{64}|[0-9a-f]{32})");
    std::smatch m; if(std::regex_search(cg, m, re)) return m.str(1).substr(0,12); // short id
    return {}; }

void ContainerScanner::scan(Report& report){
    const auto& cfg = config(); if(!cfg.containers) return;

    // Map container id -> info
    std::unordered_map<std::string, ContainerInfo> cmap;

    for(const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied)){
        if(!entry.is_directory()) continue; auto pid = entry.path().filename().string(); if(!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;
        std::ifstream cgfs(entry.path().string()+"/cgroup"); if(!cgfs) continue; std::string line; std::string joined; while(std::getline(cgfs,line)){ joined += line; joined += "\n"; }
        // Try each line quickly
        std::istringstream iss(joined); std::string l; bool attributed=false; while(std::getline(iss,l)){
            auto id = derive_container_id(l);
            if(!id.empty()){
                auto& ci = cmap[id]; ci.id = id; if(ci.pid_example.empty()) ci.pid_example = pid; ci.cgroup_path = l;
                if(l.find("docker")!=std::string::npos) ci.runtime = "docker"; else if(l.find("containerd")!=std::string::npos) ci.runtime="containerd"; else if(l.find("podman")!=std::string::npos) ci.runtime="podman"; else if(l.find("crio")!=std::string::npos) ci.runtime="crio"; else ci.runtime="unknown";
                attributed=true; break; }
        }
        if(!attributed){
            // Detect Kubernetes pause or systemd slice pattern
            if(joined.find("kubepods")!=std::string::npos){ auto& ci = cmap["kubepods"]; ci.id="kubepods"; if(ci.pid_example.empty()) ci.pid_example=pid; ci.runtime="kube"; ci.cgroup_path=joined; }
        }
    }

    for(auto& [id, ci] : cmap){
        Finding f; f.id = "container:"+id; f.title = "Container detected "+id; f.severity=Severity::Info; f.description = "Container runtime context"; f.metadata["runtime"] = ci.runtime; f.metadata["pid"] = ci.pid_example; f.metadata["cgroup"] = ci.cgroup_path; report.add_finding(name(), std::move(f));
    }
    if(cmap.empty()){
        Finding f; f.id="container:none"; f.title="No containers detected"; f.severity=Severity::Info; f.description="No container cgroup signatures found"; report.add_finding(name(), std::move(f));
    }
}

}
