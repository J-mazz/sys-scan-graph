#include "WorldWritableScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include "../core/Config.h"
#include <filesystem>

namespace fs = std::filesystem; 
namespace sys_scan {

void WorldWritableScanner::scan(Report& report) {
    std::vector<std::string> dirs = {"/etc", "/usr/bin", "/usr/local/bin", "/var"};
    for(const auto& extra : config().world_writable_dirs) dirs.push_back(extra);
    auto should_exclude = [&](const std::string& p){
        for(const auto& pat : config().world_writable_exclude) if(p.find(pat)!=std::string::npos) return true; return false; };
    for(const auto& d: dirs){
        std::error_code ec;
        for(auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it) {
            if(ec) break; const auto& p = it->path(); if(!it->is_regular_file(ec)) continue; std::string ps = p.string(); if(should_exclude(ps)) continue; if(utils::is_world_writable(ps)) { Finding f; f.id = ps; f.title = "World-writable file"; f.severity=Severity::Medium; f.description="File is world writable"; if(ps.find("/tmp/")!=std::string::npos) f.severity=Severity::Low; if(ps.find(".so")!=std::string::npos || ps.find("/bin/")!=std::string::npos) f.severity=Severity::High; report.add_finding(this->name(), std::move(f)); }
        }
    }
}

}
