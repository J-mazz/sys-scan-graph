#include "ProcessScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;
namespace sys_scan {

void ProcessScanner::scan(Report& report) {
    size_t emitted = 0;
    for(const auto& entry : fs::directory_iterator("/proc")) {
        if(!entry.is_directory()) continue;
        auto name = entry.path().filename().string();
        if(!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
        std::string status_path = entry.path().string() + "/status";
        std::ifstream ifs(status_path);
        if(!ifs) continue;
        std::string line;
        std::string uid;
        std::string gid;
        while(std::getline(ifs, line)) {
            if(line.rfind("Uid:",0)==0) {
                std::istringstream ls(line.substr(4)); ls>>uid; }
            if(line.rfind("Gid:",0)==0) { std::istringstream ls(line.substr(4)); ls>>gid; }
            if(!uid.empty() && !gid.empty()) break;
        }
    std::string cmdline_path = entry.path().string() + "/cmdline";
        std::ifstream cfs(cmdline_path, std::ios::binary);
        std::string cmd;
        if(cfs){ std::string raw; std::getline(cfs, raw, '\0'); cmd = raw; }
    extern int severity_rank(const std::string&); // silence unused in this file
    if(cmd.empty() && !config().all_processes) continue; // skip kernel threads unless flag set
    // Additional noise reduction: skip bracketed names when no cmd or special states.
    if(!config().all_processes && !cmd.empty() && cmd.front()=='[' && cmd.back()==']') continue;
    if(config().max_processes>0 && emitted >= (size_t)config().max_processes) break;
        Finding f;
        f.id = name;
        f.title = "Process " + name;
        f.severity = "info";
        f.description = cmd.empty()?"(no cmdline)":cmd;
        f.metadata["uid"] = uid;
        f.metadata["gid"] = gid;
    report.add_finding(this->name(), std::move(f));
    ++emitted;
    }
}

}
