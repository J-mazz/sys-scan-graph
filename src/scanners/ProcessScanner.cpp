#include "ProcessScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <sys/stat.h>
#include <regex>
#include <unordered_map>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace fs = std::filesystem;
namespace sys_scan {

void ProcessScanner::scan(Report& report) {
    size_t emitted = 0;
    // Preload container id mapping if container mode
    std::unordered_map<std::string,std::string> pid_to_container; // pid->container short id
    if(config().containers){
        for(const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied)){
            if(!entry.is_directory()) continue; auto pid = entry.path().filename().string(); if(!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;
            std::ifstream cg(entry.path().string()+"/cgroup"); if(!cg) continue; std::string line; while(std::getline(cg,line)){
                // reuse container id heuristic from ContainerScanner (duplicate small logic to avoid dependency)
                static std::regex re("([0-9a-f]{64}|[0-9a-f]{32})"); std::smatch m; if(std::regex_search(line,m,re)){ pid_to_container[pid] = m.str(1).substr(0,12); break; }
            }
        }
    }
    bool inventory = config().process_inventory; // if false, we suppress routine process listings
    for(const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied)) {
        if(!entry.is_directory()) continue;
        auto name = entry.path().filename().string();
        if(!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
        std::string status_path = entry.path().string() + "/status";
        std::ifstream ifs(status_path);
    if(!ifs){ report.add_warning(this->name(), WarnCode::ProcUnreadableStatus, status_path); continue; }
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
    if(cfs){ std::string raw; std::getline(cfs, raw, '\0'); cmd = raw; } else { report.add_warning(this->name(), WarnCode::ProcUnreadableCmdline, cmdline_path); }
    extern int severity_rank(const std::string&); // silence unused in this file
    if(cmd.empty() && !config().all_processes) continue; // skip kernel threads unless flag set
    // Additional noise reduction: skip bracketed names when no cmd or special states.
    if(!config().all_processes && !cmd.empty() && cmd.front()=='[' && cmd.back()==']') continue;
    if(config().max_processes>0 && emitted >= (size_t)config().max_processes) break;
        if(inventory){
            Finding f;
            f.id = name;
            f.title = "Process " + name;
            f.severity = Severity::Info;
            f.description = cmd.empty()?"(no cmdline)":cmd;
            f.metadata["uid"] = uid;
            f.metadata["gid"] = gid;
            if(config().containers){ auto it = pid_to_container.find(name); if(it!=pid_to_container.end()){ f.metadata["container_id"] = it->second; if(!config().container_id_filter.empty() && it->second != config().container_id_filter) { continue; } } else { if(!config().container_id_filter.empty()) continue; } }
            if(config().process_hash){
            // attempt to read /proc/PID/exe target and hash file contents (first 1MB stream for performance)
            std::error_code ec; auto exe_link = entry.path()/"exe"; auto target = fs::read_symlink(exe_link, ec);
            if(!ec){
                auto real = target.string(); f.metadata["exe_path"] = real;
#ifdef SYS_SCAN_HAVE_OPENSSL
                std::ifstream efs(real, std::ios::binary);
                if(efs){
                    std::vector<unsigned char> buf(8192);
                    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                    if(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)==1){
                        size_t total=0; while(efs && total < 1024*1024){ efs.read((char*)buf.data(), buf.size()); std::streamsize got = efs.gcount(); if(got<=0) break; EVP_DigestUpdate(ctx, buf.data(), (size_t)got); total += (size_t)got; }
                        unsigned char md[32]; unsigned int mdlen=0; if(EVP_DigestFinal_ex(ctx, md, &mdlen)==1 && mdlen==32){
                            static const char* hex="0123456789abcdef"; std::string hexhash; hexhash.reserve(64); for(unsigned i=0;i<32;i++){ hexhash.push_back(hex[md[i]>>4]); hexhash.push_back(hex[md[i]&0xF]); }
                            f.metadata["sha256"] = hexhash;
                        }
                    }
                    if(ctx) EVP_MD_CTX_free(ctx);
                }
#else
                f.metadata["sha256"] = "(disabled - OpenSSL not found)";
#endif
            } else {
                report.add_warning(this->name(), WarnCode::ProcExeSymlinkUnreadable, exe_link.string());
            }
            }
            report.add_finding(this->name(), std::move(f));
            ++emitted;
        }
    }
}

}
