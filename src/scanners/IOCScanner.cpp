#include "IOCScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include <filesystem>
#include <fstream>
#include <regex>
#include <unordered_set>
#include <unordered_map>
#include "../core/Config.h"
#include <sys/stat.h>

namespace fs = std::filesystem;
namespace sys_scan {

static bool is_executable(const fs::path& p){ struct stat st{}; if(stat(p.c_str(), &st)!=0) return false; return (st.st_mode & S_IXUSR)||(st.st_mode & S_IXGRP)||(st.st_mode & S_IXOTH); }
static bool has_suid(const fs::path& p){ struct stat st{}; if(lstat(p.c_str(), &st)!=0) return false; return (st.st_mode & S_ISUID); }

void IOCScanner::scan(Report& report) {
    // Heuristic 1: Suspicious process command patterns / names
    std::vector<std::regex> proc_patterns = {
        std::regex("^/tmp/.*"),
        std::regex("/dev/shm/.*"),
        std::regex("^/var/tmp/.*"),
        std::regex("^/home/.*/\\.cache/.*\\.so$"),
    std::regex("/\\.\\w{6,}/.*") // hidden random-looking dir (escape backslashes)
    };
    std::unordered_set<std::string> suspicious_names = {"kworker", "cryptominer", "xmrig", "minerd", "kthreadd", "malware", "bot"};

    // Gather world-writable dirs for quick membership (subset)
    std::vector<std::string> ww_dirs = {"/tmp", "/dev/shm", "/var/tmp"};

    // Aggregate env-only LD_* temp path hits per executable; track escalation reasons
    struct EnvAgg { std::unordered_set<std::string> pids; std::string exe; bool tmp_path=false; bool preload=false; bool libpath=false; bool untrusted=false; };
    std::unordered_map<std::string, EnvAgg> env_hits; // key = exe (or "<unknown>")

    // Process IOC aggregation structures
    struct ProcAgg { std::unordered_set<std::string> pids; std::string exe; bool any_deleted=false; bool any_ww_exec=false; bool any_pattern=false; std::string first_cmd; };
    std::unordered_map<std::string, ProcAgg> proc_hits; // key = exe or first_cmd if exe empty

    for(const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied)){
        if(!entry.is_directory()) continue; auto pid = entry.path().filename().string(); if(!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;
        auto cmd_path = entry.path()/"cmdline"; std::ifstream cfs(cmd_path, std::ios::binary); if(!cfs) continue; std::string raw; std::getline(cfs, raw, '\0'); if(raw.empty()) continue;
        bool matched=false; for(auto& r: proc_patterns){ if(std::regex_search(raw, r)) { matched=true; break; } }
        if(!matched){ for(auto& n: suspicious_names){ if(raw.find(n)!=std::string::npos){ matched=true; break; } } }

        // Deleted executable detection
        std::error_code ec; fs::path exe_link = entry.path()/"exe"; std::string exe_target; {
            std::error_code ec2; auto target = fs::read_symlink(exe_link, ec2); if(!ec2) exe_target = target.string(); else exe_target = ""; }
        bool deleted=false; if(!exe_target.empty() && exe_target.find(" (deleted)")!=std::string::npos) deleted=true;
        if(exe_target.empty()){
            // Could not read exe path (maybe permission) skip further exe heuristics
        }
        // Executing from world-writable directory
        bool ww_exec=false; if(!exe_target.empty()){
            for(auto& d: ww_dirs){ if(exe_target.rfind(d,0)==0){ ww_exec=true; break; } }
        }

    if(matched || deleted || ww_exec){
            std::string key = !exe_target.empty() ? exe_target : raw;
            auto& agg = proc_hits[key];
            agg.pids.insert(pid);
            if(agg.exe.empty() && !exe_target.empty()) agg.exe = exe_target;
            if(agg.first_cmd.empty()) agg.first_cmd = raw;
            if(matched) agg.any_pattern = true;
            if(deleted) agg.any_deleted = true;
            if(ww_exec) agg.any_ww_exec = true;
        }
        // Suspicious environment variables (LD_PRELOAD, LD_LIBRARY_PATH) with optional trust correlation
        auto environ_path = entry.path()/"environ"; std::ifstream efs(environ_path, std::ios::binary); if(efs){ std::string envdata((std::istreambuf_iterator<char>(efs)), {}); // null-delimited
            bool has_preload = envdata.find("LD_PRELOAD=")!=std::string::npos; bool has_libpath = envdata.find("LD_LIBRARY_PATH=")!=std::string::npos; if(has_preload || has_libpath){
                bool temp_ref = (envdata.find("/tmp/")!=std::string::npos || envdata.find("/dev/shm/")!=std::string::npos);
                std::string key = exe_target.empty()? std::string("<unknown>") : exe_target;
                if(temp_ref || config().ioc_env_trust){ auto& agg = env_hits[key]; agg.pids.insert(pid); if(agg.exe.empty()) agg.exe=key; agg.tmp_path = agg.tmp_path || temp_ref; agg.preload = agg.preload || has_preload; agg.libpath = agg.libpath || has_libpath; if(config().ioc_env_trust){
                        // Trust heuristic: path under /usr/bin or /bin or /usr/sbin considered trusted; else untrusted unless allowlisted
                        bool trusted=false; if(!exe_target.empty()){ trusted = (exe_target.rfind("/usr/bin/",0)==0 || exe_target.rfind("/bin/",0)==0 || exe_target.rfind("/usr/sbin/",0)==0); }
                        if(!trusted) agg.untrusted = true; }
                }
            }
        }
    }

    // Emit aggregated Process IOC findings
    for(auto& kv : proc_hits){
        auto& a = kv.second;
        // Severity escalation hierarchy
        std::string sev = "high"; // base for pattern match
        if(a.any_deleted) sev = "critical"; else if(a.any_ww_exec) sev = "high"; // keep high
    Finding f; f.id = (a.exe.empty()? kv.first : a.exe)+":proc_ioc"; f.title = "Process IOC"; f.severity = severity_from_string(sev); f.description = a.first_cmd.empty()? kv.first : a.first_cmd;
    if(a.any_pattern){ f.metadata["pattern_match"] = "true"; f.metadata["rule"] = "cmd_path_pattern"; }
    if(a.any_deleted){ f.metadata["deleted_exe"] = "true"; f.metadata["rule"] = "deleted_executable"; }
    if(a.any_ww_exec){ f.metadata["world_writable_exec"] = "true"; f.metadata["rule"] = "exec_from_world_writable"; }
    if(!a.exe.empty()) f.metadata["exe"] = a.exe; f.metadata["pid_count"] = std::to_string(a.pids.size());
        int count=0; std::string sample; for(const auto& p: a.pids){ if(count++) sample += ","; sample += p; if(count>=5) break; }
        f.metadata["sample_pids"] = sample;
        report.add_finding(this->name(), std::move(f));
    }

    // Emit aggregated env findings
    if(!env_hits.empty()){
        auto& cfg = config();
        for(auto& kv : env_hits){ const auto& key = kv.first; auto& agg = kv.second; std::string sev = "medium"; std::string rule="ld_env"; std::string desc="LD_* environment usage";
            if(agg.tmp_path){ rule += "_tmp"; desc += " referencing tmp"; }
            if(agg.untrusted){ rule += "_untrusted_exe"; if(sev!="critical") sev = "high"; }
            for(const auto& allow : cfg.ioc_allow){ if(!allow.empty() && key.find(allow) != std::string::npos){ if(sev!="critical") sev = "low"; break; } }
            if(agg.preload && agg.tmp_path && agg.untrusted) sev = "critical";
            Finding f; f.id = key+":env"; f.title = "Environment IOC"; f.severity = severity_from_string(sev); f.description = desc; f.metadata["rule"] = rule; f.metadata["exe"] = key; if(agg.tmp_path) f.metadata["tmp_path"]="true"; if(agg.preload) f.metadata["has_ld_preload"]="true"; if(agg.libpath) f.metadata["has_ld_library_path"]="true"; if(agg.untrusted) f.metadata["untrusted_exe"]="true"; f.metadata["pid_count"] = std::to_string(agg.pids.size()); int count=0; std::string sample; for(const auto& p: agg.pids){ if(count++) sample += ","; sample += p; if(count>=5) break; } f.metadata["sample_pids"] = sample; report.add_finding(this->name(), std::move(f)); }
    }

    // Optional short-lived process capture (placeholder user-space fallback if eBPF not available)
    if(config().ioc_exec_trace){
        int dur = config().ioc_exec_trace_seconds>0? config().ioc_exec_trace_seconds : 3;
        // For now, create a placeholder finding noting feature not implemented fully (eBPF required)
        Finding f; f.id = "exec_trace_session"; f.title = "Exec trace session"; f.severity = Severity::Info; f.description = "Short-lived process capture window "+std::to_string(dur)+"s (eBPF not yet implemented)"; f.metadata["duration_seconds"] = std::to_string(dur); report.add_finding(this->name(), std::move(f));
    }

    // Heuristic 2: Executables under /tmp or /dev/shm
    std::vector<std::string> temp_roots = {"/tmp", "/dev/shm"};
    for(auto& root : temp_roots){
        std::error_code ec;
        for(auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it){ if(ec){ report.add_warning(this->name(), std::string("walk_error:")+root+":"+ec.message()); break; } const auto& p = it->path(); if(!it->is_regular_file(ec)) continue; if(is_executable(p)){ Finding f; f.id = p.string(); f.title = "Executable in temp"; f.severity=Severity::High; f.description="Executable file located in temporary directory"; f.metadata["rule"] = "executable_in_temp"; report.add_finding(this->name(), std::move(f)); } }
    }
    // Heuristic 3: Unexpected SUID in home directories
    for(const auto& entry : fs::directory_iterator("/home", fs::directory_options::skip_permission_denied)){
    if(!entry.is_directory()) continue; std::error_code ec; for(auto it = fs::recursive_directory_iterator(entry.path(), fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it){ if(ec) break; if(!it->is_regular_file(ec)) continue; if(has_suid(it->path())) { Finding f; f.id = it->path().string(); f.title = "SUID in home"; f.severity=Severity::Critical; f.description="SUID binary present in user home"; f.metadata["rule"] = "suid_in_home"; report.add_finding(this->name(), std::move(f)); } }
    }

    // Heuristic 4: /etc/ld.so.preload anomalies
    if(fs::exists("/etc/ld.so.preload")){
        std::ifstream pfs("/etc/ld.so.preload"); std::string line; while(std::getline(pfs,line)){ if(line.empty()) continue; std::string lib = line; struct stat st{}; if(stat(lib.c_str(), &st)==0){
                bool ww = (st.st_mode & S_IWOTH); if(ww){ Finding f; f.id = lib; f.title="World-writable preload library"; f.severity=Severity::Critical; f.description="Library in ld.so.preload is world-writable"; f.metadata["rule"] = "preload_world_writable"; report.add_finding(this->name(), std::move(f)); }
            } else {
                Finding f; f.id = lib; f.title="Missing preload library"; f.severity=Severity::Medium; f.description="Entry in ld.so.preload missing on disk"; f.metadata["rule"] = "preload_missing"; report.add_finding(this->name(), std::move(f)); }
        }
    }
}

}
