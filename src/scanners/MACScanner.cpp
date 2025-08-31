#include "MACScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <sys/stat.h>
#include <string>

namespace fs = std::filesystem;
namespace sys_scan {

static bool file_exists(const std::string& p){ struct stat st{}; return ::stat(p.c_str(), &st)==0; }

void MACScanner::scan(Report& report) {
    // Detect container (simple heuristics) to potentially downgrade severity
    bool in_container = file_exists("/.dockerenv") || file_exists("/run/.containerenv");

    // SELinux
    bool selinux_fs = fs::exists("/sys/fs/selinux");
    bool selinux_enforcing = false; bool selinux_permissive=false; bool selinux_present=false;
    if(selinux_fs){
        selinux_present = true;
        std::string enforce = utils::read_file_trim("/sys/fs/selinux/enforce");
        if(enforce=="1") selinux_enforcing=true; else if(enforce=="0") selinux_permissive=true;
    }
    // Config file
    std::string selinux_cfg_mode;
    if(file_exists("/etc/selinux/config")){
        std::ifstream c("/etc/selinux/config"); std::string line; while(std::getline(c,line)){
            if(line.rfind("SELINUX=",0)==0){ selinux_cfg_mode = line.substr(8); break; }
        }
    }

    // AppArmor
    bool apparmor_enabled=false; std::string apparmor_mode_line;
    if(file_exists("/sys/module/apparmor/parameters/enabled")){
        apparmor_mode_line = utils::read_file_trim("/sys/module/apparmor/parameters/enabled");
        // Typical contents: "Y" or "enforce"
        if(!apparmor_mode_line.empty()) apparmor_enabled = true;
    }

    // Count profiles
    size_t apparmor_profiles=0; size_t apparmor_profiles_complain=0; size_t apparmor_unconfined_critical=0;
    std::vector<std::string> critical_bins = {"/usr/sbin/sshd","/usr/bin/dbus-daemon","/usr/sbin/nginx","/usr/bin/containerd","/usr/bin/dockerd"};
    // Scan processes attr/current for a few critical processes
    for(const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied)){
        if(!entry.is_directory()) continue; auto pid = entry.path().filename().string(); if(pid.empty() || pid[0]<'0'||pid[0]>'9') continue;
        auto commp = entry.path()/"comm"; std::ifstream cf(commp); if(!cf) continue; std::string comm; std::getline(cf, comm); if(comm.empty()) continue;
        auto attrp = entry.path()/"attr"/"current"; std::ifstream af(attrp); if(!af) continue; std::string label; std::getline(af,label); if(label.empty()) continue;
        // Count complain mode occurrences
        if(label.find("(complain)")!=std::string::npos) apparmor_profiles_complain++;
        // Rough mapping: if label == "unconfined" or contains "unconfined" treat as unconfined
        if(label.find("unconfined")!=std::string::npos){
            // Match binary path for critical bins (approx by comm or exe symlink) ignoring permission errors
            std::string exes;
            try { auto exep = fs::read_symlink(entry.path()/"exe"); exes = exep.string(); } catch(...) { /* ignore */ }
            for(const auto& crit : critical_bins){ if(exes == crit) { apparmor_unconfined_critical++; break; } }
        }
        apparmor_profiles++; // counting examined labeled processes (proxy for active profiles)
    }

    // SELinux Finding
    {
    Finding f; f.id = "selinux"; f.title = "SELinux status"; f.severity = Severity::Info; f.description = "SELinux detection";
        if(!selinux_present) {
            f.metadata["present"] = "false";
            // If AppArmor is enabled, absence of SELinux alone is not high severity (Ubuntu default)
            if(apparmor_enabled) f.severity = in_container?Severity::Info:Severity::Low; else f.severity = in_container?Severity::Info:Severity::High;
        } else {
            f.metadata["present"] = "true"; f.metadata["enforcing"] = selinux_enforcing?"true":"false"; f.metadata["permissive"] = selinux_permissive?"true":"false"; if(selinux_cfg_mode.size()) f.metadata["config_mode"] = selinux_cfg_mode;
            if(selinux_permissive) f.severity = Severity::Medium; if(selinux_enforcing) f.severity = Severity::Info;
        }
        report.add_finding(this->name(), std::move(f));
    }

    // AppArmor Finding
    {
    Finding f; f.id = "apparmor"; f.title = "AppArmor status"; f.severity = Severity::Info; f.description = "AppArmor detection";
    if(!apparmor_enabled){ f.severity = in_container? Severity::Info:Severity::High; f.metadata["enabled"] = "false"; }
        else {
            f.metadata["enabled"] = "true"; f.metadata["mode_line"] = apparmor_mode_line; f.metadata["profiles_seen"] = std::to_string(apparmor_profiles); f.metadata["complain_count"] = std::to_string(apparmor_profiles_complain); if(apparmor_unconfined_critical>0){ f.metadata["unconfined_critical"] = std::to_string(apparmor_unconfined_critical); f.severity = Severity::Medium; }
        }
        report.add_finding(this->name(), std::move(f));
    }

    // Combined Advisory
    if(!selinux_present && !apparmor_enabled){ Finding f; f.id="mac_none"; f.title="No MAC enforcement"; f.severity=in_container?Severity::Low:Severity::High; f.description="Neither SELinux nor AppArmor appears active"; report.add_finding(this->name(), std::move(f)); }
    else if(selinux_present && apparmor_enabled){ Finding f; f.id="mac_dual"; f.title="Dual MAC layers"; f.severity=Severity::Info; f.description="Both SELinux and AppArmor appear present (double-check for conflicts)"; report.add_finding(this->name(), std::move(f)); }
}

}
