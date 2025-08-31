#include "MountScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <algorithm>

namespace sys_scan {

static bool has_opt(const std::string& opts, const std::string& key){
    // crude contains match on comma boundaries
    if(opts==key) return true;
    size_t pos = 0; std::string needle = key;
    while(true){
        pos = opts.find(key, pos);
        if(pos == std::string::npos) return false;
        bool left_ok = (pos==0) || opts[pos-1]==',';
        bool right_ok = (pos + key.size() == opts.size()) || opts[pos+key.size()]==',';
        if(left_ok && right_ok) return true;
        pos += key.size();
    }
}

void MountScanner::scan(ScanContext& context){
    const auto& cfg = context.config;
    if(!cfg.hardening) return; // opt-in

    std::ifstream f("/proc/mounts");
    if(!f.is_open()) { context.report.add_warning(name(), WarnCode::MountsUnreadable, "/proc/mounts"); return; }
    std::string line;

    std::unordered_set<std::string> sensitive = {"/", "/home", "/tmp", "/var", "/var/tmp", "/boot", "/efi"};

    while(std::getline(f,line)){
        std::istringstream iss(line);
        std::string dev, mountpoint, fstype, opts; int dump, passno; // last two rarely needed
        if(!(iss>>dev>>mountpoint>>fstype>>opts>>dump>>passno)) continue;

        // Skip pseudo FS that are rarely security relevant here
        static const std::unordered_set<std::string> skip_fs = {"proc","sysfs","cgroup","cgroup2","debugfs","devpts","mqueue","hugetlbfs","tracefs"};
        if(skip_fs.count(fstype)) continue;

        bool is_sensitive = sensitive.count(mountpoint) || mountpoint.rfind("/home/",0)==0; // any /home/*

        auto emit = [&](const std::string& id_suffix, Severity sev, const std::string& title, const std::string& desc){
            Finding f; f.id = std::string("mount:") + id_suffix + ":" + mountpoint; f.title = title; f.severity = sev; f.description = desc; f.metadata["mount"] = mountpoint; f.metadata["device"] = dev; f.metadata["fstype"] = fstype; f.metadata["options"] = opts; context.report.add_finding(name(), std::move(f)); };

        // World-writable device mount detection (simplified): look for fstype ext*,xfs,btrfs and absence of nodev/nosuid/noexec on sensitive mounts or tmp
        bool is_tmp_like = (mountpoint=="/tmp" || mountpoint=="/var/tmp");
        if(is_tmp_like) {
            if(!has_opt(opts, "noexec")) emit("tmp-noexec-missing", Severity::Medium, "/tmp style mount missing noexec", "Temporary directory mount lacks noexec which can allow execution from world-writable space");
            if(!has_opt(opts, "nosuid")) emit("tmp-nosuid-missing", Severity::Medium, "/tmp style mount missing nosuid", "Temporary directory mount lacks nosuid lowering barrier to SUID exploitation");
            if(!has_opt(opts, "nodev")) emit("tmp-nodev-missing", Severity::Low, "/tmp style mount missing nodev", "Temporary directory mount lacks nodev allowing device nodes");
        }

        if(is_sensitive && mountpoint!="/" && (fstype=="ext4" || fstype=="xfs" || fstype=="btrfs")){
            // Suggest nosuid,nodev,noexec where appropriate (skip root / due to common breakage risk)
            if(!has_opt(opts, "nosuid")) emit("sensitive-nosuid-missing", Severity::Low, "Sensitive mount missing nosuid", "Expected nosuid on sensitive mount");
            if(!has_opt(opts, "nodev") && mountpoint!="/boot" && mountpoint!="/efi") emit("sensitive-nodev-missing", Severity::Low, "Sensitive mount missing nodev", "Expected nodev on non-device mount");
        }

        // Flag exec on /home (some orgs enforce noexec); treat as informational
        if(mountpoint.rfind("/home",0)==0 && has_opt(opts, "exec")) emit("home-exec", Severity::Info, "/home mounted exec", "Home directory allows execution; consider noexec for stricter hardening");

        // Unexpected bind mounts: presence of 'bind'
        if(has_opt(opts, "bind") && !is_tmp_like && !is_sensitive) emit("bind-generic", Severity::Info, "Bind mount present", "Non-standard bind mount; review necessity");

        // Missing secure boot style modules restrictions (fs.protected_symlinks etc. outside scope here)
    }
}

}
