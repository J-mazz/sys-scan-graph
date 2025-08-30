#include "WorldWritableScanner.h"
#include "../core/Report.h"
#include "../core/Utils.h"
#include "../core/Config.h"
#include <filesystem>
#include <sys/stat.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <unordered_map>
#ifdef __linux__
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem; 
namespace sys_scan {

void WorldWritableScanner::scan(Report& report) {
    std::vector<std::string> dirs = {"/etc", "/usr/bin", "/usr/local/bin", "/var"};
    for(const auto& extra : config().world_writable_dirs) dirs.push_back(extra);
    auto should_exclude = [&](const std::string& p){ for(const auto& pat : config().world_writable_exclude) if(p.find(pat)!=std::string::npos) return true; return false; };
    size_t ww_count=0; int ww_limit = config().fs_world_writable_limit;
    for(const auto& d: dirs){ std::error_code ec; for(auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it) {
            if(ec){ report.add_warning(this->name(), WarnCode::WalkError, d+":"+ec.message()); break; }
            const auto& p = it->path(); if(!it->is_regular_file(ec)) continue; std::string ps = p.string(); if(should_exclude(ps)) continue; if(utils::is_world_writable(ps)) {
                if(ww_limit>0 && static_cast<int>(ww_count) >= ww_limit) { continue; }
                Finding f; f.id = ps; f.title = "World-writable file"; f.severity=Severity::Medium; f.description="File is world writable"; if(ps.find("/tmp/")!=std::string::npos) f.severity=Severity::Low; if(ps.find(".so")!=std::string::npos || ps.find("/bin/")!=std::string::npos) f.severity=Severity::High; report.add_finding(this->name(), std::move(f)); ++ww_count; }
        }
    }

    if(!config().fs_hygiene) return; // advanced checks gated

    // 1. PATH directory world-writable detection
    const char* path_env = std::getenv("PATH"); if(path_env){ std::string pathv = path_env; std::stringstream ss(pathv); std::string seg; while(std::getline(ss, seg, ':')){ if(seg.empty()) continue; std::error_code ec; fs::path p(seg); if(!fs::exists(p, ec)) continue; if(!fs::is_directory(p, ec)) continue; struct stat st{}; if(::stat(seg.c_str(), &st)==0){ if(st.st_mode & S_IWOTH){ Finding f; f.id = seg; f.title="World-writable PATH directory"; f.severity=Severity::High; f.description="Executable search path directory is world-writable"; f.metadata["rule"] = "path_dir_world_writable"; report.add_finding(this->name(), std::move(f)); } } } }

    // 2. Setuid interpreter detection (shell / python / perl etc with suid bit)
    std::vector<std::string> interpreters = {"bash","sh","dash","zsh","ksh","python","python3","perl","ruby"};
    auto check_suid_interp = [&](const fs::path& p){ struct stat st{}; if(::lstat(p.c_str(), &st)!=0) return; if(!(st.st_mode & S_ISUID)) return; // suid
        // read shebang or name
        bool match=false; std::string fname = p.filename().string(); for(auto& i: interpreters){ if(fname==i) { match=true; break; } }
    if(!match){ std::ifstream f(p, std::ios::binary); if(f){ char buf[64]={0}; f.read(buf,63); std::string head(buf, f.gcount()); if(head.rfind("#!/",0)==0){ for(auto& i: interpreters){ if(head.find(i)!=std::string::npos){ match=true; break; } } } } }
        if(match){ Finding f; f.id = p.string(); f.title = "Setuid interpreter"; f.severity=Severity::Critical; f.description="Setuid shell or script interpreter"; f.metadata["rule"] = "setuid_interpreter"; report.add_finding(this->name(), std::move(f)); }
    };
    // Scan common bin dirs quickly (non-recursive enough?) -> recursive limited depth
    std::vector<std::string> bin_dirs = {"/usr/bin","/bin","/usr/local/bin"};
    for(const auto& bd: bin_dirs){ std::error_code ec; for(auto it = fs::directory_iterator(bd, fs::directory_options::skip_permission_denied, ec); it!=fs::directory_iterator(); ++it){ if(ec) break; if(!it->is_regular_file(ec)) continue; check_suid_interp(it->path()); } }

    // 3. Unexpected setcap binaries (file capabilities) - parse getcap -r fallback /proc filesystem if available; minimal approach: read security.capability xattr
#ifdef __linux__
    auto has_file_caps = [](const fs::path& p){ ssize_t len = ::getxattr(p.c_str(), "security.capability", nullptr, 0); return len>0; };
    for(const auto& bd: bin_dirs){ std::error_code ec; for(auto it = fs::directory_iterator(bd, fs::directory_options::skip_permission_denied, ec); it!=fs::directory_iterator(); ++it){ if(ec) break; if(!it->is_regular_file(ec)) continue; if(has_file_caps(it->path())){ struct stat st{}; if(stat(it->path().c_str(), &st)==0 && !(st.st_mode & S_ISUID)){ // exclude ones already suid (handled elsewhere)
                Finding f; f.id = it->path().string(); f.title = "File capabilities binary"; f.severity=Severity::Medium; f.description="Binary has file capabilities set"; f.metadata["rule"] = "file_capability"; report.add_finding(this->name(), std::move(f)); }
        } }
    }
#endif

    // 4. Dangling SUID hardlinks: locate files with S_ISUID and link count >1 pointing outside expected directories
    // Build map inode -> paths for scanned bin dirs
    struct InodeKey { dev_t dev; ino_t ino; bool operator==(const InodeKey& o) const { return dev==o.dev && ino==o.ino; } };
    struct InodeHash { size_t operator()(const InodeKey& k) const { return std::hash<uint64_t>()(((uint64_t)k.dev<<32) ^ (uint64_t)k.ino); } };
    std::unordered_map<InodeKey, std::vector<std::string>, InodeHash> inode_paths;
    auto collect_links = [&](const std::string& root){ std::error_code ec; for(auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it){ if(ec) break; if(!it->is_regular_file(ec)) continue; struct stat st{}; if(::lstat(it->path().c_str(), &st)!=0) continue; if(!(st.st_mode & S_ISUID)) continue; InodeKey key{st.st_dev, st.st_ino}; inode_paths[key].push_back(it->path().string()); } };
    for(const auto& bd: bin_dirs) collect_links(bd);
    // Detect same inode appearing outside canonical directories (e.g., /tmp hardlink to suid root binary)
    std::vector<std::string> suspect_roots = {"/tmp","/var/tmp","/dev/shm"};
    for(auto& kv : inode_paths){ if(kv.second.size() < 2) continue; bool has_suspect=false; bool has_system=false; for(auto& p: kv.second){ if(p.rfind("/usr/bin/",0)==0 || p.rfind("/bin/",0)==0 || p.rfind("/usr/sbin/",0)==0) has_system=true; for(auto& sr: suspect_roots){ if(p.rfind(sr,0)==0) has_suspect=true; } }
        if(has_suspect && has_system){ Finding f; f.id = kv.second.front()+":dangling_suid_link"; f.title="Dangling SUID hardlink"; f.severity=Severity::High; f.description="SUID binary hardlinked into temporary/untrusted location"; f.metadata["rule"] = "dangling_suid_hardlink"; std::string all; for(size_t i=0;i<kv.second.size(); ++i){ if(i) all += ","; all += kv.second[i]; } f.metadata["paths"] = all; report.add_finding(this->name(), std::move(f)); }
    }
}

}
