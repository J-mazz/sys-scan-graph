#include "SuidScanner.h"
#include "../core/Report.h"
#include <filesystem>
#include <sys/stat.h>
#include <unordered_map>
#include "../core/Config.h"

namespace fs = std::filesystem;
namespace sys_scan {

static bool has_suid_or_sgid(const fs::path& p) {
    struct stat st{}; if(lstat(p.c_str(), &st)!=0) return false; return (st.st_mode & S_ISUID) || (st.st_mode & S_ISGID); }

void SuidScanner::scan(Report& report) {
    std::vector<std::string> roots = {"/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin"};
    struct Key { dev_t dev; ino_t ino; };
    struct KeyHash { size_t operator()(const Key& k) const noexcept { return std::hash<dev_t>()(k.dev) ^ (std::hash<ino_t>()(k.ino)<<1); } };
    struct KeyEq { bool operator()(const Key& a, const Key& b) const noexcept { return a.dev==b.dev && a.ino==b.ino; } };
    struct Agg { std::string primary; std::vector<std::string> alt_paths; std::string severity; };
    std::unordered_map<Key, Agg, KeyHash, KeyEq> agg;
    for(const auto& r : roots) {
        std::error_code ec;
        for(auto it = fs::recursive_directory_iterator(r, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it) {
            if(ec) break; if(!it->is_regular_file(ec)) continue; const auto& path = it->path();
            if(!has_suid_or_sgid(path)) continue; struct stat st{}; if(lstat(path.c_str(), &st)!=0) continue; Key k{st.st_dev, st.st_ino};
            auto sev = std::string("medium"); std::string ps = path.string();
            if(ps.find("/usr/local/")!=std::string::npos) sev = "high"; if(ps.find("/tmp/")!=std::string::npos) sev = "critical";
            auto itagg = agg.find(k);
            if(itagg==agg.end()) {
                agg.emplace(k, Agg{ps, {}, sev});
            } else {
                // existing: add as alt path
                if(itagg->second.primary != ps) itagg->second.alt_paths.push_back(ps);
                // escalate severity if new path has higher severity rank
                if(severity_rank(sev) > severity_rank(itagg->second.severity)) itagg->second.severity = sev;
            }
        }
    }
    for(auto& kv : agg){
        Finding f; f.id = kv.second.primary; f.title = "SUID/SGID binary"; f.severity = kv.second.severity; f.description = "Binary has SUID or SGID bit set";
        if(!kv.second.alt_paths.empty()){
            // join alt paths (limit to avoid huge output)
            std::string joined; size_t limit=5; for(size_t i=0;i<kv.second.alt_paths.size() && i<limit;i++){ if(i) joined += ","; joined += kv.second.alt_paths[i]; }
            if(kv.second.alt_paths.size()>limit) joined += ",...";
            f.metadata["alt_paths"] = joined;
            f.metadata["alt_path_count"] = std::to_string(kv.second.alt_paths.size());
        }
        report.add_finding(this->name(), std::move(f));
    }
}

}
