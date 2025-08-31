#include "YaraScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <cstdio>

// Minimal optional YARA integration placeholder (no libyara dependency yet)
// Strategy: look for simple substring signatures defined in external files (pseudo-YARA) to avoid heavy dep now.
// Each rule file: one pattern per line (ignoring empty/#). When real YARA added, this module will wrap libyara.

namespace fs = std::filesystem; namespace sys_scan {

static std::vector<std::string> load_patterns(const std::string& dir){
    std::vector<std::string> pats; if(dir.empty()) return pats; std::error_code ec; if(!fs::exists(dir, ec)) return pats; for(auto& ent : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)){
        if(ec) break; if(!ent.is_regular_file()) continue; auto p = ent.path(); if(p.extension() != ".yar" && p.extension() != ".yara" && p.extension() != ".sig") continue; std::ifstream ifs(p); if(!ifs) continue; std::string line; while(std::getline(ifs,line)){ if(line.empty()||line[0]=='#') continue; if(line.size()>4096) line.resize(4096); pats.push_back(line); } }
    return pats;
}

void YaraScanner::scan(ScanContext& context){
    const auto& cfg = context.config;
    // No config flag yet; enable only if rules_dir contains a yara subdir (future: add dedicated flags)
    std::string yara_dir = cfg.rules_dir.empty()? std::string(): (cfg.rules_dir+"/yara");
    auto patterns = load_patterns(yara_dir);
    if(patterns.empty()) return; // nothing to do

    // File roots (conservative) - similar to world writable scan roots + /bin
    std::vector<std::string> roots = {"/usr/bin","/bin","/usr/local/bin"};
    // Limit total files & matches to control runtime
    size_t file_limit = 2000; size_t match_limit = 200; size_t scanned=0; size_t emitted=0;

    for(const auto& root : roots){ std::error_code ec; for(auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it){ if(ec) break; if(!it->is_regular_file(ec)) continue; if(scanned++ > file_limit) return; auto path = it->path(); std::ifstream ifs(path, std::ios::binary); if(!ifs) continue; std::string content; content.resize(8192); ifs.read(&content[0], content.size()); content.resize(ifs.gcount()); for(const auto& pat : patterns){ if(content.find(pat)!=std::string::npos){ Finding f; f.id = path.string()+":yara:"+pat.substr(0,16); f.title = "Pseudo-YARA pattern match"; f.severity=Severity::Medium; f.description="Pattern found in file prefix"; f.metadata["pattern"] = pat;   f.metadata["path"] = path.string(); context.report.add_finding(this->name(), std::move(f)); if(++emitted >= match_limit) return; }
        }
    } }
}

}
