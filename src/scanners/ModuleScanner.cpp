#include "ModuleScanner.h"
#include "../core/Report.h"
#include <fstream>
#include <sstream>
#include "../core/Config.h"
#include <sys/utsname.h>
#include <unordered_map>
#include <cstring>
#include <cstdio>
#include <memory>

namespace sys_scan {

void ModuleScanner::scan(Report& report) {
    std::ifstream ifs("/proc/modules"); if(!ifs) return; std::string line;
    auto& cfg = config();
    if(!cfg.modules_summary_only && !cfg.modules_anomalies_only){
        while(std::getline(ifs,line)) {
            std::istringstream ls(line); std::string name; ls>>name; if(name.empty()) continue; Finding f; f.id = name; f.title = "Module "+name; f.severity=Severity::Info; f.description="Loaded kernel module"; report.add_finding(this->name(), std::move(f)); }
        return;
    }
    // summary mode: gather stats
    // Build module name->path map from modules.dep
    struct utsname un{}; uname(&un); std::string rel = un.release;
    std::string dep_path = std::string("/lib/modules/") + rel + "/modules.dep";
    std::unordered_map<std::string,std::string> name_to_path;
    {
        std::ifstream dep(dep_path); std::string dline; while(std::getline(dep,dline)){
            if(dline.empty()) continue; auto colon = dline.find(':'); if(colon==std::string::npos) continue; std::string path = dline.substr(0, colon);
            auto slash = path.find_last_of('/'); std::string fname = (slash==std::string::npos)? path : path.substr(slash+1);
            // strip compression extensions
            auto strip_ext = [](std::string s){
                for(const char* ext: {".ko", ".ko.xz", ".ko.gz"}){ if(s.size()>=strlen(ext) && s.rfind(ext)==s.size()-strlen(ext)){ s = s.substr(0, s.size()-strlen(ext)); break; } }
                return s;
            };
            std::string base = strip_ext(fname);
            name_to_path[base] = path; // later entries overwrite (rare)
        }
    }

    size_t total=0; size_t likely_out_of_tree=0; size_t unsigned_count=0; size_t sample_limit=10; size_t oot_sample_limit=5; size_t unsigned_sample_limit=5;
    size_t compressed_count=0; size_t compressed_scanned=0; size_t compressed_unsigned=0;
    std::vector<std::string> sample; std::vector<std::string> oot_sample; std::vector<std::string> unsigned_sample; std::vector<std::string> compressed_unsigned_sample;
    auto read_file_prefix = [](const std::string& p, size_t max_bytes){ std::ifstream f(p, std::ios::binary); if(!f) return std::string(); std::string data; data.resize(max_bytes); f.read(&data[0], max_bytes); data.resize(f.gcount()); return data; };
    auto read_file_all = [](const std::string& p){ std::ifstream f(p, std::ios::binary); if(!f) return std::string(); std::ostringstream oss; oss<<f.rdbuf(); return oss.str(); };
    auto decompress_all = [](const std::string& cmd)->std::string{ std::string data; FILE* pipe = popen(cmd.c_str(), "r"); if(!pipe) return data; char buf[8192]; size_t n; while((n=fread(buf,1,sizeof(buf),pipe))>0){ data.append(buf,n); if(data.size() > 2*1024*1024) break; } pclose(pipe); return data; };
    auto is_out_of_tree_path = [](const std::string& p){ return p.find("/extra/")!=std::string::npos || p.find("/updates/")!=std::string::npos || p.find("dkms")!=std::string::npos || p.find("nvidia")!=std::string::npos || p.find("virtualbox")!=std::string::npos || p.find("vmware")!=std::string::npos; };
    while(std::getline(ifs,line)) {
        std::istringstream ls(line); std::string name; ls>>name; if(name.empty()) continue; ++total; if(sample.size()<sample_limit) sample.push_back(name);
        auto itp = name_to_path.find(name); std::string path = (itp==name_to_path.end()? std::string() : itp->second);
        bool oot=false; if(!path.empty() && is_out_of_tree_path(path)) { oot=true; ++likely_out_of_tree; if(oot_sample.size()<oot_sample_limit) oot_sample.push_back(name); }
        // Unsigned detection: if path points to uncompressed .ko, scan for signature marker
        bool unsigned_mod=false;
        if(!path.empty()){
            std::string full = std::string("/lib/modules/")+rel+"/"+path;
            if(path.rfind(".ko") == path.size()-3){
                // uncompressed
                auto contents = read_file_prefix(full, 4096); // signature marker near end, but often present in first blocks for signed modules header (heuristic)
                // fallback to full read if not found
                if(contents.find("Module signature appended")==std::string::npos){ contents = read_file_all(full); if(contents.find("Module signature appended")==std::string::npos) unsigned_mod=true; }
            } else if(path.rfind(".ko.xz") == path.size()-6 || path.rfind(".ko.gz") == path.size()-6){
                ++compressed_count;
                std::string cmd;
                if(path.rfind(".ko.xz") == path.size()-6) cmd = "xz -dc '"+full+"' 2>/dev/null"; else cmd = "gzip -dc '"+full+"' 2>/dev/null";
                auto contents = decompress_all(cmd);
                if(!contents.empty()){ ++compressed_scanned; if(contents.find("Module signature appended")==std::string::npos){ unsigned_mod=true; ++compressed_unsigned; if(compressed_unsigned_sample.size()<unsigned_sample_limit) compressed_unsigned_sample.push_back(name); } }
            }
        }
        if(unsigned_mod){ ++unsigned_count; if(unsigned_sample.size()<unsigned_sample_limit) unsigned_sample.push_back(name); }
        if(cfg.modules_anomalies_only){
            if(oot || unsigned_mod){
                Finding f; f.id = name; f.title = "Module anomaly: "+name; f.severity = unsigned_mod?Severity::High:Severity::Medium; f.description = unsigned_mod?"Unsigned kernel module detected":"Out-of-tree kernel module"; if(oot) f.metadata["out_of_tree"]="true"; if(unsigned_mod) f.metadata["unsigned"]="true"; if(!path.empty()) f.metadata["path"] = path; report.add_finding(this->name(), std::move(f));
            }
        }
    }
    if(cfg.modules_anomalies_only) return; // done; no summary in anomalies-only mode
    Finding f; f.id = "module_summary"; f.title = "Kernel modules summary"; f.description="Loaded kernel modules inventory";
    // Severity escalation based on findings
    Severity sev = Severity::Info; if(likely_out_of_tree>0) sev = Severity::Medium; if(unsigned_count>0) sev = Severity::High; f.severity = sev;
    f.metadata["total"] = std::to_string(total);
    f.metadata["sample"] = [&]{ std::string s; for(size_t i=0;i<sample.size();++i){ if(i) s+=","; s+=sample[i]; } return s; }();
    f.metadata["out_of_tree_count"] = std::to_string(likely_out_of_tree);
    if(!oot_sample.empty()) { std::string s; for(size_t i=0;i<oot_sample.size(); ++i){ if(i) s+=","; s+=oot_sample[i]; } f.metadata["out_of_tree_sample"] = s; }
    f.metadata["unsigned_count"] = std::to_string(unsigned_count);
    if(compressed_count>0){ f.metadata["compressed_count"] = std::to_string(compressed_count); }
    if(compressed_scanned>0){ f.metadata["compressed_scanned"] = std::to_string(compressed_scanned); }
    if(compressed_unsigned>0){ f.metadata["compressed_unsigned"] = std::to_string(compressed_unsigned); }
    if(!unsigned_sample.empty()) { std::string s; for(size_t i=0;i<unsigned_sample.size(); ++i){ if(i) s+=","; s+=unsigned_sample[i]; } f.metadata["unsigned_sample"] = s; }
    if(!compressed_unsigned_sample.empty()){ std::string s; for(size_t i=0;i<compressed_unsigned_sample.size(); ++i){ if(i) s+=","; s+=compressed_unsigned_sample[i]; } f.metadata["compressed_unsigned_sample"] = s; }
    report.add_finding(this->name(), std::move(f));
}

}
