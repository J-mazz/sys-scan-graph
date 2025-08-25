#include "ModuleScanner.h"
#include "../core/Report.h"
#include <fstream>
#include <sstream>
#include "../core/Config.h"
#include <sys/utsname.h>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstring>
#include <cstdio>
#include <memory>
#include <cstdint>
#include <vector>
#ifdef SYS_SCAN_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef SYS_SCAN_HAVE_LZMA
#include <lzma.h>
#endif

namespace sys_scan {

void ModuleScanner::scan(Report& report) {
    std::ifstream ifs("/proc/modules"); if(!ifs) return; std::string line;
    auto& cfg = config();
    if(!cfg.modules_summary_only && !cfg.modules_anomalies_only){
        while(std::getline(ifs,line)) {
            std::istringstream ls(line); std::string name; ls>>name; if(name.empty()) continue; Finding f; f.id = name; f.title = "Module "+name; f.severity=Severity::Info; f.description="Loaded kernel module"; report.add_finding(this->name(), std::move(f)); }
        return;
    }
    // summary / anomalies mode: gather stats and anomalies
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

    // Prepare built-in module name set (present in sysfs but not listed in /proc/modules)
    std::unordered_set<std::string> builtin_modules;
    {
        std::ifstream bf(std::string("/lib/modules/")+rel+"/modules.builtin"); std::string bline; while(std::getline(bf,bline)){
            if(bline.empty()) continue; auto slash = bline.find_last_of('/'); auto fname = (slash==std::string::npos)? bline : bline.substr(slash+1);
            // Strip extension variants
            auto strip_ext = [](std::string s){ for(const char* ext: {".ko", ".ko.xz", ".ko.gz"}){ if(s.size()>=strlen(ext) && s.rfind(ext)==s.size()-strlen(ext)){ s = s.substr(0, s.size()-strlen(ext)); break; } } return s; };
            builtin_modules.insert(strip_ext(fname));
        }
    }

    // Collect sysfs module directory names
    std::unordered_set<std::string> sysfs_modules;
    {
        namespace fs = std::filesystem; std::error_code ec; for(auto& ent : fs::directory_iterator("/sys/module", fs::directory_options::skip_permission_denied, ec)){
            if(ec) break; if(!ent.is_directory()) continue; sysfs_modules.insert(ent.path().filename().string());
        }
    }

    size_t total=0; size_t likely_out_of_tree=0; size_t unsigned_count=0; size_t sample_limit=10; size_t oot_sample_limit=5; size_t unsigned_sample_limit=5;
    size_t compressed_count=0; size_t compressed_scanned=0; size_t compressed_unsigned=0;
    size_t missing_file_count=0; size_t hidden_in_proc_only_count=0; size_t sysfs_only_count=0;
    size_t hidden_sample_limit=5; size_t missing_file_sample_limit=5; size_t sysfs_only_sample_limit=5;
    std::vector<std::string> sample; std::vector<std::string> oot_sample; std::vector<std::string> unsigned_sample; std::vector<std::string> compressed_unsigned_sample; std::vector<std::string> missing_file_sample; std::vector<std::string> hidden_sample; std::vector<std::string> sysfs_only_sample;

    // DKOM / LKM heuristic tracking
    size_t wx_section_modules = 0; size_t large_text_section_modules = 0; size_t suspicious_name_section_modules = 0;
    std::vector<std::string> wx_section_sample; std::vector<std::string> large_text_section_sample; std::vector<std::string> suspicious_section_name_sample;
    size_t wx_section_sample_limit = 5; size_t large_text_section_sample_limit=5; size_t suspicious_section_name_sample_limit=5;
    auto suspicious_section_name = [](const std::string& n){ if(n.empty()) return false; static const char* bad[] = {".evil",".rootkit",".hide",".__mod",".__kern",".backdoor"}; for(auto* b: bad){ if(n==b) return true; } // heuristic: very short or high entropy names unlikely except .note,.bss etc
        if(n.size()==1) return true; if(n[0]=='.' && n.size()>1 && std::isdigit((unsigned char)n[1]) && std::isdigit((unsigned char)n.back())) return true; return false; };
    auto read_file_prefix = [](const std::string& p, size_t max_bytes){ std::ifstream f(p, std::ios::binary); if(!f) return std::string(); std::string data; data.resize(max_bytes); f.read(&data[0], max_bytes); data.resize(f.gcount()); return data; };
    auto read_file_all = [](const std::string& p){ std::ifstream f(p, std::ios::binary); if(!f) return std::string(); std::ostringstream oss; oss<<f.rdbuf(); return oss.str(); };
    auto decompress_xz = [&](const std::string& full)->std::string{
#ifdef SYS_SCAN_HAVE_LZMA
    std::ifstream f(full, std::ios::binary); if(!f) return {}; std::string raw((std::istreambuf_iterator<char>(f)), {});
    if(raw.empty()) return {};
    lzma_stream strm = LZMA_STREAM_INIT; if(lzma_stream_decoder(&strm, UINT64_MAX, 0)!=LZMA_OK) return {};
    std::string out; out.reserve(65536);
    strm.next_in = reinterpret_cast<const uint8_t*>(raw.data()); strm.avail_in = raw.size(); uint8_t buf[8192];
    while(true){ strm.next_out = buf; strm.avail_out = sizeof(buf); auto rc = lzma_code(&strm, LZMA_FINISH); size_t produced = sizeof(buf)-strm.avail_out; out.append(reinterpret_cast<char*>(buf), produced); if(rc==LZMA_STREAM_END) break; if(rc!=LZMA_OK){ out.clear(); break; } if(out.size()>2*1024*1024) break; }
    lzma_end(&strm); return out;
#else
    (void)full; return std::string();
#endif
    };
    auto decompress_gz = [&](const std::string& full)->std::string{
#ifdef SYS_SCAN_HAVE_ZLIB
    gzFile g = gzopen(full.c_str(), "rb"); if(!g) return {}; std::string out; out.reserve(65536); char buf[8192]; int n; while((n=gzread(g, buf, sizeof(buf)))>0){ out.append(buf, n); if(out.size()>2*1024*1024) break; } gzclose(g); return out;
#else
    (void)full; return std::string();
#endif
    };
    auto is_out_of_tree_path = [](const std::string& p){ return p.find("/extra/")!=std::string::npos || p.find("/updates/")!=std::string::npos || p.find("dkms")!=std::string::npos || p.find("nvidia")!=std::string::npos || p.find("virtualbox")!=std::string::npos || p.find("vmware")!=std::string::npos; };
    while(std::getline(ifs,line)) {
        std::istringstream ls(line); std::string name; ls>>name; if(name.empty()) continue; ++total; if(sample.size()<sample_limit) sample.push_back(name);
        auto itp = name_to_path.find(name); std::string path = (itp==name_to_path.end()? std::string() : itp->second);
        bool oot=false; if(!path.empty() && is_out_of_tree_path(path)) { oot=true; ++likely_out_of_tree; if(oot_sample.size()<oot_sample_limit) oot_sample.push_back(name); }
        // Unsigned detection: if path points to uncompressed .ko, scan for signature marker
        bool unsigned_mod=false;
        bool missing_file=false;
        std::string full;
        if(!path.empty()){
            full = std::string("/lib/modules/")+rel+"/"+path;
            if(path.rfind(".ko") == path.size()-3){
                // uncompressed
                auto contents = read_file_prefix(full, 4096); // signature marker near end, but often present in first blocks for signed modules header (heuristic)
                // fallback to full read if not found
                if(contents.find("Module signature appended")==std::string::npos){ contents = read_file_all(full); if(contents.find("Module signature appended")==std::string::npos) unsigned_mod=true; }
            } else if(path.rfind(".ko.xz") == path.size()-6 || path.rfind(".ko.gz") == path.size()-6){
                ++compressed_count;
                std::string contents;
                if(path.rfind(".ko.xz") == path.size()-6) contents = decompress_xz(full); else contents = decompress_gz(full);
                if(contents.empty()){
                    report.add_warning(this->name(), std::string("decompress_fail:")+path);
                } else {
                    ++compressed_scanned; if(contents.find("Module signature appended")==std::string::npos){ unsigned_mod=true; ++compressed_unsigned; if(compressed_unsigned_sample.size()<unsigned_sample_limit) compressed_unsigned_sample.push_back(name); }
                }
            }
            // File existence check (indicates deleted after load or tampering)
            if(!std::filesystem::exists(full)) { missing_file=true; ++missing_file_count; if(missing_file_sample.size()<missing_file_sample_limit) missing_file_sample.push_back(name); }
        }
        if(unsigned_mod){ ++unsigned_count; if(unsigned_sample.size()<unsigned_sample_limit) unsigned_sample.push_back(name); }
        // Hidden module detection: present in /proc/modules but not in sysfs and not built-in
        if(sysfs_modules.find(name)==sysfs_modules.end() && builtin_modules.find(name)==builtin_modules.end()){
            ++hidden_in_proc_only_count; if(hidden_sample.size()<hidden_sample_limit) hidden_sample.push_back(name);
        }
        if(cfg.modules_anomalies_only){
            bool hidden_proc_only = (sysfs_modules.find(name)==sysfs_modules.end() && builtin_modules.find(name)==builtin_modules.end());
            if(oot || unsigned_mod || missing_file || hidden_proc_only){
                Finding f; f.id = name; f.title = "Module anomaly: "+name; f.severity = Severity::Medium; f.description = "Kernel module anomaly";
                if(unsigned_mod) { f.metadata["unsigned"]="true"; f.severity=Severity::High; f.description="Unsigned kernel module detected"; }
                if(oot) { f.metadata["out_of_tree"]="true"; if(f.severity < Severity::High) f.description="Out-of-tree kernel module"; }
                if(missing_file){ f.metadata["missing_file"]="true"; f.severity = Severity::High; f.description="Module file missing on disk"; }
                if(hidden_proc_only) { f.metadata["hidden_sysfs"] = "true"; f.severity = Severity::High; f.description = "Module present in /proc/modules but missing in /sys/module"; }
                // ELF section heuristics (only if we have path)
                if(!full.empty()){
                    std::ifstream ef(full, std::ios::binary); if(ef){ unsigned char ehdr[64]; ef.read((char*)ehdr, sizeof(ehdr)); if(ef.gcount() >= 52 && ehdr[0]==0x7f && ehdr[1]=='E' && ehdr[2]=='L' && ehdr[3]=='F'){
                        bool is64 = (ehdr[4]==2); bool le = (ehdr[5]==1); auto rd16=[&](const unsigned char* p){ return le? (uint16_t)p[0] | ((uint16_t)p[1]<<8) : (uint16_t)p[1] | ((uint16_t)p[0]<<8); }; auto rd32=[&](const unsigned char* p){ return le? (uint32_t)p[0] | ((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24) : (uint32_t)p[3] | ((uint32_t)p[2]<<8)|((uint32_t)p[1]<<16)|((uint32_t)p[0]<<24); }; auto rd64=[&](const unsigned char* p){ uint64_t v=0; if(le){ for(int i=7;i>=0;--i){ v = (v<<8) | p[i]; } } else { for(int i=0;i<8;i++){ v = (v<<8) | p[i]; } } return v; };
                        uint16_t e_shentsize = rd16(ehdr + (is64?58:46)); uint16_t e_shnum = rd16(ehdr + (is64?60:48)); uint32_t e_shoff32 = rd32(ehdr + (is64?40:32)); uint64_t e_shoff = is64? rd64(ehdr+40) : e_shoff32;
                        if(e_shoff && e_shentsize && e_shnum && e_shnum < 512){
                            ef.seekg(e_shoff, std::ios::beg);
                            struct SecInfo { std::string name; uint64_t flags=0; uint64_t size=0; };
                            std::vector<SecInfo> secs; secs.reserve(e_shnum);
                            std::vector<unsigned char> shbuf(e_shentsize);
                            for(uint16_t si=0; si<e_shnum; ++si){ if(!ef.read((char*)shbuf.data(), e_shentsize)) break; uint64_t flags=0; uint64_t size=0; if(is64){ flags = rd64(&shbuf[8]); size = rd64(&shbuf[32]); } else { flags = rd32(&shbuf[8]); size = rd32(&shbuf[16]); } secs.push_back({"", flags, size}); }
                            uint16_t e_shstrndx = rd16(ehdr + (is64?62:50)); if(e_shstrndx < secs.size()){
                                ef.seekg(e_shoff + (uint64_t)e_shstrndx * e_shentsize, std::ios::beg); std::vector<unsigned char> sh(e_shentsize); if(ef.read((char*)sh.data(), e_shentsize)){
                                    uint64_t stroff = is64? rd64(&sh[24]) : rd32(&sh[16]); uint64_t strsize = is64? rd64(&sh[32]) : rd32(&sh[20]); if(stroff && strsize && strsize < 1*1024*1024){ std::vector<char> strtab(strsize); ef.seekg(stroff, std::ios::beg); if(ef.read(strtab.data(), strsize)){
                                            ef.seekg(e_shoff, std::ios::beg);
                                            for(uint16_t si=0; si<secs.size(); ++si){ if(!ef.read((char*)shbuf.data(), e_shentsize)) break; uint32_t name_off = rd32(&shbuf[0]); if(name_off < strtab.size()) secs[si].name = std::string(&strtab[name_off]); }
                                        } }
                                }
                            }
                            static const uint64_t SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4; uint64_t text_size=0; uint64_t file_text_threshold=0;
                            for(const auto& s : secs){ if(s.name.empty()) continue; bool exec = (s.flags & SHF_EXECINSTR)!=0; bool write = (s.flags & SHF_WRITE)!=0; if(exec && write){ f.metadata["wx_section"]="true"; if(f.severity < Severity::High) f.severity = Severity::High; }
                                if(s.name==".text") text_size = s.size; if(suspicious_section_name(s.name)){ f.metadata["suspicious_section_name"]=s.name; if(f.severity < Severity::High) f.severity = Severity::High; }
                            }
                            // crude .text size anomaly heuristic (> 5MB) typical modules far smaller
                            if(text_size > 5*1024*1024){ f.metadata["large_text_section"] = std::to_string(text_size); if(f.severity < Severity::High) f.severity = Severity::High; }
                        }
                    }
                }
#ifdef SYS_SCAN_HAVE_OPENSSL
                if(cfg.modules_hash && !full.empty()){
                    std::ifstream mf(full, std::ios::binary); if(mf){ unsigned char md[32]; unsigned int mdlen=0; std::vector<unsigned char> buf(8192); EVP_MD_CTX* ctx = EVP_MD_CTX_new(); if(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)==1){ size_t totalb=0; while(mf && totalb < 2*1024*1024){ mf.read((char*)buf.data(), buf.size()); auto got = mf.gcount(); if(got<=0) break; EVP_DigestUpdate(ctx, buf.data(), (size_t)got); totalb += (size_t)got; } if(EVP_DigestFinal_ex(ctx, md, &mdlen)==1 && mdlen==32){ static const char* hex="0123456789abcdef"; std::string hexhash; hexhash.reserve(64); for(unsigned i=0;i<32;i++){ hexhash.push_back(hex[md[i]>>4]); hexhash.push_back(hex[md[i]&0xF]); } f.metadata["sha256"] = hexhash; } } if(ctx) EVP_MD_CTX_free(ctx); }
                }
#endif
                if(!path.empty()) f.metadata["path"] = path; report.add_finding(this->name(), std::move(f));
            }
        }
    }
    // Modules visible in sysfs only: populate set of /proc/modules for comparison
    std::unordered_set<std::string> proc_modules_set; {
        std::ifstream pm("/proc/modules"); std::string pl; while(std::getline(pm,pl)){ std::istringstream pls(pl); std::string n; pls>>n; if(!n.empty()) proc_modules_set.insert(n); }
    }
    for(const auto& m : sysfs_modules){ if(builtin_modules.find(m)!=builtin_modules.end()) continue; if(proc_modules_set.find(m)==proc_modules_set.end()){ ++sysfs_only_count; if(sysfs_only_sample.size()<sysfs_only_sample_limit) sysfs_only_sample.push_back(m); } }
    if(cfg.modules_anomalies_only) return; // done; no summary in anomalies-only mode
    Finding f; f.id = "module_summary"; f.title = "Kernel modules summary"; f.description="Loaded kernel modules inventory";
    // Severity escalation based on findings
    Severity sev = Severity::Info; if(likely_out_of_tree>0) sev = Severity::Medium; if(unsigned_count>0 || hidden_in_proc_only_count>0 || missing_file_count>0 || sysfs_only_count>0) sev = Severity::High; f.severity = sev;
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
    if(missing_file_count>0){ f.metadata["missing_file_count"] = std::to_string(missing_file_count); if(!missing_file_sample.empty()){ std::string s; for(size_t i=0;i<missing_file_sample.size(); ++i){ if(i) s+=","; s+=missing_file_sample[i]; } f.metadata["missing_file_sample"] = s; } }
    if(hidden_in_proc_only_count>0){ f.metadata["hidden_proc_only_count"] = std::to_string(hidden_in_proc_only_count); if(!hidden_sample.empty()){ std::string s; for(size_t i=0;i<hidden_sample.size(); ++i){ if(i) s+=","; s+=hidden_sample[i]; } f.metadata["hidden_proc_only_sample"] = s; } }
    if(sysfs_only_count>0){ f.metadata["sysfs_only_count"] = std::to_string(sysfs_only_count); if(!sysfs_only_sample.empty()){ std::string s; for(size_t i=0;i<sysfs_only_sample.size(); ++i){ if(i) s+=","; s+=sysfs_only_sample[i]; } f.metadata["sysfs_only_sample"] = s; } }
    // Add taint flags info
    {
        std::ifstream tf("/proc/sys/kernel/tainted"); if(tf){ std::string tv; std::getline(tf,tv); if(!tv.empty()){ f.metadata["taint_value"] = tv; // decode bits
                unsigned long val = std::strtoul(tv.c_str(), nullptr, 10); if(val){ std::string flags; struct Bit { unsigned long bit; const char* name; }; static const Bit bits[]={{0,"PROPRIETARY_MODULE"},{1,"FORCED_MODULE"},{2,"UNSAFE_SMP"},{3,"FORCED_RMMOD"},{4,"MACHINE_CHECK"},{5,"BAD_PAGE"},{6,"USER"},{7,"DIE"},{8,"OVERRIDDEN_ACPI_TABLE"},{9,"WARN"},{10,"OOPS"},{11,"HARDWARE_INCOMPAT"},{12,"SOFTWARE_INCOMPAT"},{13,"FIRMWARE_WORKAROUND"},{14,"CRAP"},{15,"FIRMWARE_BUG"},{16,"RANDSTRUCT"},{17,"PANIC"}}; for(auto& b: bits){ if(val & (1UL<<b.bit)){ if(!flags.empty()) flags+=","; flags+=b.name; } } if(!flags.empty()) f.metadata["taint_flags"] = flags; }} }
    }
    // /proc/kallsyms visibility
    {
        std::ifstream ks("/proc/kallsyms"); if(ks){ size_t lines=0; size_t limited=0; std::string kl; while(std::getline(ks,kl)) { if(++lines>5000) break; if(kl.find(' ')!=std::string::npos){ auto pos=kl.find(' '); if(pos>0 && kl[0]=='0' && kl[1]=='0') ++limited; } }
            f.metadata["kallsyms_readable"] = "yes"; f.metadata["kallsyms_sampled"] = std::to_string(lines); if(lines < 100) f.metadata["kallsyms_low"] = "true"; if(limited>0 && limited==lines) f.metadata["kallsyms_all_zero"]="true"; }
        else { f.metadata["kallsyms_readable"] = "no"; }
    }
    report.add_finding(this->name(), std::move(f));
} // end scan

} // end scan

} // namespace sys_scan
