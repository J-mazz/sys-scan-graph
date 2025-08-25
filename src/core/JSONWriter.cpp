#include "JSONWriter.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <map>
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <fstream>
#include "Config.h"
#include "Severity.h"
#include <ctime>
#include <vector>

namespace sys_scan {
namespace {
    struct HostMeta {
        std::string hostname;
        std::string kernel;
        std::string arch;
        std::string os_pretty;
        std::string os_id;
        std::string os_version;
        std::string user;
        int uid=0,euid=0,gid=0,egid=0;
        std::string cmdline;
    };

    struct CanonVal {
        enum Type { T_OBJ, T_ARR, T_STR, T_NUM } type = T_OBJ;
        std::map<std::string, CanonVal> obj;
        std::vector<CanonVal> arr;
        std::string str; // for string & number token text
        CanonVal() = default;
        explicit CanonVal(Type t): type(t) {}
    };

    // Forward decls
    static void canon_emit(const CanonVal& v, std::ostream& os);

    std::string escape(const std::string& s){ std::string o; o.reserve(s.size()+8); for(char c: s){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c < 0x20){ std::ostringstream tmp; tmp<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)(unsigned char)c; o+=tmp.str(); } else o+=c; } } return o; }

    static std::string time_to_iso(std::chrono::system_clock::time_point tp){
        if(!tp.time_since_epoch().count()) return ""; auto t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm_buf{}; gmtime_r(&t, &tm_buf); char buf[32]; std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf); return buf; }

    static HostMeta collect_host_meta(){ HostMeta h; struct utsname u{}; if(uname(&u)==0){ h.kernel=u.release; h.arch=u.machine; h.hostname=u.nodename; }
        // OS release
        std::ifstream f("/etc/os-release"); std::string line; while(std::getline(f,line)){ if(line.rfind("PRETTY_NAME=",0)==0){ std::string v=line.substr(12); if(v.size()&&v.front()=='"'&&v.back()=='"') v=v.substr(1,v.size()-2); h.os_pretty=v; } else if(line.rfind("ID=",0)==0){ std::string v=line.substr(3); if(v.size()&&v.front()=='"'&&v.back()=='"') v=v.substr(1,v.size()-2); h.os_id=v; } else if(line.rfind("VERSION_ID=",0)==0){ std::string v=line.substr(11); if(v.size()&&v.front()=='"'&&v.back()=='"') v=v.substr(1,v.size()-2); h.os_version=v; } }
        h.uid=getuid(); h.euid=geteuid(); h.gid=getgid(); h.egid=getegid(); if(auto* pw=getpwuid(h.uid); pw) h.user=pw->pw_name;
        // cmdline
        std::ifstream cf("/proc/self/cmdline", std::ios::binary); std::string raw((std::istreambuf_iterator<char>(cf)), {}); for(char c: raw){ if(c=='\0') h.cmdline.push_back(' '); else h.cmdline.push_back(c);} if(!h.cmdline.empty() && h.cmdline.front()==' ') h.cmdline.erase(h.cmdline.begin()); return h; }

    static void apply_meta_overrides(HostMeta& h){
        auto get = [](const char* k)->const char*{ const char* v=getenv(k); return (v && *v)? v: nullptr; };
        if(auto v=get("SYS_SCAN_META_HOSTNAME")) h.hostname=v;
        if(auto v=get("SYS_SCAN_META_KERNEL")) h.kernel=v;
        if(auto v=get("SYS_SCAN_META_ARCH")) h.arch=v;
        if(auto v=get("SYS_SCAN_META_OS_PRETTY")) h.os_pretty=v;
        if(auto v=get("SYS_SCAN_META_OS_ID")) h.os_id=v;
        if(auto v=get("SYS_SCAN_META_OS_VERSION")) h.os_version=v;
        if(auto v=get("SYS_SCAN_META_USER")) h.user=v;
        if(auto v=get("SYS_SCAN_META_CMDLINE")) h.cmdline=v;
        // numeric ids not overridden for now (could be added if needed)
    }

    static void canon_emit(const CanonVal& v, std::ostream& os){ switch(v.type){ case CanonVal::T_STR: os<<'"'<<escape(v.str)<<'"'; break; case CanonVal::T_NUM: os<<v.str; break; case CanonVal::T_ARR: { os<<'['; bool first=true; for(const auto& e: v.arr){ if(!first) os<<','; first=false; canon_emit(e,os);} os<<']'; } break; case CanonVal::T_OBJ: { os<<'{'; bool first=true; for(const auto& kv: v.obj){ if(!first) os<<','; first=false; os<<'"'<<escape(kv.first)<<'"'<<':'; canon_emit(kv.second, os);} os<<'}'; } break; } }
static CanonVal build_canonical(const Report& report, long long total_risk, size_t finding_total, size_t scanners_with_findings, long long duration_ms, const std::string& slowest_name, long long slowest_ms, std::chrono::system_clock::time_point earliest, std::chrono::system_clock::time_point latest, const std::map<std::string,size_t>& severity_counts, const HostMeta& host){ bool zero_time=!!std::getenv("SYS_SCAN_CANON_TIME_ZERO"); if(zero_time){ earliest={}; latest={}; duration_ms=0; } CanonVal root{CanonVal::T_OBJ}; CanonVal meta{CanonVal::T_OBJ}; meta.obj["$schema"].type=CanonVal::T_STR; meta.obj["$schema"].str="https://github.com/J-mazz/sys-scan/schema/v2.json"; auto put_str=[&](CanonVal& o,const std::string& k,const std::string& v){ o.obj[k].type=CanonVal::T_STR; o.obj[k].str=v; }; auto put_num=[&](CanonVal& o,const std::string& k,long long v){ o.obj[k].type=CanonVal::T_NUM; o.obj[k].str=std::to_string(v); }; put_str(meta,"arch",host.arch); if(!config().no_cmdline_meta && !host.cmdline.empty()) put_str(meta,"cmdline",host.cmdline); if(!config().no_user_meta){ put_str(meta,"egid",std::to_string(host.egid)); put_str(meta,"euid",std::to_string(host.euid)); put_str(meta,"gid",std::to_string(host.gid)); put_str(meta,"uid",std::to_string(host.uid)); put_str(meta,"user",host.user);} if(!config().no_hostname_meta) put_str(meta,"hostname",host.hostname); put_str(meta,"json_schema_version","2"); put_str(meta,"kernel",host.kernel); put_str(meta,"os_id",host.os_id); if(!host.os_pretty.empty()) put_str(meta,"os_pretty",host.os_pretty); if(!host.os_version.empty()) put_str(meta,"os_version",host.os_version); put_str(meta,"tool_version","0.1.0"); root.obj["meta"]=std::move(meta); CanonVal summary{CanonVal::T_OBJ}; put_num(summary,"duration_ms",duration_ms); double fps=(duration_ms>0)?(finding_total*1000.0/duration_ms):0.0; { std::ostringstream tmp; tmp.setf(std::ios::fixed); tmp<<std::setprecision(2)<<fps; std::string s=tmp.str(); while(s.size()>1 && s.back()=='0') s.pop_back(); if(!s.empty()&&s.back()=='.') s.push_back('0'); summary.obj["findings_per_second"].type=CanonVal::T_NUM; summary.obj["findings_per_second"].str=s; } put_num(summary,"finding_count_total",finding_total); put_str(summary,"finished_at", time_to_iso(latest)); put_str(summary,"scanner_count", std::to_string(report.results().size())); put_num(summary,"scanners_with_findings", scanners_with_findings); CanonVal sev_obj{CanonVal::T_OBJ}; for(const auto& kv: severity_counts){ put_num(sev_obj, kv.first, kv.second);} summary.obj["severity_counts"]=std::move(sev_obj); CanonVal slow{CanonVal::T_OBJ}; put_str(slow,"elapsed_ms", std::to_string(slowest_ms)); put_str(slow,"name", slowest_name); summary.obj["slowest_scanner"]=std::move(slow); put_str(summary,"started_at", time_to_iso(earliest)); root.obj["summary"]=std::move(summary); CanonVal res_arr{CanonVal::T_ARR}; for(const auto& r: report.results()){ CanonVal rs{CanonVal::T_OBJ}; put_str(rs,"scanner", r.scanner_name); put_str(rs,"start_time", zero_time?"":time_to_iso(r.start_time)); put_str(rs,"end_time", zero_time?"":time_to_iso(r.end_time)); long long elapsed_ms=0; if(!zero_time && r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && r.end_time>=r.start_time) elapsed_ms=std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time-r.start_time).count(); put_num(rs,"elapsed_ms", elapsed_ms); std::vector<const Finding*> filtered; for(const auto& f: r.findings){ if(severity_rank(config().min_severity)<=severity_rank_enum(f.severity)) filtered.push_back(&f);} put_num(rs,"finding_count", filtered.size()); CanonVal findings_arr{CanonVal::T_ARR}; for(const auto* fp: filtered){ const auto& f=*fp; CanonVal fv{CanonVal::T_OBJ}; put_str(fv,"description", f.description); put_str(fv,"id", f.id); put_str(fv,"risk_score", std::to_string(f.risk_score)); put_str(fv,"severity", severity_to_string(f.severity)); put_str(fv,"title", f.title); CanonVal meta_md{CanonVal::T_OBJ}; std::vector<std::pair<std::string,std::string>> meta_sorted(f.metadata.begin(), f.metadata.end()); std::sort(meta_sorted.begin(), meta_sorted.end(),[](auto&a,auto&b){ return a.first<b.first;}); for(const auto& kv: meta_sorted){ put_str(meta_md, kv.first, kv.second);} fv.obj["metadata"]=std::move(meta_md); findings_arr.arr.push_back(std::move(fv)); } rs.obj["findings"]=std::move(findings_arr); res_arr.arr.push_back(std::move(rs)); } root.obj["results"]=std::move(res_arr); CanonVal warns{CanonVal::T_ARR}; for(const auto& w: report.warnings()){ CanonVal wv{CanonVal::T_OBJ}; put_str(wv,"message", w.second); put_str(wv,"scanner", w.first); warns.arr.push_back(std::move(wv)); } root.obj["collection_warnings"]=std::move(warns); CanonVal errs{CanonVal::T_ARR}; for(const auto& e: report.errors()){ CanonVal ev{CanonVal::T_OBJ}; put_str(ev,"message", e.second); put_str(ev,"scanner", e.first); errs.arr.push_back(std::move(ev)); } root.obj["scanner_errors"]=std::move(errs); CanonVal se{CanonVal::T_OBJ}; put_num(se,"total_risk_score", total_risk); root.obj["summary_extension"]=std::move(se); return root; }
} // end anonymous namespace

// Move write implementation outside anonymous namespace to correctly match class scope
std::string JSONWriter::write(const Report& report) const {
    // Summary metrics
    const auto& results = report.results(); size_t finding_total=0; std::map<std::string,size_t> severity_counts; std::chrono::system_clock::time_point earliest{}; std::chrono::system_clock::time_point latest{}; size_t scanners_with_findings=0; long long slowest_ms=0; std::string slowest_name; long long total_risk=0; for(const auto& r: results){ finding_total+=r.findings.size(); if(!r.findings.empty()) scanners_with_findings++; if(earliest.time_since_epoch().count()==0 || (r.start_time.time_since_epoch().count() && r.start_time<earliest)) earliest=r.start_time; if(r.end_time.time_since_epoch().count() && (latest.time_since_epoch().count()==0 || r.end_time>latest)) latest=r.end_time; auto elapsed=(r.end_time.time_since_epoch().count()&&r.start_time.time_since_epoch().count())? std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time-r.start_time).count():0; if(elapsed>slowest_ms){ slowest_ms=elapsed; slowest_name=r.scanner_name;} for(const auto& f: r.findings){ severity_counts[severity_to_string(f.severity)]++; total_risk+=f.risk_score; } } long long duration_ms=0; if(earliest.time_since_epoch().count() && latest.time_since_epoch().count() && latest>=earliest) duration_ms=std::chrono::duration_cast<std::chrono::milliseconds>(latest-earliest).count(); auto host=collect_host_meta(); apply_meta_overrides(host); CanonVal root = build_canonical(report,total_risk,finding_total,scanners_with_findings,duration_ms,slowest_name,slowest_ms,earliest,latest,severity_counts,host);
    if(config().sarif){ std::ostringstream s; s << "{\"version\":\"2.1.0\",\"$schema\":\"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\"runs\":[{" << "\"tool\":{\"driver\":{\"name\":\"sys-scan\",\"informationUri\":\"https://github.com/J-mazz/sys-scan\"}}," << "\"results\":["; bool first=true; int minRank=severity_rank(config().min_severity); for(const auto& r: results){ for(const auto& f: r.findings){ if(severity_rank_enum(f.severity)<minRank) continue; if(!first) s<<","; first=false; s << "{\"ruleId\":\""<<escape(f.id)<<"\",\"level\":\""<<escape(severity_to_string(f.severity))<<"\",\"message\":{\"text\":\""<<escape(f.title)<<" - "<<escape(f.description)<<"\"},\"properties\":{\"riskScore\":"<<f.risk_score; auto it=f.metadata.find("mitre_techniques"); if(it!=f.metadata.end()){ s << ",\"mitreTechniqueIds\":["; std::string v=it->second; size_t pos=0; bool firstId=true; while(pos<v.size()){ size_t comma=v.find(',',pos); std::string tok=v.substr(pos, comma==std::string::npos? std::string::npos: comma-pos); if(!tok.empty()){ if(!firstId) s<<","; firstId=false; s<<"\""<<escape(tok)<<"\"";} if(comma==std::string::npos) break; pos=comma+1;} s<<"]"; } s << "}}"; } } s << "]}] }"; return s.str(); }
    if(config().ndjson){ std::ostringstream nd; nd << '{' << "\"type\":\"meta\",\"tool_version\":\"0.1.0\",\"schema\":\"2\""; if(!config().no_hostname_meta) nd << ",\"hostname\":\""<<escape(host.hostname)<<"\""; if(!config().no_user_meta){ nd << ",\"uid\":"<<host.uid<<",\"euid\":"<<host.euid<<",\"gid\":"<<host.gid<<",\"egid\":"<<host.egid<<",\"user\":\""<<escape(host.user)<<"\""; } if(!config().no_cmdline_meta && !host.cmdline.empty()) nd << ",\"cmdline\":\""<<escape(host.cmdline)<<"\""; nd << '}'; nd << "\n"; nd << '{' << "\"type\":\"summary_extension\",\"total_risk_score\":"<< total_risk <<'}' <<"\n"; int minRank=severity_rank(config().min_severity); for(const auto& r: results){ for(const auto& f: r.findings){ if(severity_rank_enum(f.severity)<minRank) continue; nd << '{' << "\"type\":\"finding\",\"scanner\":\""<<escape(r.scanner_name)<<"\",\"id\":\""<<escape(f.id)<<"\",\"severity\":\""<<escape(severity_to_string(f.severity))<<"\",\"risk_score\":"<<f.risk_score; auto it=f.metadata.find("mitre_techniques"); if(it!=f.metadata.end()) nd << ",\"mitre_techniques\":\""<<escape(it->second)<<"\""; nd << '}'; nd << "\n"; } } return nd.str(); }
    std::ostringstream os; canon_emit(root, os); std::string compact=os.str(); auto prettyfn=[&](const std::string& min){ std::string out; out.reserve(min.size()*2); int depth=0; bool in_string=false; bool esc=false; auto indent=[&](int d){ for(int i=0;i<d;i++) out.append("  "); }; for(size_t i=0;i<min.size();++i){ char c=min[i]; out.push_back(c); if(esc){ esc=false; continue; } if(c=='\\'){ esc=true; continue; } if(c=='"'){ in_string=!in_string; continue; } if(in_string) continue; switch(c){ case '{': case '[': out.push_back('\n'); depth++; indent(depth); break; case '}': case ']': out.push_back('\n'); depth--; if(depth<0) depth=0; indent(depth); break; case ',': out.push_back('\n'); indent(depth); break; case ':': out.push_back(' '); break; default: break; } } out.push_back('\n'); return out; };
    if(config().pretty && !config().compact) return prettyfn(compact);
    return compact;
}

} // namespace sys_scan
