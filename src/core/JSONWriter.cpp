#include "JSONWriter.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <fstream>
#include "Config.h"

namespace sys_scan {
namespace {
    std::string escape(const std::string& s){
        std::string o; o.reserve(s.size()+8);
        for(char c: s){
            switch(c){
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if(static_cast<unsigned char>(c) < 0x20){
                        std::ostringstream tmp; tmp << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c; o += tmp.str();
                    } else o += c;
            }
        }
        return o;
    }
    std::string time_to_iso(const std::chrono::system_clock::time_point& tp){
        if(tp.time_since_epoch().count()==0) return "";
        auto tt = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{}; gmtime_r(&tt, &tm);
        char buf[64]; strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }
    struct HostMeta {
        std::string hostname;
        std::string kernel;
        std::string arch;
        std::string os_id;
        std::string os_version;
        std::string os_pretty;
        std::string user;
        int uid=-1; int euid=-1; int gid=-1; int egid=-1; 
        std::string cmdline;
    };
    HostMeta collect_host_meta(){
        HostMeta hm;
        char buf[256]; if(gethostname(buf,sizeof(buf))==0){ hm.hostname = buf; }
        struct utsname un{}; if(uname(&un)==0){ hm.kernel = un.release; hm.arch = un.machine; }
        // /etc/os-release parsing
        if(auto f = std::ifstream("/etc/os-release")){
            std::string line; while(std::getline(f,line)){
                auto pos = line.find('='); if(pos==std::string::npos) continue; std::string key=line.substr(0,pos); std::string val=line.substr(pos+1);
                if(val.size()>=2 && ((val.front()=='"' && val.back()=='"')||(val.front()=='\'' && val.back()=='\''))) val = val.substr(1,val.size()-2);
                if(key=="ID") hm.os_id = val; else if(key=="VERSION_ID") hm.os_version = val; else if(key=="PRETTY_NAME") hm.os_pretty = val; }
        }
        hm.uid = getuid(); hm.euid = geteuid(); hm.gid = getgid(); hm.egid = getegid();
        if(struct passwd* pw = getpwuid(hm.uid)){ hm.user = pw->pw_name?pw->pw_name:""; }
        // command line
        if(auto f = std::ifstream("/proc/self/cmdline", std::ios::binary)){
            std::string data; std::getline(f,data,'\0'); // first arg
            // For remaining, read rest into vector
            std::string rest; std::ostringstream all; if(!data.empty()) all<<data; char c; bool newArg=true; while(f.get(c)) { if(c=='\0'){ all<<' '; newArg=true; } else { all<<c; newArg=false; } }
            hm.cmdline = all.str();
        }
        return hm;
    }
}

// For tests seeking deterministic canonical output, environment variables can override host meta fields.
static void apply_meta_overrides(HostMeta& hm){
    auto get = [](const char* k)->const char*{ const char* v=getenv(k); return (v&&*v)?v:nullptr; };
    if(auto v=get("SYS_SCAN_META_HOSTNAME")) hm.hostname=v;
    if(auto v=get("SYS_SCAN_META_KERNEL")) hm.kernel=v;
    if(auto v=get("SYS_SCAN_META_ARCH")) hm.arch=v;
    if(auto v=get("SYS_SCAN_META_OS_ID")) hm.os_id=v;
    if(auto v=get("SYS_SCAN_META_OS_VERSION")) hm.os_version=v;
    if(auto v=get("SYS_SCAN_META_OS_PRETTY")) hm.os_pretty=v;
    if(auto v=get("SYS_SCAN_META_USER")) hm.user=v;
    if(auto v=get("SYS_SCAN_META_CMDLINE")) hm.cmdline=v;
}

// RFC 8785 JSON Canonicalization (JCS) subset implementation:
// - Objects: lexicographically sorted by UTF-8 code units of property names
// - Arrays: order preserved
// - Strings: escaped per JSON spec (we reuse escape())
// - Numbers: shortest round-trip form (we format integers directly; no non-integer numbers currently emitted)
// Current data model only emits integers and strings, so floating normalization not required yet.
static std::string canonical_escape(const std::string& s){ return escape(s); }

struct CanonVal {
    enum Type { T_OBJ, T_ARR, T_STR, T_NUM, T_BOOL, T_NULL } type;
    std::map<std::string, CanonVal> obj; // sorted automatically
    std::vector<CanonVal> arr;
    std::string str; // also used for numbers canonical text
};

static void canon_emit(const CanonVal& v, std::ostringstream& os){
    switch(v.type){
        case CanonVal::T_NULL: os << "null"; return;
        case CanonVal::T_BOOL: os << v.str; return; // "true" or "false"
        case CanonVal::T_NUM: os << v.str; return;
        case CanonVal::T_STR: os << '"' << canonical_escape(v.str) << '"'; return;
        case CanonVal::T_ARR: {
            os << '['; for(size_t i=0;i<v.arr.size();++i){ if(i) os<<','; canon_emit(v.arr[i], os);} os << ']'; return; }
        case CanonVal::T_OBJ: {
            os << '{'; bool first=true; for(const auto& kv : v.obj){ if(!first) os<<','; first=false; os<<'"'<<canonical_escape(kv.first)<<'"'<<':'; canon_emit(kv.second, os);} os << '}'; return; }
    }
}

// Helper to build canonical value tree for our existing structured output so we avoid fragile string post-processing.
// Only used when config().canonical is true and not sarif/ndjson.
static CanonVal build_canonical(const Report& report, long long total_risk, size_t finding_total, size_t scanners_with_findings,
                                long long duration_ms, const std::string& slowest_name, long long slowest_ms,
                                std::chrono::system_clock::time_point earliest,
                                std::chrono::system_clock::time_point latest,
                                const std::map<std::string,size_t>& severity_counts, const HostMeta& host){
    bool zero_time = !!std::getenv("SYS_SCAN_CANON_TIME_ZERO");
    if(zero_time){ earliest = {}; latest = {}; duration_ms = 0; }
    CanonVal root{CanonVal::T_OBJ};
    // meta
    CanonVal meta{CanonVal::T_OBJ};
    meta.obj["$schema"].type=CanonVal::T_STR; meta.obj["$schema"].str="https://github.com/J-mazz/sys-scan/schema/v2.json";
    auto put_str=[&](CanonVal& o, const std::string& k, const std::string& v){ o.obj[k].type=CanonVal::T_STR; o.obj[k].str=v; };
    auto put_num=[&](CanonVal& o, const std::string& k, long long v){ o.obj[k].type=CanonVal::T_NUM; o.obj[k].str=std::to_string(v); };
    put_str(meta, "arch", host.arch); put_str(meta, "cmdline", host.cmdline); put_str(meta, "egid", std::to_string(host.egid)); put_str(meta, "euid", std::to_string(host.euid));
    put_str(meta, "gid", std::to_string(host.gid)); put_str(meta, "hostname", host.hostname); put_str(meta, "json_schema_version", "2");
    put_str(meta, "kernel", host.kernel); put_str(meta, "os_id", host.os_id); put_str(meta, "os_pretty", host.os_pretty); put_str(meta, "os_version", host.os_version);
    put_str(meta, "tool_version", "0.1.0"); put_str(meta, "uid", std::to_string(host.uid)); put_str(meta, "user", host.user);
    root.obj["meta"] = std::move(meta);

    // summary
    CanonVal summary{CanonVal::T_OBJ};
    put_num(summary, "duration_ms", duration_ms);
    // findings_per_second: compute with double but convert to string shortest (strip trailing zeros)
    double fps = (duration_ms>0)? (finding_total * 1000.0 / duration_ms) : 0.0;
    {
        std::ostringstream tmp; tmp.setf(std::ios::fixed); tmp<<std::setprecision(2)<<fps; std::string s=tmp.str();
        while(s.size()>1 && s.back()=='0') s.pop_back(); if(!s.empty() && s.back()=='.') s.push_back('0');
        summary.obj["findings_per_second"].type=CanonVal::T_NUM; summary.obj["findings_per_second"].str=s; }
    put_num(summary, "finding_count_total", finding_total);
    put_str(summary, "finished_at", time_to_iso(latest));
    put_str(summary, "scanner_count", std::to_string(report.results().size()));
    put_num(summary, "scanners_with_findings", scanners_with_findings);
    // severity_counts object
    CanonVal sev_obj{CanonVal::T_OBJ}; for(const auto& kv : severity_counts){ put_num(sev_obj, kv.first, kv.second); }
    summary.obj["severity_counts"] = std::move(sev_obj);
    CanonVal slow{CanonVal::T_OBJ}; put_str(slow, "elapsed_ms", std::to_string(slowest_ms)); put_str(slow, "name", slowest_name); summary.obj["slowest_scanner"]=std::move(slow);
    put_str(summary, "started_at", time_to_iso(earliest));
    root.obj["summary"] = std::move(summary);

    // results array
    CanonVal res_arr{CanonVal::T_ARR};
    for(const auto& r : report.results()){
        CanonVal rs{CanonVal::T_OBJ}; put_str(rs, "scanner", r.scanner_name); put_str(rs, "start_time", zero_time? std::string("") : time_to_iso(r.start_time)); put_str(rs, "end_time", zero_time? std::string("") : time_to_iso(r.end_time));
        long long elapsed_ms = 0; if(!zero_time && r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && r.end_time>=r.start_time) elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time-r.start_time).count();
        put_num(rs, "elapsed_ms", elapsed_ms);
        std::vector<const Finding*> filtered; for(const auto& f : r.findings){ if(severity_rank(config().min_severity)<= severity_rank_enum(f.severity)) filtered.push_back(&f); }
        put_num(rs, "finding_count", filtered.size());
        CanonVal findings_arr{CanonVal::T_ARR};
        for(const auto* fp : filtered){ const auto& f = *fp; CanonVal fv{CanonVal::T_OBJ}; put_str(fv, "description", f.description); put_str(fv, "id", f.id); put_str(fv, "risk_score", std::to_string(f.risk_score)); put_str(fv, "severity", severity_to_string(f.severity)); put_str(fv, "title", f.title);
            // metadata object sorted
            CanonVal meta_md{CanonVal::T_OBJ}; std::vector<std::pair<std::string,std::string>> meta_sorted(f.metadata.begin(), f.metadata.end()); std::sort(meta_sorted.begin(), meta_sorted.end(), [](auto& a, auto& b){ return a.first < b.first; }); for(const auto& kv : meta_sorted){ put_str(meta_md, kv.first, kv.second); }
            fv.obj["metadata"] = std::move(meta_md); findings_arr.arr.push_back(std::move(fv)); }
        rs.obj["findings"] = std::move(findings_arr); res_arr.arr.push_back(std::move(rs));
    }
    root.obj["results"] = std::move(res_arr);
    // collection_warnings & scanner_errors arrays
    CanonVal warns{CanonVal::T_ARR}; for(const auto& w : report.warnings()){ CanonVal wv{CanonVal::T_OBJ}; put_str(wv, "message", w.second); put_str(wv, "scanner", w.first); warns.arr.push_back(std::move(wv)); }
    root.obj["collection_warnings"] = std::move(warns);
    CanonVal errs{CanonVal::T_ARR}; for(const auto& e : report.errors()){ CanonVal ev{CanonVal::T_OBJ}; put_str(ev, "message", e.second); put_str(ev, "scanner", e.first); errs.arr.push_back(std::move(ev)); }
    root.obj["scanner_errors"] = std::move(errs);
    CanonVal se{CanonVal::T_OBJ}; put_num(se, "total_risk_score", total_risk); root.obj["summary_extension"] = std::move(se);
    return root;
}

static void append_canonical_object(std::ostringstream& os, const std::vector<std::pair<std::string,std::string>>& kvs){
    os << '{';
    for(size_t i=0;i<kvs.size();++i){ if(i) os<<','; os << '"'<<kvs[i].first<<'"'<<':'<<kvs[i].second; }
    os << '}';
}

std::string JSONWriter::write(const Report& report) const {
    const auto& results = report.results();
    // Compute summary
    size_t finding_total = 0; 
    std::map<std::string, size_t> severity_counts;
    std::chrono::system_clock::time_point earliest{}; 
    std::chrono::system_clock::time_point latest{};
    size_t scanners_with_findings = 0;
    long long slowest_ms = 0; std::string slowest_name;
    int min_rank = severity_rank(config().min_severity);
    long long total_risk = 0;
    for(const auto& r : results){
        finding_total += r.findings.size();
        if(!r.findings.empty()) scanners_with_findings++;
        if(earliest.time_since_epoch().count()==0 || (r.start_time.time_since_epoch().count() && r.start_time < earliest)) earliest = r.start_time;
        if(r.end_time.time_since_epoch().count() && (latest.time_since_epoch().count()==0 || r.end_time > latest)) latest = r.end_time;
        auto elapsed = (r.end_time.time_since_epoch().count() && r.start_time.time_since_epoch().count()) ? std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time-r.start_time).count() : 0;
        if(elapsed > slowest_ms) { slowest_ms = elapsed; slowest_name = r.scanner_name; }
        for(const auto& f : r.findings){
            severity_counts[severity_to_string(f.severity)]++;
            total_risk += f.risk_score;
        }
    }
    long long duration_ms = 0;
    if(earliest.time_since_epoch().count() && latest.time_since_epoch().count() && latest>=earliest) {
        duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(latest-earliest).count();
    }
    double findings_per_second = (duration_ms>0) ? (finding_total * 1000.0 / duration_ms) : 0.0;

    auto host = collect_host_meta();
    apply_meta_overrides(host);
    std::ostringstream os;
    os << "{\n  \"meta\": {";
    os << "\n    \"hostname\": \""<<escape(host.hostname)<<"\",";
    os << "\n    \"kernel\": \""<<escape(host.kernel)<<"\",";
    os << "\n    \"arch\": \""<<escape(host.arch)<<"\",";
    if(!host.os_pretty.empty()) os << "\n    \"os_pretty\": \""<<escape(host.os_pretty)<<"\",";
    if(!host.os_id.empty()) os << "\n    \"os_id\": \""<<escape(host.os_id)<<"\",";
    if(!host.os_version.empty()) os << "\n    \"os_version\": \""<<escape(host.os_version)<<"\",";
    os << "\n    \"user\": \""<<escape(host.user)<<"\",";
    os << "\n    \"uid\": "<<host.uid<<",";
    os << "\n    \"euid\": "<<host.euid<<",";
    os << "\n    \"gid\": "<<host.gid<<",";
    os << "\n    \"egid\": "<<host.egid<<",";
    if(!host.cmdline.empty()) os << "\n    \"cmdline\": \""<<escape(host.cmdline)<<"\",";
    os << "\n    \"tool_version\": \"0.1.0\","; // static for now
    os << "\n    \"json_schema_version\": \"2\","; // incremented due to structural changes (severity enum, risk, warnings)
    os << "\n    \"$schema\": \"https://github.com/J-mazz/sys-scan/schema/v2.json\"";
    os << "\n  },";
    os << "\n  \"summary\": {";
    os << "\n    \"scanner_count\": " << results.size() << ",";
    os << "\n    \"finding_count_total\": " << finding_total << ",";
    os << "\n    \"started_at\": \"" << time_to_iso(earliest) << "\",";
    os << "\n    \"finished_at\": \"" << time_to_iso(latest) << "\",";
    os << "\n    \"duration_ms\": " << duration_ms << ",";
    os << std::fixed << std::setprecision(2);
    os << "\n    \"findings_per_second\": " << findings_per_second << ",";
    os << "\n    \"scanners_with_findings\": " << scanners_with_findings << ",";
    os << "\n    \"slowest_scanner\": { \"name\": \"" << escape(slowest_name) << "\", \"elapsed_ms\": " << slowest_ms << " },";
    os << "\n    \"severity_counts\": {";
    size_t idx=0; for(auto& kv : severity_counts){ if(idx++) os << ","; os << "\n      \""<<escape(kv.first)<<"\": "<<kv.second; }
    if(!severity_counts.empty()) os << "\n    ";
    os << "}"; // end severity_counts
    os << "\n  },"; // end summary
    os << "\n  \"results\": [";
    for(size_t i=0;i<results.size();++i){ const auto& r = results[i];
        if(i) os << ",";
        os << "\n    {";
        os << "\n      \"scanner\": \"" << escape(r.scanner_name) << "\",";
        os << "\n      \"start_time\": \"" << time_to_iso(r.start_time) << "\",";
        os << "\n      \"end_time\": \"" << time_to_iso(r.end_time) << "\",";
        long long elapsed_ms = 0; if(r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && r.end_time>=r.start_time) elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time-r.start_time).count();
        os << "\n      \"elapsed_ms\": " << elapsed_ms << ",";
        // Filter findings
        std::vector<const Finding*> filtered;
    for(const auto& f : r.findings){ if(severity_rank(config().min_severity)<= severity_rank_enum(f.severity)) filtered.push_back(&f); }
        os << "\n      \"finding_count\": " << filtered.size() << ",";
        os << "\n      \"findings\": [";
        for(size_t j=0;j<filtered.size();++j){
            const auto& f = *filtered[j];
            if(j) os << ",";
            os << "\n        {";
            os << "\n          \"id\": \"" << escape(f.id) << "\",";
            os << "\n          \"title\": \"" << escape(f.title) << "\",";
            os << "\n          \"severity\": \"" << escape(severity_to_string(f.severity)) << "\",";
            os << "\n          \"risk_score\": " << f.risk_score << ",";
            os << "\n          \"description\": \"" << escape(f.description) << "\",";
            os << "\n          \"metadata\": {";
            // deterministic ordering of metadata keys
            std::vector<std::pair<std::string,std::string>> meta_sorted(f.metadata.begin(), f.metadata.end());
            std::sort(meta_sorted.begin(), meta_sorted.end(), [](auto& a, auto& b){ return a.first < b.first; });
            size_t k=0; for(auto& kv: meta_sorted){ if(k++) os << ","; os << "\n            \"" << escape(kv.first) << "\": \"" << escape(kv.second) << "\""; }
            if(!f.metadata.empty()) os << "\n          ";
            os << "}\n        }";
        }
        if(!r.findings.empty()) os << "\n      ";
        os << "]\n    }";
    }
    if(!results.empty()) os << "\n  ";
    os << "]";
    // warnings & errors channels
    const auto& warns = report.warnings();
    const auto& errs = report.errors();
    os << ",\n  \"collection_warnings\": [";
    for(size_t i=0;i<warns.size();++i){ if(i) os << ","; os << "{\"scanner\":\""<<escape(warns[i].first)<<"\",\"message\":\""<<escape(warns[i].second)<<"\"}"; }
    os << "],";
    os << "\n  \"scanner_errors\": [";
    for(size_t i=0;i<errs.size();++i){ if(i) os << ","; os << "{\"scanner\":\""<<escape(errs[i].first)<<"\",\"message\":\""<<escape(errs[i].second)<<"\"}"; }
    os << "],";
    os << "\n  \"summary_extension\": { \"total_risk_score\": "<< total_risk <<" }\n}"; // close root
    os << "\n";
    // Always start from a minified baseline (deterministic), then pretty-format if requested.
    auto minify = [](const std::string& raw){
        std::string out; out.reserve(raw.size()); bool in_string=false; for(size_t i=0;i<raw.size();++i){ char c=raw[i]; if(c=='"' && (i==0 || raw[i-1] != '\\')) in_string=!in_string; if(!in_string && (c=='\n'||c=='\r'||c=='\t')) continue; if(!in_string && c==' '){ // skip spaces around structural
                size_t j=i; while(j<raw.size() && raw[j]==' ') ++j; if(j<raw.size() && (raw[j]==','||raw[j]=='{'||raw[j]=='}'||raw[j]=='['||raw[j]==']'||raw[j]==':')) { i=j-1; continue; }
        }
        out.push_back(c); }
        return out;
    };
    auto pretty = [](const std::string& min){
        std::string out; out.reserve(min.size()+min.size()/4);
        int depth = 0; bool in_string=false; bool escape=false;
        auto indent = [&](int d){ for(int i=0;i<d;i++) out.append("  "); };
        for(size_t i=0;i<min.size();++i){ char c=min[i]; out.push_back(c); if(escape){ escape=false; continue; }
            if(c=='\\') { escape=true; continue; }
            if(c=='"') in_string=!in_string; if(in_string) continue; // only format outside strings
            switch(c){
                case '{': case '[': out.push_back('\n'); depth++; indent(depth); break;
                case '}': case ']': {
                    // remove newline+indent we just added if previous char was one of these cases? We adjust by rewriting.
                } break;
                case ',': out.push_back('\n'); indent(depth); break;
                case ':': out.push_back(' '); break;
            }
            if(c=='}' || c==']'){
                // We placed it already; need to reposition indentation if previous char before '}' wasn't newline
                // Simplify: backtrack any trailing whitespace/newlines inserted previously (rare due to logic) not needed.
            }
        }
        // Second pass to fix situations of '}' or ']' followed immediately by newline+indent due to depth increment earlier.
        // Simpler: re-run with smarter logic: rewrite above to delay depth change until after newline for closing braces.
        // We'll implement a cleaner formatter below using a new loop.
        // (We keep initial attempt for clarity, but replace with final output constructed next.)
        // Final cleaner pass:
        std::string final; final.reserve(out.size()); depth=0; in_string=false; escape=false;
        for(size_t i=0;i<min.size();++i){ char c=min[i]; if(escape){ final.push_back(c); escape=false; continue; }
            if(c=='\\'){ final.push_back(c); escape=true; continue; }
            if(c=='"'){ final.push_back(c); in_string=!in_string; continue; }
            if(in_string){ final.push_back(c); continue; }
            if(c=='{' || c=='['){ final.push_back(c); final.push_back('\n'); depth++; indent(depth); continue; }
            if(c=='}' || c==']'){ final.push_back('\n'); if(depth>0) depth--; indent(depth); final.push_back(c); continue; }
            if(c==','){ final.push_back(c); final.push_back('\n'); indent(depth); continue; }
            if(c==':'){ final.push_back(c); final.push_back(' '); continue; }
            if(c==' '||c=='\n' || c=='\r' || c=='\t') continue; // skip redundant
            final.push_back(c);
        }
        final.push_back('\n');
        return final;
    };
    std::string raw = os.str();
    if(config().canonical && !config().sarif && !config().ndjson){
    CanonVal root = build_canonical(report, total_risk, finding_total, scanners_with_findings, duration_ms, slowest_name, slowest_ms, earliest, latest, severity_counts, host);
        std::ostringstream canon_os; canon_emit(root, canon_os); std::string canon = canon_os.str();
        if(config().pretty) return pretty(canon); if(config().compact || !config().pretty) return canon; // canonical form is already compact
    }
    if(config().sarif){
        // Minimal SARIF 2.1.0 output (single run, results mapped from findings)
        std::ostringstream s;
        s << "{\"version\":\"2.1.0\",\"$schema\":\"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\"runs\":[{";
        s << "\"tool\":{\"driver\":{\"name\":\"sys-scan\",\"informationUri\":\"https://github.com/J-mazz/sys-scan\"}},";
        s << "\"results\":[";
        bool first=true; int minRank = severity_rank(config().min_severity);
        for(const auto& r: results){ for(const auto& f: r.findings){ if(severity_rank_enum(f.severity) < minRank) continue; if(!first) s<<","; first=false; s << "{\"ruleId\":\""<<escape(f.id)<<"\",\"level\":\""<<escape(severity_to_string(f.severity))<<"\",\"message\":{\"text\":\""<<escape(f.title)<<" - "<<escape(f.description)<<"\"},\"properties\":{\"riskScore\":"<<f.risk_score<<"}}"; }}
        s << "]}] }";
        return s.str();
    }
    if(config().ndjson){
        // Emit NDJSON: first meta, then summary_extension, then each finding line with scanner association
        std::ostringstream nd;
        // naive extraction by simple approach: we regenerate minimal objects for NDJSON
        // Meta line
        // Recollect meta similarly to earlier logic
        // (For brevity, reuse host collected above)
        nd << '{' << "\"type\":\"meta\",\"tool_version\":\"0.1.0\",\"schema\":\"2\",\"hostname\":\""<<escape(host.hostname)<<"\"}" << "\n";
        nd << '{' << "\"type\":\"summary_extension\",\"total_risk_score\":"<< total_risk <<'}' <<"\n";
        for(const auto& r: results){
            for(const auto& f: r.findings){
                if(severity_rank(config().min_severity) > severity_rank_enum(f.severity)) continue;
                nd << '{' << "\"type\":\"finding\",\"scanner\":\""<<escape(r.scanner_name)
                   <<"\",\"id\":\""<<escape(f.id)<<"\",\"severity\":\""<<severity_to_string(f.severity)
                   <<"\",\"risk_score\":"<<f.risk_score<<"}" <<"\n";
            }
        }
        return nd.str();
    }
    std::string min = minify(raw);
    if(config().compact) return min;
    if(config().pretty) return pretty(min);
    return raw; // legacy formatting (already somewhat spaced)
}

}
