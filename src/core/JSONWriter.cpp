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

static std::string canonical_escape(const std::string& s){ return escape(s); }

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
    if(config().canonical){
        // Re-parse minimal elements we already have (fast path) not implemented; for now raw is near-minified if compact.
        // A future full RFC8785 implementation would build canonical structures directly.
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
