#include "NetworkScanner.h"
#include "../core/Report.h"
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>
#include <filesystem>
#include <string>
#include "../core/Config.h"

namespace fs = std::filesystem;

namespace sys_scan {

static std::unordered_map<std::string, std::pair<std::string,std::string>> build_inode_map(){
    // inode -> (pid, exe)
    std::unordered_map<std::string, std::pair<std::string,std::string>> map;
    std::error_code top_ec;
    for(auto pit = fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied, top_ec); pit!=fs::directory_iterator(); ++pit){
        if(top_ec) break; if(!pit->is_directory()) continue; auto pid = pit->path().filename().string(); if(!std::all_of(pid.begin(),pid.end(),::isdigit)) continue;
        fs::path fd_dir = pit->path()/"fd"; std::error_code ec; if(!fs::exists(fd_dir, ec)) continue;
        std::error_code ec_dir;
        for(auto fit = fs::directory_iterator(fd_dir, fs::directory_options::skip_permission_denied, ec_dir); fit!=fs::directory_iterator(); ++fit){
            if(ec_dir){ break; }
            std::error_code ec2; auto target = fs::read_symlink(fit->path(), ec2); if(ec2) continue; std::string t = target.string(); // format: socket:[12345]
            auto pos = t.find("socket:["); if(pos==std::string::npos) continue; auto b = t.find('[', pos); auto e = t.find(']', b); if(b==std::string::npos||e==std::string::npos) continue; std::string inode = t.substr(b+1, e-b-1);
            std::string exe; std::error_code ec3; auto exepath = fs::read_symlink(pit->path()/"exe", ec3); if(!ec3) exe = exepath.string();
            map.emplace(inode, std::make_pair(pid, exe));
        }
    }
    return map;
}

static std::string hex_ip_to_v4(const std::string& h){ if(h.size()<8) return ""; unsigned int b1,b2,b3,b4; std::stringstream ss; ss<<std::hex<<h.substr(6,2); ss>>b1; ss.clear(); ss<<std::hex<<h.substr(4,2); ss>>b2; ss.clear(); ss<<std::hex<<h.substr(2,2); ss>>b3; ss.clear(); ss<<std::hex<<h.substr(0,2); ss>>b4; return std::to_string(b1)+"."+std::to_string(b2)+"."+std::to_string(b3)+"."+std::to_string(b4);} 
static std::string hex_ip6_to_str(const std::string& h){ if(h.size()<32) return ""; std::string out; for(int i=0;i<8;i++){ if(i) out+=':'; out += h.substr(i*4,4);} return out; }
static std::string tcp_state(const std::string& st){ static std::unordered_map<std::string,std::string> m={{"01","ESTABLISHED"},{"02","SYN_SENT"},{"03","SYN_RECV"},{"04","FIN_WAIT1"},{"05","FIN_WAIT2"},{"06","TIME_WAIT"},{"07","CLOSE"},{"08","CLOSE_WAIT"},{"09","LAST_ACK"},{"0A","LISTEN"},{"0B","CLOSING"}}; auto it=m.find(st); return it==m.end()?st:it->second; }

static std::string classify_tcp_severity(const std::string& state, unsigned port, const std::string& exe){
    // Basic heuristics: LISTEN on privileged unexpected high-risk ports -> medium, unusual LISTEN >1024 -> info; established stays info.
    if(state=="LISTEN"){
        if(port==22 || port==23 || port==2323) return "medium"; // ssh/telnet typical interest
        if(port==0) return "low";
        if(port < 1024){
            if(port==80 || port==443 || port==53 || port==25 || port==110 || port==995 || port==143 || port==993) return "low"; // common services
            return "medium"; // privileged uncommon
        }
    }
    return "info";
}

static std::string escalate_exposed(const std::string& current, const std::string& state, const std::string& lip){
    if(state != "LISTEN") return current;
    auto is_loopback = [&](){
        if(lip.rfind("127.",0)==0) return true; // v4 loopback
        if(lip=="::1" || lip=="0000:0000:0000:0000:0000:0000:0000:0001") return true; // simple v6 loopback forms
        if(lip=="127.0.0.1" || lip=="127.0.0.53" || lip=="127.0.0.54") return true; // common local binds
        return false;
    }();
    if(is_loopback) return current;
    // escalate one level for exposed listener
    static std::vector<std::string> order = {"info","low","medium","high","critical"};
    auto it = std::find(order.begin(), order.end(), current);
    if(it!=order.end() && it+1!=order.end()) return *(it+1);
    return current;
}

static bool state_allowed(const std::string& st){
    if(config().network_states.empty()) return true;
    for(const auto& s: config().network_states) if(s==st) return true;
    return false;
}

static void parse_tcp(const std::string& path, Report& report, const std::string& proto, const std::unordered_map<std::string, std::pair<std::string,std::string>>& inode_map, size_t& emitted){
    std::ifstream ifs(path); if(!ifs){ report.add_warning(proto, std::string("net_file_unreadable:")+path); return; } std::string header; std::getline(ifs, header);
    std::string line; size_t line_no=0; size_t parsed=0; while(std::getline(ifs,line)){
        ++line_no; if(line.find(':')==std::string::npos) continue; // quick filter
        // tokenize by whitespace (variable spacing)
        std::vector<std::string> tok; tok.reserve(20); std::string cur; std::istringstream ls(line); while(ls>>cur) tok.push_back(cur);
    if(tok.size() < 10) { if(config().network_debug) { Finding dbg; dbg.id = proto+":debug:"+std::to_string(line_no); dbg.title="netdebug raw tcp line"; dbg.severity=Severity::Info; dbg.description="Unparsed line"; dbg.metadata["raw"] = line; report.add_finding(proto, std::move(dbg)); } continue; }
        // columns (from /proc/net/tcp docs)
        // 0: sl, 1: local_address, 2: rem_address, 3: st, 4: tx_queue:rx_queue, 5: tr:when, 6: retrnsmt, 7: uid, 8: timeout, 9: inode
        const std::string& local = tok[1]; const std::string& rem = tok[2]; const std::string& st = tok[3];
        const std::string& uid_s = tok[7]; const std::string& inode_s = tok[9];
        // parse local/remote address
        auto pos = local.find(':'); if(pos==std::string::npos) continue; auto lip_hex = local.substr(0,pos); auto lport_hex = local.substr(pos+1);
        unsigned lport=0; std::stringstream ph; ph<<std::hex<<lport_hex; ph>>lport;
        auto pos2 = rem.find(':'); if(pos2==std::string::npos) continue; auto rip_hex = rem.substr(0,pos2); auto rport_hex = rem.substr(pos2+1); unsigned rport=0; std::stringstream rph; rph<<std::hex<<rport_hex; rph>>rport;
        if(lport==0 && rport==0) continue; // skip totally empty sockets
    auto state_str = tcp_state(st);
    if(config().network_listen_only && state_str != "LISTEN") continue;
    if(!state_allowed(state_str)) continue;
    Finding f; f.id = proto+":"+std::to_string(lport)+":"+inode_s; f.title = proto+" "+state_str+" "+std::to_string(lport); f.severity=Severity::Info; f.description="TCP socket";
        f.metadata["protocol"] = "tcp";
        f.metadata["state"] = tcp_state(st); f.metadata["uid"] = uid_s; f.metadata["lport"] = std::to_string(lport); f.metadata["rport"] = std::to_string(rport); f.metadata["inode"] = inode_s;
    if(path.find("tcp6")!=std::string::npos){ f.metadata["lip"] = hex_ip6_to_str(lip_hex); f.metadata["rip"] = hex_ip6_to_str(rip_hex); }
    else { f.metadata["lip"] = hex_ip_to_v4(lip_hex); f.metadata["rip"] = hex_ip_to_v4(rip_hex); }
        auto it = inode_map.find(inode_s); if(it!=inode_map.end()){ f.metadata["pid"] = it->second.first; f.metadata["exe"] = it->second.second; }
        // severity heuristic after exe known
        if(f.metadata.count("exe")){
            auto sev = classify_tcp_severity(state_str, lport, f.metadata["exe"]);
            f.severity = severity_from_string(escalate_exposed(sev, state_str, f.metadata["lip"]));
        } else {
            auto sev = classify_tcp_severity(state_str, lport, "");
            f.severity = severity_from_string(escalate_exposed(sev, state_str, f.metadata["lip"]));
        }
        report.add_finding(proto, std::move(f)); ++parsed; ++emitted; if(config().max_sockets>0 && emitted >= (size_t)config().max_sockets) break; }
    if(parsed==0 && config().network_debug){ Finding dbg; dbg.id=proto+":debug:noparsed"; dbg.title="netdebug tcp none parsed"; dbg.severity=Severity::Low; dbg.description="No TCP lines parsed from "+path; dbg.metadata["path"] = path; report.add_finding(proto, std::move(dbg)); }
}

static std::string classify_udp_severity(unsigned port, const std::string& exe){
    if(port==53) return "low"; // DNS
    if(port < 1024 && port != 68 && port != 123) return "medium"; // unusual privileged UDP
    return "info";
}

static void parse_udp(const std::string& path, Report& report, const std::string& proto, const std::unordered_map<std::string, std::pair<std::string,std::string>>& inode_map, size_t& emitted){
    std::ifstream ifs(path); if(!ifs){ report.add_warning(proto, std::string("net_file_unreadable:")+path); return; } std::string header; std::getline(ifs, header);
    std::string line; size_t line_no=0; size_t parsed=0; while(std::getline(ifs,line)){
        ++line_no; if(line.find(':')==std::string::npos) continue; std::vector<std::string> tok; tok.reserve(20); std::string cur; std::istringstream ls(line); while(ls>>cur) tok.push_back(cur);
    if(tok.size() < 10){ if(config().network_debug){ Finding dbg; dbg.id=proto+":debug:"+std::to_string(line_no); dbg.title="netdebug raw udp line"; dbg.severity=Severity::Info; dbg.description="Unparsed UDP line"; dbg.metadata["raw"] = line; report.add_finding(proto, std::move(dbg)); } continue; }
        const std::string& local = tok[1]; const std::string& inode_s = tok[9]; const std::string& uid_s = tok[7];
        auto pos = local.find(':'); if(pos==std::string::npos) continue; auto lip_hex = local.substr(0,pos); auto lport_hex = local.substr(pos+1); unsigned lport=0; std::stringstream ph; ph<<std::hex<<lport_hex; ph>>lport; if(lport==0) continue;
    Finding f; f.id = proto+":"+std::to_string(lport)+":"+inode_s; f.title = proto+" port "+std::to_string(lport); f.severity=Severity::Info; f.description="UDP socket"; f.metadata["uid"] = uid_s; f.metadata["lport"] = std::to_string(lport); f.metadata["inode"] = inode_s; f.metadata["protocol"] = "udp";
        if(path.find("udp6")!=std::string::npos) f.metadata["lip"] = hex_ip6_to_str(lip_hex); else f.metadata["lip"] = hex_ip_to_v4(lip_hex);
        auto it = inode_map.find(inode_s); if(it!=inode_map.end()){ f.metadata["pid"] = it->second.first; f.metadata["exe"] = it->second.second; }
    f.severity = severity_from_string(classify_udp_severity(lport, f.metadata.count("exe")? f.metadata["exe"] : ""));
    report.add_finding(proto, std::move(f)); ++parsed; ++emitted; if(config().max_sockets>0 && emitted >= (size_t)config().max_sockets) break; }
    if(parsed==0 && config().network_debug){ Finding dbg; dbg.id=proto+":debug:noparsed"; dbg.title="netdebug udp none parsed"; dbg.severity=Severity::Low; dbg.description="No UDP lines parsed from "+path; dbg.metadata["path"] = path; report.add_finding(proto, std::move(dbg)); }
}

void NetworkScanner::scan(Report& report) {
    auto inode_map = build_inode_map(); size_t emitted=0;
    bool want_tcp = config().network_proto.empty() || config().network_proto=="tcp";
    bool want_udp = config().network_proto.empty() || config().network_proto=="udp";
    if(want_tcp){
        parse_tcp("/proc/net/tcp", report, this->name(), inode_map, emitted); if(config().max_sockets>0 && emitted >= (size_t)config().max_sockets) return;
        parse_tcp("/proc/net/tcp6", report, this->name(), inode_map, emitted); if(config().max_sockets>0 && emitted >= (size_t)config().max_sockets) return;
    }
    if(want_udp){
        parse_udp("/proc/net/udp", report, this->name(), inode_map, emitted); if(config().max_sockets>0 && emitted >= (size_t)config().max_sockets) return;
        parse_udp("/proc/net/udp6", report, this->name(), inode_map, emitted);
    }
}

}
