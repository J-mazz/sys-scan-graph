#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/JSONWriter.h"
#include "core/Logging.h"
#include "core/RuleEngine.h"
#include <iostream>
#include <filesystem>
#include <vector>
#include "core/Config.h"
#include <fstream>
#include "core/Privilege.h"
#include "BuildInfo.h" // configured header (CMake adds generated dir to include path)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/stat.h>
#include <limits.h>

using namespace sys_scan;

static void print_help(){
    std::cout << "sys-scan options:\n";
    struct Line { std::string name; std::string help; };
    static const std::vector<Line> lines = {
        {"--enable name[,name...]", "Only run specified scanners"},
        {"--disable name[,name...]", "Disable specified scanners"},
        {"--output FILE", "Write JSON to FILE (default stdout)"},
        {"--min-severity SEV", "Filter out findings below SEV"},
        {"--fail-on SEV", "Exit non-zero if finding >= SEV"},
        {"--fail-on-count N", "Exit non-zero if finding count >= N"},
        {"--pretty", "Pretty-print JSON"},
        {"--compact", "Minified JSON output"},
        {"--canonical", "RFC8785-like canonical ordering"},
        {"--ndjson", "Emit NDJSON (meta, summary, findings)"},
        {"--sarif", "Emit SARIF 2.1.0 JSON"},
        {"--all-processes", "Include kernel/thread processes with no cmdline"},
        {"--modules-summary", "Collapse modules into summary"},
        {"--modules-anomalies-only", "Only unsigned/out-of-tree/missing/hidden modules"},
        {"--modules-hash", "Include SHA256 for module files"},
        {"--integrity", "Enable integrity scanners"},
        {"--integrity-ima", "Include IMA measurement stats"},
        {"--integrity-pkg-verify", "Run package manager verify (dpkg/rpm)"},
        {"--integrity-pkg-limit N", "Limit detailed package mismatch findings"},
        {"--integrity-pkg-rehash", "Recompute SHA256 for mismatched package files"},
        {"--integrity-pkg-rehash-limit N", "Cap package files rehashed"},
        {"--fs-hygiene", "Filesystem hygiene checks"},
        {"--fs-world-writable-limit N", "Cap world-writable file findings"},
        {"--world-writable-dirs dirs", "Extra directories for world-writable scan"},
        {"--world-writable-exclude pats", "Substrings to ignore in world-writable paths"},
        {"--process-hash", "Hash process executables"},
        {"--process-inventory", "Emit every process as a finding"},
        {"--max-processes N", "Limit process findings after filtering"},
        {"--max-sockets N", "Limit network socket findings"},
        {"--network-debug", "Emit raw network lines"},
        {"--network-listen-only", "Only include LISTEN sockets"},
        {"--network-proto tcp|udp", "Filter to protocol"},
        {"--network-states list", "Comma-separated TCP states"},
        {"--network-advanced", "Advanced network analytics"},
        {"--network-fanout N", "Total connections fanout threshold"},
        {"--network-fanout-unique N", "Unique remote IP fanout threshold"},
        {"--ioc-allow list", "IOC allow substrings (comma-separated)"},
        {"--ioc-allow-file FILE", "File with IOC allow patterns"},
        {"--ioc-env-trust", "Correlate env vars with executable trust"},
        {"--ioc-exec-trace [S]", "Short-lived exec trace (optional seconds)"},
        {"--suid-expected list", "Extra expected SUID paths"},
        {"--suid-expected-file FILE", "File listing expected SUID paths"},
        {"--parallel", "Run scanners in parallel"},
        {"--parallel-threads N", "Max parallel threads"},
        {"--hardening", "Extended hardening scanners"},
        {"--containers", "Container / namespace detection"},
        {"--container-id ID", "Limit process/network to container id"},
        {"--rules-enable", "Enable rule engine enrichment"},
        {"--rules-dir DIR", "Directory with .rule files"},
        {"--rules-allow-legacy", "Allow unsupported rule versions"},
        {"--sign-gpg KEYID", "Detached signature (requires --output)"},
        {"--slsa-level N", "SLSA provenance level"},
        {"--compliance", "Enable compliance scanners"},
        {"--compliance-standards list", "Subset of compliance standards"},
        {"--drop-priv", "Drop Linux capabilities early"},
        {"--keep-cap-dac", "Retain CAP_DAC_READ_SEARCH when dropping"},
        {"--seccomp", "Apply seccomp profile"},
        {"--seccomp-strict", "Fail if seccomp apply fails"},
        {"--no-user-meta", "Suppress user identity in meta"},
        {"--no-cmdline-meta", "Suppress cmdline in meta"},
        {"--no-hostname-meta", "Suppress hostname in meta"},
    {"--write-env FILE", ".env provenance output"},
        {"--version", "Print version & exit"},
        {"--help", "Show this help"}
    };
    for(const auto& l : lines){ std::cout << "  " << l.name; if(l.name.size() < 30) for(size_t i=l.name.size(); i<30; ++i) std::cout << ' '; else std::cout<<' '; std::cout << l.help << "\n"; }
}

static std::vector<std::string> split_csv(const std::string& s){
    std::vector<std::string> out; std::string cur; for(char c: s){ if(c==','){ if(!cur.empty()) out.push_back(cur); cur.clear(); } else cur.push_back(c);} if(!cur.empty()) out.push_back(cur); return out; }

using namespace sys_scan;

int main(int argc, char** argv) {
    Logger::instance().set_level(LogLevel::Info);
    Config cfg;
    enum class ArgKind { None, String, Int, CSV, OptionalInt };
    struct FlagSpec { const char* name; ArgKind kind; std::function<void(const std::string&)> apply; };
    auto need_int = [](const std::string& v, const char* flag){ try { return std::stoi(v); } catch(...) { std::cerr<<"Invalid integer for "<<flag<<"\n"; std::exit(2);} };
    std::vector<FlagSpec> specs = {
        {"--enable", ArgKind::CSV, [&](const std::string& v){ cfg.enable_scanners = split_csv(v); }},
        {"--disable", ArgKind::CSV, [&](const std::string& v){ cfg.disable_scanners = split_csv(v); }},
        {"--output", ArgKind::String, [&](const std::string& v){ cfg.output_file = v; }},
        {"--min-severity", ArgKind::String, [&](const std::string& v){ cfg.min_severity = v; }},
        {"--fail-on", ArgKind::String, [&](const std::string& v){ cfg.fail_on_severity = v; }},
        {"--pretty", ArgKind::None, [&](const std::string&){ cfg.pretty = true; }},
        {"--compact", ArgKind::None, [&](const std::string&){ cfg.compact = true; }},
        {"--canonical", ArgKind::None, [&](const std::string&){ cfg.canonical = true; }},
        {"--ndjson", ArgKind::None, [&](const std::string&){ cfg.ndjson = true; }},
        {"--sarif", ArgKind::None, [&](const std::string&){ cfg.sarif = true; }},
    {"--all-processes", ArgKind::None, [&](const std::string&){ cfg.all_processes = true; }},
        {"--modules-summary", ArgKind::None, [&](const std::string&){ cfg.modules_summary_only = true; }},
        {"--modules-anomalies-only", ArgKind::None, [&](const std::string&){ cfg.modules_anomalies_only = true; }},
        {"--modules-hash", ArgKind::None, [&](const std::string&){ cfg.modules_hash = true; }},
        {"--integrity", ArgKind::None, [&](const std::string&){ cfg.integrity = true; }},
        {"--integrity-ima", ArgKind::None, [&](const std::string&){ cfg.integrity_ima = true; }},
        {"--integrity-pkg-verify", ArgKind::None, [&](const std::string&){ cfg.integrity_pkg_verify = true; }},
        {"--integrity-pkg-limit", ArgKind::Int, [&](const std::string& v){ cfg.integrity_pkg_limit = need_int(v, "--integrity-pkg-limit"); }},
        {"--integrity-pkg-rehash", ArgKind::None, [&](const std::string&){ cfg.integrity_pkg_rehash = true; }},
        {"--integrity-pkg-rehash-limit", ArgKind::Int, [&](const std::string& v){ cfg.integrity_pkg_rehash_limit = need_int(v, "--integrity-pkg-rehash-limit"); }},
        {"--fs-hygiene", ArgKind::None, [&](const std::string&){ cfg.fs_hygiene = true; }},
        {"--fs-world-writable-limit", ArgKind::Int, [&](const std::string& v){ cfg.fs_world_writable_limit = need_int(v, "--fs-world-writable-limit"); }},
        {"--world-writable-dirs", ArgKind::CSV, [&](const std::string& v){ cfg.world_writable_dirs = split_csv(v); }},
        {"--world-writable-exclude", ArgKind::CSV, [&](const std::string& v){ cfg.world_writable_exclude = split_csv(v); }},
        {"--process-hash", ArgKind::None, [&](const std::string&){ cfg.process_hash = true; }},
        {"--process-inventory", ArgKind::None, [&](const std::string&){ cfg.process_inventory = true; }},
        {"--max-processes", ArgKind::Int, [&](const std::string& v){ cfg.max_processes = need_int(v, "--max-processes"); }},
        {"--max-sockets", ArgKind::Int, [&](const std::string& v){ cfg.max_sockets = need_int(v, "--max-sockets"); }},
        {"--network-debug", ArgKind::None, [&](const std::string&){ cfg.network_debug = true; }},
        {"--network-listen-only", ArgKind::None, [&](const std::string&){ cfg.network_listen_only = true; }},
        {"--network-proto", ArgKind::String, [&](const std::string& v){ cfg.network_proto = v; }},
        {"--network-states", ArgKind::CSV, [&](const std::string& v){ cfg.network_states = split_csv(v); }},
        {"--network-advanced", ArgKind::None, [&](const std::string&){ cfg.network_advanced = true; }},
        {"--network-fanout", ArgKind::Int, [&](const std::string& v){ cfg.network_fanout_threshold = need_int(v, "--network-fanout"); }},
        {"--network-fanout-unique", ArgKind::Int, [&](const std::string& v){ cfg.network_fanout_unique_threshold = need_int(v, "--network-fanout-unique"); }},
        {"--ioc-allow", ArgKind::CSV, [&](const std::string& v){ cfg.ioc_allow = split_csv(v); }},
        {"--ioc-allow-file", ArgKind::String, [&](const std::string& v){ cfg.ioc_allow_file = v; }},
        {"--ioc-env-trust", ArgKind::None, [&](const std::string&){ cfg.ioc_env_trust = true; }},
        {"--ioc-exec-trace", ArgKind::OptionalInt, [&](const std::string& v){ cfg.ioc_exec_trace = true; if(!v.empty()) cfg.ioc_exec_trace_seconds = need_int(v, "--ioc-exec-trace"); }},
        {"--suid-expected", ArgKind::CSV, [&](const std::string& v){ cfg.suid_expected_add = split_csv(v); }},
        {"--suid-expected-file", ArgKind::String, [&](const std::string& v){ cfg.suid_expected_file = v; }},
        {"--parallel", ArgKind::None, [&](const std::string&){ cfg.parallel = true; }},
        {"--parallel-threads", ArgKind::Int, [&](const std::string& v){ cfg.parallel_max_threads = need_int(v, "--parallel-threads"); }},
        {"--hardening", ArgKind::None, [&](const std::string&){ cfg.hardening = true; }},
        {"--containers", ArgKind::None, [&](const std::string&){ cfg.containers = true; }},
        {"--container-id", ArgKind::String, [&](const std::string& v){ cfg.container_id_filter = v; }},
        {"--rules-enable", ArgKind::None, [&](const std::string&){ cfg.rules_enable = true; }},
        {"--rules-dir", ArgKind::String, [&](const std::string& v){ cfg.rules_dir = v; }},
        {"--rules-allow-legacy", ArgKind::None, [&](const std::string&){ cfg.rules_allow_legacy = true; }},
        {"--sign-gpg", ArgKind::String, [&](const std::string& v){ cfg.sign_gpg = true; cfg.sign_gpg_key = v; }},
        {"--slsa-level", ArgKind::String, [&](const std::string& v){ setenv("SYS_SCAN_SLSA_LEVEL_RUNTIME", v.c_str(), 1); }},
        {"--compliance", ArgKind::None, [&](const std::string&){ cfg.compliance = true; }},
        {"--compliance-standards", ArgKind::CSV, [&](const std::string& v){ cfg.compliance_standards = split_csv(v); }},
        {"--drop-priv", ArgKind::None, [&](const std::string&){ cfg.drop_priv = true; }},
        {"--keep-cap-dac", ArgKind::None, [&](const std::string&){ cfg.keep_cap_dac = true; }},
        {"--seccomp", ArgKind::None, [&](const std::string&){ cfg.seccomp = true; }},
        {"--seccomp-strict", ArgKind::None, [&](const std::string&){ cfg.seccomp_strict = true; }},
        {"--no-user-meta", ArgKind::None, [&](const std::string&){ cfg.no_user_meta = true; }},
        {"--no-cmdline-meta", ArgKind::None, [&](const std::string&){ cfg.no_cmdline_meta = true; }},
        {"--no-hostname-meta", ArgKind::None, [&](const std::string&){ cfg.no_hostname_meta = true; }},
        {"--write-env", ArgKind::String, [&](const std::string& v){ cfg.write_env_file = v; }},
        {"--fail-on-count", ArgKind::Int, [&](const std::string& v){ cfg.fail_on_count = need_int(v, "--fail-on-count"); }}
    };
    auto find_spec = [&](const std::string& flag)->FlagSpec*{ for(auto& s: specs) if(flag==s.name) return &s; return nullptr; };
    for(int i=1;i<argc;++i){ std::string a = argv[i]; if(a=="--help"){ print_help(); return 0; } if(a=="--version"){ std::cout << "sys-scan " << sys_scan::buildinfo::APP_VERSION << " (git=" << sys_scan::buildinfo::GIT_COMMIT << ", compiler=" << sys_scan::buildinfo::COMPILER_ID << " " << sys_scan::buildinfo::COMPILER_VERSION << ", cxx_std=" << sys_scan::buildinfo::CXX_STANDARD << ")\n"; return 0; } auto* spec = find_spec(a); if(!spec){ std::cerr << "Unknown arg: "<<a<<"\n"; print_help(); return 2; } std::string val; switch(spec->kind){ case ArgKind::None: break; case ArgKind::String: case ArgKind::Int: case ArgKind::CSV: { if(i+1>=argc){ std::cerr << "Missing value for "<<a<<"\n"; return 2; } val = argv[++i]; break;} case ArgKind::OptionalInt: { if(i+1<argc && argv[i+1][0] != '-') val = argv[++i]; break;} } spec->apply(val); }
    set_config(cfg);

    // Post-parse validation & normalization
    // Normalize ioc_exec_trace default duration
    if(cfg.ioc_exec_trace && cfg.ioc_exec_trace_seconds == 0) cfg.ioc_exec_trace_seconds = 3;
    // Conflict detection: sarif vs ndjson
    if(cfg.sarif && cfg.ndjson){ std::cerr << "--sarif and --ndjson are mutually exclusive\n"; return 2; }
    // pretty vs compact: if both set, compact wins (documented behavior)
    if(cfg.pretty && cfg.compact){ cfg.pretty = false; }
    // Required value checks
    if(cfg.sign_gpg && cfg.output_file.empty()){ std::cerr << "--sign-gpg requires --output FILE\n"; return 2; }
    // Basic severity validation (accepted severities)
    static const std::vector<std::string> allowed_sev = {"Info","Low","Medium","High","Critical"};
    auto is_allowed = [&](const std::string& s){ if(s.empty()) return true; return std::find(allowed_sev.begin(), allowed_sev.end(), s) != allowed_sev.end(); };
    if(!is_allowed(cfg.min_severity)){ std::cerr << "Invalid --min-severity value: "<<cfg.min_severity<<"\n"; return 2; }
    if(!is_allowed(cfg.fail_on_severity)){ std::cerr << "Invalid --fail-on value: "<<cfg.fail_on_severity<<"\n"; return 2; }
    if(!cfg.container_id_filter.empty() && !cfg.containers){ std::cerr << "--container-id requires --containers\n"; return 2; }

    // Post-parse: load IOC allowlist file if provided
    if(!cfg.ioc_allow_file.empty()) {
        std::ifstream af(cfg.ioc_allow_file); if(af){ std::string line; while(std::getline(af,line)) { if(line.empty()) continue; if(line[0]=='#') continue; cfg.ioc_allow.push_back(line); } }
        set_config(cfg); // update global with merged allowlist
    }
    if(!cfg.suid_expected_file.empty()) {
        std::ifstream ef(cfg.suid_expected_file); if(ef){ std::string line; while(std::getline(ef,line)){ if(line.empty()) continue; if(line[0]=='#') continue; cfg.suid_expected_add.push_back(line); } }
        set_config(cfg);
    }

    ScannerRegistry registry;
    if(cfg.drop_priv){ drop_capabilities(cfg.keep_cap_dac); }
    // Apply seccomp earlier (after capability drop, before scanning) for stronger containment
    if(cfg.seccomp){ if(!apply_seccomp_profile()){ std::cerr << "Failed to apply seccomp profile"; if(cfg.seccomp_strict) return 4; else std::cerr << " (continuing)\n"; } }
    if(cfg.rules_enable){
        if(cfg.rules_dir.empty()) { std::cerr << "--rules-enable requires --rules-dir\n"; return 2; }
        // Canonicalize rule directory path (resolves symlinks) to avoid ambiguity
        char rbuf[PATH_MAX]; std::string canon_rules = cfg.rules_dir;
        if(realpath(cfg.rules_dir.c_str(), rbuf)) canon_rules = rbuf; // fallback to original if fails
        struct stat rs{}; if(stat(canon_rules.c_str(), &rs)!=0){ std::cerr << "Rules directory not accessible: "<<canon_rules<<"\n"; return 2; }
        bool insecure=false;
        // Insecure if not owned by root OR writable by group/others
        if(rs.st_uid != 0) insecure = true;
        if(rs.st_mode & (S_IWGRP | S_IWOTH)) insecure = true;
        if(insecure){
            std::cerr << "Refusing to load rules from insecure directory (must be root-owned and not group/other-writable): "<<canon_rules<<"\n";
            return 5;
        }
        // Use canonical path for loading
        std::string warn; rule_engine().load_dir(canon_rules, warn); if(!warn.empty()) Logger::instance().warn(std::string("rules:")+warn);
        bool hasUnsupported=false; for(const auto& w : rule_engine().warnings()){ if(w.code=="unsupported_version") { hasUnsupported=true; break; } }
        if(hasUnsupported && !cfg.rules_allow_legacy){ std::cerr << "Unsupported rule_version detected. Use --rules-allow-legacy to proceed.\n"; return 3; }
    }
    registry.register_all_default();

    Report report;
    registry.run_all(report);

    JSONWriter writer;
    std::string json = writer.write(report);

    if(cfg.pretty){
        // very naive pretty: insert newlines after commas that precede quotes and braces already present; JSON already mostly formatted.
    }
    if(cfg.output_file.empty()) std::cout << json; else { std::ofstream ofs(cfg.output_file); ofs<<json; }
    if(!cfg.write_env_file.empty()){
        std::string exe; char pathbuf[4096]; ssize_t n = readlink("/proc/self/exe", pathbuf, sizeof(pathbuf)-1); if(n>0){ pathbuf[n]=0; exe=pathbuf; }
        std::string hexhash;
#ifdef SYS_SCAN_HAVE_OPENSSL
        if(!exe.empty()){
            FILE* fp=fopen(exe.c_str(),"rb"); if(fp){ unsigned char md[32]; unsigned int mdlen=0; EVP_MD_CTX* ctx=EVP_MD_CTX_new(); if(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)==1){ unsigned char bufh[8192]; size_t got; while((got=fread(bufh,1,sizeof(bufh),fp))>0){ EVP_DigestUpdate(ctx, bufh, got);} if(EVP_DigestFinal_ex(ctx, md, &mdlen)==1 && mdlen==32){ static const char* hx="0123456789abcdef"; for(unsigned i=0;i<32;i++){ hexhash.push_back(hx[md[i]>>4]); hexhash.push_back(hx[md[i]&0xF]); } } } if(ctx) EVP_MD_CTX_free(ctx); fclose(fp);} }
#endif
        std::ofstream envf(cfg.write_env_file);
    envf << "SYS_SCAN_VERSION="<<sys_scan::buildinfo::APP_VERSION<<"\n";
        envf << "SYS_SCAN_BINARY_SHA256="<<hexhash<<"\n";
    }
    // (seccomp already applied earlier; no reapplication here)

    // Optional GPG signing (secure fork/exec path, avoids shell injection)
    if(cfg.sign_gpg){
        if(cfg.output_file.empty()){
            std::cerr << "--sign-gpg requires --output FILE (cannot sign stdout)\n";
        } else {
            // Canonicalize output file path before signing to ensure we sign the intended target
            std::string of = cfg.output_file; char obuf[PATH_MAX]; if(realpath(cfg.output_file.c_str(), obuf)) of = obuf;
            // Basic key id validation: allow hex fingerprints or short key IDs (8+ hex) and emails in angle brackets
            // Accept patterns: hex (16-40 chars), or word chars + @ + domain inside < > for uid selection.
            const std::string& key = cfg.sign_gpg_key;
            bool key_ok = false;
            if(!key.empty()){
                bool hex_only = true; for(char c: key){ if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))){ hex_only=false; break; } }
                if(hex_only && key.size() >= 8 && key.size() <= 64) key_ok = true;
                if(!key_ok){
                    // crude email-like uid detection inside optional < >
                    auto lt = key.find('<'); auto gt = key.find('>');
                    std::string inner = (lt!=std::string::npos && gt!=std::string::npos && gt>lt)? key.substr(lt+1, gt-lt-1): key;
                    auto atpos = inner.find('@');
                    if(atpos!=std::string::npos && atpos>0 && atpos+1 < inner.size()) key_ok = true;
                }
            }
            if(!key_ok){
                std::cerr << "Refusing to use GPG key identifier due to validation failure: '"<<key<<"'\n";
            } else {
                std::string sigfile = of + ".asc";
                pid_t pid = fork();
                if(pid < 0){
                    std::cerr << "fork() failed for GPG signing\n";
                } else if(pid == 0){
                    // Child: exec gpg
                    // Build argv vector
                    std::vector<char*> argv;
                    auto push = [&](const std::string& s){ argv.push_back(const_cast<char*>(s.c_str())); };
                    push("gpg");
                    push("--batch"); push("--yes"); push("--armor"); push("--detach-sign");
                    push("-u"); push(key);
                    push("-o"); push(sigfile);
                    push(of);
                    argv.push_back(nullptr);
                    // Clear potentially dangerous env vars (minimal hardening)
                    unsetenv("GPG_AGENT_INFO");
                    execvp("gpg", argv.data());
                    _exit(127); // exec failed
                } else {
                    int status = 0; if(waitpid(pid, &status, 0) < 0){ std::cerr << "waitpid failed for GPG signing\n"; }
                    if(!(WIFEXITED(status) && WEXITSTATUS(status)==0)){
                        std::cerr << "GPG signing failed (status="<<status<<") for output: "<<cfg.output_file<<"\n";
                    }
                }
            }
        }
    }

    if(!cfg.fail_on_severity.empty()) {
        int thresh = severity_rank(cfg.fail_on_severity);
        const auto& results = report.results();
    for(const auto& r: results){ for(const auto& f: r.findings){ if(severity_rank_enum(f.severity) >= thresh) return 1; } }
    }
    if(cfg.fail_on_count > 0){
        size_t total=0; for(const auto& r: report.results()) total += r.findings.size();
        if(total >= static_cast<size_t>(cfg.fail_on_count)) return 1;
    }
    return 0;
}
