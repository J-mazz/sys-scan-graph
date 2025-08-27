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

using namespace sys_scan;

static void print_help(){
    std::cout << "sys-scan options:\n"
              << "  --enable name[,name...]    Only run specified scanners\n"
              << "  --disable name[,name...]   Disable specified scanners\n"
              << "  --output FILE              Write JSON to FILE (default stdout)\n"
              << "  --min-severity SEV         Filter out findings below SEV\n"
              << "  --fail-on SEV              Exit non-zero if finding >= SEV\n"
              << "  --pretty                   Pretty-print JSON\n"
              << "  --all-processes            Include kernel/thread processes with no cmdline\n"
              << "  --world-writable-dirs dirs Additional comma-separated directories\n"
              << "  --world-writable-exclude pats Comma-separated substrings to ignore in world-writable paths\n"
              << "  --max-processes N          Limit number of process findings after filtering\n"
              << "  --compact                  Minified JSON output\n"
              << "  --max-sockets N            Limit number of network socket findings\n"
              << "  --network-debug            Emit raw unparsed network lines for troubleshooting\n"
              << "  --network-listen-only      Only include listening sockets (UDP all bound ports)\n"
              << "  --network-proto tcp|udp    Filter network scanner to protocol\n"
              << "  --network-states list      Comma-separated TCP states (e.g. LISTEN,ESTABLISHED)\n"
              << "  --network-advanced         Enable advanced network analytics (exposure/fanout)\n"
              << "  --network-fanout N         Threshold for total connections per process (default 100)\n"
              << "  --network-fanout-unique N  Threshold for unique remote IPs per process (default 50)\n"
              << "  --ioc-allow list           Comma-separated substrings to treat as benign for env-only IOC (e.g. /snap/,/usr/lib/firefox)\n"
              << "  --modules-summary          Collapse module list into single summary finding\n"
              << "  --modules-hash             Include SHA256 of module file (if OpenSSL available; anomalies/summary modes)\n"
              << "  --fs-hygiene               Enable advanced filesystem hygiene checks (PATH ww dirs, setuid interpreters, setcap, dangling suid hardlinks)\n"
              << "  --integrity                Enable integrity / package verification scanners\n"
              << "  --integrity-ima            Include IMA measurement stats (if /sys/kernel/security/ima exists)\n"
              << "  --integrity-pkg-verify     Enable dpkg/rpm verify (where available)\n"
              << "  --integrity-pkg-limit N    Limit detailed package mismatch findings (default 200)\n"
              << "  --rules-enable            Enable rule engine enrichment\n"
              << "  --rules-dir DIR           Directory containing .rule files\n"
              << "  --rules-allow-legacy      Do not fail if unsupported rule_version encountered (emit warning)\n"
              << "  --process-hash             Include SHA256 of process executable (if OpenSSL available)\n"
              << "  --process-inventory        Emit all processes (default: only anomalies)\n"
              << "  --ioc-allow-file FILE     Newline-delimited additional allowlist patterns (supports # comments)\n"
              << "  --fail-on-count N         Exit non-zero if total finding count >= N (after filtering)\n"
              << "  --modules-anomalies-only  Only emit unsigned/out-of-tree module findings (oversrides summary/detail)\n"
              << "  --suid-expected list      Comma-separated extra expected SUID paths (exact or suffix)\n"
              << "  --suid-expected-file FILE Newline-delimited expected SUID paths (# comments)\n"
              << "  --canonical               Emit canonical (RFC8785-like) JSON ordering\n"
              << "  --ndjson                  Emit NDJSON (one JSON object per line: meta, summary, findings)\n"
              << "  --sarif                   Emit SARIF 2.1.0 JSON (subset)\n"
              << "  --parallel                Run scanners in parallel (deterministic output order)\n"
              << "  --parallel-threads N      Max parallel threads (default=hardware concurrency)\n"
              << "  --hardening               Enable extended hardening/attack-surface checks\n"
              << "  --containers              Enable container / namespace detection and attribution\n"
              << "  --container-id ID         Limit certain scanners to a specific container id (heuristic)\n"
              << "                             (requires --containers)\n"
              << "  --ioc-env-trust           Correlate LD_* env vars with executable trust (unsigned/tmp paths escalate)\n"
              << "  --ioc-exec-trace [S]      Capture short-lived processes via eBPF execve trace for S seconds (default 3)\n"
              << "  --no-user-meta            Suppress user/uid/gid/euid/egid in meta section\n"
              << "  --no-cmdline-meta         Suppress process command line in meta section\n"
              << "  --no-hostname-meta        Suppress hostname in meta section\n"
              << "  --sign-gpg KEYID          Detached ASCII-armored GPG sign output file (requires --output)\n"
              << "  --slsa-level N            Declare SLSA provenance level (propagated in metadata)\n"
              << "  --compliance              Enable compliance scanners (technical control checks)\n"
              << "  --compliance-standards list  Comma-separated standards subset (e.g. pci_dss_4_0,hipaa_security_rule)\n"
              << "  --drop-priv               Drop Linux capabilities early (retain none unless --keep-cap-dac)\n"
              << "  --keep-cap-dac            Retain CAP_DAC_READ_SEARCH when dropping capabilities\n"
              << "  --seccomp                 Apply restrictive seccomp-bpf profile post-initialization\n"
              << "  --seccomp-strict          Treat seccomp apply failure as fatal (exit non-zero)\n"
              << "  --write-env FILE          Write env-style provenance (.env) file with binary hash/version\n"
              << "  --version                 Print version & provenance summary and exit\n"
              << "  --help                     Show this help\n";
}

static std::vector<std::string> split_csv(const std::string& s){
    std::vector<std::string> out; std::string cur; for(char c: s){ if(c==','){ if(!cur.empty()) out.push_back(cur); cur.clear(); } else cur.push_back(c);} if(!cur.empty()) out.push_back(cur); return out; }

using namespace sys_scan;

int main(int argc, char** argv) {
    Logger::instance().set_level(LogLevel::Info);
    Config cfg;
    for(int i=1;i<argc;++i){
        std::string a = argv[i];
        auto need_val = [&](const char* flag){ if(i+1>=argc){ std::cerr<<"Missing value for "<<flag<<"\n"; std::exit(2);} return std::string(argv[++i]); };
        if(a=="--enable") cfg.enable_scanners = split_csv(need_val("--enable"));
        else if(a=="--disable") cfg.disable_scanners = split_csv(need_val("--disable"));
        else if(a=="--output") cfg.output_file = need_val("--output");
        else if(a=="--min-severity") cfg.min_severity = need_val("--min-severity");
        else if(a=="--fail-on") cfg.fail_on_severity = need_val("--fail-on");
        else if(a=="--pretty") cfg.pretty = true;
        else if(a=="--all-processes") cfg.all_processes = true;
    else if(a=="--world-writable-dirs") cfg.world_writable_dirs = split_csv(need_val("--world-writable-dirs"));
    else if(a=="--world-writable-exclude") cfg.world_writable_exclude = split_csv(need_val("--world-writable-exclude"));
    else if(a=="--max-processes") cfg.max_processes = std::stoi(need_val("--max-processes"));
    else if(a=="--max-sockets") cfg.max_sockets = std::stoi(need_val("--max-sockets"));
    else if(a=="--compact") cfg.compact = true;
    else if(a=="--network-debug") cfg.network_debug = true;
    else if(a=="--network-listen-only") cfg.network_listen_only = true;
    else if(a=="--network-proto") cfg.network_proto = need_val("--network-proto");
    else if(a=="--network-states") cfg.network_states = split_csv(need_val("--network-states"));
    else if(a=="--network-advanced") cfg.network_advanced = true;
    else if(a=="--network-fanout") cfg.network_fanout_threshold = std::stoi(need_val("--network-fanout"));
    else if(a=="--network-fanout-unique") cfg.network_fanout_unique_threshold = std::stoi(need_val("--network-fanout-unique"));
    else if(a=="--ioc-allow") cfg.ioc_allow = split_csv(need_val("--ioc-allow"));
    else if(a=="--modules-summary") cfg.modules_summary_only = true;
    else if(a=="--modules-hash") cfg.modules_hash = true;
    else if(a=="--fs-hygiene") cfg.fs_hygiene = true;
    else if(a=="--integrity") cfg.integrity = true;
    else if(a=="--integrity-ima") cfg.integrity_ima = true;
    else if(a=="--integrity-pkg-verify") cfg.integrity_pkg_verify = true;
    else if(a=="--integrity-pkg-limit") cfg.integrity_pkg_limit = std::stoi(need_val("--integrity-pkg-limit"));
    else if(a=="--rules-enable") cfg.rules_enable = true;
    else if(a=="--rules-dir") cfg.rules_dir = need_val("--rules-dir");
    else if(a=="--rules-allow-legacy") cfg.rules_allow_legacy = true;
    else if(a=="--process-hash") cfg.process_hash = true;
    else if(a=="--process-inventory") cfg.process_inventory = true;
    else if(a=="--ioc-allow-file") cfg.ioc_allow_file = need_val("--ioc-allow-file");
    else if(a=="--fail-on-count") cfg.fail_on_count = std::stoi(need_val("--fail-on-count"));
    else if(a=="--modules-anomalies-only") cfg.modules_anomalies_only = true;
    else if(a=="--suid-expected") cfg.suid_expected_add = split_csv(need_val("--suid-expected"));
    else if(a=="--suid-expected-file") cfg.suid_expected_file = need_val("--suid-expected-file");
    else if(a=="--canonical") cfg.canonical = true;
    else if(a=="--ndjson") cfg.ndjson = true;
    else if(a=="--sarif") cfg.sarif = true;
    else if(a=="--parallel") cfg.parallel = true;
    else if(a=="--parallel-threads") cfg.parallel_max_threads = std::stoi(need_val("--parallel-threads"));
    else if(a=="--hardening") cfg.hardening = true;
    else if(a=="--containers") cfg.containers = true;
    else if(a=="--container-id") cfg.container_id_filter = need_val("--container-id");
    else if(a=="--ioc-env-trust") cfg.ioc_env_trust = true;
    else if(a=="--ioc-exec-trace") { cfg.ioc_exec_trace = true; if(i+1<argc && argv[i+1][0] != '-') { cfg.ioc_exec_trace_seconds = std::stoi(argv[++i]); } }
    else if(a=="--no-user-meta") cfg.no_user_meta = true;
    else if(a=="--no-cmdline-meta") cfg.no_cmdline_meta = true;
    else if(a=="--no-hostname-meta") cfg.no_hostname_meta = true;
    else if(a=="--drop-priv") cfg.drop_priv = true;
    else if(a=="--keep-cap-dac") cfg.keep_cap_dac = true;
    else if(a=="--seccomp") cfg.seccomp = true;
    else if(a=="--write-env") cfg.write_env_file = need_val("--write-env");
    else if(a=="--sign-gpg") { cfg.sign_gpg = true; cfg.sign_gpg_key = need_val("--sign-gpg"); }
    else if(a=="--slsa-level") { /* override provided at runtime if not baked */ setenv("SYS_SCAN_SLSA_LEVEL_RUNTIME", need_val("--slsa-level").c_str(), 1); }
    else if(a=="--compliance") cfg.compliance = true;
    else if(a=="--compliance-standards") cfg.compliance_standards = split_csv(need_val("--compliance-standards"));
    else if(a=="--version") { std::cout << "sys-scan " << sys_scan::buildinfo::APP_VERSION
          << " (git=" << sys_scan::buildinfo::GIT_COMMIT
          << ", compiler=" << sys_scan::buildinfo::COMPILER_ID << " " << sys_scan::buildinfo::COMPILER_VERSION
          << ", cxx_std=" << sys_scan::buildinfo::CXX_STANDARD
          << ")\n"; return 0; }
    else if(a=="--help") { print_help(); return 0; }
        else { std::cerr << "Unknown arg: "<<a<<"\n"; print_help(); return 2; }
    }
    set_config(cfg);

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
        std::string warn; rule_engine().load_dir(cfg.rules_dir, warn); if(!warn.empty()) Logger::instance().warn(std::string("rules:")+warn);
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
    if(cfg.seccomp){ if(!apply_seccomp_profile()){ std::cerr << "Failed to apply seccomp profile (continuing)\n"; } }
    // (seccomp applied earlier)

    // Optional GPG signing
    if(cfg.sign_gpg){
        if(cfg.output_file.empty()){
            std::cerr << "--sign-gpg requires --output FILE (cannot sign stdout)\n";
        } else {
            std::string sigfile = cfg.output_file + ".asc";
            std::string cmd = "gpg --batch --yes --armor --detach-sign -u " + cfg.sign_gpg_key + " -o " + sigfile + " " + cfg.output_file;
            int rc = std::system(cmd.c_str());
            if(rc!=0){ std::cerr << "GPG signing failed (rc="<<rc<<") for command: "<<cmd<<"\n"; }
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
