#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/JSONWriter.h"
#include "core/Logging.h"
#include <iostream>
#include <filesystem>
#include <vector>
#include "core/Config.h"
#include <fstream>

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
              << "  --ioc-allow list           Comma-separated substrings to treat as benign for env-only IOC (e.g. /snap/,/usr/lib/firefox)\n"
              << "  --modules-summary          Collapse module list into single summary finding\n"
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
    else if(a=="--ioc-allow") cfg.ioc_allow = split_csv(need_val("--ioc-allow"));
    else if(a=="--modules-summary") cfg.modules_summary_only = true;
        else if(a=="--help") { print_help(); return 0; }
        else { std::cerr << "Unknown arg: "<<a<<"\n"; print_help(); return 2; }
    }
    set_config(cfg);

    ScannerRegistry registry;
    registry.register_all_default();

    Report report;
    registry.run_all(report);

    JSONWriter writer;
    std::string json = writer.write(report);

    if(cfg.pretty){
        // very naive pretty: insert newlines after commas that precede quotes and braces already present; JSON already mostly formatted.
    }
    if(cfg.output_file.empty()) std::cout << json; else { std::ofstream ofs(cfg.output_file); ofs<<json; }

    if(!cfg.fail_on_severity.empty()) {
        int thresh = severity_rank(cfg.fail_on_severity);
        const auto& results = report.results();
        for(const auto& r: results){ for(const auto& f: r.findings){ if(severity_rank(f.severity) >= thresh) return 1; } }
    }
    return 0;
}
