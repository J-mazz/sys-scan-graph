// GCOVR_EXCL_START
import sys_scan.types;
import sys_scan.report;
import sys_scan.scanner;
import sys_scan.interfaces;
import sys_scan.system_services;
import sys_scan.config;
import sys_scan.registry;

// Import Converted Scanners
import sys_scan.scanners.auditd;
import sys_scan.scanners.systemd;
import sys_scan.scanners.process;
import sys_scan.scanners.network;
import sys_scan.scanners.kernel;
import sys_scan.scanners.mount;
import sys_scan.scanners.fs_perms;
import sys_scan.scanners.mac;
import sys_scan.scanners.integrity;
import sys_scan.scanners.ioc;
import sys_scan.scanners.container;
import sys_scan.scanners.yara;
import sys_scan.scanners.modules;
import sys_scan.scanners.ebpf;

#include <iostream>
#include <vector>
#include <memory>
#include <string>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <array>
#include <numeric>
#include <chrono>
#include <nlohmann/json.hpp>

using nlohmann::json;
using namespace sys_scan;

namespace {

void print_usage(const char* prog){
    std::cout << "Usage: " << prog << " [--output FILE] [--canonical] [--enable NAME]... [--disable NAME] [--test-root PATH]" << std::endl;
    std::cout << "Scanner toggles: --no-hardening --no-process-inventory --all-processes --no-user-meta --listen-only --fast-scan --modules-summary-only --containers --integrity --ioc-trace [--ioc-trace-seconds N] --rules-enable --yara-root PATH" << std::endl;
}

bool has_arg(int argc, char** argv, int i){ return i+1 < argc; }

bool parse_int_arg(const char* value, int& out){
    try {
        size_t idx{};
        int v = std::stoi(value, &idx);
        if(idx != std::strlen(value)) return false; // trailing junk
        out = v;
        return true;
    } catch(...) {
        return false;
    }
}

using SeverityCounts = std::array<int, 6>;

json severity_counts_json(const SeverityCounts& counts){
    static constexpr const char* names[] = {"info","low","medium","high","critical","error"};
    json obj = json::object();
    for(size_t i=0; i<counts.size(); ++i){
        obj[names[i]] = counts[i];
    }
    return obj;
}

void print_config_summary(const Config& cfg, const std::vector<std::string>& registered) {
    std::vector<std::string> enabled;
    enabled.reserve(registered.size());
    for (const auto& name : registered) {
        bool explicitly_enabled = cfg.enable_scanners.empty() || std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), name) != cfg.enable_scanners.end();
        bool explicitly_disabled = std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), name) != cfg.disable_scanners.end();
        if (explicitly_enabled && !explicitly_disabled) {
            enabled.push_back(name);
        }
    }
    std::cerr << "Scanners enabled (after filters): ";
    for (size_t i = 0; i < enabled.size(); ++i) {
        std::cerr << enabled[i];
        if (i + 1 < enabled.size()) std::cerr << ", ";
    }
    std::cerr << "\n";
}

}

int main(int argc, char** argv) {
    // 1. Defaults suited for useful output
    Config cfg;
    cfg.hardening = true;
    cfg.process_inventory = true;

    for (int i=1; i<argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { print_usage(argv[0]); return 0; }
        else if (arg == "--output" && has_arg(argc, argv, i)) { cfg.output_file = argv[++i]; }
        else if (arg == "--canonical") { cfg.canonical = true; }
        else if (arg == "--enable" || arg == "--scanner") { if(has_arg(argc,argv,i)) cfg.enable_scanners.push_back(argv[++i]); }
        else if (arg == "--disable") { if(has_arg(argc,argv,i)) cfg.disable_scanners.push_back(argv[++i]); }
        else if (arg == "--test-root") { if(has_arg(argc,argv,i)) cfg.test_root = argv[++i]; }
        else if (arg == "--no-hardening") { cfg.hardening = false; }
        else if (arg == "--no-process-inventory") { cfg.process_inventory = false; }
        else if (arg == "--all-processes") { cfg.all_processes = true; }
        else if (arg == "--no-user-meta") { cfg.no_user_meta = true; }
        else if (arg == "--listen-only") { cfg.network_listen_only = true; }
        else if (arg == "--fast-scan") { cfg.fast_scan = true; }
        else if (arg == "--modules-summary-only") { cfg.modules_summary_only = true; }
        else if (arg == "--containers") { cfg.containers = true; }
        else if (arg == "--integrity") { cfg.integrity = true; }
        else if (arg == "--ioc-trace") { cfg.ioc_exec_trace = true; }
        else if (arg == "--ioc-trace-seconds" && has_arg(argc, argv, i)) {
            int seconds = 0;
            if(!parse_int_arg(argv[++i], seconds) || seconds < 0){
                std::cerr << "Invalid value for --ioc-trace-seconds; expected non-negative integer\n";
                return 2;
            }
            cfg.ioc_exec_trace_seconds = seconds;
        }
        else if (arg == "--rules-enable") { cfg.rules_enable = true; }
        else if (arg == "--yara-root" && has_arg(argc, argv, i)) { cfg.yara_scan_roots.push_back(argv[++i]); }
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Normalize dependent flags
    if (cfg.ioc_exec_trace_seconds > 0 && !cfg.ioc_exec_trace) {
        cfg.ioc_exec_trace = true;
        std::cerr << "Info: enabling --ioc-trace because --ioc-trace-seconds was provided" << std::endl;
    }

    // 2. Composition Root: Instantiate Services
    RealFileSystem fs;
    RealProcessRunner runner;
    RealSystemInfo sysinfo;
    RealSleeper sleeper;

    // 3. Register Scanners with Dependency Injection
    ScannerRegistry registry;
    registry.register_scanner(std::make_unique<AuditdScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<SystemdUnitScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<ProcessScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<NetworkScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<KernelScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<MountScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<FsPermsScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<MACScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<IntegrityScanner>(cfg, fs, runner));
    registry.register_scanner(std::make_unique<IOCScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<ModuleScanner>(cfg, fs, sysinfo));
    registry.register_scanner(std::make_unique<ContainerScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<YaraScanner>(cfg, fs));
    registry.register_scanner(std::make_unique<EbpfScanner>(cfg, fs, sleeper));

    // 3a. Summarize effective scanners
    print_config_summary(cfg, registry.registered_names());

    // 4. Run Scanners
    Report report;
    registry.run_all(report, cfg);

    // 5. Prepare JSON (ground_truth_v1 compatible)
    json j;
    j["$schema"] = "https://github.com/J-mazz/sys-scan/schema/v4.json";
    j["version"] = "ground_truth_v1";
    j["correlations"] = json::array();
    j["reductions"] = json::object();
    j["summaries"] = json::object();
    j["actions"] = json::array();

    // Flatten raw findings into enriched_findings with minimal required fields
    std::vector<ScanResult> results = report.results();
    std::sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b){ return a.scanner_name < b.scanner_name; });
    for (auto& r : results) {
        std::sort(r.findings.begin(), r.findings.end(), [](const Finding& a, const Finding& b){ return a.id < b.id; });
    }

    // 4a. Aggregate metrics
    SeverityCounts global_counts{};
    json scanner_metrics = json::array();
    std::size_t total_findings = 0;

    json enriched = json::array();
    json raw_results = json::array();

    for (const auto& res : results) {
        SeverityCounts local_counts{};
        json raw_findings = json::array();
        for (const auto& f : res.findings) {
            json meta = json::object();
            for (const auto& kv : f.metadata) meta[kv.first] = kv.second;

            json rf;
            rf["id"] = f.id;
            rf["title"] = f.title;
            rf["severity"] = severity_to_string(f.severity);
            rf["description"] = f.description;
            rf["metadata"] = meta;
            raw_findings.push_back(rf);

            const auto idx = static_cast<size_t>(f.severity);
            if (idx < local_counts.size()) {
                ++local_counts[idx];
                ++global_counts[idx];
            }

            json ef;
            ef["id"] = f.id;
            ef["title"] = f.title;
            ef["severity"] = severity_to_string(f.severity);
            ef["risk_score"] = severity_risk_score(f.severity);
            ef["base_severity_score"] = f.base_severity_score == 0 ? severity_risk_score(f.severity) : f.base_severity_score;
            ef["description"] = f.description;
            ef["metadata"] = meta;
            ef["operational_error"] = f.operational_error;
            ef["category"] = "";
            ef["tags"] = json::array();
            ef["risk_subscores"] = {
                {"impact", 0.0}, {"exposure", 0.0}, {"anomaly", 0.0}, {"confidence", 0.0}
            };
            ef["correlation_refs"] = json::array();
            ef["baseline_status"] = "unknown";
            ef["severity_source"] = "raw";
            ef["allowlist_reason"] = nullptr;
            ef["probability_actionable"] = 0.0;
            ef["graph_degree"] = 0;
            ef["cluster_id"] = "";
            ef["rationale"] = "";
            ef["risk_total"] = ef["risk_score"];
            ef["host_role"] = "";
            ef["host_role_rationale"] = "";
            ef["metric_drift"] = json::object();
            enriched.push_back(ef);
        }

        raw_results.push_back({{"scanner", res.scanner_name}, {"findings", raw_findings}});

        const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(res.end_time - res.start_time).count();
        total_findings += res.findings.size();
        scanner_metrics.push_back({
            {"scanner", res.scanner_name},
            {"duration_ms", duration_ms},
            {"findings", res.findings.size()},
            {"severity_counts", severity_counts_json(local_counts)}
        });
    }

    // map warnings/errors
    json warn = json::array();
    for (const auto& w : report.warnings()) {
        warn.push_back({{"scanner", w.first}, {"message", w.second}});
    }
    json errs = json::array();
    for (const auto& e : report.errors()) {
        errs.push_back({{"scanner", e.first}, {"message", e.second}});
    }

    j["enriched_findings"] = enriched;
    j["raw_reference"] = {
        {"results", raw_results},
        {"warnings", warn},
        {"errors", errs}
    };

    j["metrics"] = {
        {"total_findings", total_findings},
        {"severity_counts", severity_counts_json(global_counts)},
        {"scanners", scanner_metrics}
    };

    // 6. Output
    const int indent = cfg.canonical ? 2 : -1;
    if (cfg.output_file.empty()) {
        std::cout << j.dump(indent) << std::endl;
    } else {
        std::ofstream ofs(cfg.output_file, std::ios::out | std::ios::trunc);
        if(!ofs.is_open()) {
            std::cerr << "Failed to open output file: " << cfg.output_file << "\n";
            return 3;
        }
        ofs << j.dump(indent);
        if(!ofs.good()) {
            std::cerr << "Failed to write output file: " << cfg.output_file << "\n";
            return 3;
        }
    }

    return 0;
}
// GCOVR_EXCL_STOP
