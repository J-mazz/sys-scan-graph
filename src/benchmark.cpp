#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <sys/resource.h>
#include <unistd.h>

#include "core/Config.h"
#include "core/Report.h"
#include "core/ScannerRegistry.h"
#include "core/Scanner.h"
#include "core/ScanContext.h"

namespace fs = std::filesystem;
namespace sys_scan {

class PerformanceBenchmark {
public:
    struct BenchmarkResult {
        std::string scanner_name;
        std::chrono::milliseconds duration;
        size_t findings_count;
        size_t memory_usage_kb;
        std::string status;
    };

    static void run_comprehensive_benchmark() {
        std::cout << "=== C++ Performance Benchmark Suite ===\n";
        std::cout << "Establishing performance baselines for optimization...\n\n";

        // Create test configuration
        Config cfg;
        cfg.enable_scanners = {"ioc", "processes", "suid_sgid",
                              "world_writable", "kernel_params", "modules",
                              "mac", "mounts", "kernel_hardening",
                              "systemd_units", "auditd", "containers",
                              "integrity", "yara"
#ifdef SYS_SCAN_HAVE_EBPF
                              , "ebpf_exec_trace"
#endif
                              };
        cfg.min_severity = "info";
        cfg.hardening = true;
        cfg.integrity = true;
        cfg.rules_enable = true;

        // Run individual scanner benchmarks
        std::vector<BenchmarkResult> results;

        // Test each scanner individually - expanded to include all available scanners
        std::vector<std::string> scanners = {
            "ioc", "processes", "suid_sgid",
            "world_writable", "kernel_params", "modules",
            "mac", "mounts", "kernel_hardening",
            "systemd_units", "auditd", "containers",
            "integrity", "yara"
#ifdef SYS_SCAN_HAVE_EBPF
            , "ebpf_exec_trace"
#endif
        };

        for (const auto& scanner_name : scanners) {
            auto result = benchmark_single_scanner(scanner_name, cfg);
            results.push_back(result);

            std::cout << "✓ " << scanner_name << ": "
                      << result.duration.count() << "ms, "
                      << result.findings_count << " findings\n";
        }

        // Run full scan benchmark
        std::cout << "\n--- Full Scan Benchmark ---\n";
        auto full_result = benchmark_full_scan(cfg);
        std::cout << "✓ Full scan: " << full_result.duration.count() << "ms, "
                  << full_result.findings_count << " total findings\n";

        // Generate performance report
        generate_performance_report(results, full_result);

        std::cout << "\n=== Benchmark Complete ===\n";
        std::cout << "Results saved to: performance_baseline.json\n";
    }

private:
    static BenchmarkResult benchmark_single_scanner(const std::string& scanner_name, const Config& cfg) {
        BenchmarkResult result;
        result.scanner_name = scanner_name;

        try {
            // Create report and scanner registry
            Report report;
            ScannerRegistry registry;

            // Create config with only the target scanner enabled
            Config single_cfg = cfg;
            single_cfg.enable_scanners = {scanner_name};
            single_cfg.disable_scanners.clear();

            // Register all default scanners with config
            registry.register_all_default(single_cfg);

            // Create scan context
            ScanContext context(single_cfg, report);

            // Measure execution time
            auto start = std::chrono::high_resolution_clock::now();

            // Run the scanner
            registry.run_all(context);

            auto end = std::chrono::high_resolution_clock::now();
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            result.findings_count = report.total_findings();
            result.status = "success";

            // Estimate memory usage (simplified)
            result.memory_usage_kb = estimate_memory_usage();

        } catch (const std::exception& e) {
            result.status = std::string("error: ") + e.what();
            result.duration = std::chrono::milliseconds(0);
            result.findings_count = 0;
        }

        return result;
    }

    static BenchmarkResult benchmark_full_scan(const Config& cfg) {
        BenchmarkResult result;
        result.scanner_name = "full_scan";

        try {
            // Create report and scanner registry
            Report report;
            ScannerRegistry registry;

            // Register all default scanners with config
            registry.register_all_default(cfg);

            // Create scan context
            ScanContext context(cfg, report);

            // Measure execution time
            auto start = std::chrono::high_resolution_clock::now();

            // Run all scanners
            registry.run_all(context);

            auto end = std::chrono::high_resolution_clock::now();
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            result.findings_count = report.total_findings();
            result.status = "success";

            // Estimate memory usage
            result.memory_usage_kb = estimate_memory_usage();

        } catch (const std::exception& e) {
            result.status = std::string("error: ") + e.what();
            result.duration = std::chrono::milliseconds(0);
            result.findings_count = 0;
        }

        return result;
    }

    static size_t estimate_memory_usage() {
        // Use getrusage for more accurate memory measurement
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            // Return maximum resident set size in KB
            return usage.ru_maxrss;
        }
        // Fallback to simple estimate
        return 1024 * 10; // 10MB estimate
    }

    static void generate_performance_report(const std::vector<BenchmarkResult>& results,
                                          const BenchmarkResult& full_result) {
        std::ofstream report_file("performance_baseline.json");
        report_file << "{\n";
        report_file << "  \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
        report_file << "  \"system_info\": {\n";
        report_file << "    \"cpu_cores\": " << std::thread::hardware_concurrency() << ",\n";
        report_file << "    \"hostname\": \"" << get_hostname() << "\"\n";
        report_file << "  },\n";
        report_file << "  \"individual_scanners\": [\n";

        for (size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            report_file << "    {\n";
            report_file << "      \"name\": \"" << result.scanner_name << "\",\n";
            report_file << "      \"duration_ms\": " << result.duration.count() << ",\n";
            report_file << "      \"findings_count\": " << result.findings_count << ",\n";
            report_file << "      \"memory_kb\": " << result.memory_usage_kb << ",\n";
            report_file << "      \"status\": \"" << result.status << "\"\n";
            report_file << "    }";
            if (i < results.size() - 1) report_file << ",";
            report_file << "\n";
        }

        report_file << "  ],\n";
        report_file << "  \"full_scan\": {\n";
        report_file << "    \"duration_ms\": " << full_result.duration.count() << ",\n";
        report_file << "    \"findings_count\": " << full_result.findings_count << ",\n";
        report_file << "    \"memory_kb\": " << full_result.memory_usage_kb << ",\n";
        report_file << "    \"status\": \"" << full_result.status << "\"\n";
        report_file << "  }\n";
        report_file << "}\n";
    }

    static std::string get_hostname() {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            return std::string(hostname);
        }
        return "unknown";
    }
};

} // namespace sys_scan

int main(int argc, char* argv[]) {
    try {
        sys_scan::PerformanceBenchmark::run_comprehensive_benchmark();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Benchmark failed: " << e.what() << std::endl;
        return 1;
    }
}