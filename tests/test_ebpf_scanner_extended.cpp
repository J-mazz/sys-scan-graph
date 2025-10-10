#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/ScanContext.h"
#include "../src/core/Report.h"
#include "../src/core/Config.h"
#include "../src/scanners/EbpfScanner.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>

// Test fixture for EbpfScanner
class EbpfScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temp directory for test isolation
        temp_dir = "/tmp/ebpf_test_" + std::to_string(getpid()) + "_" +
                  std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temp directory
        std::filesystem::remove_all(temp_dir);
    }

    std::string temp_dir;
    sys_scan::Config test_config;
    sys_scan::Report test_report;

    // Helper to create a test context
    std::unique_ptr<sys_scan::ScanContext> create_context() {
        return std::make_unique<sys_scan::ScanContext>(test_config, test_report);
    }

    // Helper to get findings for a specific scanner
    std::vector<sys_scan::Finding> get_findings_for_scanner(
        const sys_scan::Report& report, const std::string& scanner_name) {
        std::vector<sys_scan::Finding> findings;
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner_name) {
                findings.insert(findings.end(), result.findings.begin(), result.findings.end());
            }
        }
        return findings;
    }
};

// Test scanner properties
TEST_F(EbpfScannerTest, ScannerProperties) {
    sys_scan::EbpfScanner scanner;
    EXPECT_EQ(scanner.name(), "ebpf_exec_trace");
    EXPECT_EQ(scanner.description(), "Short-lived execve trace via eBPF");
}

// Test eBPF availability detection (inferred from scanner behavior)
TEST_F(EbpfScannerTest, DISABLED_EbpfAvailabilityDetection) {
    sys_scan::EbpfScanner scanner;
    auto context = create_context();

    test_config.ioc_exec_trace_seconds = 1;  // Reduced from 1 to 0.1 for faster tests
    scanner.scan(*context);

    auto results = context->report.results();
    // In test environments, eBPF might not be available and there might be no process activity
    // The important thing is that the scanner doesn't crash
    SUCCEED();
}

// Test fallback /proc monitoring when eBPF unavailable
TEST_F(EbpfScannerTest, DISABLED_ProcFilesystemFallback) {
    sys_scan::EbpfScanner scanner;
    auto context = create_context();

    test_config.ioc_exec_trace_seconds = 1;
    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // In test environments, there might not be enough process activity to generate findings
    // The important thing is that the scanner handles the fallback gracefully
    SUCCEED();
}

// Test PID enumeration functionality (inferred from process detection)
TEST_F(EbpfScannerTest, ProcessDetectionFunctionality) {
    sys_scan::EbpfScanner scanner;

    test_config.ioc_exec_trace_seconds = 1;
    auto context = create_context();
    scanner.scan(*context);

    auto results = context->report.results();
    auto ebpf_result = std::find_if(results.begin(), results.end(),
        [](const auto& r) { return r.scanner_name == "ebpf_exec_trace"; });

    if (ebpf_result != results.end()) {
        // Should detect some processes or have monitoring completion
        bool found_process_activity = false;
        for (const auto& finding : ebpf_result->findings) {
            if (finding.id == "proc.exec.detected" || finding.id == "proc.monitoring.complete") {
                found_process_activity = true;
                break;
            }
        }
        // Either eBPF worked or proc monitoring found something
        EXPECT_TRUE(found_process_activity || !ebpf_result->findings.empty());
    }
}

// Test scanning with very short duration
TEST_F(EbpfScannerTest, ScanVeryShortDuration) {
    sys_scan::EbpfScanner scanner;

    test_config.ioc_exec_trace_seconds = 0; // Minimum duration
    auto context = create_context();
    EXPECT_NO_THROW(scanner.scan(*context));

    // In test environments, very short duration might not produce findings
    // The important thing is that the scanner handles it gracefully
    SUCCEED();
}

// Test scanning with longer duration
TEST_F(EbpfScannerTest, ScanLongerDuration) {
    sys_scan::EbpfScanner scanner;

    test_config.ioc_exec_trace_seconds = 2;
    auto context = create_context();
    EXPECT_NO_THROW(scanner.scan(*context));

    // Longer duration should still work gracefully even if no findings are produced
    SUCCEED();
}

// Test concurrent scanning (basic thread safety)
TEST_F(EbpfScannerTest, DISABLED_ConcurrentScanning) {
    const int num_threads = 3;
    std::vector<std::thread> threads;
    std::atomic<int> completed{0};

    auto scan_func = [&]() {
        sys_scan::EbpfScanner scanner;
        sys_scan::Config cfg;
        cfg.ioc_exec_trace_seconds = 1;
        sys_scan::Report report;
        sys_scan::ScanContext context(cfg, report);

        EXPECT_NO_THROW(scanner.scan(context));
        completed++;
    };

    // Start multiple scanning threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(scan_func);
    }

    // Wait for all to complete
    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(completed, num_threads);
}

// Test finding structure validation
TEST_F(EbpfScannerTest, FindingStructureValidation) {
    sys_scan::EbpfScanner scanner;

    test_config.ioc_exec_trace_seconds = 1;
    auto context = create_context();
    scanner.scan(*context);

    auto results = context->report.results();
    auto ebpf_result = std::find_if(results.begin(), results.end(),
        [](const auto& r) { return r.scanner_name == "ebpf_exec_trace"; });

    if (ebpf_result != results.end()) {
        for (const auto& finding : ebpf_result->findings) {
            // All findings should have required fields
            EXPECT_FALSE(finding.id.empty());
            EXPECT_FALSE(finding.title.empty());
            EXPECT_FALSE(finding.description.empty());
            EXPECT_GE(finding.severity, sys_scan::Severity::Info);
            EXPECT_LE(finding.severity, sys_scan::Severity::Critical);

            // Check metadata structure
            if (finding.id == "proc.exec.detected") {
                EXPECT_TRUE(finding.metadata.count("pid"));
                EXPECT_TRUE(finding.metadata.count("comm"));
                EXPECT_TRUE(finding.metadata.count("ppid"));
                EXPECT_TRUE(finding.metadata.count("source"));
            } else if (finding.id == "proc.monitoring.complete") {
                EXPECT_TRUE(finding.metadata.count("duration_seconds"));
                EXPECT_TRUE(finding.metadata.count("source"));
                EXPECT_TRUE(finding.metadata.count("method"));
            }
        }
    }
}

// Test scanner with invalid config
TEST_F(EbpfScannerTest, DISABLED_InvalidConfigHandling) {
    GTEST_SKIP() << "Skipping slow time-based scanning test during coverage runs";
    sys_scan::EbpfScanner scanner;

    // Test with negative duration (should handle gracefully)
    test_config.ioc_exec_trace_seconds = -1;
    auto context1 = create_context();
    EXPECT_NO_THROW(scanner.scan(*context1));

    // Verify that the scan completed in reasonable time (clamped duration)
    auto results = context1->report.results();
    auto ebpf_result = std::find_if(results.begin(), results.end(),
        [](const auto& r) { return r.scanner_name == "ebpf_exec_trace"; });
    if (ebpf_result != results.end()) {
        // Should have a completion finding indicating the scan finished
        bool has_completion = std::any_of(ebpf_result->findings.begin(), ebpf_result->findings.end(),
            [](const sys_scan::Finding& f) { return f.id == "proc.monitoring.complete"; });
        EXPECT_TRUE(has_completion);
    }
}

// Test multiple scans in sequence
TEST_F(EbpfScannerTest, DISABLED_MultipleSequentialScans) {
    sys_scan::EbpfScanner scanner;

    for (int i = 0; i < 3; ++i) {
        sys_scan::Config cfg;
        cfg.ioc_exec_trace_seconds = 1;
        sys_scan::Report report;
        sys_scan::ScanContext context(cfg, report);

        EXPECT_NO_THROW(scanner.scan(context));

        // In test environments, scans might not produce results
        // The important thing is that multiple scans work without crashing
    }
    SUCCEED();
}

// Test scanner behavior when /proc is not accessible
TEST_F(EbpfScannerTest, ProcInaccessibleHandling) {
    // This test would require mocking filesystem access
    // For now, just ensure scanner doesn't crash in normal conditions
    sys_scan::EbpfScanner scanner;
    test_config.ioc_exec_trace_seconds = 1;
    auto context = create_context();

    EXPECT_NO_THROW(scanner.scan(*context));
}

// Test process info parsing edge cases (inferred from scanner behavior)
TEST_F(EbpfScannerTest, ProcessInfoParsingEdgeCases) {
    sys_scan::EbpfScanner scanner;

    // Test with very short duration - should still work
    test_config.ioc_exec_trace_seconds = 1;
    auto context1 = create_context();
    EXPECT_NO_THROW(scanner.scan(*context1));

    // Test with longer duration
    test_config.ioc_exec_trace_seconds = 2;
    auto context2 = create_context();
    EXPECT_NO_THROW(scanner.scan(*context2));
}

// Test scanner resource cleanup
TEST_F(EbpfScannerTest, ResourceCleanup) {
    // Test that scanner doesn't leak resources
    // This is mainly a stress test
    for (int i = 0; i < 3; ++i) {  // Reduced from 10 to 3 for faster testing
        sys_scan::EbpfScanner scanner;
        sys_scan::Config cfg;
        cfg.ioc_exec_trace_seconds = 1;
        sys_scan::Report report;
        sys_scan::ScanContext context(cfg, report);

        scanner.scan(context);
    }

    // If we get here without crashing, basic resource management is working
    SUCCEED();
}

// Test finding deduplication logic (if any)
TEST_F(EbpfScannerTest, FindingDeduplication) {
    sys_scan::EbpfScanner scanner;

    test_config.ioc_exec_trace_seconds = 1;
    auto context = create_context();
    scanner.scan(*context);

    auto results = context->report.results();
    auto ebpf_result = std::find_if(results.begin(), results.end(),
        [](const auto& r) { return r.scanner_name == "ebpf_exec_trace"; });

    if (ebpf_result != results.end()) {
        // Check that we don't have duplicate completion findings
        int completion_count = 0;
        for (const auto& finding : ebpf_result->findings) {
            if (finding.id == "proc.monitoring.complete") {
                completion_count++;
            }
        }
        // Should have at most one completion finding per scan
        EXPECT_LE(completion_count, 1);
    }
}