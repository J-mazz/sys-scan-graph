#include "core/ExitCodeHandler.h"
#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include <gtest/gtest.h>
#include <vector>
#include <memory>

namespace sys_scan {

class ExitCodeHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }

    ExitCodeHandler handler;
};

// Test exit code with no findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeNoFindings) {
    Config cfg;
    Report report;

    // No findings should result in exit code 0
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with info severity findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeInfoFindings) {
    Config cfg;
    Report report;

    // Create a scan result with info severity finding
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_finding",
        "Test Finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });

    report.add_result(result);

    // Info findings should result in exit code 0 (below fail threshold)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with low severity findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeLowFindings) {
    Config cfg;
    Report report;

    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "low_finding",
        "Low finding",
        Severity::Low,
        "Description",
        {},
        30,
        false
    });
    report.add_result(result);

    // Low findings should result in exit code 0 (below fail threshold)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with medium severity findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeMediumFindings) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    Report report;

    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "medium_finding",
        "Medium finding",
        Severity::Medium,
        "Description",
        {},
        50,
        false
    });
    report.add_result(result);

    // Medium findings with medium fail threshold should result in exit code 1
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with high severity findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeHighFindings) {
    Config cfg;
    cfg.fail_on_severity = "high";
    Report report;

    // Create a scan result with high severity finding
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_finding",
        "Test Finding",
        Severity::High,
        "Description",
        {},
        80,
        false
    });

    report.add_result(result);

    // High findings with high fail threshold should result in exit code 1
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with mixed severity findings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeMixedFindings) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    Report report;

    // Create a scan result with mixed severity findings
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "info_finding",
        "Info finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });
    result.findings.push_back(Finding{
        "low_finding",
        "Low finding",
        Severity::Low,
        "Description",
        {},
        30,
        false
    });
    result.findings.push_back(Finding{
        "medium_finding",
        "Medium finding",
        Severity::Medium,
        "Description",
        {},
        50,
        false
    });

    report.add_result(result);

    // Mixed findings with medium threshold should result in exit code 1 (due to medium finding)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with count threshold
TEST_F(ExitCodeHandlerTest, CalculateExitCodeCountThreshold) {
    Config cfg;
    cfg.fail_on_count = 3;
    Report report;

    // Create a scan result with exactly 3 findings
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add exactly 3 findings
    for (int i = 0; i < 3; ++i) {
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description",
            {},
            10,
            false
        });
    }
    report.add_result(result);

    // Exactly 3 findings should result in exit code 1
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code below count threshold
TEST_F(ExitCodeHandlerTest, CalculateExitCodeBelowCountThreshold) {
    Config cfg;
    cfg.fail_on_count = 5;
    Report report;

    // Create a scan result with only 3 findings (below threshold)
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add only 3 findings (below threshold)
    for (int i = 0; i < 3; ++i) {
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description",
            {},
            10,
            false
        });
    }
    report.add_result(result);

    // Below count threshold should result in exit code 0
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with both severity and count thresholds
TEST_F(ExitCodeHandlerTest, CalculateExitCodeSeverityAndCount) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 2;
    Report report;

    // Create a scan result with 2 low severity findings
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add 2 low severity findings (below severity threshold but at count threshold)
    for (int i = 0; i < 2; ++i) {
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Low,
            "Description",
            {},
            30,
            false
        });
    }
    report.add_result(result);

    // Should result in exit code 0 (severity threshold not met, even though count is met)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with multiple scanner results
TEST_F(ExitCodeHandlerTest, CalculateExitCodeMultipleScanners) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    Report report;

    // Scanner 1: Low severity findings
    ScanResult result1;
    result1.scanner_name = "scanner1";
    result1.start_time = std::chrono::system_clock::now();
    result1.end_time = std::chrono::system_clock::now();
    result1.findings.push_back(Finding{
        "low_finding",
        "Low finding",
        Severity::Low,
        "Description",
        {},
        30,
        false
    });
    report.add_result(result1);

    // Scanner 2: Medium severity findings
    ScanResult result2;
    result2.scanner_name = "scanner2";
    result2.start_time = std::chrono::system_clock::now();
    result2.end_time = std::chrono::system_clock::now();
    result2.findings.push_back(Finding{
        "medium_finding",
        "Medium finding",
        Severity::Medium,
        "Description",
        {},
        50,
        false
    });
    report.add_result(result2);

    // Should result in exit code 1 (due to medium finding in scanner 2)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with empty scanner results
TEST_F(ExitCodeHandlerTest, CalculateExitCodeEmptyScannerResults) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    Report report;

    // Add empty scanner result
    ScanResult result;
    result.scanner_name = "empty_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    // No findings added
    report.add_result(result);

    // Should result in exit code 0 (no findings)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

// Test exit code with high severity findings and low threshold
TEST_F(ExitCodeHandlerTest, CalculateExitCodeHighSeverityLowThreshold) {
    Config cfg;
    cfg.fail_on_severity = "low";  // Low threshold
    Report report;

    // Create a scan result with high severity finding
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "high_finding",
        "High finding",
        Severity::High,
        "Description",
        {},
        80,
        false
    });
    report.add_result(result);

    // High severity with low threshold should result in exit code 1
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code calculation with different severity rankings
TEST_F(ExitCodeHandlerTest, CalculateExitCodeSeverityRanking) {
    Config cfg;
    cfg.fail_on_severity = "medium";
    Report report;

    // Create a scan result with findings of different severities
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add findings of different severities
    result.findings.push_back(Finding{"info", "Info", Severity::Info, "Desc", {}, 10, false});
    result.findings.push_back(Finding{"low", "Low", Severity::Low, "Desc", {}, 30, false});
    result.findings.push_back(Finding{"medium", "Medium", Severity::Medium, "Desc", {}, 50, false});
    result.findings.push_back(Finding{"high", "High", Severity::High, "Desc", {}, 80, false});
    report.add_result(result);

    // Should result in exit code 1 (highest severity is high, which exceeds medium threshold)
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with zero count threshold
TEST_F(ExitCodeHandlerTest, CalculateExitCodeZeroCountThreshold) {
    Config cfg;
    cfg.fail_on_count = 0;  // Any finding should fail
    Report report;

    // Create a scan result with any finding
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "any_finding",
        "Any finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });
    report.add_result(result);

    // Any finding with zero count threshold should result in exit code 1
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 1);
}

// Test exit code with very high count threshold
TEST_F(ExitCodeHandlerTest, CalculateExitCodeHighCountThreshold) {
    Config cfg;
    cfg.fail_on_count = 1000;  // Very high threshold
    Report report;

    // Create a scan result with only a few findings
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add only a few findings
    for (int i = 0; i < 5; ++i) {
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description",
            {},
            10,
            false
        });
    }
    report.add_result(result);

    // Few findings with high count threshold should result in exit code 0
    EXPECT_EQ(handler.calculate_exit_code(report, cfg), 0);
}

} // namespace sys_scan