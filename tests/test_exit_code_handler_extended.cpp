#include "core/ExitCodeHandler.h"
#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include <gtest/gtest.h>
#include <vector>
#include <limits>

namespace sys_scan {

class ExitCodeHandlerExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }

    ExitCodeHandler handler;
};

// Test exit code with extreme severity scores
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeExtremeSeverityScores) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    // Test with high severity finding
    ScanResult result;
    result.scanner_name = "extreme_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "extreme_finding",
        "Finding with extreme severity",
        Severity::High,
        "Description",
        {},
        100,  // High severity score
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed medium threshold
}

// Test exit code with minimum severity scores
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeMinimumSeverityScores) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    // Test with low severity finding
    ScanResult result;
    result.scanner_name = "min_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "min_finding",
        "Finding with minimum severity",
        Severity::Low,
        "Description",
        {},
        10,  // Low severity score
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // Should not exceed medium threshold
}

// Test exit code with very large number of findings
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeLargeFindingCount) {
    Config cfg;
    cfg.fail_on_count = 50;  // Set count threshold

    Report report;

    ScanResult result;
    result.scanner_name = "large_count_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add many findings with low severity
    for (int i = 0; i < 100; ++i) {
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description " + std::to_string(i),
            {},
            10,  // Low severity
            false
        });
    }
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed count threshold
}

// Test exit code with mixed severity levels and threshold boundaries
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeMixedSeveritiesBoundary) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    ScanResult result;
    result.scanner_name = "boundary_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add findings at threshold boundary
    result.findings.push_back(Finding{"below_threshold", "Below threshold", Severity::Low, "Description", {}, 30, false});
    result.findings.push_back(Finding{"at_threshold", "At threshold", Severity::Medium, "Description", {}, 50, false});
    result.findings.push_back(Finding{"above_threshold", "Above threshold", Severity::High, "Description", {}, 80, false});

    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed threshold due to medium/high findings
}

// Test exit code with zero count threshold
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeZeroCountThreshold) {
    Config cfg;
    cfg.fail_on_count = 0;  // Any finding should fail

    Report report;

    ScanResult result;
    result.scanner_name = "zero_threshold_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "any_finding",
        "Any finding",
        Severity::Info,
        "Description",
        {},
        1,  // Any positive severity
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed zero count threshold
}

// Test exit code with maximum count threshold
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeMaximumCountThreshold) {
    Config cfg;
    cfg.fail_on_count = std::numeric_limits<int>::max();  // Very high threshold

    Report report;

    ScanResult result;
    result.scanner_name = "max_threshold_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "single_finding",
        "Single finding",
        Severity::High,
        "Description",
        {},
        100,
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // Should not exceed maximum count threshold
}

// Test exit code with negative count threshold
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeNegativeCountThreshold) {
    Config cfg;
    cfg.fail_on_count = -1;  // Negative threshold (should be ignored)

    Report report;

    ScanResult result;
    result.scanner_name = "negative_threshold_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "negative_severity_finding",
        "Finding with negative severity",
        Severity::Info,
        "Description",
        {},
        -10,  // Negative severity
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // Negative count threshold should be ignored
}

// Test exit code with empty report
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeEmptyReport) {
    Config cfg;
    cfg.fail_on_severity = "medium";

    Report report;  // Empty report with no results

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // Empty report should return success
}

// Test exit code with multiple scanners having different severities
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeMultipleScannersMixedSeverities) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    // Scanner 1 with low severity findings
    ScanResult result1;
    result1.scanner_name = "low_severity_scanner";
    result1.start_time = std::chrono::system_clock::now();
    result1.end_time = std::chrono::system_clock::now();
    result1.findings.push_back(Finding{"low_finding", "Low finding", Severity::Low, "Description", {}, 30, false});
    report.add_result(result1);

    // Scanner 2 with high severity findings
    ScanResult result2;
    result2.scanner_name = "high_severity_scanner";
    result2.start_time = std::chrono::system_clock::now();
    result2.end_time = std::chrono::system_clock::now();
    result2.findings.push_back(Finding{"high_finding", "High finding", Severity::High, "Description", {}, 90, false});
    report.add_result(result2);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed threshold due to high severity finding
}

// Test exit code with findings having zero severity
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeZeroSeverityFindings) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    ScanResult result;
    result.scanner_name = "zero_severity_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add multiple findings with zero severity
    for (int i = 0; i < 10; ++i) {
        result.findings.push_back(Finding{
            "zero_severity_" + std::to_string(i),
            "Zero severity finding " + std::to_string(i),
            Severity::Info,
            "Description " + std::to_string(i),
            {},
            0,  // Zero severity
            false
        });
    }
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // Zero severity should not exceed medium threshold
}

// Test exit code with very high threshold and very low severity findings
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeHighThresholdLowSeverity) {
    Config cfg;
    cfg.fail_on_severity = "critical";  // Very high threshold

    Report report;

    ScanResult result;
    result.scanner_name = "high_threshold_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add findings with very low severity
    result.findings.push_back(Finding{"very_low_1", "Very low severity 1", Severity::Info, "Description", {}, 1, false});
    result.findings.push_back(Finding{"very_low_2", "Very low severity 2", Severity::Low, "Description", {}, 5, false});
    result.findings.push_back(Finding{"very_low_3", "Very low severity 3", Severity::Medium, "Description", {}, 25, false});

    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // All findings below critical threshold
}

// Test exit code with threshold exactly matching finding severity
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeThresholdEqualsSeverity) {
    Config cfg;
    cfg.fail_on_severity = "high";  // Set threshold to high

    Report report;

    ScanResult result;
    result.scanner_name = "exact_threshold_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{"exact_match", "Exact threshold match", Severity::High, "Description", {}, 80, false});

    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed threshold when severity equals threshold
}

// Test exit code with multiple findings where only some exceed threshold
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodePartialThresholdExceedance) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    ScanResult result;
    result.scanner_name = "partial_exceed_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Mix of findings below and above threshold
    result.findings.push_back(Finding{"below_1", "Below threshold 1", Severity::Low, "Description", {}, 30, false});
    result.findings.push_back(Finding{"below_2", "Below threshold 2", Severity::Low, "Description", {}, 40, false});
    result.findings.push_back(Finding{"above_1", "Above threshold 1", Severity::High, "Description", {}, 80, false});
    result.findings.push_back(Finding{"below_3", "Below threshold 3", Severity::Medium, "Description", {}, 50, false});

    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed threshold due to high severity finding
}

// Test exit code with scanner results having no findings
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeScannerWithNoFindings) {
    Config cfg;
    cfg.fail_on_severity = "medium";  // Set threshold to medium

    Report report;

    // Add scanner with no findings
    ScanResult result;
    result.scanner_name = "empty_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    // No findings added
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0);  // No findings should result in success
}

// Test exit code with very large count threshold and maximum severity findings
TEST_F(ExitCodeHandlerExtendedTest, CalculateExitCodeLargeCountThresholdMaxSeverity) {
    Config cfg;
    cfg.fail_on_count = 1000;  // Very large count threshold
    cfg.fail_on_severity = "info";  // Very low severity threshold

    Report report;

    ScanResult result;
    result.scanner_name = "large_threshold_max_severity_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "max_severity_few_findings",
        "Maximum severity with few findings",
        Severity::High,
        "Description",
        {},
        100,
        false
    });
    report.add_result(result);

    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1);  // Should exceed severity threshold despite large count threshold
}

} // namespace sys_scan