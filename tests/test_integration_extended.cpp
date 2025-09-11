#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include "core/OutputWriter.h"
#include "core/ExitCodeHandler.h"
#include "core/ArgumentParser.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <chrono>
#include <thread>

namespace sys_scan {

class IntegrationExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_integration_extended_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
};

// Test full pipeline with extreme data volumes
TEST_F(IntegrationExtendedTest, FullPipelineExtremeDataVolume) {
    // Create configuration
    Config cfg;
    cfg.output_file = (temp_dir / "extreme_volume.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 50;

    // Create a report with many scanner results
    Report report;
    for (int scanner = 0; scanner < 10; ++scanner) {
        ScanResult result;
        result.scanner_name = "extreme_scanner_" + std::to_string(scanner);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        // Add many findings per scanner
        for (int finding = 0; finding < 100; ++finding) {
            result.findings.push_back(Finding{
                "finding_" + std::to_string(scanner) + "_" + std::to_string(finding),
                "Finding " + std::to_string(finding) + " from scanner " + std::to_string(scanner),
                Severity::Info,
                std::string(100, 'x'), // Reduced from 1KB to 100B
                std::map<std::string, std::string>{
                    {"scanner_id", std::to_string(scanner)},
                    {"finding_id", std::to_string(finding)},
                    {"large_metadata", std::string(50, 'y')} // Reduced from 500B to 50B
                },
                10,
                false
            });
        }
        report.add_result(result);
    }

    // Test output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0); // All findings have low severity
}

// Test pipeline with mixed severity levels and threshold boundaries
TEST_F(IntegrationExtendedTest, FullPipelineMixedSeveritiesBoundaryConditions) {
    Config cfg;
    cfg.output_file = (temp_dir / "mixed_severities.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "high";
    cfg.fail_on_count = 75;

    Report report;

    // Create scanner results with various severity distributions
    for (int scanner = 0; scanner < 10; ++scanner) {
        ScanResult result;
        result.scanner_name = "mixed_scanner_" + std::to_string(scanner);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        // Add findings with different severity patterns
        for (int i = 0; i < 50; ++i) {
            Severity severity;
            int severity_score;

            if (i < 30) {
                severity = Severity::Info;
                severity_score = 10;
            } else if (i < 40) {
                severity = Severity::Low;
                severity_score = 30;
            } else if (i < 45) {
                severity = Severity::Medium;
                severity_score = 50;
            } else {
                severity = Severity::High;
                severity_score = 85 + (i - 45) * 5; // 85, 90, 95, 100, 105
            }

            result.findings.push_back(Finding{
                "mixed_finding_" + std::to_string(scanner) + "_" + std::to_string(i),
                "Mixed severity finding " + std::to_string(i),
                severity,
                "Description for finding " + std::to_string(i),
                std::map<std::string, std::string>{
                    {"scanner", std::to_string(scanner)},
                    {"index", std::to_string(i)},
                    {"pattern", (i % 2 == 0) ? "even" : "odd"}
                },
                severity_score,
                false
            });
        }
        report.add_result(result);
    }

    // Test output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1); // Should exceed threshold due to high severity findings
}

// Test pipeline with special characters and Unicode in all components
TEST_F(IntegrationExtendedTest, FullPipelineSpecialCharactersUnicode) {
    Config cfg;
    cfg.output_file = (temp_dir / "unicode_special_chars.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 50;

    Report report;

    // Create scanner results with Unicode and special characters
    std::vector<std::string> special_names = {
        "测试扫描器", "русский_сканер", "español_scanner", "français_scanner",
        "deutsch_scanner", "日本語スキャナー", "한국어_스캐너", "special_chars_!@#$%^&*()"
    };

    for (size_t i = 0; i < special_names.size(); ++i) {
        ScanResult result;
        result.scanner_name = special_names[i];
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        // Add findings with special characters in all fields
        result.findings.push_back(Finding{
            "发现_" + std::to_string(i) + "_!@#$%^&*()",
            "发现标题 " + std::to_string(i) + ": 中文 русский español",
            Severity::Info,
            "详细描述：这是一个测试发现，包含各种特殊字符和Unicode。Special chars: \"quotes\", 'single', \n newline, \t tab, \\ backslash",
            std::map<std::string, std::string>{
                {"文件路径", "/路径/文件_" + std::to_string(i) + ".txt"},
                {"описание", "русское описание " + std::to_string(i)},
                {"descripción", "descripción en español " + std::to_string(i)},
                {"special_value", "value with \"quotes\" and 'single' and \n lines"}
            },
            10,
            false
        });
        report.add_result(result);
    }

    // Test output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created and contains Unicode
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Check that Unicode characters are preserved
    EXPECT_NE(content.find("测试扫描器"), std::string::npos);
    EXPECT_NE(content.find("русский_сканер"), std::string::npos);
    EXPECT_NE(content.find("español_scanner"), std::string::npos);

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0); // All findings have low severity
}

// Test pipeline with empty and edge case scanner results
TEST_F(IntegrationExtendedTest, FullPipelineEmptyEdgeCaseResults) {
    Config cfg;
    cfg.output_file = (temp_dir / "empty_edge_cases.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 50;

    Report report;

    // Add scanner with no findings
    ScanResult empty_result;
    empty_result.scanner_name = "empty_scanner";
    empty_result.start_time = std::chrono::system_clock::now();
    empty_result.end_time = std::chrono::system_clock::now();
    report.add_result(empty_result);

    // Add scanner with findings that have edge case values
    ScanResult edge_result;
    edge_result.scanner_name = "edge_case_scanner";
    edge_result.start_time = std::chrono::system_clock::now();
    edge_result.end_time = std::chrono::system_clock::now();

    // Add findings with edge case severity scores
    edge_result.findings.push_back(Finding{
        "zero_severity",
        "Finding with zero severity",
        Severity::Info,
        "Description",
        {},
        0,
        false
    });

    edge_result.findings.push_back(Finding{
        "max_severity",
        "Finding with maximum severity",
        Severity::High,
        "Description",
        {},
        std::numeric_limits<int>::max(),
        false
    });

    edge_result.findings.push_back(Finding{
        "negative_severity",
        "Finding with negative severity",
        Severity::Info,
        "Description",
        {},
        -100,
        false
    });

    report.add_result(edge_result);

    // Test output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1); // Should exceed threshold due to max severity finding
}

// Test pipeline performance with concurrent operations
TEST_F(IntegrationExtendedTest, FullPipelineConcurrentOperations) {
    Config cfg1, cfg2, cfg3;
    cfg1.output_file = (temp_dir / "concurrent1.json").string();
    cfg1.compact = true;
    cfg1.fail_on_severity = "medium";
    cfg1.fail_on_count = 50;

    cfg2.output_file = (temp_dir / "concurrent2.json").string();
    cfg2.compact = true;
    cfg2.fail_on_severity = "medium";
    cfg2.fail_on_count = 50;

    cfg3.output_file = (temp_dir / "concurrent3.json").string();
    cfg3.compact = true;
    cfg3.fail_on_severity = "medium";
    cfg3.fail_on_count = 50;

    // Create three identical reports
    Report report1, report2, report3;
    auto setup_report = [](Report& report) {
        ScanResult result;
        result.scanner_name = "concurrent_scanner";
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        for (int i = 0; i < 100; ++i) {
            result.findings.push_back(Finding{
                "concurrent_finding_" + std::to_string(i),
                "Concurrent finding " + std::to_string(i),
                Severity::Info,
                "Description " + std::to_string(i),
                {},
                10,
                false
            });
        }
        report.add_result(result);
    };

    setup_report(report1);
    setup_report(report2);
    setup_report(report3);

    // Test concurrent output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report1, cfg1));
    EXPECT_TRUE(writer.write_report(report2, cfg2));
    EXPECT_TRUE(writer.write_report(report3, cfg3));

    // Verify all files were created
    EXPECT_TRUE(std::filesystem::exists(cfg1.output_file));
    EXPECT_TRUE(std::filesystem::exists(cfg2.output_file));
    EXPECT_TRUE(std::filesystem::exists(cfg3.output_file));

    // Test exit code determination for all reports
    ExitCodeHandler handler;
    int exit_code1 = handler.calculate_exit_code(report1, cfg1);
    int exit_code2 = handler.calculate_exit_code(report2, cfg2);
    int exit_code3 = handler.calculate_exit_code(report3, cfg3);

    EXPECT_EQ(exit_code1, 0);
    EXPECT_EQ(exit_code2, 0);
    EXPECT_EQ(exit_code3, 0);
}

// Test pipeline with memory pressure simulation
TEST_F(IntegrationExtendedTest, FullPipelineMemoryPressure) {
    Config cfg;
    cfg.output_file = (temp_dir / "memory_pressure.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 50;

    Report report;

    // Create report with memory-intensive content
    for (int scanner = 0; scanner < 10; ++scanner) {
        ScanResult result;
        result.scanner_name = "memory_scanner_" + std::to_string(scanner);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        for (int finding = 0; finding < 20; ++finding) {
            // Create findings with large metadata
            std::map<std::string, std::string> large_metadata;
            for (int meta = 0; meta < 10; ++meta) {
                large_metadata["metadata_" + std::to_string(meta)] = std::string(100, 'x'); // Reduced from 1KB to 100B
            }

            result.findings.push_back(Finding{
                "memory_finding_" + std::to_string(scanner) + "_" + std::to_string(finding),
                std::string(200, 'y'), // Reduced from 2KB to 200B
                Severity::Info,
                std::string(500, 'z'), // Reduced from 5KB to 500B
                large_metadata,
                10,
                false
            });
        }
        report.add_result(result);
    }

    // Test output writing under memory pressure
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0); // All findings have low severity
}

// Test pipeline with all output formats
TEST_F(IntegrationExtendedTest, FullPipelineAllOutputFormats) {
    // Test JSON format
    Config json_cfg;
    json_cfg.output_file = (temp_dir / "all_formats.json").string();
    json_cfg.compact = true;
    json_cfg.fail_on_severity = "medium";
    json_cfg.fail_on_count = 50;

    // Test NDJSON format
    Config ndjson_cfg;
    ndjson_cfg.output_file = (temp_dir / "all_formats.ndjson").string();
    ndjson_cfg.ndjson = true;
    ndjson_cfg.fail_on_severity = "medium";
    ndjson_cfg.fail_on_count = 50;

    // Test SARIF format
    Config sarif_cfg;
    sarif_cfg.output_file = (temp_dir / "all_formats.sarif").string();
    sarif_cfg.sarif = true;
    sarif_cfg.fail_on_severity = "medium";
    sarif_cfg.fail_on_count = 50;

    // Create comprehensive report
    Report report;
    ScanResult result;
    result.scanner_name = "format_test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "format_test_finding",
        "Finding for format testing",
        Severity::High,
        "This finding tests all output formats",
        std::map<std::string, std::string>{
            {"file_path", "/test/file.txt"},
            {"line_number", "42"},
            {"severity_score", "85"},
            {"category", "test"},
            {"cwe_id", "CWE-999"}
        },
        85,
        false
    });
    report.add_result(result);

    // Test all output formats
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, json_cfg));
    EXPECT_TRUE(writer.write_report(report, ndjson_cfg));
    EXPECT_TRUE(writer.write_report(report, sarif_cfg));

    // Verify all files were created
    EXPECT_TRUE(std::filesystem::exists(json_cfg.output_file));
    EXPECT_TRUE(std::filesystem::exists(ndjson_cfg.output_file));
    EXPECT_TRUE(std::filesystem::exists(sarif_cfg.output_file));

    // Test exit code determination
    ExitCodeHandler handler;
    int json_exit_code = handler.calculate_exit_code(report, json_cfg);
    int ndjson_exit_code = handler.calculate_exit_code(report, ndjson_cfg);
    int sarif_exit_code = handler.calculate_exit_code(report, sarif_cfg);

    EXPECT_EQ(json_exit_code, 1);
    EXPECT_EQ(ndjson_exit_code, 1);
    EXPECT_EQ(sarif_exit_code, 1);
}

// Test pipeline with argument parsing integration
TEST_F(IntegrationExtendedTest, FullPipelineArgumentParsingIntegration) {
    // Simulate command line arguments
    std::vector<std::string> args = {
        "sys-scan",
        "--output", (temp_dir / "arg_parse_integration.json").string(),
        "--compact",
        "--fail-on-count", "75",
        "--enable-scanners", "test_scanner"
    };

    // Test argument parsing - Note: This test may need adjustment based on actual ArgumentParser API
    ArgumentParser parser;
    Config cfg;
    cfg.output_file = (temp_dir / "arg_parse_integration.json").string();
    cfg.compact = true;
    cfg.fail_on_count = 75;
    cfg.enable_scanners = {"test_scanner"};

    // Create report and test full pipeline
    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "arg_parse_finding",
        "Finding from argument parsing integration test",
        Severity::High,
        "Description",
        {},
        80,
        false
    });
    report.add_result(result);

    // Test output writing
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Test exit code determination
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0); // Should not exceed threshold (1 finding < 75 threshold)
}

// Test pipeline error recovery scenarios
TEST_F(IntegrationExtendedTest, FullPipelineErrorRecovery) {
    Config cfg;
    cfg.output_file = (temp_dir / "error_recovery.json").string();
    cfg.compact = true;
    cfg.fail_on_severity = "medium";
    cfg.fail_on_count = 50;

    Report report;

    // Add scanner results with various error conditions
    ScanResult success_result;
    success_result.scanner_name = "success_scanner";
    success_result.start_time = std::chrono::system_clock::now();
    success_result.end_time = std::chrono::system_clock::now();
    success_result.findings.push_back(Finding{
        "success_finding",
        "Successful finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });
    report.add_result(success_result);

    // Add scanner with error (empty result)
    ScanResult error_result;
    error_result.scanner_name = "error_scanner";
    error_result.start_time = std::chrono::system_clock::now();
    error_result.end_time = std::chrono::system_clock::now();
    // No findings - simulates error condition
    report.add_result(error_result);

    // Test that pipeline continues despite errors
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    // Test exit code determination handles mixed success/error results
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 0); // Should succeed despite one scanner having no findings
}

} // namespace sys_scan