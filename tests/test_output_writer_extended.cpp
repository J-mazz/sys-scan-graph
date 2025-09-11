#include "core/OutputWriter.h"
#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>
#include <vector>
#include <limits>

namespace sys_scan {

class OutputWriterExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_output_writer_extended_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    OutputWriter writer;
};

// Test JSON output with extreme finding counts
TEST_F(OutputWriterExtendedTest, WriteReportExtremeFindingCounts) {
    Config cfg;
    cfg.output_file = (temp_dir / "extreme_findings.json").string();
    cfg.compact = true;

    Report report;

    // Create a scan result with many findings
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add a large number of findings
    for (int i = 0; i < 1000; ++i) {  // Reasonable number for testing extreme cases
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description " + std::to_string(i),
            std::map<std::string, std::string>{{"index", std::to_string(i)}},
            10,
            false
        });
    }
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created and is valid JSON
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("results"));
    EXPECT_EQ(json["results"][0]["findings"].size(), 1000);
}

// Test JSON output with very large metadata
TEST_F(OutputWriterExtendedTest, WriteReportLargeMetadata) {
    Config cfg;
    cfg.output_file = (temp_dir / "large_metadata.json").string();
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Create finding with very large metadata
    std::map<std::string, std::string> large_metadata;
    for (int i = 0; i < 100; ++i) {  // Reduced from 1,000 to 100
        large_metadata["key_" + std::to_string(i)] = std::string(100, 'x') + std::to_string(i);
    }

    result.findings.push_back(Finding{
        "large_metadata_finding",
        "Finding with large metadata",
        Severity::Info,
        std::string(1000, 'y'), // Large description
        large_metadata,
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created and is valid JSON
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("results"));
    EXPECT_TRUE(json["results"][0]["findings"][0].contains("metadata"));
}

// Test NDJSON output with special characters
TEST_F(OutputWriterExtendedTest, WriteReportNDJSONSpecialCharacters) {
    Config cfg;
    cfg.output_file = (temp_dir / "special_chars.ndjson").string();
    cfg.ndjson = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add finding with special characters in all fields
    result.findings.push_back(Finding{
        "special_chars_测试",
        "Special chars: \"quotes\", 'single', \n newline, \t tab, \\ backslash",
        Severity::Info,
        "Description with special chars: éñüñicode, 中文, русский",
        std::map<std::string, std::string>{
            {"key with spaces", "value with \"quotes\""},
            {"unicode_key_测试", "unicode_value_中文"},
            {"special_value", "value\nwith\nlines"}
        },
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // NDJSON should contain multiple lines
    std::istringstream iss(content);
    std::string line;
    int line_count = 0;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            line_count++;
            // Each line should be valid JSON
            auto json = nlohmann::json::parse(line);
            EXPECT_TRUE(json.is_object());
        }
    }
    EXPECT_GE(line_count, 2);  // At least meta and summary
}

// Test SARIF output with complex findings
TEST_F(OutputWriterExtendedTest, WriteReportSARIFComplexFindings) {
    Config cfg;
    cfg.output_file = (temp_dir / "complex.sarif").string();
    cfg.sarif = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add finding with complex metadata
    result.findings.push_back(Finding{
        "complex_finding",
        "Complex finding with detailed information",
        Severity::High,
        "This is a detailed description of a complex finding that includes multiple pieces of information and context.",
        std::map<std::string, std::string>{
            {"file_path", "/etc/passwd"},
            {"line_number", "123"},
            {"severity_score", "85"},
            {"category", "security"},
            {"cwe_id", "CWE-200"},
            {"cvss_score", "7.5"},
            {"exploitability", "high"},
            {"remediation", "Update permissions on sensitive files"}
        },
        85,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("$schema"));
    EXPECT_TRUE(json.contains("version"));
    EXPECT_EQ(json["version"], "2.1.0");
    EXPECT_TRUE(json.contains("runs"));
    EXPECT_TRUE(json["runs"][0].contains("results"));
}

// Test output with empty scanner results
TEST_F(OutputWriterExtendedTest, WriteReportEmptyScannerResults) {
    Config cfg;
    cfg.output_file = (temp_dir / "empty_results.json").string();
    cfg.compact = true;

    Report report;

    // Add scanner result with no findings
    ScanResult result;
    result.scanner_name = "empty_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    // No findings added
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("results"));
    EXPECT_EQ(json["results"][0]["findings"].size(), 0);
}

// Test output with very long scanner names
TEST_F(OutputWriterExtendedTest, WriteReportLongScannerNames) {
    Config cfg;
    cfg.output_file = (temp_dir / "long_names.json").string();
    cfg.compact = true;

    Report report;

    // Create scanner name with maximum length
    std::string long_name(1000, 'a');
    ScanResult result;
    result.scanner_name = long_name;
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "test_finding",
        "Test finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_EQ(json["results"][0]["scanner"], long_name);
}

// Test output with Unicode characters in all fields
TEST_F(OutputWriterExtendedTest, WriteReportUnicodeCharacters) {
    Config cfg;
    cfg.output_file = (temp_dir / "unicode.json").string();
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "测试扫描器";  // Chinese
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    result.findings.push_back(Finding{
        "测试发现",  // Chinese
        "发现标题",  // Chinese
        Severity::Info,
        "详细描述：这是一个测试发现，包含各种Unicode字符。Русский, Español, Français, Deutsch, 日本語, 한국어",  // Multiple languages
        std::map<std::string, std::string>{
            {"文件路径", "/路径/文件.txt"},  // Chinese
            {"описание", "русское описание"},  // Russian
            {"descripción", "descripción en español"}  // Spanish
        },
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_EQ(json["results"][0]["scanner"], "测试扫描器");
    EXPECT_EQ(json["results"][0]["findings"][0]["id"], "测试发现");
}

// Test output with nested metadata structures
TEST_F(OutputWriterExtendedTest, WriteReportNestedMetadata) {
    Config cfg;
    cfg.output_file = (temp_dir / "nested_metadata.json").string();
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "nested_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Create metadata with nested structure (as string values)
    result.findings.push_back(Finding{
        "nested_finding",
        "Finding with nested metadata",
        Severity::Info,
        "Description",
        std::map<std::string, std::string>{
            {"json_data", "{\"nested\": {\"key\": \"value\", \"array\": [1, 2, 3]}}"},
            {"xml_data", "<root><nested><key>value</key></nested></root>"},
            {"csv_data", "header1,header2\nvalue1,value2\nvalue3,value4"}
        },
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json["results"][0]["findings"][0]["metadata"].contains("json_data"));
    EXPECT_TRUE(json["results"][0]["findings"][0]["metadata"].contains("xml_data"));
    EXPECT_TRUE(json["results"][0]["findings"][0]["metadata"].contains("csv_data"));
}

// Test output with concurrent access simulation
TEST_F(OutputWriterExtendedTest, WriteReportConcurrentAccess) {
    Config cfg1, cfg2;
    cfg1.output_file = (temp_dir / "concurrent1.json").string();
    cfg1.compact = true;
    cfg2.output_file = (temp_dir / "concurrent2.json").string();
    cfg2.compact = true;

    Report report1, report2;

    // Create identical reports
    ScanResult result;
    result.scanner_name = "concurrent_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "concurrent_finding",
        "Concurrent finding",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });

    report1.add_result(result);
    report2.add_result(result);

    // Write both reports (simulating concurrent access)
    EXPECT_TRUE(writer.write_report(report1, cfg1));
    EXPECT_TRUE(writer.write_report(report2, cfg2));

    // Verify both files were created
    EXPECT_TRUE(std::filesystem::exists(cfg1.output_file));
    EXPECT_TRUE(std::filesystem::exists(cfg2.output_file));
}

// Test output with memory pressure simulation
TEST_F(OutputWriterExtendedTest, WriteReportMemoryPressure) {
    Config cfg;
    cfg.output_file = (temp_dir / "memory_pressure.json").string();
    cfg.compact = true;

    Report report;

    // Create many scanner results with many findings each
    for (int scanner = 0; scanner < 100; ++scanner) {
        ScanResult result;
        result.scanner_name = "scanner_" + std::to_string(scanner);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();

        for (int finding = 0; finding < 100; ++finding) {
            result.findings.push_back(Finding{
                "finding_" + std::to_string(scanner) + "_" + std::to_string(finding),
                "Finding " + std::to_string(finding) + " from scanner " + std::to_string(scanner),
                Severity::Info,
                std::string(500, 'x'), // Large description
                std::map<std::string, std::string>{
                    {"scanner_id", std::to_string(scanner)},
                    {"finding_id", std::to_string(finding)},
                    {"large_data", std::string(1000, 'y')}
                },
                10,
                false
            });
        }
        report.add_result(result);
    }

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_EQ(json["results"].size(), 100);

    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(json["results"][i]["findings"].size(), 100);
    }
}

// Test output with all severity levels
TEST_F(OutputWriterExtendedTest, WriteReportAllSeverityLevels) {
    Config cfg;
    cfg.output_file = (temp_dir / "all_severities.json").string();
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "severity_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add findings with all severity levels
    result.findings.push_back(Finding{"info_finding", "Info finding", Severity::Info, "Info description", {}, 10, false});
    result.findings.push_back(Finding{"low_finding", "Low finding", Severity::Low, "Low description", {}, 30, false});
    result.findings.push_back(Finding{"medium_finding", "Medium finding", Severity::Medium, "Medium description", {}, 50, false});
    result.findings.push_back(Finding{"high_finding", "High finding", Severity::High, "High description", {}, 80, false});

    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_EQ(json["results"][0]["findings"].size(), 4);

    // Verify all severity levels are present
    std::vector<std::string> severities;
    for (const auto& finding : json["results"][0]["findings"]) {
        severities.push_back(finding["severity"]);
    }

    EXPECT_TRUE(std::find(severities.begin(), severities.end(), "info") != severities.end());
    EXPECT_TRUE(std::find(severities.begin(), severities.end(), "low") != severities.end());
    EXPECT_TRUE(std::find(severities.begin(), severities.end(), "medium") != severities.end());
    EXPECT_TRUE(std::find(severities.begin(), severities.end(), "high") != severities.end());
}

// Test output with timestamp edge cases
TEST_F(OutputWriterExtendedTest, WriteReportTimestampEdgeCases) {
    Config cfg;
    cfg.output_file = (temp_dir / "timestamps.json").string();
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "timestamp_scanner";

    // Test with minimum timestamp
    result.start_time = std::chrono::system_clock::time_point::min();
    result.end_time = std::chrono::system_clock::time_point::max();

    result.findings.push_back(Finding{
        "timestamp_finding",
        "Finding with edge case timestamps",
        Severity::Info,
        "Description",
        {},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json["results"][0].contains("start_time"));
    EXPECT_TRUE(json["results"][0].contains("end_time"));
}

} // namespace sys_scan