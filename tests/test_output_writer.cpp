#include "core/OutputWriter.h"
#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

namespace sys_scan {

class OutputWriterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_output_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    OutputWriter writer;
};

// Test JSON output to file
TEST_F(OutputWriterTest, WriteReportToFile) {
    Config cfg;
    cfg.output_file = (temp_dir / "test_output.json").string();
    cfg.compact = true;

    Report report;
    // Add a simple finding to the report
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_id",
        "Test finding",
        Severity::Info,
        "Test description",
        std::map<std::string, std::string>{{"key", "value"}},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    // Verify file was created and contains expected content
    EXPECT_TRUE(std::filesystem::exists(cfg.output_file));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Parse JSON and verify structure
    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("meta"));
    EXPECT_TRUE(json.contains("results"));
    EXPECT_TRUE(json.contains("summary"));
    EXPECT_EQ(json["results"].size(), 1);
    EXPECT_EQ(json["results"][0]["scanner"], "test_scanner");
}

// Test JSON output to stdout (when no output file specified)
TEST_F(OutputWriterTest, WriteReportToStdout) {
    Config cfg;
    cfg.output_file = "";  // Empty means stdout
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_id",
        "Test finding",
        Severity::Info,
        "Test description",
        std::map<std::string, std::string>{{"key", "value"}},
        10,
        false
    });
    report.add_result(result);

    // Capture stdout
    testing::internal::CaptureStdout();
    EXPECT_TRUE(writer.write_report(report, cfg));
    std::string output = testing::internal::GetCapturedStdout();

    // Verify output contains expected JSON
    EXPECT_FALSE(output.empty());
    auto json = nlohmann::json::parse(output);
    EXPECT_TRUE(json.contains("meta"));
    EXPECT_TRUE(json.contains("results"));
}

// Test pretty JSON output
TEST_F(OutputWriterTest, WriteReportPrettyFormat) {
    Config cfg;
    cfg.output_file = (temp_dir / "test_pretty.json").string();
    cfg.pretty = true;
    cfg.compact = false;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_id",
        "Test finding",
        Severity::Info,
        "Test description",
        std::map<std::string, std::string>{{"key", "value"}},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Pretty format should contain newlines and indentation
    EXPECT_NE(content.find('\n'), std::string::npos);
    EXPECT_NE(content.find("  "), std::string::npos);
}

// Test NDJSON output format
TEST_F(OutputWriterTest, WriteReportNDJSONFormat) {
    Config cfg;
    cfg.output_file = (temp_dir / "test.ndjson").string();
    cfg.ndjson = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_id",
        "Test finding",
        Severity::Info,
        "Test description",
        std::map<std::string, std::string>{{"key", "value"}},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // NDJSON should contain multiple lines (meta, summary, findings)
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

// Test SARIF output format
TEST_F(OutputWriterTest, WriteReportSARIFFormat) {
    Config cfg;
    cfg.output_file = (temp_dir / "test.sarif").string();
    cfg.sarif = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "test_id",
        "Test finding",
        Severity::Info,
        "Test description",
        std::map<std::string, std::string>{{"key", "value"}},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("$schema"));
    EXPECT_TRUE(json.contains("version"));
    EXPECT_EQ(json["version"], "2.1.0");
    EXPECT_TRUE(json.contains("runs"));
}

// Test environment file generation
TEST_F(OutputWriterTest, WriteEnvironmentFile) {
    Config cfg;
    cfg.write_env_file = (temp_dir / "test.env").string();
    cfg.output_file = (temp_dir / "test.json").string();

    // Create a dummy output file first
    std::ofstream dummy_file(cfg.output_file);
    dummy_file << "{\"test\": \"data\"}";
    dummy_file.close();

    EXPECT_TRUE(writer.write_env_file(cfg));

    // Verify environment file was created
    EXPECT_TRUE(std::filesystem::exists(cfg.write_env_file));

    std::ifstream env_file(cfg.write_env_file);
    std::string content((std::istreambuf_iterator<char>(env_file)), std::istreambuf_iterator<char>());

    // Environment file should contain variable assignments
    EXPECT_NE(content.find("SYS_SCAN_OUTPUT_FILE="), std::string::npos);
    EXPECT_NE(content.find("SYS_SCAN_SHA256="), std::string::npos);
}

// Test environment file with non-existent output file
TEST_F(OutputWriterTest, WriteEnvironmentFileNoOutput) {
    Config cfg;
    cfg.write_env_file = (temp_dir / "test.env").string();
    cfg.output_file = "/non/existent/file.json";

    // Should fail when output file doesn't exist
    EXPECT_FALSE(writer.write_env_file(cfg));
}

// Test output to non-existent directory
TEST_F(OutputWriterTest, WriteReportToInvalidPath) {
    Config cfg;
    cfg.output_file = "/non/existent/directory/test.json";

    Report report;
    EXPECT_FALSE(writer.write_report(report, cfg));
}

// Test empty report
TEST_F(OutputWriterTest, WriteEmptyReport) {
    Config cfg;
    cfg.output_file = (temp_dir / "empty.json").string();
    cfg.compact = true;

    Report report;  // Empty report

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_TRUE(json.contains("meta"));
    EXPECT_TRUE(json.contains("results"));
    EXPECT_TRUE(json.contains("summary"));
    EXPECT_TRUE(json["results"].empty());
}

// Test report with multiple scanners
TEST_F(OutputWriterTest, WriteReportMultipleScanners) {
    Config cfg;
    cfg.output_file = (temp_dir / "multi_scanner.json").string();
    cfg.compact = true;

    Report report;

    // Add multiple scanner results
    for (int i = 1; i <= 3; ++i) {
        ScanResult result;
        result.scanner_name = "scanner_" + std::to_string(i);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = std::chrono::system_clock::now();
        result.findings.push_back(Finding{
            "finding_" + std::to_string(i),
            "Finding " + std::to_string(i),
            Severity::Info,
            "Description " + std::to_string(i),
            std::map<std::string, std::string>{{"scanner", std::to_string(i)}},
            i * 10,
            false
        });
        report.add_result(result);
    }

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);
    EXPECT_EQ(json["results"].size(), 3);

    // Verify each scanner result
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(json["results"][i]["scanner"], "scanner_" + std::to_string(i + 1));
    }
}

// Test canonical ordering
TEST_F(OutputWriterTest, WriteReportCanonicalOrdering) {
    Config cfg;
    cfg.output_file = (temp_dir / "canonical.json").string();
    cfg.canonical = true;
    cfg.compact = true;

    Report report;
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();
    result.findings.push_back(Finding{
        "z_finding",
        "Z Finding",
        Severity::Info,
        "Z Description",
        std::map<std::string, std::string>{{"z_key", "value"}, {"a_key", "value"}},
        10,
        false
    });
    result.findings.push_back(Finding{
        "a_finding",
        "A Finding",
        Severity::Info,
        "A Description",
        std::map<std::string, std::string>{{"z_key", "value"}, {"a_key", "value"}},
        10,
        false
    });
    report.add_result(result);

    EXPECT_TRUE(writer.write_report(report, cfg));

    std::ifstream file(cfg.output_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto json = nlohmann::json::parse(content);

    // With canonical ordering, findings should be sorted by ID
    EXPECT_EQ(json["results"][0]["findings"][0]["id"], "a_finding");
    EXPECT_EQ(json["results"][0]["findings"][1]["id"], "z_finding");
}

} // namespace sys_scan