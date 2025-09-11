#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/JSONWriter.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include <nlohmann/json.hpp>
#include <chrono>

namespace sys_scan {

class JSONWriterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test config
        config.enable_scanners = {"test_scanner"};
        config.canonical = true;
        config.pretty = false;
        config.compact = false;
        config.ndjson = false;
        config.sarif = false;
        config.min_severity = "info";
    }

    Config config;
    Report report;
    JSONWriter writer;
};

TEST_F(JSONWriterTest, EmptyReport) {
    std::string json_output = writer.write(report, config);

    // Should produce valid JSON
    ASSERT_FALSE(json_output.empty());

    // Parse the JSON to verify it's valid
    nlohmann::json parsed;
    EXPECT_NO_THROW(parsed = nlohmann::json::parse(json_output));

    // Check basic structure
    EXPECT_TRUE(parsed.contains("meta"));
    EXPECT_TRUE(parsed.contains("summary"));
    EXPECT_TRUE(parsed.contains("results"));
    EXPECT_TRUE(parsed["results"].is_array());
}

TEST_F(JSONWriterTest, ReportWithSingleFinding) {
    // Create a test finding
    Finding finding;
    finding.id = "TEST-001";
    finding.title = "Test Finding";
    finding.description = "This is a test finding";
    finding.severity = Severity::Medium;
    finding.base_severity_score = 5;
    finding.metadata["test_key"] = "test_value";

    // Create a scan result
    ScanResult result;
    result.scanner_name = "test_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = result.start_time + std::chrono::milliseconds(100);
    result.findings.push_back(finding);

    report.add_result(std::move(result));

    std::string json_output = writer.write(report, config);

    // Parse and verify
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Check results array
    EXPECT_EQ(parsed["results"].size(), 1);
    auto& result_json = parsed["results"][0];

    EXPECT_EQ(result_json["scanner"], "test_scanner");
    EXPECT_EQ(result_json["finding_count"], 1);

    // Check findings
    auto& findings_json = result_json["findings"];
    EXPECT_EQ(findings_json.size(), 1);

    auto& finding_json = findings_json[0];
    EXPECT_EQ(finding_json["id"], "TEST-001");
    EXPECT_EQ(finding_json["title"], "Test Finding");
    EXPECT_EQ(finding_json["description"], "This is a test finding");
    EXPECT_EQ(finding_json["severity"], "medium");
    EXPECT_EQ(finding_json["base_severity_score"], "5");

    // Check metadata
    EXPECT_TRUE(finding_json["metadata"].contains("test_key"));
    EXPECT_EQ(finding_json["metadata"]["test_key"], "test_value");
}

TEST_F(JSONWriterTest, MultipleScanners) {
    // Add multiple scan results
    for (int i = 0; i < 3; ++i) {
        ScanResult result;
        result.scanner_name = "scanner_" + std::to_string(i);
        result.start_time = std::chrono::system_clock::now();
        result.end_time = result.start_time + std::chrono::milliseconds(50 * (i + 1));

        Finding finding;
        finding.id = "FINDING-" + std::to_string(i);
        finding.title = "Finding " + std::to_string(i);
        finding.severity = static_cast<Severity>(i % 4); // Cycle through severity levels
        finding.base_severity_score = (i + 1) * 2;

        result.findings.push_back(finding);
        report.add_result(std::move(result));
    }

    std::string json_output = writer.write(report, config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Check we have 3 results
    EXPECT_EQ(parsed["results"].size(), 3);

    // Check summary
    EXPECT_EQ(parsed["summary"]["scanner_count"], "3");
    EXPECT_EQ(parsed["summary"]["scanners_with_findings"], 3);
    EXPECT_EQ(parsed["summary"]["finding_count_total"], 3);
    EXPECT_EQ(parsed["summary"]["finding_count_emitted"], 3);
}

TEST_F(JSONWriterTest, PrettyPrint) {
    Config pretty_config = config;
    pretty_config.pretty = true;
    pretty_config.compact = false;

    Finding finding;
    finding.id = "PRETTY-001";
    finding.title = "Pretty Test";

    ScanResult result;
    result.scanner_name = "pretty_scanner";
    result.findings.push_back(finding);

    report.add_result(std::move(result));

    std::string json_output = writer.write(report, pretty_config);

    // Pretty output should contain newlines and indentation
    EXPECT_NE(json_output.find('\n'), std::string::npos);
    EXPECT_NE(json_output.find("  "), std::string::npos);

    // Should still be valid JSON
    nlohmann::json parsed = nlohmann::json::parse(json_output);
    EXPECT_TRUE(parsed.contains("results"));
}

TEST_F(JSONWriterTest, CompactOutput) {
    Config compact_config = config;
    compact_config.pretty = false;
    compact_config.compact = true;

    Finding finding;
    finding.id = "COMPACT-001";
    finding.title = "Compact Test";

    ScanResult result;
    result.scanner_name = "compact_scanner";
    result.findings.push_back(finding);

    report.add_result(std::move(result));

    std::string json_output = writer.write(report, compact_config);

    // Compact output should not contain extra whitespace
    EXPECT_EQ(json_output.find('\n'), std::string::npos);
    EXPECT_EQ(json_output.find("  "), std::string::npos);

    // Should still be valid JSON
    nlohmann::json parsed = nlohmann::json::parse(json_output);
    EXPECT_TRUE(parsed.contains("results"));
}

TEST_F(JSONWriterTest, SeverityFiltering) {
    Config high_severity_config = config;
    high_severity_config.min_severity = "high";

    // Add findings with different severities
    std::vector<Severity> severities = {Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical};

    ScanResult result;
    result.scanner_name = "severity_test";

    for (size_t i = 0; i < severities.size(); ++i) {
        Finding finding;
        finding.id = "SEV-" + std::to_string(i);
        finding.severity = severities[i];
        finding.base_severity_score = static_cast<int>(i + 1);
        result.findings.push_back(finding);
    }

    report.add_result(std::move(result));

    std::string json_output = writer.write(report, high_severity_config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Should only include High and Critical findings (2 total)
    auto& findings = parsed["results"][0]["findings"];
    EXPECT_EQ(findings.size(), 2);

    // Check that only high severity findings are included
    for (const auto& finding : findings) {
        std::string severity = finding["severity"];
        EXPECT_TRUE(severity == "high" || severity == "critical");
    }
}

TEST_F(JSONWriterTest, WarningsAndErrors) {
    // Add warnings and errors using proper WarnCode enum
    report.add_warning("test_scanner", WarnCode::Generic, "WARN001:Test warning");
    report.add_partial_warning("test_scanner", "Partial warning message");
    report.add_error("test_scanner", "Test error message");

    std::string json_output = writer.write(report, config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Check warnings
    EXPECT_TRUE(parsed.contains("collection_warnings"));
    EXPECT_EQ(parsed["collection_warnings"].size(), 1);
    EXPECT_EQ(parsed["collection_warnings"][0]["code"], "generic");
    EXPECT_EQ(parsed["collection_warnings"][0]["detail"], "WARN001:Test warning");

    // Check partial warnings
    EXPECT_TRUE(parsed.contains("partial_warnings"));
    EXPECT_EQ(parsed["partial_warnings"].size(), 1);
    EXPECT_EQ(parsed["partial_warnings"][0]["message"], "Partial warning message");

    // Check errors
    EXPECT_TRUE(parsed.contains("scanner_errors"));
    EXPECT_EQ(parsed["scanner_errors"].size(), 1);
    EXPECT_EQ(parsed["scanner_errors"][0]["message"], "Test error message");
}

TEST_F(JSONWriterTest, CanonicalSorting) {
    Config canonical_config = config;
    canonical_config.canonical = true;

    ScanResult result;
    result.scanner_name = "sort_test";

    // Add findings in non-alphabetical order
    std::vector<std::string> ids = {"Z-001", "A-001", "M-001", "B-001"};

    for (const auto& id : ids) {
        Finding finding;
        finding.id = id;
        finding.title = "Finding " + id;
        result.findings.push_back(finding);
    }

    report.add_result(std::move(result));

    std::string json_output = writer.write(report, canonical_config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    auto& findings = parsed["results"][0]["findings"];

    // In canonical mode, findings should be sorted by ID
    EXPECT_EQ(findings[0]["id"], "A-001");
    EXPECT_EQ(findings[1]["id"], "B-001");
    EXPECT_EQ(findings[2]["id"], "M-001");
    EXPECT_EQ(findings[3]["id"], "Z-001");
}

TEST_F(JSONWriterTest, MetaInformation) {
    std::string json_output = writer.write(report, config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Check meta object exists and has required fields
    EXPECT_TRUE(parsed["meta"].contains("$schema"));
    EXPECT_TRUE(parsed["meta"].contains("json_schema_version"));
    EXPECT_TRUE(parsed["meta"].contains("tool_version"));
    EXPECT_TRUE(parsed["meta"].contains("arch"));
    EXPECT_TRUE(parsed["meta"].contains("kernel"));
    EXPECT_TRUE(parsed["meta"].contains("os_id"));

    // Check schema URL
    EXPECT_EQ(parsed["meta"]["$schema"], "https://github.com/J-mazz/sys-scan/schema/v2.json");
    EXPECT_EQ(parsed["meta"]["json_schema_version"], "2");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan