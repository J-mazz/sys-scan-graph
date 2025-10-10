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

TEST_F(JSONWriterTest, SarifOutput) {
    Config sarif_config = config;
    sarif_config.sarif = true;
    sarif_config.min_severity = "medium";

    // Add findings with different severities and MITRE techniques
    ScanResult result;
    result.scanner_name = "sarif_test";

    Finding low_finding;
    low_finding.id = "LOW-001";
    low_finding.title = "Low severity finding";
    low_finding.severity = Severity::Low;
    low_finding.base_severity_score = 2;
    result.findings.push_back(low_finding);

    Finding medium_finding;
    medium_finding.id = "MEDIUM-001";
    medium_finding.title = "Medium severity finding";
    medium_finding.description = "This is a medium finding";
    medium_finding.severity = Severity::Medium;
    medium_finding.base_severity_score = 5;
    medium_finding.metadata["mitre_techniques"] = "T1059,T1071";
    result.findings.push_back(medium_finding);

    Finding high_finding;
    high_finding.id = "HIGH-001";
    high_finding.title = "High severity finding";
    high_finding.description = "This is a high finding";
    high_finding.severity = Severity::High;
    high_finding.base_severity_score = 8;
    result.findings.push_back(high_finding);

    report.add_result(std::move(result));

    std::string sarif_output = writer.write(report, sarif_config);

    // Should produce valid JSON
    nlohmann::json parsed = nlohmann::json::parse(sarif_output);

    // Check SARIF structure
    EXPECT_EQ(parsed["$schema"], "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json");
    EXPECT_EQ(parsed["version"], "2.1.0");
    EXPECT_TRUE(parsed.contains("runs"));
    EXPECT_EQ(parsed["runs"].size(), 1);

    auto& run = parsed["runs"][0];
    EXPECT_TRUE(run.contains("tool"));
    EXPECT_EQ(run["tool"]["driver"]["name"], "sys-scan");
    EXPECT_EQ(run["tool"]["driver"]["informationUri"], "https://github.com/J-mazz/sys-scan");

    // Should only include medium and high severity findings (low is filtered out)
    EXPECT_TRUE(run.contains("results"));
    EXPECT_EQ(run["results"].size(), 2);

    // Check first result (medium severity)
    auto& result1 = run["results"][0];
    EXPECT_EQ(result1["ruleId"], "MEDIUM-001");
    EXPECT_EQ(result1["level"], "medium");
    EXPECT_TRUE(result1.contains("message"));
    EXPECT_TRUE(result1["message"].contains("text"));
    EXPECT_THAT(result1["message"]["text"], ::testing::HasSubstr("Medium severity finding"));
    EXPECT_THAT(result1["message"]["text"], ::testing::HasSubstr("This is a medium finding"));
    EXPECT_EQ(result1["properties"]["baseSeverityScore"], 5);
    EXPECT_TRUE(result1["properties"].contains("mitreTechniqueIds"));
    EXPECT_EQ(result1["properties"]["mitreTechniqueIds"].size(), 2);
    EXPECT_EQ(result1["properties"]["mitreTechniqueIds"][0], "T1059");
    EXPECT_EQ(result1["properties"]["mitreTechniqueIds"][1], "T1071");

    // Check second result (high severity)
    auto& result2 = run["results"][1];
    EXPECT_EQ(result2["ruleId"], "HIGH-001");
    EXPECT_EQ(result2["level"], "high");
    EXPECT_EQ(result2["properties"]["baseSeverityScore"], 8);
    EXPECT_FALSE(result2["properties"].contains("mitreTechniqueIds")); // No MITRE techniques
}

TEST_F(JSONWriterTest, NdjsonOutput) {
    Config ndjson_config = config;
    ndjson_config.ndjson = true;
    ndjson_config.timings = true;
    ndjson_config.min_severity = "medium";

    // Add test data
    ScanResult result1;
    result1.scanner_name = "ndjson_scanner1";
    result1.start_time = std::chrono::system_clock::now();
    result1.end_time = result1.start_time + std::chrono::milliseconds(150);

    Finding finding1;
    finding1.id = "NDJSON-001";
    finding1.title = "NDJSON Test Finding";
    finding1.severity = Severity::High;
    finding1.base_severity_score = 8;
    finding1.metadata["mitre_techniques"] = "T1001,T1002";
    result1.findings.push_back(finding1);

    ScanResult result2;
    result2.scanner_name = "ndjson_scanner2";
    result2.start_time = std::chrono::system_clock::now();
    result2.end_time = result2.start_time + std::chrono::milliseconds(200);

    Finding finding2;
    finding2.id = "NDJSON-002";
    finding2.title = "Another NDJSON Finding";
    finding2.severity = Severity::Medium;
    finding2.base_severity_score = 5;
    result2.findings.push_back(finding2);

    // Low severity finding that should be filtered out
    Finding finding3;
    finding3.id = "NDJSON-003";
    finding3.title = "Low severity finding";
    finding3.severity = Severity::Low;
    finding3.base_severity_score = 2;
    result2.findings.push_back(finding3);

    report.add_result(std::move(result1));
    report.add_result(std::move(result2));

    std::string ndjson_output = writer.write(report, ndjson_config);

    // Split into lines
    std::vector<std::string> lines;
    std::istringstream iss(ndjson_output);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    // Should have: meta, summary, 2 timing lines, summary_extension, 2 finding lines = 7 lines
    EXPECT_EQ(lines.size(), 7);

    // Parse each line as JSON
    std::vector<nlohmann::json> parsed_lines;
    for (const auto& l : lines) {
        parsed_lines.push_back(nlohmann::json::parse(l));
    }

    // Check meta line
    EXPECT_EQ(parsed_lines[0]["type"], "meta");
    EXPECT_TRUE(parsed_lines[0].contains("tool_version"));
    EXPECT_EQ(parsed_lines[0]["schema"], "2");

    // Check summary line
    EXPECT_EQ(parsed_lines[1]["type"], "summary");
    EXPECT_TRUE(parsed_lines[1].contains("duration_ms"));
    EXPECT_EQ(parsed_lines[1]["scanner_count"], 2);
    EXPECT_EQ(parsed_lines[1]["scanners_with_findings"], 2);
    EXPECT_EQ(parsed_lines[1]["finding_count_total"], 3);
    EXPECT_EQ(parsed_lines[1]["finding_count_emitted"], 2); // Only medium/high severity

    // Check timing lines (should be 2)
    EXPECT_EQ(parsed_lines[2]["type"], "timing");
    EXPECT_EQ(parsed_lines[2]["scanner"], "ndjson_scanner1");
    EXPECT_EQ(parsed_lines[2]["elapsed_ms"], 150);

    EXPECT_EQ(parsed_lines[3]["type"], "timing");
    EXPECT_EQ(parsed_lines[3]["scanner"], "ndjson_scanner2");
    EXPECT_EQ(parsed_lines[3]["elapsed_ms"], 200);

    // Check summary extension
    EXPECT_EQ(parsed_lines[4]["type"], "summary_extension");
    EXPECT_TRUE(parsed_lines[4].contains("total_risk_score"));
    EXPECT_TRUE(parsed_lines[4].contains("emitted_risk_score"));

    // Check finding lines (should be 2, filtered by severity)
    EXPECT_EQ(parsed_lines[5]["type"], "finding");
    EXPECT_EQ(parsed_lines[5]["scanner"], "ndjson_scanner1");
    EXPECT_EQ(parsed_lines[5]["id"], "NDJSON-001");
    EXPECT_EQ(parsed_lines[5]["severity"], "high");
    EXPECT_EQ(parsed_lines[5]["base_severity_score"], 8);
    EXPECT_EQ(parsed_lines[5]["mitre_techniques"], "T1001,T1002");

    EXPECT_EQ(parsed_lines[6]["type"], "finding");
    EXPECT_EQ(parsed_lines[6]["scanner"], "ndjson_scanner2");
    EXPECT_EQ(parsed_lines[6]["id"], "NDJSON-002");
    EXPECT_EQ(parsed_lines[6]["severity"], "medium");
    EXPECT_EQ(parsed_lines[6]["base_severity_score"], 5);
}

TEST_F(JSONWriterTest, TimingsOutput) {
    Config timings_config = config;
    timings_config.timings = true;

    // Add scan results with different elapsed times
    ScanResult result1;
    result1.scanner_name = "fast_scanner";
    result1.start_time = std::chrono::system_clock::now();
    result1.end_time = result1.start_time + std::chrono::milliseconds(50);

    ScanResult result2;
    result2.scanner_name = "slow_scanner";
    result2.start_time = std::chrono::system_clock::now();
    result2.end_time = result2.start_time + std::chrono::milliseconds(200);

    ScanResult result3;
    result3.scanner_name = "no_timing_scanner";
    // No start/end times set

    report.add_result(std::move(result1));
    report.add_result(std::move(result2));
    report.add_result(std::move(result3));

    std::string json_output = writer.write(report, timings_config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // Check that timings array exists in meta
    EXPECT_TRUE(parsed["meta"].contains("timings"));
    auto& timings = parsed["meta"]["timings"];
    EXPECT_EQ(timings.size(), 3);

    // Check timing entries (order may vary, so check all)
    bool found_fast = false, found_slow = false, found_no_timing = false;
    for (const auto& timing : timings) {
        std::string scanner = timing["scanner"];
        if (scanner == "fast_scanner") {
            EXPECT_EQ(timing["elapsed_ms"], 50);
            found_fast = true;
        } else if (scanner == "slow_scanner") {
            EXPECT_EQ(timing["elapsed_ms"], 200);
            found_slow = true;
        } else if (scanner == "no_timing_scanner") {
            EXPECT_EQ(timing["elapsed_ms"], 0);
            found_no_timing = true;
        }
    }

    EXPECT_TRUE(found_fast);
    EXPECT_TRUE(found_slow);
    EXPECT_TRUE(found_no_timing);
}

TEST_F(JSONWriterTest, MetaSuppressionFlags) {
    // Test no_user_meta flag
    Config no_user_config = config;
    no_user_config.no_user_meta = true;

    std::string json_output = writer.write(report, no_user_config);
    nlohmann::json parsed = nlohmann::json::parse(json_output);

    // User-related fields should be absent
    EXPECT_FALSE(parsed["meta"].contains("uid"));
    EXPECT_FALSE(parsed["meta"].contains("euid"));
    EXPECT_FALSE(parsed["meta"].contains("gid"));
    EXPECT_FALSE(parsed["meta"].contains("egid"));
    EXPECT_FALSE(parsed["meta"].contains("user"));

    // Other meta fields should still be present
    EXPECT_TRUE(parsed["meta"].contains("hostname"));
    EXPECT_TRUE(parsed["meta"].contains("kernel"));
    EXPECT_TRUE(parsed["meta"].contains("arch"));

    // Test no_hostname_meta flag
    Config no_hostname_config = config;
    no_hostname_config.no_hostname_meta = true;

    json_output = writer.write(report, no_hostname_config);
    parsed = nlohmann::json::parse(json_output);

    EXPECT_FALSE(parsed["meta"].contains("hostname"));
    EXPECT_TRUE(parsed["meta"].contains("uid")); // user fields should be present

    // Test no_cmdline_meta flag
    Config no_cmdline_config = config;
    no_cmdline_config.no_cmdline_meta = true;

    json_output = writer.write(report, no_cmdline_config);
    parsed = nlohmann::json::parse(json_output);

    EXPECT_FALSE(parsed["meta"].contains("cmdline"));
    EXPECT_TRUE(parsed["meta"].contains("hostname"));
    EXPECT_TRUE(parsed["meta"].contains("uid"));

    // Test all suppression flags together
    Config all_suppressed_config = config;
    all_suppressed_config.no_user_meta = true;
    all_suppressed_config.no_hostname_meta = true;
    all_suppressed_config.no_cmdline_meta = true;

    json_output = writer.write(report, all_suppressed_config);
    parsed = nlohmann::json::parse(json_output);

    // All sensitive fields should be absent
    EXPECT_FALSE(parsed["meta"].contains("uid"));
    EXPECT_FALSE(parsed["meta"].contains("euid"));
    EXPECT_FALSE(parsed["meta"].contains("gid"));
    EXPECT_FALSE(parsed["meta"].contains("egid"));
    EXPECT_FALSE(parsed["meta"].contains("user"));
    EXPECT_FALSE(parsed["meta"].contains("hostname"));
    EXPECT_FALSE(parsed["meta"].contains("cmdline"));

    // But essential fields should remain
    EXPECT_TRUE(parsed["meta"].contains("$schema"));
    EXPECT_TRUE(parsed["meta"].contains("tool_version"));
    EXPECT_TRUE(parsed["meta"].contains("arch"));
    EXPECT_TRUE(parsed["meta"].contains("kernel"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan