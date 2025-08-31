#include "core/ArgumentParser.h"
#include "core/ConfigValidator.h"
#include "core/OutputWriter.h"
#include "core/GPGSigner.h"
#include "core/RuleEngineInitializer.h"
#include "core/ExitCodeHandler.h"
#include "core/Config.h"
#include "core/Report.h"
#include "core/ScannerRegistry.h"
#include "core/ScanContext.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

namespace sys_scan {

class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_integration_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
};

// Test complete flow: argument parsing -> validation -> scanning -> output -> exit code
TEST_F(IntegrationTest, CompleteScanWorkflow) {
    // Setup test arguments - create persistent strings to avoid dangling pointers
    std::string output_path = (temp_dir / "test_output.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--output", output_path.c_str(),
        "--compact",
        "--min-severity", "info"
    };

    Config cfg;
    ArgumentParser arg_parser;

    // Step 1: Parse arguments
    ASSERT_TRUE(arg_parser.parse(6, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, output_path);
    EXPECT_TRUE(cfg.compact);
    EXPECT_EQ(cfg.min_severity, "info");

    // Step 2: Validate configuration
    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Step 3: Apply optimizations
    config_validator.apply_fast_scan_optimizations(cfg);

    // Step 4: Initialize rule engine (disabled for this test)
    cfg.rules_enable = false;
    RuleEngineInitializer rule_initializer;
    ASSERT_TRUE(rule_initializer.initialize(cfg));

    // Step 5: Register and run scanners
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    // Verify we got some results
    ASSERT_FALSE(report.results().empty());

    // Step 6: Write output
    OutputWriter output_writer;
    ASSERT_TRUE(output_writer.write_report(report, cfg));

    // Verify output file was created
    ASSERT_TRUE(std::filesystem::exists(cfg.output_file));

    // Step 7: Calculate exit code
    ExitCodeHandler exit_handler;
    int exit_code = exit_handler.calculate_exit_code(report, cfg);

    // Exit code should be 0 or 1 depending on findings
    EXPECT_TRUE(exit_code == 0 || exit_code == 1);
}

// Test workflow with different output formats
TEST_F(IntegrationTest, MultipleOutputFormats) {
    std::string output_path = (temp_dir / "test.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--output", output_path.c_str(),
        "--pretty",
        "--ndjson"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(4, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Run minimal scan
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;

    // Test pretty JSON
    cfg.pretty = true;
    cfg.compact = false;
    cfg.ndjson = false;
    cfg.sarif = false;
    ASSERT_TRUE(output_writer.write_report(report, cfg));

    // Test NDJSON
    cfg.pretty = false;
    cfg.ndjson = true;
    ASSERT_TRUE(output_writer.write_report(report, cfg));

    // Test SARIF
    cfg.ndjson = false;
    cfg.sarif = true;
    ASSERT_TRUE(output_writer.write_report(report, cfg));
}

// Test environment file generation workflow
TEST_F(IntegrationTest, EnvironmentFileGeneration) {
    std::string output_path = (temp_dir / "test_output.json").string();
    std::string env_path = (temp_dir / "test.env").string();
    
    const char* argv[] = {
        "sys-scan",
        "--output", output_path.c_str(),
        "--write-env", env_path.c_str()
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, output_path);
    EXPECT_EQ(cfg.write_env_file, env_path);
}
TEST_F(IntegrationTest, SeverityFilteringWorkflow) {
    std::string output_path = (temp_dir / "filtered.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--output", output_path.c_str(),
        "--min-severity", "medium",
        "--fail-on", "high",
        "--compact"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(8, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    EXPECT_EQ(cfg.min_severity, "medium");
    EXPECT_EQ(cfg.fail_on_severity, "high");

    // Run scan
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;
    ASSERT_TRUE(output_writer.write_report(report, cfg));

    ExitCodeHandler exit_handler;
    int exit_code = exit_handler.calculate_exit_code(report, cfg);
    EXPECT_TRUE(exit_code == 0 || exit_code == 1);
}
TEST_F(IntegrationTest, ScannerEnableDisableWorkflow) {
    std::string output_path = (temp_dir / "selective.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--enable", "processes,network",
        "--disable", "modules",
        "--output", output_path.c_str(),
        "--compact"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(7, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Verify scanner configuration
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "processes") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "network") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "modules") != cfg.disable_scanners.end());

    // Run scan with selective scanners
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;
    ASSERT_TRUE(output_writer.write_report(report, cfg));
}
TEST_F(IntegrationTest, ErrorHandlingWorkflow) {
    // Test with invalid output path
    const char* argv[] = {
        "sys-scan",
        "--output", "/non/existent/directory/output.json",
        "--compact"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(3, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Run scan
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;
    // This should fail due to invalid output path
    EXPECT_FALSE(output_writer.write_report(report, cfg));
}
TEST_F(IntegrationTest, FastScanOptimizationWorkflow) {
    std::string output_path = (temp_dir / "fast_scan.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--fast-scan",
        "--output", output_path.c_str(),
        "--compact"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(4, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Apply fast scan optimizations
    config_validator.apply_fast_scan_optimizations(cfg);

    // Verify fast scan settings
    EXPECT_FALSE(cfg.integrity);
    EXPECT_FALSE(cfg.ioc_exec_trace);
    EXPECT_TRUE(cfg.modules_summary_only);

    // Run optimized scan
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;
    ASSERT_TRUE(output_writer.write_report(report, cfg));
}
TEST_F(IntegrationTest, ExternalFileLoadingWorkflow) {
    // Create test IOC allow file
    auto ioc_file = temp_dir / "test_ioc_allow.txt";
    std::ofstream ioc_stream(ioc_file);
    ioc_stream << "test_ioc_1\n";
    ioc_stream << "test_ioc_2\n";
    ioc_stream.close();

    std::string ioc_file_path = ioc_file.string();
    std::string output_path = (temp_dir / "external_files.json").string();
    
    const char* argv[] = {
        "sys-scan",
        "--ioc-allow-file", ioc_file_path.c_str(),
        "--output", output_path.c_str(),
        "--compact"
    };

    Config cfg;
    ArgumentParser arg_parser;
    ASSERT_TRUE(arg_parser.parse(5, const_cast<char**>(argv), cfg));

    ConfigValidator config_validator;
    ASSERT_TRUE(config_validator.validate(cfg));

    // Load external files
    ASSERT_TRUE(config_validator.load_external_files(cfg));

    // Verify external files were loaded
    EXPECT_EQ(cfg.ioc_allow.size(), 2);
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test_ioc_1") != cfg.ioc_allow.end());
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test_ioc_2") != cfg.ioc_allow.end());

    // Run scan
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    Report report;
    ScanContext context(cfg, report);
    registry.run_all(context);

    OutputWriter output_writer;
    ASSERT_TRUE(output_writer.write_report(report, cfg));
}} // namespace sys_scan
