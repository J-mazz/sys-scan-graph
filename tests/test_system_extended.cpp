#include "core/Config.h"
#include "core/Report.h"
#include "core/Scanner.h"
#include "core/OutputWriter.h"
#include "core/ExitCodeHandler.h"
#include "core/ArgumentParser.h"
#include "core/ConfigValidator.h"
#include "core/Severity.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <chrono>
#include <thread>
#include <nlohmann/json.hpp>

namespace sys_scan {

class SystemExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_system_extended_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
};

// Test complete system with extreme values and edge cases
TEST_F(SystemExtendedTest, CompleteSystemExtremeValuesEdgeCases) {
    Config cfg;
    cfg.output_file = (temp_dir / "extreme_values.json").string();
    cfg.compact = true;
    cfg.fail_on_count = 50;

    // Test with extreme scanner names and configurations
    cfg.enable_scanners = {"", std::string(10000, 'a'), "normal_scanner"};

    // Create report with extreme data
    Report report;
    ScanResult result;
    result.scanner_name = "extreme_scanner";
    result.start_time = std::chrono::system_clock::now();
    result.end_time = std::chrono::system_clock::now();

    // Add findings with extreme metadata
    for (int i = 0; i < 1000; ++i) {
        result.findings.push_back(Finding{
            "extreme_finding_" + std::to_string(i),
            "Finding with extreme metadata " + std::to_string(i),
            Severity::Info,
            std::string(5000, 'x'), // Very long description
            std::map<std::string, std::string>{
                {"key" + std::to_string(i), std::string(1000, 'y')}, // Very long metadata values
                {"extreme_test", "edge_case"}
            },
            10,
            false
        });
    }
    report.add_result(result);

    // Test configuration validation
    ConfigValidator validator;
    EXPECT_THROW(validator.validate(cfg), std::runtime_error);

    // Test output writing with extreme data
    OutputWriter writer;
    EXPECT_TRUE(writer.write_report(report, cfg));

    // Test exit code with extreme threshold
    ExitCodeHandler handler;
    int exit_code = handler.calculate_exit_code(report, cfg);
    EXPECT_EQ(exit_code, 1); // Should exceed threshold (1000 findings > 50 threshold)
}

} // namespace sys_scan