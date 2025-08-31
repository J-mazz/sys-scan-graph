#include "core/ArgumentParser.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <vector>
#include <string>

namespace sys_scan {

class ArgumentParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

// Test basic argument parsing
TEST_F(ArgumentParserTest, ParseBasicArguments) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--output", "test.json", "--compact"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, "test.json");
    EXPECT_TRUE(cfg.compact);
}

// Test help flag
TEST_F(ArgumentParserTest, ParseHelpFlag) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--help"};

    // Help should return false (indicating early exit)
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test version flag
TEST_F(ArgumentParserTest, ParseVersionFlag) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--version"};

    // Version should return false (indicating early exit)
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test enable/disable flags
TEST_F(ArgumentParserTest, ParseEnableDisableFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--enable", "processes,network", "--disable", "modules"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "processes") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "network") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "modules") != cfg.disable_scanners.end());
}

// Test output format flags
TEST_F(ArgumentParserTest, ParseOutputFormatFlags) {
    ArgumentParser parser;
    Config cfg;

    // Test pretty format
    const char* argv1[] = {"sys-scan", "--pretty"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv1), cfg));
    EXPECT_TRUE(cfg.pretty);

    // Test compact format
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--compact"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv2), cfg2));
    EXPECT_TRUE(cfg2.compact);

    // Test NDJSON format
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--ndjson"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv3), cfg3));
    EXPECT_TRUE(cfg3.ndjson);

    // Test SARIF format
    Config cfg4;
    const char* argv4[] = {"sys-scan", "--sarif"};
    EXPECT_TRUE(parser.parse(2, const_cast<char**>(argv4), cfg4));
    EXPECT_TRUE(cfg4.sarif);
}

// Test severity filtering
TEST_F(ArgumentParserTest, ParseSeverityFilter) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--min-severity", "medium"};

    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.min_severity, "medium");
}

// Test fail-on flags
TEST_F(ArgumentParserTest, ParseFailOnFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--fail-on", "high", "--fail-on-count", "5"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.fail_on_severity, "high");
    EXPECT_EQ(cfg.fail_on_count, 5);
}

// Test scanner-specific flags
TEST_F(ArgumentParserTest, ParseScannerSpecificFlags) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--all-processes", "--modules-summary", "--integrity"};

    EXPECT_TRUE(parser.parse(4, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.all_processes);
    EXPECT_TRUE(cfg.modules_summary_only);
    EXPECT_TRUE(cfg.integrity);
}

// Test CSV parsing
TEST_F(ArgumentParserTest, ParseCSVArguments) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--ioc-allow", "test1,test2,test3"};

    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.ioc_allow.size(), 3);
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test1") != cfg.ioc_allow.end());
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test2") != cfg.ioc_allow.end());
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test3") != cfg.ioc_allow.end());
}

// Test integer arguments
TEST_F(ArgumentParserTest, ParseIntegerArguments) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--max-processes", "100", "--max-sockets", "50"};

    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.max_processes, 100);
    EXPECT_EQ(cfg.max_sockets, 50);
}

// Test invalid integer argument
TEST_F(ArgumentParserTest, ParseInvalidIntegerArgument) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--max-processes", "invalid"};

    // Should fail with invalid integer
    EXPECT_FALSE(parser.parse(3, const_cast<char**>(argv), cfg));
}

// Test unknown flag
TEST_F(ArgumentParserTest, ParseUnknownFlag) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--unknown-flag"};

    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test conflicting output formats
TEST_F(ArgumentParserTest, ParseConflictingOutputFormats) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--pretty", "--compact"};

    // Should allow both (compact takes precedence in actual usage)
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.pretty);
    EXPECT_TRUE(cfg.compact);
}

// Test empty arguments
TEST_F(ArgumentParserTest, ParseEmptyArguments) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan"};

    EXPECT_TRUE(parser.parse(1, const_cast<char**>(argv), cfg));
    // Default values should be set
    EXPECT_FALSE(cfg.compact);
    EXPECT_FALSE(cfg.pretty);
    EXPECT_EQ(cfg.output_file, "");
}

// Test multiple CSV values
TEST_F(ArgumentParserTest, ParseMultipleCSVValues) {
    ArgumentParser parser;
    Config cfg;
    const char* argv[] = {"sys-scan", "--suid-expected", "binary1,binary2,/usr/bin/sudo"};

    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.suid_expected_add.size(), 3);
    EXPECT_TRUE(std::find(cfg.suid_expected_add.begin(), cfg.suid_expected_add.end(), "binary1") != cfg.suid_expected_add.end());
    EXPECT_TRUE(std::find(cfg.suid_expected_add.begin(), cfg.suid_expected_add.end(), "/usr/bin/sudo") != cfg.suid_expected_add.end());
}

} // namespace sys_scan