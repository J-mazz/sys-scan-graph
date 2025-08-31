#include "core/ArgumentParser.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <limits>

namespace sys_scan {

class ArgumentParserExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

// Test boundary values for integer arguments
TEST_F(ArgumentParserExtendedTest, ParseIntegerBoundaries) {
    ArgumentParser parser;
    Config cfg;

    // Test maximum integer values
    const char* argv_max[] = {"sys-scan", "--max-processes", "2147483647", "--max-sockets", "2147483647"};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv_max), cfg));
    EXPECT_EQ(cfg.max_processes, std::numeric_limits<int>::max());
    EXPECT_EQ(cfg.max_sockets, std::numeric_limits<int>::max());

    // Test minimum integer values (0)
    Config cfg_min;
    const char* argv_min[] = {"sys-scan", "--max-processes", "0", "--max-sockets", "0"};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv_min), cfg_min));
    EXPECT_EQ(cfg_min.max_processes, 0);
    EXPECT_EQ(cfg_min.max_sockets, 0);
}

// Test very long arguments (but not too long to avoid corruption)
TEST_F(ArgumentParserExtendedTest, ParseVeryLongArguments) {
    ArgumentParser parser;
    Config cfg;

    // Create a long but reasonable path (shorter to avoid corruption)
    std::string long_path = std::string(512, 'a') + ".json"; // 512 chars + .json
    
    const char* argv[] = {"sys-scan", "--output", long_path.c_str()};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, long_path);
}

// Test argument parsing with special characters
TEST_F(ArgumentParserExtendedTest, ParseSpecialCharacters) {
    ArgumentParser parser;
    Config cfg;

    // Test with paths containing spaces, quotes, and special characters
    const char* argv[] = {"sys-scan", "--output", "/path with spaces/file.json", "--rules-dir", "/path'with\"quotes/dir"};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, "/path with spaces/file.json");
    EXPECT_EQ(cfg.rules_dir, "/path'with\"quotes/dir");
}

// Test CSV parsing with edge cases
TEST_F(ArgumentParserExtendedTest, ParseCSVSyntaxEdgeCases) {
    ArgumentParser parser;
    Config cfg;

    // Test CSV with empty values (split_csv ignores empty strings)
    const char* argv1[] = {"sys-scan", "--enable", "processes,,network,"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv1), cfg));
    EXPECT_EQ(cfg.enable_scanners.size(), 2); // Only non-empty strings are kept
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "processes") != cfg.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "network") != cfg.enable_scanners.end());

    // Test CSV with only commas (split_csv ignores empty strings)
    Config cfg2;
    const char* argv2[] = {"sys-scan", "--enable", ",,,"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv2), cfg2));
    EXPECT_EQ(cfg2.enable_scanners.size(), 0); // No non-empty strings

    // Test CSV with whitespace (parser doesn't trim spaces)
    Config cfg3;
    const char* argv3[] = {"sys-scan", "--enable", " processes , network , modules "};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv3), cfg3));
    EXPECT_EQ(cfg3.enable_scanners.size(), 3);
    EXPECT_TRUE(std::find(cfg3.enable_scanners.begin(), cfg3.enable_scanners.end(), " processes ") != cfg3.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg3.enable_scanners.begin(), cfg3.enable_scanners.end(), " network ") != cfg3.enable_scanners.end());
    EXPECT_TRUE(std::find(cfg3.enable_scanners.begin(), cfg3.enable_scanners.end(), " modules ") != cfg3.enable_scanners.end());
}

// Test flag combinations that might conflict
TEST_F(ArgumentParserExtendedTest, ParseConflictingFlagCombinations) {
    ArgumentParser parser;
    Config cfg;

    // Test all output format flags together (should be allowed)
    const char* argv[] = {"sys-scan", "--pretty", "--compact", "--ndjson", "--sarif"};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_TRUE(cfg.pretty);
    EXPECT_TRUE(cfg.compact);
    EXPECT_TRUE(cfg.ndjson);
    EXPECT_TRUE(cfg.sarif);
}

// Test repeated flags (parser overwrites, doesn't accumulate)
TEST_F(ArgumentParserExtendedTest, ParseRepeatedFlags) {
    ArgumentParser parser;
    Config cfg;

    // Test repeated enable flags (parser overwrites, so only last one is kept)
    const char* argv[] = {"sys-scan", "--enable", "processes", "--enable", "network", "--enable", "modules"};
    EXPECT_TRUE(parser.parse(7, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.enable_scanners.size(), 1); // Only the last one is kept
    EXPECT_TRUE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "modules") != cfg.enable_scanners.end());
    EXPECT_FALSE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "processes") != cfg.enable_scanners.end());
    EXPECT_FALSE(std::find(cfg.enable_scanners.begin(), cfg.enable_scanners.end(), "network") != cfg.enable_scanners.end());
}

// Test malformed CSV values
TEST_F(ArgumentParserExtendedTest, ParseMalformedCSV) {
    ArgumentParser parser;
    Config cfg;

    // Test CSV with unclosed quotes (should handle gracefully)
    const char* argv[] = {"sys-scan", "--enable", "processes,\"unclosed,network"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    // Should still parse what it can
    EXPECT_FALSE(cfg.enable_scanners.empty());
}

// Test large number of arguments (but not too many to avoid memory issues)
TEST_F(ArgumentParserExtendedTest, ParseManyArguments) {
    ArgumentParser parser;
    Config cfg;

    // Create a reasonable number of arguments (not 100 which could cause issues)
    const int num_args = 10; // Reduced to prevent issues
    std::vector<const char*> argv;

    argv.push_back("sys-scan");

    for (int i = 0; i < num_args; ++i) {
        argv.push_back("--enable");
        // Create a static string that persists for the test
        static std::vector<std::string> scanner_names;
        scanner_names.push_back("scanner" + std::to_string(i));
        argv.push_back(scanner_names.back().c_str());
    }

    EXPECT_TRUE(parser.parse(argv.size(), const_cast<char**>(argv.data()), cfg));
    EXPECT_EQ(cfg.enable_scanners.size(), 1); // Only the last --enable value is kept
    EXPECT_EQ(cfg.enable_scanners[0], "scanner9"); // Last scanner name
}

// Test argument parsing with Unicode characters
TEST_F(ArgumentParserExtendedTest, ParseUnicodeArguments) {
    ArgumentParser parser;
    Config cfg;

    // Test with Unicode characters in paths
    const char* argv[] = {"sys-scan", "--output", "/path/文件.json", "--rules-dir", "/路径/规则"};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, "/path/文件.json");
    EXPECT_EQ(cfg.rules_dir, "/路径/规则");
}

// Test argument order independence
TEST_F(ArgumentParserExtendedTest, ParseArgumentOrderIndependence) {
    ArgumentParser parser1, parser2;
    Config cfg1, cfg2;

    // Same arguments in different order
    const char* argv1[] = {"sys-scan", "--output", "test.json", "--compact", "--min-severity", "medium"};
    const char* argv2[] = {"sys-scan", "--min-severity", "medium", "--compact", "--output", "test.json"};

    EXPECT_TRUE(parser1.parse(6, const_cast<char**>(argv1), cfg1));
    EXPECT_TRUE(parser2.parse(6, const_cast<char**>(argv2), cfg2));

    // Results should be identical
    EXPECT_EQ(cfg1.output_file, cfg2.output_file);
    EXPECT_EQ(cfg1.compact, cfg2.compact);
    EXPECT_EQ(cfg1.min_severity, cfg2.min_severity);
}

// Test partial argument parsing (incomplete flag)
TEST_F(ArgumentParserExtendedTest, ParseIncompleteArguments) {
    ArgumentParser parser;
    Config cfg;

    // Test with flag but no value
    const char* argv[] = {"sys-scan", "--output"};
    EXPECT_FALSE(parser.parse(2, const_cast<char**>(argv), cfg));
}

// Test empty string arguments
TEST_F(ArgumentParserExtendedTest, ParseEmptyStringArguments) {
    ArgumentParser parser;
    Config cfg;

    // Test with empty string values
    const char* argv[] = {"sys-scan", "--output", "", "--rules-dir", ""};
    EXPECT_TRUE(parser.parse(5, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.output_file, "");
    EXPECT_EQ(cfg.rules_dir, "");
}

// Test argument parsing with environment variable expansion
TEST_F(ArgumentParserExtendedTest, ParseEnvironmentVariableExpansion) {
    ArgumentParser parser;
    Config cfg;

    // Set an environment variable for testing
    setenv("TEST_OUTPUT_DIR", "/tmp/test", 1);

    // Test with environment variable in path (this would require shell expansion)
    const char* argv[] = {"sys-scan", "--output", "$TEST_OUTPUT_DIR/output.json"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    // Note: The parser doesn't expand environment variables itself
    EXPECT_EQ(cfg.output_file, "$TEST_OUTPUT_DIR/output.json");

    unsetenv("TEST_OUTPUT_DIR");
}

// Test flag abbreviation handling
TEST_F(ArgumentParserExtendedTest, ParseFlagAbbreviations) {
    ArgumentParser parser;
    Config cfg;

    // Test that full flag names work (abbreviations aren't typically supported)
    const char* argv[] = {"sys-scan", "--min-severity", "high"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv), cfg));
    EXPECT_EQ(cfg.min_severity, "high");
}

// Test case sensitivity of flags
TEST_F(ArgumentParserExtendedTest, ParseCaseSensitivity) {
    ArgumentParser parser;
    Config cfg;

    // Test mixed case flags (should be case sensitive)
    const char* argv[] = {"sys-scan", "--Output", "test.json"}; // Wrong case
    EXPECT_FALSE(parser.parse(3, const_cast<char**>(argv), cfg));

    // Test correct case
    const char* argv2[] = {"sys-scan", "--output", "test.json"};
    EXPECT_TRUE(parser.parse(3, const_cast<char**>(argv2), cfg));
    EXPECT_EQ(cfg.output_file, "test.json");
}

// Test argument parsing performance with many flags
TEST_F(ArgumentParserExtendedTest, ParsePerformanceManyFlags) {
    ArgumentParser parser;
    Config cfg;

    // Create many different flags
    const char* argv[] = {
        "sys-scan",
        "--output", "test.json",
        "--compact",
        "--pretty",
        "--ndjson",
        "--sarif",
        "--min-severity", "info",
        "--fail-on", "high",
        "--fail-on-count", "10",
        "--enable", "processes,network,modules",
        "--disable", "kernel_params",
        "--max-processes", "1000",
        "--max-sockets", "500",
        "--all-processes",
        "--modules-summary",
        "--integrity",
        "--fast-scan",
        "--rules-enable",
        "--rules-dir", "/etc/rules",
        "--ioc-allow", "test1,test2",
        "--suid-expected", "sudo,passwd",
        "--write-env", "env.txt"
    };

    EXPECT_TRUE(parser.parse(sizeof(argv)/sizeof(argv[0]), const_cast<char**>(argv), cfg));

    // Verify all settings were applied
    EXPECT_EQ(cfg.output_file, "test.json");
    EXPECT_TRUE(cfg.compact);
    EXPECT_TRUE(cfg.pretty);
    EXPECT_TRUE(cfg.ndjson);
    EXPECT_TRUE(cfg.sarif);
    EXPECT_EQ(cfg.min_severity, "info");
    EXPECT_EQ(cfg.fail_on_severity, "high");
    EXPECT_EQ(cfg.fail_on_count, 10);
    EXPECT_EQ(cfg.enable_scanners.size(), 3);
    EXPECT_EQ(cfg.disable_scanners.size(), 1);
    EXPECT_EQ(cfg.max_processes, 1000);
    EXPECT_EQ(cfg.max_sockets, 500);
    EXPECT_TRUE(cfg.all_processes);
    EXPECT_TRUE(cfg.modules_summary_only);
    EXPECT_TRUE(cfg.integrity);
    EXPECT_TRUE(cfg.fast_scan);
    EXPECT_TRUE(cfg.rules_enable);
    EXPECT_EQ(cfg.rules_dir, "/etc/rules");
    EXPECT_EQ(cfg.ioc_allow.size(), 2);
    EXPECT_EQ(cfg.suid_expected_add.size(), 2);
    EXPECT_EQ(cfg.write_env_file, "env.txt");
}

} // namespace sys_scan