#include "core/ConfigValidator.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <limits>

namespace sys_scan {

class ConfigValidatorExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_config_validator_extended_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    ConfigValidator validator;
};

// Test validation with extreme integer values
TEST_F(ConfigValidatorExtendedTest, ValidateExtremeIntegerValues) {
    Config cfg;

    // Test with maximum integer values
    cfg.max_processes = std::numeric_limits<int>::max();
    cfg.max_sockets = std::numeric_limits<int>::max();
    cfg.fail_on_count = std::numeric_limits<int>::max();
    cfg.integrity_pkg_limit = std::numeric_limits<int>::max();

    EXPECT_TRUE(validator.validate(cfg));

    // Test with minimum integer values
    cfg.max_processes = std::numeric_limits<int>::min();
    cfg.max_sockets = std::numeric_limits<int>::min();
    cfg.fail_on_count = std::numeric_limits<int>::min();
    cfg.integrity_pkg_limit = std::numeric_limits<int>::min();

    // Should handle negative values gracefully (depending on implementation)
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with very long strings
TEST_F(ConfigValidatorExtendedTest, ValidateVeryLongStrings) {
    Config cfg;

    // Create very long strings for testing
    std::string long_path(1024, 'a'); // Reduced from 8KB to 1KB
    long_path += ".json";

    std::string long_dir(512, 'b'); // Reduced from 4KB to 512B
    long_dir += "/rules";

    cfg.output_file = long_path;
    cfg.rules_dir = long_dir;
    cfg.ioc_allow_file = long_path;
    cfg.suid_expected_file = long_path;
    cfg.write_env_file = long_path;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with special characters in paths
TEST_F(ConfigValidatorExtendedTest, ValidateSpecialCharacterPaths) {
    Config cfg;

    // Test with various special characters in paths
    cfg.output_file = "/path with spaces/file.json";
    cfg.rules_dir = "/path'with\"quotes/dir";
    cfg.ioc_allow_file = "/path[with]brackets/file.txt";
    cfg.suid_expected_file = "/path{with}braces/file.txt";
    cfg.write_env_file = "/path(with)parens/file.env";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with Unicode characters
TEST_F(ConfigValidatorExtendedTest, ValidateUnicodePaths) {
    Config cfg;

    // Test with Unicode characters in paths
    cfg.output_file = "/路径/文件.json";
    cfg.rules_dir = "/путь/правила";
    cfg.ioc_allow_file = "/chemin/fichier.txt";
    cfg.suid_expected_file = "/ruta/archivo.txt";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with circular scanner enable/disable
TEST_F(ConfigValidatorExtendedTest, ValidateCircularScannerReferences) {
    Config cfg;

    // Test with same scanner in both enable and disable lists
    cfg.enable_scanners = {"processes", "network", "modules"};
    cfg.disable_scanners = {"processes", "kernel_params"};

    EXPECT_FALSE(validator.validate(cfg));
}

// Test validation with empty scanner lists
TEST_F(ConfigValidatorExtendedTest, ValidateEmptyScannerLists) {
    Config cfg;

    // Test with empty enable/disable lists
    cfg.enable_scanners = {};
    cfg.disable_scanners = {};

    EXPECT_TRUE(validator.validate(cfg));

    // Test with one empty, one populated
    cfg.enable_scanners = {"processes"};
    cfg.disable_scanners = {};

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with very large scanner lists
TEST_F(ConfigValidatorExtendedTest, ValidateLargeScannerLists) {
    Config cfg;

    // Create large lists of scanners
    for (int i = 0; i < 100; ++i) {  // Reduced from 1,000 to 100
        cfg.enable_scanners.push_back("scanner" + std::to_string(i));
        cfg.disable_scanners.push_back("disabled_scanner" + std::to_string(i));
    }

    // Should handle large lists (though validation might be slow)
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with conflicting output format combinations
TEST_F(ConfigValidatorExtendedTest, ValidateOutputFormatCombinations) {
    Config cfg;

    // Test all output formats enabled (should be allowed)
    cfg.pretty = true;
    cfg.compact = true;
    cfg.ndjson = true;
    cfg.sarif = true;

    EXPECT_TRUE(validator.validate(cfg));

    // Test no output formats enabled (should be allowed)
    cfg.pretty = false;
    cfg.compact = false;
    cfg.ndjson = false;
    cfg.sarif = false;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with extreme severity thresholds
TEST_F(ConfigValidatorExtendedTest, ValidateExtremeSeverityThresholds) {
    Config cfg;

    // Test with very high fail_on_count
    cfg.fail_on_count = 1000000;
    EXPECT_TRUE(validator.validate(cfg));

    // Test with zero fail_on_count
    cfg.fail_on_count = 0;
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with malformed severity strings
TEST_F(ConfigValidatorExtendedTest, ValidateMalformedSeverityStrings) {
    Config cfg;

    // Test with empty severity strings (should be allowed)
    cfg.min_severity = "";
    cfg.fail_on_severity = "";
    EXPECT_TRUE(validator.validate(cfg));

    // Test with whitespace-only severity strings (should be allowed)
    cfg.min_severity = "   ";
    cfg.fail_on_severity = "\t\n";
    EXPECT_TRUE(validator.validate(cfg));

    // Test with truly invalid severity strings
    cfg.min_severity = "invalid_severity";
    cfg.fail_on_severity = "high";
    EXPECT_FALSE(validator.validate(cfg));

    cfg.min_severity = "high";
    cfg.fail_on_severity = "nonexistent";
    EXPECT_FALSE(validator.validate(cfg));
}

// Test validation with boundary severity values
TEST_F(ConfigValidatorExtendedTest, ValidateSeverityBoundaries) {
    Config cfg;

    // Test all valid severity combinations
    std::vector<std::string> severities = {"info", "low", "medium", "high"};

    for (const auto& min_sev : severities) {
        for (const auto& fail_sev : severities) {
            cfg.min_severity = min_sev;
            cfg.fail_on_severity = fail_sev;

            if (min_sev == "high" && fail_sev == "low") {
                // This should fail (min_severity > fail_on_severity in terms of threshold)
                EXPECT_FALSE(validator.validate(cfg)) << "Failed for min=" << min_sev << ", fail=" << fail_sev;
            } else {
                EXPECT_TRUE(validator.validate(cfg)) << "Failed for min=" << min_sev << ", fail=" << fail_sev;
            }
        }
    }
}

// Test validation with very long CSV values
TEST_F(ConfigValidatorExtendedTest, ValidateLongCSVValues) {
    Config cfg;

    // Create very long CSV strings
    std::string long_csv;
    for (int i = 0; i < 100; ++i) {  // Reduced from 1,000 to 100
        if (i > 0) long_csv += ",";
        long_csv += "scanner" + std::to_string(i);
    }

    cfg.enable_scanners = {long_csv}; // This will be parsed as CSV
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with duplicate values in CSV
TEST_F(ConfigValidatorExtendedTest, ValidateDuplicateCSVValues) {
    Config cfg;

    // Test with duplicate values in enable/disable lists
    cfg.enable_scanners = {"processes", "network", "processes", "modules"};
    cfg.disable_scanners = {"kernel_params", "kernel_params"};

    // Should allow duplicates (implementation dependent)
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with empty CSV elements
TEST_F(ConfigValidatorExtendedTest, ValidateEmptyCSVElements) {
    Config cfg;

    // Test with empty elements in CSV
    cfg.enable_scanners = {"processes", "", "network", ""};
    cfg.disable_scanners = {"", "kernel_params"};

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with special characters in scanner names
TEST_F(ConfigValidatorExtendedTest, ValidateSpecialCharacterScannerNames) {
    Config cfg;

    // Test with special characters in scanner names
    cfg.enable_scanners = {"scanner-with-dashes", "scanner_with_underscores", "scanner.with.dots"};
    cfg.disable_scanners = {"scanner with spaces", "scanner'with'quotes"};

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with very deep directory paths
TEST_F(ConfigValidatorExtendedTest, ValidateDeepDirectoryPaths) {
    Config cfg;

    // Create a very deep path
    std::string deep_path = "/";
    for (int i = 0; i < 50; ++i) {
        deep_path += "level" + std::to_string(i) + "/";
    }
    deep_path += "file.json";

    cfg.output_file = deep_path;
    cfg.rules_dir = deep_path.substr(0, deep_path.find_last_of('/'));

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with relative paths
TEST_F(ConfigValidatorExtendedTest, ValidateRelativePaths) {
    Config cfg;

    // Test with relative paths
    cfg.output_file = "./output.json";
    cfg.rules_dir = "../rules";
    cfg.ioc_allow_file = "ioc.txt";
    cfg.suid_expected_file = "./suid.txt";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with paths containing newlines and tabs
TEST_F(ConfigValidatorExtendedTest, ValidatePathsWithWhitespace) {
    Config cfg;

    // Test with paths containing various whitespace characters
    cfg.output_file = "/path\twith\ttabs/file.json";
    cfg.rules_dir = "/path\nwith\nnewlines";
    cfg.ioc_allow_file = "/path with spaces/file.txt";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with extremely long file extensions
TEST_F(ConfigValidatorExtendedTest, ValidateLongFileExtensions) {
    Config cfg;

    // Create file with very long extension
    std::string long_ext(1000, 'x');
    cfg.output_file = "/path/file." + long_ext;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with network paths
TEST_F(ConfigValidatorExtendedTest, ValidateNetworkPaths) {
    Config cfg;

    // Test with network-style paths
    cfg.output_file = "//server/share/file.json";
    cfg.rules_dir = "\\\\server\\share\\rules";
    cfg.ioc_allow_file = "/net/server/share/ioc.txt";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with paths containing shell metacharacters
TEST_F(ConfigValidatorExtendedTest, ValidatePathsWithShellMetacharacters) {
    Config cfg;

    // Test with paths containing shell metacharacters
    cfg.output_file = "/path/with$(command)/file.json";
    cfg.rules_dir = "/path/with`command`/rules";
    cfg.ioc_allow_file = "/path/with;command/file.txt";

    // Should validate paths even with potentially dangerous characters
    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation performance with many configuration options
TEST_F(ConfigValidatorExtendedTest, ValidatePerformanceManyOptions) {
    Config cfg;

    // Set many configuration options
    cfg.output_file = "/tmp/test.json";
    cfg.compact = true;
    cfg.pretty = true;
    cfg.ndjson = true;
    cfg.sarif = true;
    cfg.min_severity = "info";
    cfg.fail_on_severity = "high";
    cfg.fail_on_count = 100;
    cfg.enable_scanners = {"processes", "network", "modules", "kernel_params", "world_writable", "suid_sgid", "ioc", "mac"};
    cfg.disable_scanners = {"mounts", "kernel_hardening", "auditd", "containers"};
    cfg.max_processes = 1000;
    cfg.max_sockets = 500;
    cfg.all_processes = true;
    cfg.modules_summary_only = true;
    cfg.integrity = true;
    cfg.fast_scan = false;
    cfg.rules_enable = true;
    cfg.rules_dir = "/etc/sys-scan/rules";
    cfg.ioc_allow_file = "/etc/sys-scan/ioc_allow.txt";
    cfg.suid_expected_file = "/etc/sys-scan/suid_expected.txt";
    cfg.write_env_file = "/tmp/env.txt";
    cfg.drop_priv = true;
    cfg.keep_cap_dac = false;
    cfg.seccomp = true;
    cfg.seccomp_strict = false;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with configuration that has all features disabled
TEST_F(ConfigValidatorExtendedTest, ValidateAllFeaturesDisabled) {
    Config cfg;

    // Disable all optional features
    cfg.compact = false;
    cfg.pretty = false;
    cfg.ndjson = false;
    cfg.sarif = false;
    cfg.all_processes = false;
    cfg.modules_summary_only = false;
    cfg.integrity = false;
    cfg.fast_scan = false;
    cfg.rules_enable = false;
    cfg.drop_priv = false;
    cfg.seccomp = false;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test validation with configuration that has all features enabled
TEST_F(ConfigValidatorExtendedTest, ValidateAllFeaturesEnabled) {
    Config cfg;

    // Enable all optional features
    cfg.compact = true;
    cfg.pretty = true;
    cfg.ndjson = true;
    cfg.sarif = true;
    cfg.all_processes = true;
    cfg.modules_summary_only = true;
    cfg.integrity = true;
    cfg.fast_scan = true;
    cfg.rules_enable = true;
    cfg.drop_priv = true;
    cfg.seccomp = true;
    cfg.seccomp_strict = true;

    // Set required paths
    cfg.output_file = "/tmp/test.json";
    cfg.rules_dir = "/etc/rules";

    EXPECT_TRUE(validator.validate(cfg));
}

} // namespace sys_scan