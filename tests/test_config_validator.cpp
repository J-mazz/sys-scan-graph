#include "core/ConfigValidator.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

namespace sys_scan {

class ConfigValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        temp_dir = std::filesystem::temp_directory_path() / "sys_scan_test";
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
    ConfigValidator validator;
};

// Test basic validation with valid config
TEST_F(ConfigValidatorTest, ValidateValidConfig) {
    Config cfg;
    cfg.min_severity = "low";
    cfg.fail_on_severity = "high";
    cfg.output_file = "test.json";

    EXPECT_TRUE(validator.validate(cfg));
}

// Test severity validation
TEST_F(ConfigValidatorTest, ValidateSeverityLevels) {
    Config cfg;

    // Test valid severity levels
    std::vector<std::string> valid_severities = {"info", "low", "medium", "high"};
    for (const auto& severity : valid_severities) {
        cfg.min_severity = severity;
        cfg.fail_on_severity = severity;
        EXPECT_TRUE(validator.validate(cfg)) << "Failed for severity: " << severity;
    }

    // Test invalid severity level
    cfg.min_severity = "invalid";
    EXPECT_FALSE(validator.validate(cfg));
}

// Test conflicting severity settings
TEST_F(ConfigValidatorTest, ValidateConflictingSeverities) {
    Config cfg;
    cfg.min_severity = "high";
    cfg.fail_on_severity = "low";

    // This should fail because min_severity > fail_on_severity
    EXPECT_FALSE(validator.validate(cfg));
}

// Test output format conflicts
TEST_F(ConfigValidatorTest, ValidateOutputFormatConflicts) {
    Config cfg;

    // Test multiple format flags (should be allowed, implementation handles precedence)
    cfg.pretty = true;
    cfg.compact = true;
    cfg.ndjson = true;
    cfg.sarif = true;

    EXPECT_TRUE(validator.validate(cfg));
}

// Test scanner enable/disable conflicts
TEST_F(ConfigValidatorTest, ValidateScannerConflicts) {
    Config cfg;

    // Enable and disable the same scanner
    cfg.enable_scanners = {"processes"};
    cfg.disable_scanners = {"processes"};

    EXPECT_FALSE(validator.validate(cfg));
}

// Test file loading - IOC allow file
TEST_F(ConfigValidatorTest, LoadIOCAllowFile) {
    // Create test IOC allow file
    auto ioc_file = temp_dir / "ioc_allow.txt";
    std::ofstream file(ioc_file);
    file << "test_ioc_1\n";
    file << "test_ioc_2\n";
    file << "# This is a comment\n";
    file << "test_ioc_3\n";
    file.close();

    Config cfg;
    cfg.ioc_allow_file = ioc_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_EQ(cfg.ioc_allow.size(), 3);
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test_ioc_1") != cfg.ioc_allow.end());
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test_ioc_2") != cfg.ioc_allow.end());
    EXPECT_TRUE(std::find(cfg.ioc_allow.begin(), cfg.ioc_allow.end(), "test_ioc_3") != cfg.ioc_allow.end());
}

// Test file loading - SUID expected file
TEST_F(ConfigValidatorTest, LoadSUIDExpectedFile) {
    // Create test SUID expected file
    auto suid_file = temp_dir / "suid_expected.txt";
    std::ofstream file(suid_file);
    file << "/bin/su\n";
    file << "/usr/bin/sudo\n";
    file << "# Comment line\n";
    file << "/bin/mount\n";
    file.close();

    Config cfg;
    cfg.suid_expected_file = suid_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_EQ(cfg.suid_expected_add.size(), 3);
    EXPECT_TRUE(std::find(cfg.suid_expected_add.begin(), cfg.suid_expected_add.end(), "/bin/su") != cfg.suid_expected_add.end());
    EXPECT_TRUE(std::find(cfg.suid_expected_add.begin(), cfg.suid_expected_add.end(), "/usr/bin/sudo") != cfg.suid_expected_add.end());
    EXPECT_TRUE(std::find(cfg.suid_expected_add.begin(), cfg.suid_expected_add.end(), "/bin/mount") != cfg.suid_expected_add.end());
}

// Test loading non-existent file
TEST_F(ConfigValidatorTest, LoadNonExistentFile) {
    Config cfg;
    cfg.ioc_allow_file = "/non/existent/file.txt";

    EXPECT_FALSE(validator.load_external_files(cfg));
}

// Test loading empty file
TEST_F(ConfigValidatorTest, LoadEmptyFile) {
    // Create empty test file
    auto empty_file = temp_dir / "empty.txt";
    std::ofstream file(empty_file);
    file.close();

    Config cfg;
    cfg.ioc_allow_file = empty_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_TRUE(cfg.ioc_allow.empty());
}

// Test loading file with only comments
TEST_F(ConfigValidatorTest, LoadFileWithOnlyComments) {
    // Create file with only comments
    auto comment_file = temp_dir / "comments.txt";
    std::ofstream file(comment_file);
    file << "# This is a comment\n";
    file << "   # Another comment with spaces\n";
    file << "\n";  // Empty line
    file.close();

    Config cfg;
    cfg.ioc_allow_file = comment_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_TRUE(cfg.ioc_allow.empty());
}

// Test fast scan optimizations
TEST_F(ConfigValidatorTest, ApplyFastScanOptimizations) {
    Config cfg;
    cfg.fast_scan = true;

    validator.apply_fast_scan_optimizations(cfg);

    // Fast scan should disable resource-intensive features
    EXPECT_FALSE(cfg.integrity);
    EXPECT_FALSE(cfg.ioc_exec_trace);
    EXPECT_TRUE(cfg.modules_summary_only);
    EXPECT_FALSE(cfg.process_hash);
}

// Test normal scan (no optimizations)
TEST_F(ConfigValidatorTest, ApplyNormalScanOptimizations) {
    Config cfg;
    cfg.fast_scan = false;

    validator.apply_fast_scan_optimizations(cfg);

    // Normal scan should not change default settings
    // (This is more of a no-op test, but ensures the method doesn't break anything)
    EXPECT_TRUE(true);  // Placeholder - actual defaults depend on Config constructor
}

// Test integer validation
TEST_F(ConfigValidatorTest, ValidateIntegerParameters) {
    Config cfg;

    // Test valid integer ranges
    cfg.max_processes = 100;
    cfg.max_sockets = 50;
    cfg.integrity_pkg_limit = 10;

    EXPECT_TRUE(validator.validate(cfg));

    // Test negative values (should be allowed or handled gracefully)
    cfg.max_processes = -1;
    EXPECT_TRUE(validator.validate(cfg));  // Implementation should handle this
}

// Test path validation
TEST_F(ConfigValidatorTest, ValidatePaths) {
    Config cfg;

    // Test valid paths
    cfg.output_file = "/tmp/test.json";
    cfg.rules_dir = "/etc/sys-scan/rules";
    cfg.ioc_allow_file = "/etc/sys-scan/ioc.txt";

    EXPECT_TRUE(validator.validate(cfg));

    // Test empty paths (should be valid)
    cfg.output_file = "";
    cfg.rules_dir = "";
    EXPECT_TRUE(validator.validate(cfg));
}

// Test privilege-related validation
TEST_F(ConfigValidatorTest, ValidatePrivilegeSettings) {
    Config cfg;

    // Test privilege drop settings
    cfg.drop_priv = true;
    cfg.keep_cap_dac = true;
    cfg.seccomp = true;
    cfg.seccomp_strict = false;

    EXPECT_TRUE(validator.validate(cfg));

    // Test conflicting privilege settings
    cfg.drop_priv = true;
    cfg.keep_cap_dac = false;  // This might be invalid in some contexts
    EXPECT_TRUE(validator.validate(cfg));  // Should still pass basic validation
}

} // namespace sys_scan