#include "core/ConfigValidator.h"
#include "core/Config.h"
#include <gtest/gtest.h>
#include <algorithm>
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

// Test ioc_exec_trace default duration normalization
TEST_F(ConfigValidatorTest, NormalizeIOCExecTraceDuration) {
    Config cfg;
    cfg.ioc_exec_trace = true;
    cfg.ioc_exec_trace_seconds = 0;

    EXPECT_TRUE(validator.validate(cfg));
    EXPECT_EQ(cfg.ioc_exec_trace_seconds, 3); // Should be normalized to 3
}

// Test ioc_exec_trace with non-zero duration
TEST_F(ConfigValidatorTest, IOCExecTraceWithNonZeroDuration) {
    Config cfg;
    cfg.ioc_exec_trace = true;
    cfg.ioc_exec_trace_seconds = 10;

    EXPECT_TRUE(validator.validate(cfg));
    EXPECT_EQ(cfg.ioc_exec_trace_seconds, 10); // Should remain unchanged
}

// Test pretty/compact conflict resolution
TEST_F(ConfigValidatorTest, PrettyCompactConflict) {
    Config cfg;
    cfg.pretty = true;
    cfg.compact = true;

    EXPECT_TRUE(validator.validate(cfg));
    EXPECT_FALSE(cfg.pretty); // pretty should be disabled when compact is set
    EXPECT_TRUE(cfg.compact);
}

// Test sign_gpg requires output_file
TEST_F(ConfigValidatorTest, SignGPGRequiresOutputFile) {
    Config cfg;
    cfg.sign_gpg = true;
    cfg.output_file = "";

    EXPECT_FALSE(validator.validate(cfg)); // Should fail
}

// Test sign_gpg with output_file
TEST_F(ConfigValidatorTest, SignGPGWithOutputFile) {
    Config cfg;
    cfg.sign_gpg = true;
    cfg.output_file = "test.json";

    EXPECT_TRUE(validator.validate(cfg)); // Should pass
}

// Test container_id_filter requires containers flag
TEST_F(ConfigValidatorTest, ContainerIdRequiresContainers) {
    Config cfg;
    cfg.container_id_filter = "abc123";
    cfg.containers = false;

    EXPECT_FALSE(validator.validate(cfg)); // Should fail
}

// Test container_id_filter with containers enabled
TEST_F(ConfigValidatorTest, ContainerIdWithContainersEnabled) {
    Config cfg;
    cfg.container_id_filter = "abc123";
    cfg.containers = true;

    EXPECT_TRUE(validator.validate(cfg)); // Should pass
}

// Test severity validation with whitespace
TEST_F(ConfigValidatorTest, SeverityValidationWithWhitespace) {
    Config cfg;
    cfg.min_severity = "  low  \n";
    cfg.fail_on_severity = "\thigh\t";

    EXPECT_TRUE(validator.validate(cfg)); // Should trim and validate
}

// Test severity validation with empty string
TEST_F(ConfigValidatorTest, SeverityValidationEmptyString) {
    Config cfg;
    cfg.min_severity = "";
    cfg.fail_on_severity = "";

    EXPECT_TRUE(validator.validate(cfg)); // Empty severities should be allowed
}

// Test severity validation with all whitespace
TEST_F(ConfigValidatorTest, SeverityValidationAllWhitespace) {
    Config cfg;
    cfg.min_severity = "   \t\n   ";
    cfg.fail_on_severity = "   ";

    EXPECT_TRUE(validator.validate(cfg)); // All whitespace treated as empty
}

// Test severity validation case insensitive
TEST_F(ConfigValidatorTest, SeverityValidationCaseInsensitive) {
    Config cfg;
    cfg.min_severity = "HIGH";
    cfg.fail_on_severity = "CRITICAL";

    EXPECT_TRUE(validator.validate(cfg)); // Should accept uppercase
}

// Test severity validation mixed case
TEST_F(ConfigValidatorTest, SeverityValidationMixedCase) {
    Config cfg;
    cfg.min_severity = "MeDiUm";
    cfg.fail_on_severity = "HiGh";

    EXPECT_TRUE(validator.validate(cfg)); // Should accept mixed case
}

// Test severity rank function
TEST_F(ConfigValidatorTest, SeverityRankFunction) {
    EXPECT_EQ(validator.severity_rank("info"), 0);
    EXPECT_EQ(validator.severity_rank("low"), 1);
    EXPECT_EQ(validator.severity_rank("medium"), 2);
    EXPECT_EQ(validator.severity_rank("high"), 3);
    EXPECT_EQ(validator.severity_rank("critical"), 4);
    EXPECT_EQ(validator.severity_rank("error"), 5);
    EXPECT_EQ(validator.severity_rank("invalid"), -1);
}

// Test severity rank case insensitive
TEST_F(ConfigValidatorTest, SeverityRankCaseInsensitive) {
    EXPECT_EQ(validator.severity_rank("INFO"), 0);
    EXPECT_EQ(validator.severity_rank("LOW"), 1);
    EXPECT_EQ(validator.severity_rank("HIGH"), 3);
}

// Test scanner name validation - too long
TEST_F(ConfigValidatorTest, ScannerNameTooLong) {
    Config cfg;
    cfg.enable_scanners = {std::string(1001, 'a')}; // Too long

    EXPECT_THROW(validator.validate(cfg), std::runtime_error);
}

// Test scanner name validation - invalid characters
TEST_F(ConfigValidatorTest, ScannerNameInvalidCharacters) {
    Config cfg;
    cfg.enable_scanners = {"scanner\x01name"}; // Control character

    EXPECT_THROW(validator.validate(cfg), std::runtime_error);
}

// Test scanner name validation - empty name skipped
TEST_F(ConfigValidatorTest, ScannerNameEmpty) {
    Config cfg;
    cfg.enable_scanners = {"", "valid_scanner", ""};
    cfg.disable_scanners = {"other_scanner"};

    EXPECT_TRUE(validator.validate(cfg)); // Empty names should be skipped
}

// Test fast scan optimization with explicitly enabled scanners
TEST_F(ConfigValidatorTest, FastScanWithExplicitlyEnabledScanners) {
    Config cfg;
    cfg.fast_scan = true;
    cfg.enable_scanners = {"modules"}; // Explicitly enabled

    validator.apply_fast_scan_optimizations(cfg);

    // Should not disable explicitly enabled scanners
    auto it = std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "modules");
    EXPECT_EQ(it, cfg.disable_scanners.end());
}

// Test fast scan optimization without explicitly enabled scanners
TEST_F(ConfigValidatorTest, FastScanWithoutExplicitlyEnabledScanners) {
    Config cfg;
    cfg.fast_scan = true;

    validator.apply_fast_scan_optimizations(cfg);

    // Should disable resource-intensive scanners
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "modules") != cfg.disable_scanners.end());
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "integrity") != cfg.disable_scanners.end());
    EXPECT_TRUE(std::find(cfg.disable_scanners.begin(), cfg.disable_scanners.end(), "ebpf") != cfg.disable_scanners.end());
    EXPECT_TRUE(cfg.modules_summary_only);
}

// Test IOC allowlist with leading/trailing whitespace
TEST_F(ConfigValidatorTest, IOCAllowlistWithWhitespace) {
    auto ioc_file = temp_dir / "ioc_whitespace.txt";
    std::ofstream file(ioc_file);
    file << "  ioc_with_leading_space\n";
    file << "\tioc_with_tab\n";
    file << "ioc_with_trailing_space  \n";
    file << "   ioc_with_both   \n";
    file.close();

    Config cfg;
    cfg.ioc_allow_file = ioc_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    // Leading whitespace should be trimmed
    EXPECT_EQ(cfg.ioc_allow.size(), 4);
}

// Test IOC allowlist with empty lines
TEST_F(ConfigValidatorTest, IOCAllowlistWithEmptyLines) {
    auto ioc_file = temp_dir / "ioc_empty_lines.txt";
    std::ofstream file(ioc_file);
    file << "ioc1\n";
    file << "\n";
    file << "   \n"; // Line with only whitespace
    file << "ioc2\n";
    file.close();

    Config cfg;
    cfg.ioc_allow_file = ioc_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_EQ(cfg.ioc_allow.size(), 2);
}

// Test SUID expected file with empty lines
TEST_F(ConfigValidatorTest, SUIDExpectedWithEmptyLines) {
    auto suid_file = temp_dir / "suid_empty.txt";
    std::ofstream file(suid_file);
    file << "/bin/su\n";
    file << "\n";
    file << "/usr/bin/sudo\n";
    file.close();

    Config cfg;
    cfg.suid_expected_file = suid_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_EQ(cfg.suid_expected_add.size(), 2);
}

// Test loading both IOC and SUID files
TEST_F(ConfigValidatorTest, LoadBothExternalFiles) {
    auto ioc_file = temp_dir / "ioc.txt";
    std::ofstream ioc(ioc_file);
    ioc << "ioc1\n";
    ioc.close();

    auto suid_file = temp_dir / "suid.txt";
    std::ofstream suid(suid_file);
    suid << "/bin/su\n";
    suid.close();

    Config cfg;
    cfg.ioc_allow_file = ioc_file.string();
    cfg.suid_expected_file = suid_file.string();

    EXPECT_TRUE(validator.load_external_files(cfg));
    EXPECT_EQ(cfg.ioc_allow.size(), 1);
    EXPECT_EQ(cfg.suid_expected_add.size(), 1);
}

// Test loading with one file failing
TEST_F(ConfigValidatorTest, LoadExternalFilesOneFails) {
    auto ioc_file = temp_dir / "ioc.txt";
    std::ofstream ioc(ioc_file);
    ioc << "ioc1\n";
    ioc.close();

    Config cfg;
    cfg.ioc_allow_file = ioc_file.string();
    cfg.suid_expected_file = "/nonexistent/file.txt";

    EXPECT_FALSE(validator.load_external_files(cfg)); // Should fail if any fails
}

// Test additional severity combinations
TEST_F(ConfigValidatorTest, SeverityRelationshipValidation) {
    Config cfg;

    // Test medium vs high (should pass)
    cfg.min_severity = "medium";
    cfg.fail_on_severity = "high";
    EXPECT_TRUE(validator.validate(cfg));

    // Test info vs medium (should pass)
    cfg.min_severity = "info";
    cfg.fail_on_severity = "medium";
    EXPECT_TRUE(validator.validate(cfg));

    // Test critical vs critical (should pass - equal)
    cfg.min_severity = "critical";
    cfg.fail_on_severity = "critical";
    EXPECT_TRUE(validator.validate(cfg));
}

} // namespace sys_scan