#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include "../src/scanners/AuditdScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"

namespace fs = std::filesystem;

class AuditdScannerExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory structure like the basic test
        test_dir = std::filesystem::temp_directory_path() / "auditd_extended_test";
        std::filesystem::create_directories(test_dir);

        // Create audit rules directory
        audit_rules_dir = test_dir / "etc" / "audit" / "rules.d";
        std::filesystem::create_directories(audit_rules_dir);

        // Create main audit rules file path
        audit_rules_file = audit_rules_dir / "audit.rules";
    }

    void TearDown() override {
        try {
            fs::remove_all(test_dir);
        } catch (...) {
            // Ignore cleanup errors
        }
    }

    fs::path test_dir;
    fs::path audit_rules_dir;
    fs::path audit_rules_file;

    // Helper to create test audit rules file
    void create_audit_rules(const std::string& content, const std::string& filename = "audit.rules") {
        std::ofstream file(audit_rules_dir / filename);
        ASSERT_TRUE(file.is_open());
        file << content;
        file.close();
    }

    // Helper to create rules.d file
    void create_rules_d_file(const std::string& content, const std::string& filename) {
        std::ofstream file(audit_rules_dir / filename);
        ASSERT_TRUE(file.is_open());
        file << content;
        file.close();
    }

    // Helper to run scanner (like basic test - no unique_ptr)
    std::vector<sys_scan::Finding> run_scanner(bool hardening_enabled = true) {
        sys_scan::Config config;
        config.hardening = hardening_enabled;
        config.test_root = test_dir.string();

        sys_scan::Report report;
        sys_scan::ScanContext context(config, report);

        sys_scan::AuditdScanner scanner;
        scanner.scan(context);

        // Get findings from the report
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner.name()) {
                return result.findings;
            }
        }
        return {};
    }
};

// Test scanning with empty rules files
TEST_F(AuditdScannerExtendedTest, ScanWithEmptyRulesFiles) {
    create_audit_rules("");

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should report missing audit rules
}

// Test scanning with rules files containing only comments
TEST_F(AuditdScannerExtendedTest, ScanWithCommentOnlyRulesFiles) {
    std::string content = R"(
# This is a comment
; This is also a comment
# Another comment line
# More comments
)";

    create_audit_rules(content);

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should report missing audit rules despite comments
}

// Test scanning with rules files containing special characters
TEST_F(AuditdScannerExtendedTest, ScanWithSpecialCharacters) {
    std::string content = R"(
-S execve -k "special!@#$%^&*()_+-=[]{}|;':\",./<>?"
-S setuid -k setuid
-w /path with spaces -p x -k spaces
)";

    create_audit_rules(content);

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle special characters
}

// Test scanning with rules files containing Unicode characters
TEST_F(AuditdScannerExtendedTest, ScanWithUnicodeCharacters) {
    std::string content = R"(
# Rules with Unicode: 测试 中文 русский español
-S execve -k "execve_测试"
-S setuid -k "setuid_中文"
-w /path/russkij -p x -k "русский"
)";

    create_audit_rules(content);

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle Unicode
}

// Test scanning with malformed regex patterns (should not crash)
TEST_F(AuditdScannerExtendedTest, ScanWithMalformedRegexPatterns) {
    // Create rules that might cause regex issues
    std::string content = R"(
-S execve -k execve
[unclosed bracket
-w /path -p [invalid
-S setuid -k setuid
)";

    create_audit_rules(content);

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should not crash on malformed patterns
}

// Test scanning with mixed valid and invalid rules files
TEST_F(AuditdScannerExtendedTest, ScanWithMixedValidInvalidRules) {
    // Valid rules file
    create_audit_rules("-S execve -k execve\n-S setuid -k setuid\n");

    // Invalid rules file (binary data)
    auto invalid_path = audit_rules_dir / "invalid.rules";
    std::ofstream invalid_file(invalid_path, std::ios::binary);
    for (int i = 0; i < 10; ++i) {
        invalid_file.put(static_cast<char>(i));
    }
    invalid_file.close();

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle mixed valid/invalid files
}

// Test scanning with rules files that are actually directories (should skip)
TEST_F(AuditdScannerExtendedTest, ScanWithDirectoryInsteadOfFile) {
    // Create a directory where a rules file should be
    fs::create_directories(audit_rules_dir / "fake.rules");

    // Create a valid rules file
    create_audit_rules("-S execve -k execve\n");

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should skip directories and still process valid files
}

// Test scanning with deeply nested rules.d structure
TEST_F(AuditdScannerExtendedTest, ScanWithNestedRulesStructure) {
    // Create nested subdirectories in rules.d
    fs::create_directories(audit_rules_dir / "subdir");

    // Create rules files at different levels
    create_rules_d_file("-S execve -k execve\n", "top.rules");
    std::ofstream sub_file(audit_rules_dir / "subdir" / "sub.rules");
    sub_file << "-S setuid -k setuid\n";
    sub_file.close();

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle nested structures
}

// Test scanning with rules files containing invalid UTF-8 sequences
TEST_F(AuditdScannerExtendedTest, ScanWithInvalidUTF8) {
    // Create file with invalid UTF-8
    auto rules_path = audit_rules_file;
    std::ofstream file(rules_path, std::ios::binary);
    file << "-S execve -k execve\n";
    // Invalid UTF-8 sequence
    file.put(static_cast<char>(0xFF));
    file.put(static_cast<char>(0xFE));
    file.put(static_cast<char>(0xFD));
    file << "\n-S setuid -k setuid\n";
    file.close();

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle invalid UTF-8 gracefully
}

// Test scanning with rules files that are symlinks
TEST_F(AuditdScannerExtendedTest, ScanWithSymlinkRules) {
    // Create target file
    std::string target_content = "-S execve -k execve\n-S setuid -k setuid\n";
    auto target_path = test_dir / "etc" / "audit" / "target.rules";
    std::ofstream target_file(target_path);
    target_file << target_content;
    target_file.close();

    // Create symlink
    auto link_path = audit_rules_dir / "link.rules";
    if (symlink(target_path.c_str(), link_path.c_str()) == 0) {
        auto findings = run_scanner();
        EXPECT_GE(findings.size(), 1); // Should handle symlinks
    } else {
        // If symlink creation fails, skip test
        SUCCEED();
    }
}

// Test scanning with rules files containing embedded newlines in keys
TEST_F(AuditdScannerExtendedTest, ScanWithEmbeddedNewlines) {
    // Create file with embedded newlines
    auto rules_path = audit_rules_file;
    std::ofstream file(rules_path, std::ios::binary);
    file << "-S execve -k \"execve\nwith\nnewlines\"\n";
    file << "-S setuid -k setuid\n";
    file.close();

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle embedded newlines
}

// Test scanning with rules files containing control characters
TEST_F(AuditdScannerExtendedTest, ScanWithControlCharacters) {
    // Create file with control characters
    auto rules_path = audit_rules_file;
    std::ofstream file(rules_path, std::ios::binary);
    file << "-S execve -k execve";
    for (int i = 1; i <= 10; ++i) {
        file.put(static_cast<char>(i)); // Control characters
    }
    file << "\n-S setuid -k setuid\n";
    file.close();

    auto findings = run_scanner();
    EXPECT_GE(findings.size(), 1); // Should handle control characters
}

// Test scanning with very long file paths
TEST_F(AuditdScannerExtendedTest, ScanWithVeryLongPaths) {
    // Create nested directory structure with long names
    std::string long_name(100, 'a'); // Long directory name
    auto long_dir = audit_rules_dir / long_name;

    try {
        fs::create_directories(long_dir);

        std::string content = "-S execve -k execve\n-S setuid -k setuid\n";
        std::ofstream file(long_dir / "test.rules");
        file << content;
        file.close();

        auto findings = run_scanner();
        EXPECT_GE(findings.size(), 1); // Should handle long paths
    } catch (...) {
        // If filesystem can't handle long paths, skip test
        SUCCEED();
    }
}

// Test scanning with rules files that exceed filesystem path limits
TEST_F(AuditdScannerExtendedTest, ScanWithPathLimitExceedance) {
    // Try to create a file with a name that exceeds typical path limits
    std::string long_filename(150, 'a');
    long_filename += ".rules";

    try {
        std::string content = "-S execve -k execve\n";
        std::ofstream file(audit_rules_dir / long_filename);
        file << content;
        file.close();

        // Also create a normal file
        create_audit_rules("-S setuid -k setuid\n");

        auto findings = run_scanner();
        EXPECT_GE(findings.size(), 1); // Should handle path limit issues
    } catch (...) {
        // If filesystem can't handle long names, skip test
        SUCCEED();
    }

}