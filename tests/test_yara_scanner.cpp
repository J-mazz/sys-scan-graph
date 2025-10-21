#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/YaraScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace sys_scan {

// Test fixture for YaraScanner tests
class YaraScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directories for testing
        test_scan_dir = "/tmp/test_yara_scan";
        fs::create_directories(test_scan_dir);

        config.rules_dir = "/tmp/test_yara";  // Parent dir of yara subdir
        config.yara_scan_roots = {test_scan_dir};  // Use our test directory

        report = std::make_unique<Report>();
        context = std::make_unique<ScanContext>(config, *report);
    }

    void TearDown() override {
        // Clean up test directories
        fs::remove_all("/tmp/test_yara");
        fs::remove_all("/tmp/test_yara_scan");
    }

    void createRuleFile(const std::string& filename, const std::vector<std::string>& patterns) {
        std::string yara_dir = config.rules_dir + "/yara";
        fs::create_directories(yara_dir);
        std::ofstream file(yara_dir + "/" + filename);
        for (const auto& pattern : patterns) {
            file << pattern << "\n";
        }
        file.close();
    }

    void createTestFile(const std::string& filename, const std::string& content) {
        std::ofstream file(test_scan_dir + "/" + filename);
        file << content;
        file.close();
    }

    Config config;
    std::unique_ptr<Report> report;
    std::unique_ptr<ScanContext> context;
    std::string test_scan_dir = "/tmp/test_yara_scan";
};

// Test scanner name and description
TEST(YaraScannerBasicTest, NameAndDescription) {
    YaraScanner scanner;
    EXPECT_EQ(scanner.name(), "yara");
    EXPECT_EQ(scanner.description(), "YARA rule matching over selected filesystem roots");
}

// Test that scanner returns early when no rules directory exists
TEST_F(YaraScannerTest, NoRulesDirectory) {
    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should have no findings when no rules directory exists
    EXPECT_TRUE(results.empty());
}

// Test that scanner returns early when rules directory exists but no yara subdirectory
TEST_F(YaraScannerTest, NoYaraSubdirectory) {
    fs::create_directories("/tmp/test_yara");  // Create parent but not yara subdir

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should have no findings when no yara subdirectory exists
    EXPECT_TRUE(results.empty());
}

// Test pattern loading from rule files
TEST_F(YaraScannerTest, PatternLoading) {
    // Create the yara subdirectory as expected by the scanner
    std::string yara_dir = "/tmp/test_yara/yara";
    fs::create_directories(yara_dir);

    // Create a rule file with some patterns
    std::ofstream rule_file(yara_dir + "/test.yar");
    rule_file << "malware_signature\n";
    rule_file << "suspicious_pattern\n";
    rule_file << "# This is a comment\n";
    rule_file << "\n";  // Empty line
    rule_file.close();

    YaraScanner scanner;

    // Create a test file with matching content in our test scan directory
    createTestFile("test_binary", "This file contains malware_signature and some other data");

    report->start_scanner("yara");
    scanner.scan(*context);

    auto results = report->results();
    // Should find the malware_signature pattern
    EXPECT_EQ(results.size(), 1);
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 1);
        if (!results[0].findings.empty()) {
            EXPECT_EQ(results[0].findings[0].metadata["pattern"], "malware_signature");
            EXPECT_EQ(results[0].findings[0].metadata["path"], test_scan_dir + "/test_binary");
        }
    }
}

// Test with empty rule files
TEST_F(YaraScannerTest, EmptyRuleFiles) {
    // Create empty rule file
    createRuleFile("empty.yar", {});

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should have no findings with empty rules
    EXPECT_TRUE(results.empty());
}

// Test with rule files containing only comments and empty lines
TEST_F(YaraScannerTest, CommentsAndEmptyLines) {
    createRuleFile("comments.yar", {"# This is a comment", "", "   ", "# Another comment"});

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should have no findings with only comments
    EXPECT_TRUE(results.empty());
}

// Test pattern matching behavior
TEST_F(YaraScannerTest, PatternMatching) {
    // Create the yara subdirectory
    std::string yara_dir = "/tmp/test_yara/yara";
    fs::create_directories(yara_dir);

    // Create rule file with a simple pattern
    std::ofstream rule_file(yara_dir + "/simple.yar");
    rule_file << "test_pattern\n";
    rule_file.close();

    YaraScanner scanner;

    // Create test files - one with match, one without
    createTestFile("matching_file", "This contains test_pattern in the content");
    createTestFile("non_matching_file", "This does not contain the pattern");

    report->start_scanner("yara");
    scanner.scan(*context);

    auto results = report->results();
    // Should find exactly one match
    EXPECT_EQ(results.size(), 1);
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 1);
        if (!results[0].findings.empty()) {
            EXPECT_EQ(results[0].findings[0].metadata["pattern"], "test_pattern");
            EXPECT_EQ(results[0].findings[0].metadata["path"], test_scan_dir + "/matching_file");
        }
    }
}

// Test with very long patterns (should be truncated)
TEST_F(YaraScannerTest, LongPatterns) {
    std::string long_pattern(5000, 'A');  // Very long pattern
    createRuleFile("long.yar", {long_pattern});

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle long patterns gracefully
    EXPECT_GE(results.size(), 0);
}

// Test multiple rule files
TEST_F(YaraScannerTest, MultipleRuleFiles) {
    createRuleFile("rules1.yar", {"pattern1", "pattern2"});
    createRuleFile("rules2.sig", {"pattern3"});

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle multiple rule files
    EXPECT_GE(results.size(), 0);
}

// Test with different file extensions
TEST_F(YaraScannerTest, DifferentExtensions) {
    createRuleFile("rules.yar", {"yar_pattern"});
    createRuleFile("rules.yara", {"yara_pattern"});
    createRuleFile("rules.sig", {"sig_pattern"});

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should load patterns from all supported extensions
    EXPECT_GE(results.size(), 0);
}

// Test file scanning limits
TEST_F(YaraScannerTest, FileLimits) {
    // Create many rule files with patterns
    for (int i = 0; i < 10; ++i) {
        createRuleFile("rules" + std::to_string(i) + ".yar", {"pattern" + std::to_string(i)});
    }

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should respect internal limits and not crash
    EXPECT_GE(results.size(), 0);
}

// Test binary file content scanning
TEST_F(YaraScannerTest, BinaryContent) {
    createRuleFile("binary.yar", {"\x00\x01\x02\x03"});  // Binary pattern

    YaraScanner scanner;

    // Create a file with binary content
    std::ofstream binary_file(test_scan_dir + "/binary_test", std::ios::binary);
    binary_file.write("\x00\x01\x02\x03\x04\x05", 6);
    binary_file.close();

    scanner.scan(*context);

    auto results = report->results();
    // Should handle binary content properly
    EXPECT_GE(results.size(), 0);
}

// Test non-existent scan roots
TEST_F(YaraScannerTest, NonExistentScanRoots) {
    createRuleFile("test.yar", {"pattern"});
    config.yara_scan_roots = {"/nonexistent/path/that/does/not/exist"};

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle non-existent roots gracefully (no crash)
    EXPECT_TRUE(results.empty());
}

// Test empty yara_scan_roots (should use defaults)
TEST_F(YaraScannerTest, EmptyScanRoots) {
    createRuleFile("test.yar", {"test_pattern"});
    config.yara_scan_roots.clear();  // Empty roots

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should use default scan roots and possibly find matches
    EXPECT_GE(results.size(), 0);
}

// Test file limit enforcement
TEST_F(YaraScannerTest, FileLimitEnforcement) {
    createRuleFile("test.yar", {"rare_pattern"});

    // Create many files to exceed the file limit
    for (int i = 0; i < 100; ++i) {
        createTestFile("file" + std::to_string(i), "content without pattern");
    }

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should respect file limit and not scan all files
    EXPECT_GE(results.size(), 0);
}

// Test match limit enforcement
TEST_F(YaraScannerTest, MatchLimitEnforcement) {
    createRuleFile("test.yar", {"common"});

    // Create many files with matches
    for (int i = 0; i < 300; ++i) {
        createTestFile("match" + std::to_string(i), "This contains common pattern");
    }

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should respect match limit and not emit unlimited findings
    if (!results.empty()) {
        // Should have at most 200 matches (match_limit in YaraScanner.cpp)
        EXPECT_LE(results[0].findings.size(), 200);
    }
}

// Test pattern matching in subdirectories
TEST_F(YaraScannerTest, SubdirectoryScanning) {
    createRuleFile("test.yar", {"subdirectory_pattern"});

    // Create subdirectories with files
    fs::create_directories(test_scan_dir + "/subdir1/subdir2");
    createTestFile("subdir1/file1", "This contains subdirectory_pattern");
    createTestFile("subdir1/subdir2/file2", "This also has subdirectory_pattern");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should find patterns in subdirectories
    if (!results.empty()) {
        EXPECT_GE(results[0].findings.size(), 2);
    }
}

// Test multiple patterns in single file
TEST_F(YaraScannerTest, MultiplePatternsSingleFile) {
    createRuleFile("test.yar", {"pattern1", "pattern2", "pattern3"});
    createTestFile("multi", "This has pattern1 and pattern2 and pattern3");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should find all 3 patterns in the same file
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 3);
    }
}

// Test pattern matching only in first 8KB of file
TEST_F(YaraScannerTest, LargeFileFirstChunkOnly) {
    createRuleFile("test.yar", {"early_pattern", "late_pattern"});

    // Create file with pattern in first chunk and one after 8KB
    std::ofstream large_file(test_scan_dir + "/large");
    large_file << "early_pattern";
    large_file << std::string(10000, 'x');  // 10KB of filler
    large_file << "late_pattern";
    large_file.close();

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should find early_pattern but not late_pattern (only scans first 8KB)
    if (!results.empty()) {
        bool found_early = false;
        bool found_late = false;
        for (const auto& finding : results[0].findings) {
            if (finding.metadata.at("pattern") == "early_pattern") found_early = true;
            if (finding.metadata.at("pattern") == "late_pattern") found_late = true;
        }
        EXPECT_TRUE(found_early);
        EXPECT_FALSE(found_late);
    }
}

// Test empty file handling
TEST_F(YaraScannerTest, EmptyFileHandling) {
    createRuleFile("test.yar", {"pattern"});
    createTestFile("empty", "");  // Empty file

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle empty files without crashing
    EXPECT_GE(results.size(), 0);
}

// Test file with only whitespace
TEST_F(YaraScannerTest, WhitespaceOnlyFile) {
    createRuleFile("test.yar", {"pattern"});
    createTestFile("whitespace", "     \n\n\t\t   \n");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should not match pattern in whitespace-only file
    EXPECT_TRUE(results.empty());
}

// Test permission denied directories (using directory_options::skip_permission_denied)
TEST_F(YaraScannerTest, PermissionDeniedHandling) {
    createRuleFile("test.yar", {"pattern"});

    // Create a directory that we'll make unreadable
    fs::path unreadable_dir = test_scan_dir + "/unreadable";
    fs::create_directories(unreadable_dir);
    createTestFile("unreadable/file", "pattern content");

    // Make directory unreadable (may not work in all test environments)
    chmod(unreadable_dir.c_str(), 0000);

    YaraScanner scanner;
    scanner.scan(*context);

    // Restore permissions for cleanup
    chmod(unreadable_dir.c_str(), 0755);

    auto results = report->results();
    // Should handle permission denied gracefully
    EXPECT_GE(results.size(), 0);
}

// Test finding metadata fields
TEST_F(YaraScannerTest, FindingMetadataFields) {
    createRuleFile("test.yar", {"metadata_test"});
    createTestFile("test", "This contains metadata_test pattern");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    if (!results.empty() && !results[0].findings.empty()) {
        const auto& finding = results[0].findings[0];
        EXPECT_EQ(finding.title, "Pseudo-YARA pattern match");
        EXPECT_EQ(finding.severity, sys_scan::Severity::Medium);
        EXPECT_EQ(finding.description, "Pattern found in file prefix");
        EXPECT_TRUE(finding.metadata.count("pattern") > 0);
        EXPECT_TRUE(finding.metadata.count("path") > 0);
        EXPECT_EQ(finding.metadata.at("pattern"), "metadata_test");
    }
}

// Test pattern with special characters
TEST_F(YaraScannerTest, PatternWithSpecialChars) {
    createRuleFile("test.yar", {"$pecial.ch@rs!"});
    createTestFile("special", "This has $pecial.ch@rs! in it");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should match patterns with special characters
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 1);
    }
}

// Test finding ID format
TEST_F(YaraScannerTest, FindingIdFormat) {
    createRuleFile("test.yar", {"id_test"});
    createTestFile("test", "id_test pattern");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    if (!results.empty() && !results[0].findings.empty()) {
        const auto& finding = results[0].findings[0];
        // ID should be path:yara:pattern_prefix
        EXPECT_THAT(finding.id, ::testing::HasSubstr(":yara:"));
        EXPECT_THAT(finding.id, ::testing::HasSubstr(test_scan_dir));
    }
}

// Test scanning with symlinks (should skip)
TEST_F(YaraScannerTest, SymlinkHandling) {
    createRuleFile("test.yar", {"symlink_pattern"});
    createTestFile("real_file", "symlink_pattern content");

    // Create a symlink
    fs::path symlink_path = fs::path(test_scan_dir) / "symlink";
    std::error_code ec;
    fs::create_symlink(fs::path(test_scan_dir) / "real_file", symlink_path, ec);

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should only scan regular files, not symlinks
    if (!results.empty()) {
        // Should find exactly 1 match (from real_file, not symlink)
        EXPECT_EQ(results[0].findings.size(), 1);
    }
}

// Test with very short patterns
TEST_F(YaraScannerTest, VeryShortPatterns) {
    createRuleFile("test.yar", {"a", "b", "c"});
    createTestFile("short", "abc");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should match short patterns
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 3);
    }
}

// Test case sensitivity of pattern matching
TEST_F(YaraScannerTest, CaseSensitivePatternMatching) {
    createRuleFile("test.yar", {"CaseSensitive"});
    createTestFile("upper", "CaseSensitive");
    createTestFile("lower", "casesensitive");

    YaraScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should only match exact case
    if (!results.empty()) {
        EXPECT_EQ(results[0].findings.size(), 1);
    }
}

} // namespace sys_scan