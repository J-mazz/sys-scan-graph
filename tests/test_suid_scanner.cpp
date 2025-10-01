#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include "../src/scanners/SuidScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"

namespace fs = std::filesystem;
namespace sys_scan {

class SuidScannerTest : public ::testing::Test {
protected:
    fs::path test_dir;
    fs::path bin_dir;
    fs::path sbin_dir;
    fs::path usr_bin_dir;
    fs::path usr_sbin_dir;
    fs::path usr_local_bin_dir;
    fs::path usr_local_sbin_dir;

    void SetUp() override {
        // Create temporary test directory structure
        test_dir = fs::temp_directory_path() / "suid_scanner_test";
        fs::create_directories(test_dir);

        // Create directory structure matching scanner roots
        bin_dir = test_dir / "bin";
        sbin_dir = test_dir / "sbin";
        usr_bin_dir = test_dir / "usr" / "bin";
        usr_sbin_dir = test_dir / "usr" / "sbin";
        usr_local_bin_dir = test_dir / "usr" / "local" / "bin";
        usr_local_sbin_dir = test_dir / "usr" / "local" / "sbin";

        fs::create_directories(bin_dir);
        fs::create_directories(sbin_dir);
        fs::create_directories(usr_bin_dir);
        fs::create_directories(usr_sbin_dir);
        fs::create_directories(usr_local_bin_dir);
        fs::create_directories(usr_local_sbin_dir);
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    // Helper to create a test file with specific permissions
    void createTestFile(const fs::path& path, mode_t mode = 0644) {
        std::ofstream file(path);
        file << "#!/bin/bash\necho 'test'\n";
        file.close();

        // Set permissions
        chmod(path.c_str(), mode);
    }

    // Helper to create a SUID/SGID file
    void createSuidFile(const fs::path& path, bool suid = true, bool sgid = false) {
        createTestFile(path, 0755);

        // Add SUID/SGID bits
        mode_t mode = 0755;
        if (suid) mode |= S_ISUID;
        if (sgid) mode |= S_ISGID;

        chmod(path.c_str(), mode);
    }

    // Helper to run scanner and get findings
    std::vector<Finding> runScanner() {
        Config config;
        config.test_root = test_dir.string();

        Report report;
        ScanContext context(config, report);

        SuidScanner scanner;
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

// Test SUID file detection
TEST_F(SuidScannerTest, DetectsSuidFiles) {
    createSuidFile(bin_dir / "suid_binary");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto suid_finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("suid_binary") != std::string::npos; });
    ASSERT_NE(suid_finding, findings.end());
    EXPECT_EQ(suid_finding->title, "SUID/SGID binary");
    EXPECT_EQ(suid_finding->severity, Severity::Medium);
}

// Test SGID file detection
TEST_F(SuidScannerTest, DetectsSgidFiles) {
    createSuidFile(sbin_dir / "sgid_binary", false, true);

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto sgid_finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("sgid_binary") != std::string::npos; });
    ASSERT_NE(sgid_finding, findings.end());
    EXPECT_EQ(sgid_finding->title, "SUID/SGID binary");
}

// Test SUID+SGID file detection
TEST_F(SuidScannerTest, DetectsSuidSgidFiles) {
    createSuidFile(usr_bin_dir / "suid_sgid_binary", true, true);

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("suid_sgid_binary") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
}

// Test expected SUID paths are marked as expected and reduced severity
TEST_F(SuidScannerTest, ExpectedPathsMarkedAsExpected) {
    createSuidFile(usr_bin_dir / "passwd");  // Expected path

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("passwd") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->metadata.at("expected"), "true");
    EXPECT_EQ(finding->severity, Severity::Low);
}

// Test severity classification for /usr/local/ paths
TEST_F(SuidScannerTest, HighSeverityForUsrLocal) {
    createSuidFile(usr_local_bin_dir / "suspicious_binary");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("suspicious_binary") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->severity, Severity::High);
}

// Test severity classification for /tmp/ paths (if scanner checked there)
TEST_F(SuidScannerTest, CriticalSeverityForTmp) {
    // Create a tmp directory in test structure
    auto tmp_dir = test_dir / "tmp";
    fs::create_directories(tmp_dir);
    createSuidFile(tmp_dir / "dangerous_binary");

    auto findings = runScanner();

    // The scanner doesn't scan /tmp by default, so this should not find anything
    // This test verifies the scanner doesn't accidentally scan unexpected paths
    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("dangerous_binary") != std::string::npos; });
    EXPECT_EQ(finding, findings.end());
}

// Test multiple SUID files in different directories
TEST_F(SuidScannerTest, MultipleSuidFiles) {
    createSuidFile(usr_bin_dir / "binary1");
    createSuidFile(usr_bin_dir / "binary2");
    createSuidFile(usr_bin_dir / "binary3");

    auto findings = runScanner();

    // Should find all three
    EXPECT_GE(findings.size(), 3);

    bool found1 = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("binary1") != std::string::npos; });
    bool found2 = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("binary2") != std::string::npos; });
    bool found3 = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("binary3") != std::string::npos; });

    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
    EXPECT_TRUE(found3);
}

// Test that regular files without SUID/SGID are not detected
TEST_F(SuidScannerTest, IgnoresRegularFiles) {
    createTestFile(bin_dir / "regular_binary", 0755);  // No SUID/SGID bits

    auto findings = runScanner();

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("regular_binary") != std::string::npos; });
    EXPECT_EQ(finding, findings.end());
}

// Test that directories are not treated as SUID files
TEST_F(SuidScannerTest, IgnoresDirectories) {
    fs::create_directories(bin_dir / "some_directory");
    chmod((bin_dir / "some_directory").c_str(), 0755 | S_ISUID);  // Try to set SUID on directory

    auto findings = runScanner();

    // Directories should not be reported even with SUID bit
    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("some_directory") != std::string::npos; });
    EXPECT_EQ(finding, findings.end());
}

// Test that symlinks are handled correctly (lstat should be used)
TEST_F(SuidScannerTest, HandlesSymlinks) {
    createSuidFile(bin_dir / "real_binary");
    fs::create_symlink("real_binary", bin_dir / "symlink_binary");

    auto findings = runScanner();

    // Should only report the real file, not the symlink
    auto real_finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("real_binary") != std::string::npos; });
    auto symlink_finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("symlink_binary") != std::string::npos; });

    EXPECT_NE(real_finding, findings.end());
    EXPECT_EQ(symlink_finding, findings.end());
}

// Test expected filename matching (not just full path)
TEST_F(SuidScannerTest, ExpectedFilenameMatching) {
    createSuidFile(usr_bin_dir / "sudo");  // Expected filename

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("sudo") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->metadata.at("expected"), "true");
    EXPECT_EQ(finding->severity, Severity::Low);
}

// Test that non-existent directories don't cause crashes
TEST_F(SuidScannerTest, HandlesMissingDirectories) {
    // Remove one of the expected directories
    fs::remove_all(bin_dir);

    // Scanner should handle missing directories gracefully
    EXPECT_NO_THROW({
        auto findings = runScanner();
        // Should still work and find files in existing directories
    });
}

// Test deduplication of hardlinked files
TEST_F(SuidScannerTest, DeduplicatesHardlinks) {
    createSuidFile(bin_dir / "original_binary");

    // Create a hard link
    fs::create_hard_link(bin_dir / "original_binary", bin_dir / "hardlinked_binary");

    auto findings = runScanner();

    // Should only report one finding (deduplicated by inode)
    auto original_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("original_binary") != std::string::npos ||
                               f.id.find("hardlinked_binary") != std::string::npos; });
    EXPECT_EQ(original_findings, 1);
}

// Test that scanner respects test_root configuration
TEST_F(SuidScannerTest, RespectsTestRoot) {
    // Create a SUID file in the test directory
    createSuidFile(bin_dir / "test_root_binary");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    // All findings should be within the test_root
    for (const auto& finding : findings) {
        EXPECT_THAT(finding.id, ::testing::StartsWith(test_dir.string()));
    }
}

} // namespace sys_scan