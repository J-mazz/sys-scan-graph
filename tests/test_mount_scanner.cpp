#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/MountScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include <filesystem>
#include <fstream>
#include <unistd.h>

// Test fixture for MountScanner
class MountScannerTest : public ::testing::Test {
protected:
    std::string temp_dir;
    sys_scan::Config config_;
    sys_scan::Report report_;

    void SetUp() override {
        // Create temporary directory for test files
        char template_path[] = "/tmp/mount_test_XXXXXX";
        temp_dir = mkdtemp(template_path);
        ASSERT_FALSE(temp_dir.empty()) << "Failed to create temp directory";
        std::cout << "Created temp dir: " << temp_dir << std::endl;

        // Set up default config
        config_.hardening = true;
    }

    void TearDown() override {
        // Clean up temporary directory
        if (!temp_dir.empty()) {
            std::filesystem::remove_all(temp_dir);
        }
    }

    // Helper to create a test context
    std::unique_ptr<sys_scan::ScanContext> create_context(bool hardening_enabled = true) {
        config_.hardening = hardening_enabled;
        return std::make_unique<sys_scan::ScanContext>(config_, report_);
    }

    // Helper to create a temporary mounts file
    std::string create_mounts_file(const std::string& content) {
        std::string file_path = temp_dir + "/mounts";
        std::cout << "Creating mounts file: " << file_path << std::endl;
        std::ofstream file(file_path);
        file << content;
        file.close();
        std::cout << "Wrote content: " << content << std::endl;
        return file_path;
    }

    // Helper to get findings for a specific scanner
    std::vector<sys_scan::Finding> get_findings_for_scanner(
        const sys_scan::Report& report, const std::string& scanner_name) {
        std::vector<sys_scan::Finding> findings;
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner_name) {
                findings.insert(findings.end(), result.findings.begin(), result.findings.end());
            }
        }
        return findings;
    }

    // Helper to find a finding by ID
    const sys_scan::Finding* find_finding_by_id(
        const std::vector<sys_scan::Finding>& findings,
        const std::string& id) {
        for (const auto& finding : findings) {
            if (finding.id == id) {
                return &finding;
            }
        }
        return nullptr;
    }
};

// Test basic scanner properties
TEST_F(MountScannerTest, ScannerProperties) {
    sys_scan::MountScanner scanner;
    EXPECT_EQ(scanner.name(), "mounts");
    EXPECT_EQ(scanner.description(), "Checks mount options and surfaces risky configurations");
}

// Test scanner is disabled when hardening is disabled
TEST_F(MountScannerTest, ScanDisabledWhenHardeningDisabled) {
    auto context = create_context(false);
    sys_scan::MountScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_TRUE(findings.empty());
}

// Test /tmp mount missing noexec
TEST_F(MountScannerTest, ScanTmpMountMissingNoexec) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp ext4 rw,nosuid,nodev,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1); // Should find tmp-noexec-missing

    const auto* noexec_finding = find_finding_by_id(findings, "mount:tmp-noexec-missing:/tmp");
    ASSERT_NE(noexec_finding, nullptr);
    EXPECT_EQ(noexec_finding->metadata.at("mount"), "/tmp");
    EXPECT_EQ(noexec_finding->metadata.at("device"), "/dev/sda1");
    EXPECT_EQ(noexec_finding->severity, sys_scan::Severity::Medium);
    EXPECT_EQ(noexec_finding->title, "/tmp style mount missing noexec");
}

// Test secure /tmp mount (all options present)
TEST_F(MountScannerTest, ScanSecureTmpMount) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp ext4 rw,noexec,nosuid,nodev,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 0); // Should find no issues
}

// Test /home mount missing options
TEST_F(MountScannerTest, ScanHomeMountMissingOptions) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda2 /home ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 2); // Should find sensitive-nosuid, sensitive-nodev

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:sensitive-nosuid-missing:/home");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->metadata.at("mount"), "/home");
    EXPECT_EQ(nosuid_finding->metadata.at("device"), "/dev/sda2");
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nosuid_finding->title, "Sensitive mount missing nosuid");
}

// Test /tmp mount missing nodev
TEST_F(MountScannerTest, ScanTmpMountMissingNodev) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp ext4 rw,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 4); // Should find tmp-nosuid, tmp-nodev, sensitive-nosuid, sensitive-nodev

    const auto* nodev_finding = find_finding_by_id(findings, "mount:tmp-nodev-missing:/tmp");
    ASSERT_NE(nodev_finding, nullptr);
    EXPECT_EQ(nodev_finding->metadata.at("mount"), "/tmp");
    EXPECT_EQ(nodev_finding->metadata.at("device"), "/dev/sda1");
    EXPECT_EQ(nodev_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nodev_finding->title, "/tmp style mount missing nodev");
}

// Test /tmp mount missing nosuid
TEST_F(MountScannerTest, ScanTmpMountMissingNosuid) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp ext4 rw,noexec,nodev,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 2); // Should find tmp-nosuid, sensitive-nosuid

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:tmp-nosuid-missing:/tmp");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->metadata.at("mount"), "/tmp");
    EXPECT_EQ(nosuid_finding->metadata.at("device"), "/dev/sda1");
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Medium);
    EXPECT_EQ(nosuid_finding->title, "/tmp style mount missing nosuid");
}

// Test /home mount with exec (should find issue)
TEST_F(MountScannerTest, ScanHomeMountWithExec) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda3 /home ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 2); // Should find missing nosuid and nodev

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:sensitive-nosuid-missing:/home");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nosuid_finding->title, "Sensitive mount missing nosuid");

    const auto* nodev_finding = find_finding_by_id(findings, "mount:sensitive-nodev-missing:/home");
    ASSERT_NE(nodev_finding, nullptr);
    EXPECT_EQ(nodev_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nodev_finding->title, "Sensitive mount missing nodev");
}

// Test /home subdirectory mount
TEST_F(MountScannerTest, ScanHomeSubdirectory) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda3 /home/user ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 2); // Should find missing nosuid and nodev

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:sensitive-nosuid-missing:/home/user");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Low);
}

// Test bind mount generic
TEST_F(MountScannerTest, ScanBindMountGeneric) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/mnt/source /mnt/data ext4 rw,bind,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1);

    const auto* bind_finding = find_finding_by_id(findings, "mount:bind-generic:/mnt/data");
    ASSERT_NE(bind_finding, nullptr);
    EXPECT_EQ(bind_finding->severity, sys_scan::Severity::Info);
    EXPECT_EQ(bind_finding->title, "Bind mount present");
}

// Test skips pseudo filesystems
TEST_F(MountScannerTest, ScanSkipsPseudoFilesystems) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content =
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "/dev/sda1 /tmp ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // Should only find /tmp issues, not proc/sysfs
    ASSERT_EQ(findings.size(), 5); // tmp-noexec, tmp-nosuid, tmp-nodev, sensitive-nosuid, sensitive-nodev for /tmp
}

// Test multiple mounts
TEST_F(MountScannerTest, ScanMultipleMounts) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content =
        "/dev/sda1 /tmp ext4 rw,relatime 0 0\n"
        "/dev/sda2 /var/tmp ext4 rw,relatime 0 0\n"
        "/dev/sda3 /home ext4 rw,nosuid,nodev,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 10); // 5 issues for /tmp + 5 issues for /var/tmp
}

// Test /boot mount with nodev
TEST_F(MountScannerTest, ScanBootMountWithNodev) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /boot ext4 rw,nosuid,nodev,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // /boot should only check for nosuid, not nodev/noexec, and nosuid is present
    ASSERT_EQ(findings.size(), 0);
}

// Test /boot mount missing nosuid
TEST_F(MountScannerTest, ScanBootMountMissingNosuid) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /boot ext4 rw,nodev,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1);

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:sensitive-nosuid-missing:/boot");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Low);
}

// Test /var/tmp mount missing noexec
TEST_F(MountScannerTest, ScanVarTmpMount) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda2 /var/tmp ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 5); // tmp-noexec, tmp-nosuid, tmp-nodev, sensitive-nosuid, sensitive-nodev

    const auto* noexec_finding = find_finding_by_id(findings, "mount:tmp-noexec-missing:/var/tmp");
    ASSERT_NE(noexec_finding, nullptr);
    EXPECT_EQ(noexec_finding->metadata.at("mount"), "/var/tmp");
    EXPECT_EQ(noexec_finding->severity, sys_scan::Severity::Medium);
}

// Test /home mount missing nosuid
TEST_F(MountScannerTest, ScanSensitiveMountMissingNosuid) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda3 /home ext4 rw,nodev,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1);

    const auto* nosuid_finding = find_finding_by_id(findings, "mount:sensitive-nosuid-missing:/home");
    ASSERT_NE(nosuid_finding, nullptr);
    EXPECT_EQ(nosuid_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nosuid_finding->title, "Sensitive mount missing nosuid");
}

// Test /home mount missing nodev
TEST_F(MountScannerTest, ScanSensitiveMountMissingNodev) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda3 /home ext4 rw,nosuid,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1);

    const auto* nodev_finding = find_finding_by_id(findings, "mount:sensitive-nodev-missing:/home");
    ASSERT_NE(nodev_finding, nullptr);
    EXPECT_EQ(nodev_finding->severity, sys_scan::Severity::Low);
    EXPECT_EQ(nodev_finding->title, "Sensitive mount missing nodev");
}

// Test /tmp mount with all required options
TEST_F(MountScannerTest, ScanTmpMountWithAllOptions) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp ext4 rw,noexec,nodev,nosuid,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_TRUE(findings.empty()); // Should have no findings
}

// Test /home mount with all required options
TEST_F(MountScannerTest, ScanHomeMountWithAllOptions) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda3 /home ext4 rw,nosuid,nodev,noexec,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_TRUE(findings.empty()); // Should have no findings
}

// Test root mount (should be ignored)
TEST_F(MountScannerTest, ScanRootMount) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 / ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_TRUE(findings.empty()); // Root mount should be ignored
}

// Test malformed mount line
TEST_F(MountScannerTest, ScanWithMalformedMountLine) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "malformed line\n/dev/sda1 /tmp ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // Should still process the valid line
    ASSERT_EQ(findings.size(), 5); // tmp-noexec, tmp-nosuid, tmp-nodev, sensitive-nosuid, sensitive-nodev for /tmp
}

// Test incomplete mount line
TEST_F(MountScannerTest, ScanWithIncompleteMountLine) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1\n/dev/sda1 /tmp ext4 rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // Should still process the valid line
    ASSERT_EQ(findings.size(), 5); // tmp-noexec, tmp-nosuid, tmp-nodev, sensitive-nosuid, sensitive-nodev for /tmp
}

// Test unsupported filesystem (should still check mount options)
TEST_F(MountScannerTest, ScanWithUnsupportedFilesystem) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp unknown_fs rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 3); // Should still check tmp mount options but not sensitive checks for unknown fs
}

// Test XFS filesystem
TEST_F(MountScannerTest, ScanWithXfsFilesystem) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp xfs rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 5); // Should check mount options for XFS tmp
}

// Test Btrfs filesystem
TEST_F(MountScannerTest, ScanWithBtrfsFilesystem) {
    auto context = create_context(true);
    sys_scan::MountScanner scanner;

    std::string mounts_content = "/dev/sda1 /tmp btrfs rw,relatime 0 0\n";
    std::string mounts_file = create_mounts_file(mounts_content);

    scanner.scan(*context, mounts_file);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 5); // Should check mount options for Btrfs tmp
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}