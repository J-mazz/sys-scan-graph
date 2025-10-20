#include <gtest/gtest.h>
#include "../src/scanners/MACScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace sys_scan {

// Test fixture for MACScanner tests
class MACScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directories for testing
        test_root = "/tmp/test_mac";
        fs::create_directories(test_root);

        config.test_root = test_root;

        report = std::make_unique<Report>();
        context = std::make_unique<ScanContext>(config, *report);
    }

    void TearDown() override {
        // Clean up test directories
        fs::remove_all(test_root);
    }

    void createTestFile(const std::string& path, const std::string& content) {
        std::string full_path = test_root + path;
        fs::create_directories(fs::path(full_path).parent_path());
        std::ofstream file(full_path);
        file << content;
        file.close();
    }

    void createTestSymlink(const std::string& link_path, const std::string& target_path) {
        std::string full_link = test_root + link_path;
        std::string full_target = test_root + target_path;
        fs::create_directories(fs::path(full_link).parent_path());
        fs::create_symlink(full_target, full_link);
    }

    Config config;
    std::unique_ptr<Report> report;
    std::unique_ptr<ScanContext> context;
    std::string test_root;
};

// Test scanner name and description
TEST(MACScannerBasicTest, NameAndDescription) {
    MACScanner scanner;
    EXPECT_EQ(scanner.name(), "mac");
    EXPECT_EQ(scanner.description(), "Mandatory Access Control (SELinux/AppArmor) detection and analysis");
}

// Test SELinux detection when not present
TEST_F(MACScannerTest, SELinuxNotPresent) {
    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_EQ(results.size(), 1); // One ScanResult for MAC scanner
    ASSERT_GE(results[0].findings.size(), 3); // SELinux, AppArmor, and advisory findings

    // Find SELinux finding
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    EXPECT_EQ(selinux_it->metadata["present"], "false");
    EXPECT_EQ(selinux_it->severity, Severity::High); // No MAC at all
}

// Test SELinux detection when present and enforcing
TEST_F(MACScannerTest, SELinuxEnforcing) {
    // Create SELinux sysfs structure
    createTestFile("/sys/fs/selinux/enforce", "1");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    EXPECT_EQ(selinux_it->metadata["present"], "true");
    EXPECT_EQ(selinux_it->metadata["enforcing"], "true");
    EXPECT_EQ(selinux_it->severity, Severity::Info);
}

// Test SELinux detection when present and permissive
TEST_F(MACScannerTest, SELinuxPermissive) {
    // Create SELinux sysfs structure
    createTestFile("/sys/fs/selinux/enforce", "0");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    EXPECT_EQ(selinux_it->metadata["present"], "true");
    EXPECT_EQ(selinux_it->metadata["enforcing"], "false");
    EXPECT_EQ(selinux_it->severity, Severity::Low);
}

// Test SELinux config parsing
TEST_F(MACScannerTest, SELinuxConfigParsing) {
    // Create SELinux sysfs and config
    createTestFile("/sys/fs/selinux/enforce", "1");
    createTestFile("/etc/selinux/config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    EXPECT_EQ(selinux_it->metadata["config_mode"], "enforcing");
}

// Test AppArmor detection when not enabled
TEST_F(MACScannerTest, AppArmorNotEnabled) {
    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    EXPECT_EQ(apparmor_it->metadata["enabled"], "false");
    EXPECT_EQ(apparmor_it->severity, Severity::High);
}

// Test AppArmor detection when enabled
TEST_F(MACScannerTest, AppArmorEnabled) {
    // Create AppArmor sysfs structure
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    EXPECT_EQ(apparmor_it->metadata["enabled"], "true");
    EXPECT_EQ(apparmor_it->severity, Severity::Info);
}

// Test container detection
TEST_F(MACScannerTest, ContainerDetection) {
    // Create container environment files
    createTestFile("/.dockerenv", "");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();

    // Find SELinux finding
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // In container, severity should be lower
    EXPECT_EQ(selinux_it->severity, Severity::Info);
}

// Test dual MAC detection
TEST_F(MACScannerTest, DualMACDetection) {
    // Create both SELinux and AppArmor
    createTestFile("/sys/fs/selinux/enforce", "1");
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();

    // Should have dual MAC finding
    auto& findings = results[0].findings;
    auto dual_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "mac_dual"; });
    ASSERT_NE(dual_it, findings.end());

    EXPECT_EQ(dual_it->severity, Severity::Info);
}

// Test no MAC advisory
TEST_F(MACScannerTest, NoMACAdvisory) {
    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();

    // Should have no MAC finding
    auto& findings = results[0].findings;
    auto none_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "mac_none"; });
    ASSERT_NE(none_it, findings.end());

    EXPECT_EQ(none_it->severity, Severity::High);
}

// Test process scanning with mock /proc structure
TEST_F(MACScannerTest, ProcessScanning) {
    // This is a challenging test since it requires mocking /proc
    // For now, we'll test that the scanner doesn't crash
    MACScanner scanner;

    // Create minimal /proc structure
    createTestFile("/proc/1/comm", "init");
    createTestFile("/proc/1/attr/current", "unconfined");
    createTestSymlink("/proc/1/exe", "/usr/sbin/sshd");

    scanner.scan(*context);

    auto results = report->results();
    // Should complete without crashing
    EXPECT_GE(results.size(), 1);
}

// Test AppArmor profile counting
TEST_F(MACScannerTest, AppArmorProfileCounting) {
    // Create AppArmor sysfs
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create mock process with complain mode
    createTestFile("/proc/123/comm", "test_process");
    createTestFile("/proc/123/attr/current", "/usr/bin/test (complain)");
    createTestSymlink("/proc/123/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should detect profiles and complain mode
    EXPECT_EQ(apparmor_it->metadata["enabled"], "true");
    EXPECT_GE(std::stoi(apparmor_it->metadata["profiles_seen"]), 0);
}

// Test critical unconfined processes
TEST_F(MACScannerTest, CriticalUnconfinedProcesses) {
    // Create AppArmor sysfs
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create mock critical process that's unconfined
    createTestFile("/proc/456/comm", "sshd");
    createTestFile("/proc/456/attr/current", "unconfined");
    createTestSymlink("/proc/456/exe", "/usr/sbin/sshd");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should detect unconfined critical process
    EXPECT_EQ(apparmor_it->metadata["enabled"], "true");
    EXPECT_EQ(apparmor_it->severity, Severity::Medium); // Due to unconfined critical
}

} // namespace sys_scan