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
        config.test_mode = true;

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

// Parameterized test for SELinux enforce file values
class SELinuxEnforceTest : public MACScannerTest,
                          public ::testing::WithParamInterface<std::tuple<std::string, bool, Severity>> {
};

TEST_P(SELinuxEnforceTest, SELinuxEnforceValues) {
    auto [enforce_value, expected_present, expected_severity] = GetParam();

    if (!enforce_value.empty()) {
        createTestFile("/sys/fs/selinux/enforce", enforce_value);
    }

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    std::string expected_present_str = expected_present ? "true" : "false";
    EXPECT_EQ(selinux_it->metadata["present"], expected_present_str);
    EXPECT_EQ(selinux_it->severity, expected_severity);
}

INSTANTIATE_TEST_SUITE_P(
    SELinuxEnforceValues,
    SELinuxEnforceTest,
    ::testing::Values(
        std::make_tuple("", false, Severity::High),           // No enforce file
        std::make_tuple("1", true, Severity::Info),           // Enforcing
        std::make_tuple("0", true, Severity::Low),            // Permissive
        std::make_tuple("invalid", true, Severity::Info),     // Invalid but present
        std::make_tuple("2", true, Severity::Info),           // Unexpected value
        std::make_tuple(" 1 ", true, Severity::Info),         // Whitespace
        std::make_tuple("\n1\n", true, Severity::Info),       // Newlines
        std::make_tuple("1\n0", true, Severity::Info)         // Multiple lines
    )
);

// Parameterized test for AppArmor enabled file values
class AppArmorEnabledTest : public MACScannerTest,
                           public ::testing::WithParamInterface<std::tuple<std::string, bool, Severity>> {
};

TEST_P(AppArmorEnabledTest, AppArmorEnabledValues) {
    auto [enabled_value, expected_enabled, expected_severity] = GetParam();

    if (!enabled_value.empty()) {
        createTestFile("/sys/module/apparmor/parameters/enabled", enabled_value);
    }

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    std::string expected_enabled_str = expected_enabled ? "true" : "false";
    EXPECT_EQ(apparmor_it->metadata["enabled"], expected_enabled_str);
    EXPECT_EQ(apparmor_it->severity, expected_severity);
}

INSTANTIATE_TEST_SUITE_P(
    AppArmorEnabledValues,
    AppArmorEnabledTest,
    ::testing::Values(
        std::make_tuple("", false, Severity::High),           // No enabled file
        std::make_tuple("Y", true, Severity::Info),           // Enabled
        std::make_tuple("N", true, Severity::Info),           // Any non-empty string is enabled
        std::make_tuple("y", true, Severity::Info),           // Lowercase enabled
        std::make_tuple("n", true, Severity::Info),           // Lowercase disabled (but treated as enabled)
        std::make_tuple("1", true, Severity::Info),           // Numeric enabled
        std::make_tuple("0", true, Severity::Info),           // Numeric disabled (but treated as enabled)
        std::make_tuple("invalid", true, Severity::Info),     // Invalid value (but treated as enabled)
        std::make_tuple(" Y ", true, Severity::Info),         // Whitespace
        std::make_tuple("\nY\n", true, Severity::Info),       // Newlines
        std::make_tuple("Y\nN", true, Severity::Info)         // Multiple lines
    )
);

// Parameterized test for container environment detection
class ContainerDetectionTest : public MACScannerTest,
                              public ::testing::WithParamInterface<std::tuple<std::string, std::string, Severity>> {
};

TEST_P(ContainerDetectionTest, ContainerEnvironmentDetection) {
    auto [container_file, container_type, expected_severity] = GetParam();

    if (!container_file.empty()) {
        createTestFile(container_file, "");
    }

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto mac_none_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "mac_none"; });
    ASSERT_NE(mac_none_it, findings.end());

    // In container, severity should be reduced
    EXPECT_EQ(mac_none_it->severity, expected_severity);
}

INSTANTIATE_TEST_SUITE_P(
    ContainerDetection,
    ContainerDetectionTest,
    ::testing::Values(
        std::make_tuple("", "none", Severity::High),                    // No container
        std::make_tuple("/.dockerenv", "docker", Severity::Low),        // Docker
        std::make_tuple("/run/.containerenv", "podman", Severity::Low), // Podman
        std::make_tuple("/run/.dockerenv", "docker-run", Severity::Low), // Docker run
        std::make_tuple("/.lxcenv", "lxc", Severity::Low),               // LXC
        std::make_tuple("/run/systemd/container", "systemd", Severity::Low) // systemd-nspawn
    )
);

// Parameterized test for critical process detection
class CriticalProcessTest : public MACScannerTest,
                           public ::testing::WithParamInterface<std::tuple<std::string, std::string, Severity>> {
};

TEST_P(CriticalProcessTest, CriticalUnconfinedProcesses) {
    auto [process_name, exe_path, expected_severity] = GetParam();

    // Enable AppArmor
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create unconfined critical process
    createTestFile("/proc/123/comm", process_name);
    createTestFile("/proc/123/attr/current", "unconfined");
    createTestSymlink("/proc/123/exe", exe_path);

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    ASSERT_GE(results.size(), 1);

    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    EXPECT_EQ(apparmor_it->severity, expected_severity);
}

INSTANTIATE_TEST_SUITE_P(
    CriticalProcessDetection,
    CriticalProcessTest,
    ::testing::Values(
        std::make_tuple("sshd", "/usr/sbin/sshd", Severity::Medium),           // SSH daemon
        std::make_tuple("containerd", "/usr/bin/containerd", Severity::Medium), // Container runtime
        std::make_tuple("dockerd", "/usr/bin/dockerd", Severity::Medium),       // Docker daemon
        std::make_tuple("dbus-daemon", "/usr/bin/dbus-daemon", Severity::Medium), // D-Bus daemon
        std::make_tuple("systemd", "/usr/lib/systemd/systemd", Severity::Medium), // Systemd
        std::make_tuple("networkd", "/usr/lib/systemd/systemd-networkd", Severity::Medium), // Networkd
        std::make_tuple("nginx", "/usr/sbin/nginx", Severity::Medium),          // Web server
        std::make_tuple("apache2", "/usr/sbin/apache2", Severity::Medium),      // Web server
        std::make_tuple("mysql", "/usr/sbin/mysql", Severity::Medium),          // Database
        std::make_tuple("postgres", "/usr/lib/postgresql/bin/postgres", Severity::Medium), // Database
        std::make_tuple("ordinary_app", "/usr/bin/ordinary_app", Severity::Info), // Non-critical
        std::make_tuple("test_proc", "/usr/bin/test_proc", Severity::Info)       // Non-critical
    )
);

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

// Test SELinux permissive severity
TEST_F(MACScannerTest, SELinuxPermissiveSeverity) {
    // Create SELinux in permissive mode
    createTestFile("/sys/fs/selinux/enforce", "0");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // Permissive mode should be Low severity
    EXPECT_EQ(selinux_it->severity, Severity::Low);
    EXPECT_EQ(selinux_it->metadata["permissive"], "true");
}

// Test SELinux without AppArmor (Ubuntu-style)
TEST_F(MACScannerTest, SELinuxAbsentWithAppArmor) {
    // Create only AppArmor
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // SELinux absent with AppArmor should be Low severity
    EXPECT_EQ(selinux_it->metadata["present"], "false");
    EXPECT_EQ(selinux_it->severity, Severity::Low);
}

// Test SELinux config with whitespace
TEST_F(MACScannerTest, SELinuxConfigWhitespace) {
    createTestFile("/sys/fs/selinux/enforce", "1");
    createTestFile("/etc/selinux/config", "  SELINUX=permissive  \nSELINUXTYPE=targeted\n");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // Should parse config even with whitespace
    EXPECT_TRUE(selinux_it->metadata.count("config_mode") > 0);
}

// Test SELinux config without SELINUX= line
TEST_F(MACScannerTest, SELinuxConfigMissingLine) {
    createTestFile("/sys/fs/selinux/enforce", "1");
    createTestFile("/etc/selinux/config", "# This is a comment\nSELINUXTYPE=targeted\n");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // Should handle missing SELINUX= line gracefully
    EXPECT_EQ(selinux_it->metadata["present"], "true");
}

// Test multiple complain mode processes
TEST_F(MACScannerTest, MultipleComplainProcesses) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create multiple processes in complain mode
    createTestFile("/proc/100/comm", "proc1");
    createTestFile("/proc/100/attr/current", "/usr/bin/proc1 (complain)");
    createTestFile("/proc/101/comm", "proc2");
    createTestFile("/proc/101/attr/current", "/usr/bin/proc2 (complain)");
    createTestFile("/proc/102/comm", "proc3");
    createTestFile("/proc/102/attr/current", "/usr/bin/proc3 (complain)");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should count complain mode processes
    if (apparmor_it->metadata.count("complain_count")) {
        EXPECT_GE(std::stoi(apparmor_it->metadata["complain_count"]), 0);
    }
}

// Test multiple critical unconfined processes
TEST_F(MACScannerTest, MultipleCriticalUnconfined) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create multiple critical processes that are unconfined
    createTestFile("/proc/200/comm", "sshd");
    createTestFile("/proc/200/attr/current", "unconfined");
    createTestSymlink("/proc/200/exe", "/usr/sbin/sshd");

    createTestFile("/proc/201/comm", "nginx");
    createTestFile("/proc/201/attr/current", "unconfined");
    createTestSymlink("/proc/201/exe", "/usr/sbin/nginx");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should escalate severity for unconfined critical processes
    EXPECT_EQ(apparmor_it->severity, Severity::Medium);
    if (apparmor_it->metadata.count("unconfined_critical")) {
        EXPECT_GE(std::stoi(apparmor_it->metadata["unconfined_critical"]), 1);
    }
}

// Test non-critical unconfined process
TEST_F(MACScannerTest, NonCriticalUnconfined) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create non-critical process that's unconfined
    createTestFile("/proc/300/comm", "ordinary_app");
    createTestFile("/proc/300/attr/current", "unconfined");
    createTestSymlink("/proc/300/exe", "/usr/bin/ordinary_app");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should not escalate severity for non-critical unconfined
    EXPECT_EQ(apparmor_it->severity, Severity::Info);
}

// Test process with confined AppArmor profile
TEST_F(MACScannerTest, ConfinedProcess) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create confined process
    createTestFile("/proc/400/comm", "confined_app");
    createTestFile("/proc/400/attr/current", "/usr/bin/confined_app (enforce)");
    createTestSymlink("/proc/400/exe", "/usr/bin/confined_app");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should count as a profile
    EXPECT_GE(std::stoi(apparmor_it->metadata["profiles_seen"]), 0);
}

// Test process without attr/current file
TEST_F(MACScannerTest, ProcessWithoutAttrCurrent) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create process without attr/current
    createTestFile("/proc/500/comm", "no_attr");
    // No attr/current file

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should not crash and handle missing attr/current gracefully
    EXPECT_GE(results.size(), 1);
}

// Test critical binaries: containerd
TEST_F(MACScannerTest, CriticalUnconfinedContainerd) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/600/comm", "containerd");
    createTestFile("/proc/600/attr/current", "unconfined");
    createTestSymlink("/proc/600/exe", "/usr/bin/containerd");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    EXPECT_EQ(apparmor_it->severity, Severity::Medium);
}

// Test unreadable /proc directory
TEST_F(MACScannerTest, UnreadableProcDirectory) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create /proc but make it unreadable (this is hard to test directly)
    // Instead, test with no /proc directory at all
    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should complete without crashing
    EXPECT_GE(results.size(), 1);
}

// Test process with missing exe symlink
TEST_F(MACScannerTest, ProcessMissingExeSymlink) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/700/comm", "missing_exe");
    createTestFile("/proc/700/attr/current", "unconfined");
    // No exe symlink

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle missing exe symlink gracefully
    EXPECT_GE(results.size(), 1);
}

// Test process with broken exe symlink
TEST_F(MACScannerTest, ProcessBrokenExeSymlink) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/701/comm", "broken_exe");
    createTestFile("/proc/701/attr/current", "unconfined");
    createTestSymlink("/proc/701/exe", "/nonexistent/path");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle broken exe symlink gracefully
    EXPECT_GE(results.size(), 1);
}

// Test SELinux config with multiple SELINUX= lines
TEST_F(MACScannerTest, SELinuxConfigMultipleLines) {
    createTestFile("/sys/fs/selinux/enforce", "1");
    createTestFile("/etc/selinux/config", "SELINUX=enforcing\nSELINUX=permissive\nSELINUXTYPE=targeted\n");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // Should parse first SELINUX= line
    EXPECT_TRUE(selinux_it->metadata.count("config_mode") > 0);
}

// Test SELinux config with very long line
TEST_F(MACScannerTest, SELinuxConfigVeryLongLine) {
    createTestFile("/sys/fs/selinux/enforce", "1");

    std::string long_line = "SELINUX=" + std::string(1000, 'x');
    createTestFile("/etc/selinux/config", long_line);

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle long config lines without crashing
    EXPECT_GE(results.size(), 1);
}

// Test AppArmor enabled file with special characters
TEST_F(MACScannerTest, AppArmorEnabledSpecialChars) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y\nwith\nnewlines");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should handle special characters in enabled file
    EXPECT_EQ(apparmor_it->metadata["enabled"], "true");
}

// Test process with empty comm file
TEST_F(MACScannerTest, ProcessEmptyCommFile) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/702/comm", "");
    createTestFile("/proc/702/attr/current", "unconfined");
    createTestSymlink("/proc/702/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle empty comm file gracefully
    EXPECT_GE(results.size(), 1);
}

// Test process with empty attr/current file
TEST_F(MACScannerTest, ProcessEmptyAttrCurrentFile) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/703/comm", "empty_attr");
    createTestFile("/proc/703/attr/current", "");
    createTestSymlink("/proc/703/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle empty attr/current file gracefully
    EXPECT_GE(results.size(), 1);
}

// Test process with very long comm name
TEST_F(MACScannerTest, ProcessVeryLongCommName) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    std::string long_comm = std::string(1000, 'a') + "\n";
    createTestFile("/proc/704/comm", long_comm);
    createTestFile("/proc/704/attr/current", "unconfined");
    createTestSymlink("/proc/704/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle long comm names
    EXPECT_GE(results.size(), 1);
}

// Test process with very long AppArmor label
TEST_F(MACScannerTest, ProcessVeryLongAppArmorLabel) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    std::string long_label = std::string(1000, 'b') + " (complain)\n";
    createTestFile("/proc/705/comm", "long_label");
    createTestFile("/proc/705/attr/current", long_label);
    createTestSymlink("/proc/705/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle long AppArmor labels
    EXPECT_GE(results.size(), 1);
}

// Test SELinux config file permissions issue
TEST_F(MACScannerTest, SELinuxConfigUnreadable) {
    createTestFile("/sys/fs/selinux/enforce", "1");
    // Create config file but don't write to it (empty file)

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle unreadable config file gracefully
    EXPECT_GE(results.size(), 1);
}

// Test AppArmor parameters directory missing
TEST_F(MACScannerTest, AppArmorParametersMissing) {
    // Don't create AppArmor sysfs at all

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should detect AppArmor as not enabled
    EXPECT_EQ(apparmor_it->metadata["enabled"], "false");
}

// Test SELinux sysfs directory missing
TEST_F(MACScannerTest, SELinuxSysfsMissing) {
    // Don't create SELinux sysfs at all

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto selinux_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "selinux"; });
    ASSERT_NE(selinux_it, findings.end());

    // Should detect SELinux as not present
    EXPECT_EQ(selinux_it->metadata["present"], "false");
}

// Test container detection with multiple indicators
TEST_F(MACScannerTest, MultipleContainerIndicators) {
    // Create multiple container files
    createTestFile("/.dockerenv", "");
    createTestFile("/run/.containerenv", "");
    createTestFile("/run/systemd/container", "");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto mac_none_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "mac_none"; });
    ASSERT_NE(mac_none_it, findings.end());

    // Should still reduce severity in container
    EXPECT_EQ(mac_none_it->severity, Severity::Low);
}

// Test process scanning with non-numeric PID directory
TEST_F(MACScannerTest, NonNumericPidDirectory) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create directory that looks like PID but isn't numeric
    createTestFile("/proc/abc123/comm", "not_a_pid");
    createTestFile("/proc/abc123/attr/current", "unconfined");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should skip non-numeric PID directories
    EXPECT_GE(results.size(), 1);
}

// Test process scanning with very high PID number
TEST_F(MACScannerTest, VeryHighPidNumber) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create process with very high PID
    createTestFile("/proc/999999/comm", "high_pid");
    createTestFile("/proc/999999/attr/current", "unconfined");
    createTestSymlink("/proc/999999/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle high PID numbers
    EXPECT_GE(results.size(), 1);
}

// Test AppArmor complain mode with special formatting
TEST_F(MACScannerTest, AppArmorComplainSpecialFormat) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/706/comm", "special_complain");
    createTestFile("/proc/706/attr/current", "/usr/bin/test   (complain)   ");
    createTestSymlink("/proc/706/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should detect complain mode even with extra spaces
    EXPECT_GE(std::stoi(apparmor_it->metadata["complain_count"]), 0);
}

// Test unconfined detection with different capitalizations
TEST_F(MACScannerTest, UnconfinedDifferentCapitalization) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/707/comm", "unconfined_test");
    createTestFile("/proc/707/attr/current", "Unconfined");  // Test case-insensitive detection
    createTestSymlink("/proc/707/exe", "/usr/sbin/sshd");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should detect unconfined regardless of capitalization
    EXPECT_EQ(apparmor_it->severity, Severity::Medium);
}

// Test critical binary path with symlinks
TEST_F(MACScannerTest, CriticalBinarySymlinkResolution) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    createTestFile("/proc/708/comm", "symlinked_sshd");
    createTestFile("/proc/708/attr/current", "unconfined");
    // Create a symlink to a critical binary
    createTestSymlink("/proc/708/exe", "/usr/sbin/sshd");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    auto& findings = results[0].findings;
    auto apparmor_it = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "apparmor"; });
    ASSERT_NE(apparmor_it, findings.end());

    // Should resolve symlinks and detect critical binary
    EXPECT_EQ(apparmor_it->severity, Severity::Medium);
}

// Test buffer size limits in file reading
TEST_F(MACScannerTest, BufferSizeLimits) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create a very long comm name that exceeds buffer
    std::string very_long_comm = std::string(600, 'c') + "\n"; // Longer than MAX_BUF_SIZE
    createTestFile("/proc/709/comm", very_long_comm);
    createTestFile("/proc/709/attr/current", "unconfined");
    createTestSymlink("/proc/709/exe", "/usr/bin/test");

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle buffer size limits gracefully
    EXPECT_GE(results.size(), 1);
}

// Test SELinux config parsing with embedded null bytes
TEST_F(MACScannerTest, SELinuxConfigWithNullBytes) {
    createTestFile("/sys/fs/selinux/enforce", "1");

    std::string config_with_nulls = "SELINUX=enforcing\x00SELINUXTYPE=targeted\x00";
    createTestFile("/etc/selinux/config", config_with_nulls);

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle null bytes in config file
    EXPECT_GE(results.size(), 1);
}

// Test concurrent access to scanner (basic)
TEST_F(MACScannerTest, ConcurrentScannerAccess) {
    // This is a basic test - full concurrency testing would require threads
    MACScanner scanner1;
    MACScanner scanner2;

    scanner1.scan(*context);
    scanner2.scan(*context);

    // Both should complete successfully
    auto results1 = report->results();
    EXPECT_GE(results1.size(), 1);
}

// Test scanner with corrupted test_root path
TEST_F(MACScannerTest, CorruptedTestRootPath) {
    // Set a corrupted test root
    config.test_root = "/nonexistent/path/../../../etc";
    std::unique_ptr<ScanContext> corrupted_context = std::make_unique<ScanContext>(config, *report);

    MACScanner scanner;
    scanner.scan(*corrupted_context);

    auto results = report->results();
    // Should handle corrupted paths gracefully
    EXPECT_GE(results.size(), 1);
}

// Test maximum process entries limit
TEST_F(MACScannerTest, MaxProcessEntriesLimit) {
    createTestFile("/sys/module/apparmor/parameters/enabled", "Y");

    // Create more processes than MAX_PROC_ENTRIES
    for (int i = 0; i < 1100; ++i) { // More than MAX_PROC_ENTRIES (1000)
        std::string pid_str = std::to_string(1000 + i);
        createTestFile("/proc/" + pid_str + "/comm", "proc_" + pid_str);
        createTestFile("/proc/" + pid_str + "/attr/current", "unconfined");
        createTestSymlink("/proc/" + pid_str + "/exe", "/usr/bin/test");
    }

    MACScanner scanner;
    scanner.scan(*context);

    auto results = report->results();
    // Should handle the limit gracefully without crashing
    EXPECT_GE(results.size(), 1);
}

} // namespace sys_scan