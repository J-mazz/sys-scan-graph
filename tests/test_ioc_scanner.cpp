#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include "../src/scanners/IOCScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"

namespace fs = std::filesystem;
namespace sys_scan {

class IOCScannerTest : public ::testing::Test {
protected:
    fs::path test_dir;
    fs::path proc_dir;

    void SetUp() override {
        // Create temporary test directory structure
        test_dir = "/tmp/ioc_test";
        fs::create_directories(test_dir);

        // Create proc directory structure
        proc_dir = test_dir / "proc";
        fs::create_directories(proc_dir);
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    // Helper to create a test process directory
    void createTestProcess(int pid, const std::string& cmdline, const std::string& exe_target = "", const std::string& environ = "") {
        fs::path proc_pid = proc_dir / std::to_string(pid);
        fs::create_directories(proc_pid);

        // Create cmdline file
        if (!cmdline.empty()) {
            std::ofstream cmdline_file(proc_pid / "cmdline", std::ios::binary);
            cmdline_file.write(cmdline.data(), cmdline.size());
            cmdline_file.close();
        }

        // Create exe symlink
        if (!exe_target.empty()) {
            fs::path exe_path = proc_pid / "exe";
            if (exe_target == "(deleted)") {
                // Create a symlink to a non-existent file
                symlink("(deleted)", exe_path.c_str());
            } else {
                // Create symlink to target
                symlink(exe_target.c_str(), exe_path.c_str());
            }
        }

        // Create environ file
        if (!environ.empty()) {
            std::ofstream environ_file(proc_pid / "environ", std::ios::binary);
            environ_file.write(environ.data(), environ.size());
            environ_file.close();
        }
    }

    // Helper to run scanner and get findings
    std::vector<Finding> runScanner() {
        Config config;
        config.test_root = test_dir.string();

        Report report;
        ScanContext context(config, report);

        IOCScanner scanner;
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

// Test detection of suspicious process names
TEST_F(IOCScannerTest, DetectsSuspiciousProcessNames) {
    createTestProcess(1234, "cryptominer\x00--pool\x00stratum+tcp://pool.example.com:3333");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("cryptominer") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->title, "Process IOC Detected");
    EXPECT_EQ(finding->severity, Severity::Low);
    EXPECT_THAT(finding->description, ::testing::HasSubstr("suspicious patterns"));
    EXPECT_EQ(finding->metadata.at("pattern_match"), "true");
}

// Test detection of processes with deleted executables
TEST_F(IOCScannerTest, DetectsDeletedExecutables) {
    createTestProcess(5678, "myprocess\x00arg1", "(deleted)");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("(deleted)") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->severity, Severity::Critical);
    EXPECT_THAT(finding->description, ::testing::HasSubstr("deleted executable"));
    EXPECT_EQ(finding->metadata.at("deleted_executable"), "true");
}

// Test detection of processes with world-writable executables
TEST_F(IOCScannerTest, DetectsWorldWritableExecutables) {
    createTestProcess(9999, "suspicious\x00script", "/tmp/malicious_script");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("/tmp/malicious_script") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->severity, Severity::High);
    EXPECT_THAT(finding->description, ::testing::HasSubstr("world-writable executable"));
    EXPECT_EQ(finding->metadata.at("world_writable_executable"), "true");
}

// Test detection of processes with suspicious environment variables
TEST_F(IOCScannerTest, DetectsSuspiciousEnvironment) {
    createTestProcess(1111, "normal_process", "/bin/normal", "LD_PRELOAD=/tmp/malicious.so");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("/bin/normal") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->severity, Severity::Medium);
    EXPECT_THAT(finding->description, ::testing::HasSubstr("suspicious environment"));
    EXPECT_EQ(finding->metadata.at("environment_issue"), "true");
}

// Test detection of processes with world-writable paths in command line
TEST_F(IOCScannerTest, DetectsWorldWritablePathsInCmdline) {
    createTestProcess(2222, "script /tmp/suspicious.sh");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("script") != std::string::npos; });
    ASSERT_NE(finding, findings.end());
    EXPECT_EQ(finding->severity, Severity::Low);
    EXPECT_EQ(finding->metadata.at("pattern_match"), "true");
}

// Test that normal processes are not flagged
TEST_F(IOCScannerTest, IgnoresNormalProcesses) {
    createTestProcess(3333, "bash\x00-c\x00echo hello", "/bin/bash", "PATH=/usr/bin:/bin\x00HOME=/home/user");

    auto findings = runScanner();

    // Should not find any IOCs for normal bash process
    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("/bin/bash") != std::string::npos; });
    EXPECT_EQ(finding, findings.end());
}

// Test multiple suspicious processes
TEST_F(IOCScannerTest, HandlesMultipleSuspiciousProcesses) {
    createTestProcess(4444, "cryptominer\x00--pool\x00stratum+tcp://pool.example.com:3333");
    createTestProcess(5555, "xmrig\x00-o\x00pool.minexmr.com:4444");
    createTestProcess(6666, "normal_process", "/tmp/suspicious_exe");

    auto findings = runScanner();
    EXPECT_GE(findings.size(), 3);

    // Check that all three are detected
    bool found_crypto = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("cryptominer") != std::string::npos; });
    bool found_xmrig = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("xmrig") != std::string::npos; });
    bool found_tmp = std::any_of(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("/tmp/suspicious_exe") != std::string::npos; });

    EXPECT_TRUE(found_crypto);
    EXPECT_TRUE(found_xmrig);
    EXPECT_TRUE(found_tmp);
}

// Test that scanner respects test_root configuration
TEST_F(IOCScannerTest, RespectsTestRoot) {
    createTestProcess(7777, "cryptominer\x00--evil");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    // Should find the test process, not real system processes
    auto finding = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.at("pid") == "7777"; });
    EXPECT_NE(finding, findings.end());
}

// Test handling of missing process files
TEST_F(IOCScannerTest, HandlesMissingProcessFiles) {
    // Create process directory but no files
    fs::create_directories(proc_dir / "8888");

    // Scanner should handle missing files gracefully
    EXPECT_NO_THROW({
        auto findings = runScanner();
        // Should not crash
    });
}

// Test handling of invalid PID directories
TEST_F(IOCScannerTest, HandlesInvalidPidDirectories) {
    // Create non-numeric directory
    fs::create_directories(proc_dir / "notapid");

    // Scanner should ignore non-numeric directories
    EXPECT_NO_THROW({
        auto findings = runScanner();
        // Should not crash
    });
}

} // namespace sys_scan