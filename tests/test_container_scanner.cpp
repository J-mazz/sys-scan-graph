#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include "../src/scanners/ContainerScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"

namespace fs = std::filesystem;
namespace sys_scan {

class ContainerScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory structure
        test_dir = std::filesystem::temp_directory_path() / "container_test";
        std::filesystem::create_directories(test_dir);

        // Create /proc structure
        proc_dir = test_dir / "proc";
        std::filesystem::create_directories(proc_dir);
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    fs::path test_dir;
    fs::path proc_dir;

    // Helper to create a mock /proc/pid directory with cgroup file
    void createProcEntry(const std::string& pid, const std::string& cgroup_content) {
        auto pid_dir = proc_dir / pid;
        std::filesystem::create_directories(pid_dir);

        std::ofstream cgroup_file(pid_dir / "cgroup");
        cgroup_file << cgroup_content;
        cgroup_file.close();
    }

    // Helper to run scanner and get findings
    std::vector<Finding> runScanner(bool containers_enabled = true) {
        Config config;
        config.containers = containers_enabled;
        config.test_root = test_dir.string();

        Report report;
        ScanContext context(config, report);

        ContainerScanner scanner;
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

// Test derive_container_id function
TEST_F(ContainerScannerTest, DeriveContainerId64Char) {
    std::string cgroup = "0::/system.slice/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "1234567890ab");
}

TEST_F(ContainerScannerTest, DeriveContainerId32Char) {
    std::string cgroup = "0::/system.slice/containerd-abcdef1234567890abcdef1234567890.scope";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "abcdef123456");
}

TEST_F(ContainerScannerTest, DeriveContainerIdShort) {
    std::string cgroup = "0::/system.slice/docker-12345.scope";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "");  // Too short, should return empty
}

TEST_F(ContainerScannerTest, DeriveContainerIdNoHex) {
    std::string cgroup = "0::/system.slice/systemd.scope";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "");
}

TEST_F(ContainerScannerTest, DeriveContainerIdMultipleRuns) {
    std::string cgroup = "0::/system.slice/docker-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "abcdef123456");  // Should return first 64-char run
}

TEST_F(ContainerScannerTest, DeriveContainerIdEmbedded) {
    std::string cgroup = "0::/kubepods/burstable/pod12345678-90ab-cdef-1234-567890abcdef/abcdef1234567890abcdef1234567890abcdef";
    std::string id = ContainerScanner::derive_container_id(cgroup);
    EXPECT_EQ(id, "abcdef123456");
}

// Test scanner disabled when containers is false
TEST_F(ContainerScannerTest, ScanDisabledWhenContainersDisabled) {
    createProcEntry("123", "0::/system.slice/docker-abcdef1234567890abcdef1234567890.scope");

    auto findings = runScanner(false);
    EXPECT_TRUE(findings.empty());
}

// Test Docker container detection
TEST_F(ContainerScannerTest, ScanDockerContainer) {
    createProcEntry("123", "0::/system.slice/docker-abcdef1234567890abcdef1234567890.scope");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->id, "container:abcdef123456");
    EXPECT_EQ(container->metadata.at("runtime"), "docker");
    EXPECT_EQ(container->metadata.at("pid"), "123");
    EXPECT_THAT(container->metadata.at("cgroup"), ::testing::HasSubstr("docker"));
}

// Test containerd container detection
TEST_F(ContainerScannerTest, ScanContainerdContainer) {
    createProcEntry("456", "0::/system.slice/containerd-1234567890abcdef1234567890abcdef.scope");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->id, "container:1234567890ab");
    EXPECT_EQ(container->metadata.at("runtime"), "containerd");
    EXPECT_EQ(container->metadata.at("pid"), "456");
}

// Test Podman container detection
TEST_F(ContainerScannerTest, ScanPodmanContainer) {
    createProcEntry("789", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abcdef1234567890abcdef1234567890.scope");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->id, "container:abcdef123456");
    EXPECT_EQ(container->metadata.at("runtime"), "podman");
}

// Test CRI-O container detection
TEST_F(ContainerScannerTest, ScanCrioContainer) {
    createProcEntry("101", "0::/system.slice/crio-1234567890abcdef1234567890abcdef.scope");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->id, "container:1234567890ab");
    EXPECT_EQ(container->metadata.at("runtime"), "crio");
}

// Test unknown runtime detection
TEST_F(ContainerScannerTest, ScanUnknownRuntime) {
    createProcEntry("202", "0::/system.slice/custom-abcdef1234567890abcdef1234567890.scope");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->metadata.at("runtime"), "unknown");
}

// Test Kubernetes pod detection
TEST_F(ContainerScannerTest, ScanKubernetesPod) {
    createProcEntry("303", "0::/kubepods/burstable/pod12345678-90ab-cdef-1234-567890abcdef\n");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:kubepods"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->metadata.at("runtime"), "kube");
    EXPECT_EQ(container->metadata.at("pid"), "303");
}

// Test multiple containers detection
TEST_F(ContainerScannerTest, ScanMultipleContainers) {
    createProcEntry("111", "0::/system.slice/docker-abcdef1234567890abcdef1234567890.scope");
    createProcEntry("222", "0::/system.slice/containerd-1234567890abcdef1234567890abcdef.scope");
    createProcEntry("333", "0::/system.slice/podman-fedcba0987654321fedcba0987654321.scope");

    auto findings = runScanner();

    // Should have 3 container findings
    auto container_findings = std::count_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    EXPECT_EQ(container_findings, 3);

    // Check each runtime is detected
    auto docker = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("runtime") && f.metadata.at("runtime") == "docker"; });
    EXPECT_NE(docker, findings.end());

    auto containerd = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("runtime") && f.metadata.at("runtime") == "containerd"; });
    EXPECT_NE(containerd, findings.end());

    auto podman = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.metadata.count("runtime") && f.metadata.at("runtime") == "podman"; });
    EXPECT_NE(podman, findings.end());
}

// Test no containers detected
TEST_F(ContainerScannerTest, ScanNoContainers) {
    // Create a regular process without container markers
    createProcEntry("999", "0::/system.slice/sshd.service");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto none = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:none"; });
    ASSERT_NE(none, findings.end());
    EXPECT_EQ(none->title, "No containers detected");
    EXPECT_EQ(none->severity, Severity::Info);
}

// Test empty cgroup file
TEST_F(ContainerScannerTest, ScanEmptyCgroup) {
    createProcEntry("404", "");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto none = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:none"; });
    ASSERT_NE(none, findings.end());
}

// Test malformed cgroup content
TEST_F(ContainerScannerTest, ScanMalformedCgroup) {
    createProcEntry("505", "invalid cgroup format without colons\nanother line");

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto none = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:none"; });
    ASSERT_NE(none, findings.end());
}

// Test non-numeric pid directory (should be skipped)
TEST_F(ContainerScannerTest, ScanNonNumericPid) {
    auto non_num_dir = proc_dir / "notapid";
    std::filesystem::create_directories(non_num_dir);
    std::ofstream cgroup_file(non_num_dir / "cgroup");
    cgroup_file << "0::/system.slice/docker-abcdef1234567890abcdef1234567890.scope";
    cgroup_file.close();

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto none = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:none"; });
    ASSERT_NE(none, findings.end());
}

// Test missing cgroup file
TEST_F(ContainerScannerTest, ScanMissingCgroupFile) {
    auto pid_dir = proc_dir / "606";
    std::filesystem::create_directories(pid_dir);
    // Don't create cgroup file

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto none = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:none"; });
    ASSERT_NE(none, findings.end());
}

// Test container with multiple cgroup lines
TEST_F(ContainerScannerTest, ScanMultipleCgroupLines) {
    std::string cgroup_content =
        "0::/system.slice/sshd.service\n"
        "1::/system.slice/docker-abcdef1234567890abcdef1234567890.scope\n"
        "2::/user.slice/user-1000.slice\n";

    createProcEntry("707", cgroup_content);

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto container = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id.find("container:") == 0 && f.id != "container:none"; });
    ASSERT_NE(container, findings.end());
    EXPECT_EQ(container->id, "container:abcdef123456");
    EXPECT_EQ(container->metadata.at("runtime"), "docker");
}

// Test kubepods detection with multiple lines
TEST_F(ContainerScannerTest, ScanKubepodsMultipleLines) {
    std::string cgroup_content =
        "0::/system.slice/sshd.service\n"
        "1::/kubepods/burstable/pod12345678-90ab-cdef-1234-567890abcdef\n"
        "2::/user.slice/user-1000.slice\n";

    createProcEntry("808", cgroup_content);

    auto findings = runScanner();
    ASSERT_GE(findings.size(), 1);

    auto kubepods = std::find_if(findings.begin(), findings.end(),
        [](const Finding& f) { return f.id == "container:kubepods"; });
    ASSERT_NE(kubepods, findings.end());
    EXPECT_EQ(kubepods->metadata.at("runtime"), "kube");
}

} // namespace sys_scan