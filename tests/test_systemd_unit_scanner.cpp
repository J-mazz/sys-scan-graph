#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/SystemdUnitScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

// Mock filesystem operations for testing
class SystemdUnitScannerTest : public ::testing::Test {
protected:
    std::string temp_dir;
    sys_scan::Config config_;
    sys_scan::Report report_;

    void SetUp() override {
        // Create temporary directory for test files
        char template_path[] = "/tmp/systemd_test_XXXXXX";
        temp_dir = mkdtemp(template_path);
        ASSERT_FALSE(temp_dir.empty());
    }

    void TearDown() override {
        // Clean up temporary directory
        std::filesystem::remove_all(temp_dir);
    }

    // Helper to create a test systemd directory structure
    void create_systemd_structure(const std::string& base_dir) {
        std::filesystem::create_directories(base_dir + "/etc/systemd/system");
        std::filesystem::create_directories(base_dir + "/usr/lib/systemd/system");
        std::filesystem::create_directories(base_dir + "/lib/systemd/system");
    }

    // Helper to create a test service file
    void create_service_file(const std::string& dir, const std::string& filename, const std::string& content) {
        std::ofstream file(dir + "/" + filename);
        ASSERT_TRUE(file.is_open());
        file << content;
        file.close();
    }

    // Helper to create scan context
    std::unique_ptr<sys_scan::ScanContext> create_context(bool hardening_enabled = true, const std::string& test_root = "") {
        config_.hardening = hardening_enabled;
        config_.test_root = test_root;
        return std::make_unique<sys_scan::ScanContext>(config_, report_);
    }

    // Helper to get findings for a specific scanner
    std::vector<sys_scan::Finding> get_findings_for_scanner(const sys_scan::Report& report, const std::string& scanner_name) {
        for (const auto& result : report.results()) {
            if (result.scanner_name == scanner_name) {
                return result.findings;
            }
        }
        return {};
    }
};

TEST_F(SystemdUnitScannerTest, ScanDisabledWhenHardeningDisabled) {
    sys_scan::SystemdUnitScanner scanner;
    auto context = create_context(false);

    scanner.scan(*context);

    // Should not add any findings when hardening is disabled
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_EQ(findings.size(), 0);
}

TEST_F(SystemdUnitScannerTest, ScanWithNoSystemdDirectories) {
    sys_scan::SystemdUnitScanner scanner;
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should not crash and should not add findings when directories don't exist
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_EQ(findings.size(), 0);
}

TEST_F(SystemdUnitScannerTest, ScanEmptySystemdDirectories) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should not add findings for empty directories
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_EQ(findings.size(), 0);
}

TEST_F(SystemdUnitScannerTest, ScanServiceFileWithoutExecStart) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a unit file without ExecStart (not a service)
    std::string unit_content = R"(
[Unit]
Description=Test Unit
After=network.target

[Install]
WantedBy=multi-user.target
)";

    create_service_file(temp_dir + "/etc/systemd/system", "test.unit", unit_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should not add findings for units without ExecStart
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_EQ(findings.size(), 0);
}

TEST_F(SystemdUnitScannerTest, ScanServiceFileWithExecStart) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with ExecStart
    std::string service_content = R"(
[Unit]
Description=Test Service
After=network.target

[Service]
ExecStart=/usr/bin/test
Type=simple

[Install]
WantedBy=multi-user.target
)";

    create_service_file(temp_dir + "/etc/systemd/system", "test.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should add findings for each hardening directive
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GT(findings.size(), 0);

    // Check that findings are generated for the service
    bool found_test_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "test.service") {
            found_test_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_test_service);
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithAllHardeningDirectives) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with all hardening directives properly set
    std::string service_content = R"(
[Unit]
Description=Hardened Service

[Service]
ExecStart=/usr/bin/test
Type=simple
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
CapabilityBoundingSet=
RestrictNamespaces=yes
RestrictSUIDSGID=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
)";

    create_service_file(temp_dir + "/etc/systemd/system", "hardened.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should have findings for hardened.service
    bool found_hardened_service = false;
    int info_findings = 0;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "hardened.service") {
            found_hardened_service = true;
            if (finding.severity == sys_scan::Severity::Info) {
                info_findings++;
            }
        }
    }
    EXPECT_TRUE(found_hardened_service);
    EXPECT_GT(info_findings, 0); // Should have some good findings
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithMissingHardeningDirectives) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with minimal configuration
    std::string service_content = R"(
[Unit]
Description=Basic Service

[Service]
ExecStart=/usr/bin/test
Type=simple

[Install]
WantedBy=multi-user.target
)";

    create_service_file(temp_dir + "/etc/systemd/system", "basic.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should have findings with warnings/errors for missing directives
    bool found_basic_service = false;
    int non_info_findings = 0;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "basic.service") {
            found_basic_service = true;
            if (finding.severity != sys_scan::Severity::Info) {
                non_info_findings++;
            }
        }
    }
    EXPECT_TRUE(found_basic_service);
    EXPECT_GT(non_info_findings, 0); // Should have some warning/error findings
}

TEST_F(SystemdUnitScannerTest, ScanMultipleServices) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create multiple service files
    std::string service1_content = R"(
[Service]
ExecStart=/usr/bin/service1
NoNewPrivileges=yes
)";

    std::string service2_content = R"(
[Service]
ExecStart=/usr/bin/service2
PrivateTmp=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "service1.service", service1_content);
    create_service_file(temp_dir + "/usr/lib/systemd/system", "service2.service", service2_content);

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should have findings for both services
    bool found_service1 = false;
    bool found_service2 = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit")) {
            if (finding.metadata.at("unit") == "service1.service") {
                found_service1 = true;
            } else if (finding.metadata.at("unit") == "service2.service") {
                found_service2 = true;
            }
        }
    }
    EXPECT_TRUE(found_service1);
    EXPECT_TRUE(found_service2);
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithSpecialProtectSystem) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service with ProtectSystem=full (should be flagged)
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
ProtectSystem=full
)";

    create_service_file(temp_dir + "/etc/systemd/system", "protectfull.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should flag ProtectSystem=full as bad
    bool found_bad_protect_system = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "protectfull.service" &&
            finding.metadata.count("key") && finding.metadata.at("key") == "ProtectSystem" &&
            finding.severity != sys_scan::Severity::Info) {
            found_bad_protect_system = true;
            break;
        }
    }
    EXPECT_TRUE(found_bad_protect_system);
}TEST_F(SystemdUnitScannerTest, ScanServiceWithCommentsAndEmptyLines) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with comments and empty lines
    std::string service_content = R"(
# This is a comment
[Unit]
Description=Test Service

[Service]
# Another comment

ExecStart=/usr/bin/test

# Comment before install
[Install]
WantedBy=multi-user.target
)";

    create_service_file(temp_dir + "/etc/systemd/system", "commented.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should parse correctly despite comments and empty lines
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_commented_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "commented.service") {
            found_commented_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_commented_service);
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithLongLines) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with very long lines (near buffer limits)
    std::string long_value(400, 'a'); // Long value
    std::string service_content = "[Service]\nExecStart=/usr/bin/test\nCapabilityBoundingSet=" + long_value + "\n";

    create_service_file(temp_dir + "/etc/systemd/system", "longline.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle long lines gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithInvalidPath) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with path too long for buffer
    std::string long_filename(300, 'a');
    long_filename += ".service";

    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
)";

    // Try to create file with long name - may fail on filesystem level
    std::ofstream file(temp_dir + "/etc/systemd/system/" + long_filename);
    if (file.is_open()) {
        file << service_content;
        file.close();

        // If file creation succeeded, test that scanner handles it gracefully
        auto context = create_context(true, temp_dir);
        scanner.scan(*context);
        // Should not crash
        auto findings = get_findings_for_scanner(context->report, scanner.name());
        EXPECT_GE(findings.size(), 0);
    } else {
        // File creation failed (expected on some filesystems), just test that scanner doesn't crash
        auto context = create_context(true, temp_dir);
        scanner.scan(*context);
        // Should not crash even without the problematic file
        auto findings = get_findings_for_scanner(context->report, scanner.name());
        EXPECT_GE(findings.size(), 0);
    }
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithEmptyValues) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with empty values
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
CapabilityBoundingSet=
NoNewPrivileges=
)";

    create_service_file(temp_dir + "/etc/systemd/system", "emptyvalues.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should handle empty values appropriately
    bool found_emptyvalues_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "emptyvalues.service") {
            found_emptyvalues_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_emptyvalues_service);
}

TEST_F(SystemdUnitScannerTest, ScanServiceWithWhitespace) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create a service file with extra whitespace
    std::string service_content = R"(
[Service]
  ExecStart  =  /usr/bin/test
NoNewPrivileges   =   yes
   PrivateTmp=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "whitespace.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should trim whitespace and parse correctly
    bool found_whitespace_service = false;
    bool found_good_nonewprivileges = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "whitespace.service") {
            found_whitespace_service = true;
            if (finding.metadata.count("key") && finding.metadata.at("key") == "NoNewPrivileges" &&
                finding.severity == sys_scan::Severity::Info) {
                found_good_nonewprivileges = true;
            }
        }
    }
    EXPECT_TRUE(found_whitespace_service);
    EXPECT_TRUE(found_good_nonewprivileges);
}

TEST_F(SystemdUnitScannerTest, ScanMultipleDirectories) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create services in different directories
    create_service_file(temp_dir + "/etc/systemd/system", "etc-service.service",
                       "[Service]\nExecStart=/usr/bin/etc\nNoNewPrivileges=yes\n");
    create_service_file(temp_dir + "/usr/lib/systemd/system", "usr-service.service",
                       "[Service]\nExecStart=/usr/bin/usr\nPrivateTmp=yes\n");
    create_service_file(temp_dir + "/lib/systemd/system", "lib-service.service",
                       "[Service]\nExecStart=/usr/bin/lib\nProtectSystem=strict\n");

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should find services from all directories
    bool found_etc = false, found_usr = false, found_lib = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit")) {
            const std::string& unit = finding.metadata.at("unit");
            if (unit == "etc-service.service") found_etc = true;
            else if (unit == "usr-service.service") found_usr = true;
            else if (unit == "lib-service.service") found_lib = true;
        }
    }
    EXPECT_TRUE(found_etc);
    EXPECT_TRUE(found_usr);
    EXPECT_TRUE(found_lib);
}

TEST_F(SystemdUnitScannerTest, FindingMetadataContainsExpectedFields) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
NoNewPrivileges=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "metadata.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Check metadata fields
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "metadata.service") {
            EXPECT_TRUE(finding.metadata.count("key"));
            EXPECT_TRUE(finding.metadata.count("expected"));
            EXPECT_TRUE(finding.id.find("systemd:") == 0);
            EXPECT_TRUE(finding.title.find("metadata.service") == 0);
            break;
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}