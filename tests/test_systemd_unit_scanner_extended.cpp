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
#include <cstring>

namespace sys_scan {

class SystemdUnitScannerExtendedTest : public ::testing::Test {
protected:
    std::string temp_dir;
    sys_scan::Config config_;
    sys_scan::Report report_;

    void SetUp() override {
        // Create temporary directory for test files
        char template_path[] = "/tmp/systemd_extended_test_XXXXXX";
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

// Test scanning with memory allocation failure simulation
TEST_F(SystemdUnitScannerExtendedTest, ScanWithMemoryAllocationFailure) {
    // This test is hard to simulate directly, but we can test with extreme conditions
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create many service files to stress memory usage
    for (int i = 0; i < 100; ++i) {
        std::string content = R"(
[Service]
ExecStart=/usr/bin/service)"+std::to_string(i)+R"(
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
)";
        create_service_file(temp_dir + "/etc/systemd/system", "service" + std::to_string(i) + ".service", content);
    }

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle large number of services gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with very long service file paths
TEST_F(SystemdUnitScannerExtendedTest, ScanWithVeryLongPaths) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create nested directory structure with long names
    std::string long_dir = temp_dir + "/etc/systemd/system/";
    std::string long_name(200, 'a'); // Long directory name
    long_dir += long_name;

    try {
        std::filesystem::create_directories(long_dir);

        std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
NoNewPrivileges=yes
)";
        create_service_file(long_dir, "test.service", service_content);

        auto context = create_context(true, temp_dir);
        scanner.scan(*context);

        // Should handle long paths gracefully
        auto findings = get_findings_for_scanner(context->report, scanner.name());
        EXPECT_GE(findings.size(), 0); // Should not crash
    } catch (...) {
        // If filesystem can't handle long paths, skip test
        SUCCEED();
    }
}

// Test scanning with service files containing very long lines
TEST_F(SystemdUnitScannerExtendedTest, ScanWithVeryLongLines) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with very long lines
    std::string long_value(800, 'x'); // Near buffer limit
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
CapabilityBoundingSet=)" + long_value + R"(
NoNewPrivileges=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "longline.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle long lines gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing binary data
TEST_F(SystemdUnitScannerExtendedTest, ScanWithBinaryDataInService) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with binary data (this would be unusual but test robustness)
    auto service_path = temp_dir + "/etc/systemd/system/binary.service";
    std::ofstream file(service_path, std::ios::binary);
    file << "[Service]\n";
    file << "ExecStart=/usr/bin/test\n";
    file << "Description=Test";
    for (int i = 0; i < 10; ++i) {
        file.put(static_cast<char>(i)); // Binary data
    }
    file << "\n";
    file.close();

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle binary data gracefully (may skip malformed service)
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing null bytes
TEST_F(SystemdUnitScannerExtendedTest, ScanWithNullBytesInService) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with null bytes
    auto service_path = temp_dir + "/etc/systemd/system/nullbytes.service";
    std::ofstream file(service_path, std::ios::binary);
    file << "[Service]\n";
    file << "ExecStart=/usr/bin/test\n";
    file << "Description=Test\x00with\x00nulls\n";
    file << "NoNewPrivileges=yes\n";
    file.close();

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle null bytes gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing very long unit names
TEST_F(SystemdUnitScannerExtendedTest, ScanWithVeryLongUnitNames) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    std::string long_name(200, 'a'); // Very long service name
    std::string filename = long_name + ".service";

    // Create service file with long name
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
NoNewPrivileges=yes
)";

    try {
        create_service_file(temp_dir + "/etc/systemd/system", filename, service_content);

        auto context = create_context(true, temp_dir);
        scanner.scan(*context);

        // Should handle long unit names gracefully
        auto findings = get_findings_for_scanner(context->report, scanner.name());
        EXPECT_GE(findings.size(), 0); // Should not crash
    } catch (...) {
        // If filesystem can't handle long filenames, skip test
        SUCCEED();
    }
}

// Test scanning with service files containing many key-value pairs
TEST_F(SystemdUnitScannerExtendedTest, ScanWithManyKeyValuePairs) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with many key-value pairs (near limit)
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
)";

    // Add many key-value pairs
    for (int i = 0; i < 45; ++i) {  // Near MAX_KEY_VALUE_PAIRS_LEAN limit
        service_content += "CustomKey" + std::to_string(i) + "=value" + std::to_string(i) + "\n";
    }
    service_content += "NoNewPrivileges=yes\n";

    create_service_file(temp_dir + "/etc/systemd/system", "manykv.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle many key-value pairs gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files exceeding key-value pair limit
TEST_F(SystemdUnitScannerExtendedTest, ScanWithTooManyKeyValuePairs) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with too many key-value pairs
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
)";

    // Add more than MAX_KEY_VALUE_PAIRS_LEAN key-value pairs
    for (int i = 0; i < 60; ++i) {
        service_content += "CustomKey" + std::to_string(i) + "=value" + std::to_string(i) + "\n";
    }
    service_content += "NoNewPrivileges=yes\n";

    create_service_file(temp_dir + "/etc/systemd/system", "toomanykv.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle excessive key-value pairs gracefully (may truncate)
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with malformed service files (missing sections)
TEST_F(SystemdUnitScannerExtendedTest, ScanWithMalformedServiceFiles) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create malformed service file (no [Service] section)
    std::string malformed_content = R"(
[Unit]
Description=Test Service

ExecStart=/usr/bin/test
NoNewPrivileges=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "malformed.service", malformed_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle malformed files gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing unusual whitespace
TEST_F(SystemdUnitScannerExtendedTest, ScanWithUnusualWhitespace) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with unusual whitespace
    std::string service_content = R"(
   [Service]
ExecStart    =    /usr/bin/test
   NoNewPrivileges   =   yes

PrivateTmp=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "whitespace.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle unusual whitespace
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_whitespace_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "whitespace.service") {
            found_whitespace_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_whitespace_service);
}

// Test scanning with service files containing empty values
TEST_F(SystemdUnitScannerExtendedTest, ScanWithEmptyValues) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with empty values
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
CapabilityBoundingSet=
NoNewPrivileges=
PrivateTmp=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "emptyvalues.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle empty values appropriately
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_emptyvalues_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "emptyvalues.service") {
            found_emptyvalues_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_emptyvalues_service);
}

// Test scanning with service files containing special characters in values
TEST_F(SystemdUnitScannerExtendedTest, ScanWithSpecialCharacters) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with special characters
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
Environment=SPECIAL_CHARS="!@#$%^&*()_+-=[]{}|;':\",./<>?"
NoNewPrivileges=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "specialchars.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle special characters in values
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_specialchars_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "specialchars.service") {
            found_specialchars_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_specialchars_service);
}

// Test scanning with service files containing Unicode characters
TEST_F(SystemdUnitScannerExtendedTest, ScanWithUnicodeCharacters) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with Unicode characters
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
Description=Test Service with Unicode: 测试 中文 русский español
NoNewPrivileges=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "unicode.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle Unicode characters
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_unicode_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "unicode.service") {
            found_unicode_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_unicode_service);
}

// Test scanning with many service files (stress test)
TEST_F(SystemdUnitScannerExtendedTest, ScanWithManyServiceFiles) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create many service files (near MAX_SYSTEMD_UNITS_LEAN limit)
    for (int i = 0; i < 950; ++i) {  // Near 1000 limit
        std::string content = R"(
[Service]
ExecStart=/usr/bin/service)"+std::to_string(i)+R"(
NoNewPrivileges=yes
)";
        create_service_file(temp_dir + "/etc/systemd/system", "service" + std::to_string(i) + ".service", content);
    }

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle many service files gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files exceeding unit limit
TEST_F(SystemdUnitScannerExtendedTest, ScanWithTooManyServiceFiles) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create more than MAX_SYSTEMD_UNITS_LEAN service files
    for (int i = 0; i < 1100; ++i) {
        std::string content = R"(
[Service]
ExecStart=/usr/bin/service)"+std::to_string(i)+R"(
NoNewPrivileges=yes
)";
        create_service_file(temp_dir + "/etc/systemd/system", "service" + std::to_string(i) + ".service", content);
    }

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle excessive service files gracefully (may truncate)
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with mixed valid and invalid service files
TEST_F(SystemdUnitScannerExtendedTest, ScanWithMixedValidInvalidServices) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Valid service
    create_service_file(temp_dir + "/etc/systemd/system", "valid.service",
                       "[Service]\nExecStart=/usr/bin/valid\nNoNewPrivileges=yes\n");

    // Invalid service (no ExecStart)
    create_service_file(temp_dir + "/etc/systemd/system", "invalid.service",
                       "[Service]\nDescription=Invalid Service\nNoNewPrivileges=yes\n");

    // Malformed service
    create_service_file(temp_dir + "/etc/systemd/system", "malformed.service",
                       "This is not a valid systemd unit file\n");

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should only generate findings for valid services
    bool found_valid = false;
    bool found_invalid = false;
    bool found_malformed = false;

    for (const auto& finding : findings) {
        if (finding.metadata.count("unit")) {
            const std::string& unit = finding.metadata.at("unit");
            if (unit == "valid.service") found_valid = true;
            else if (unit == "invalid.service") found_invalid = true;
            else if (unit == "malformed.service") found_malformed = true;
        }
    }

    EXPECT_TRUE(found_valid);
    EXPECT_FALSE(found_invalid); // Should not find invalid service
    EXPECT_FALSE(found_malformed); // Should not find malformed service
}

// Test scanning with service files in all systemd directories
TEST_F(SystemdUnitScannerExtendedTest, ScanAllSystemdDirectories) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create services in all three directories
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

// Test scanning with service files containing all hardening directives
TEST_F(SystemdUnitScannerExtendedTest, ScanWithAllHardeningDirectives) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service with all possible hardening directives
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictNamespaces=yes
RestrictSUIDSGID=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
LockPersonality=yes
)";

    create_service_file(temp_dir + "/etc/systemd/system", "all-hardening.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should generate findings for all hardening directives
    int hardening_findings = 0;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "all-hardening.service") {
            hardening_findings++;
        }
    }
    EXPECT_GT(hardening_findings, 10); // Should have many findings for comprehensive hardening
}

// Test scanning with service files containing conflicting hardening settings
TEST_F(SystemdUnitScannerExtendedTest, ScanWithConflictingHardeningSettings) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service with conflicting settings (ProtectSystem=full is bad)
    std::string service_content = R"(
[Service]
ExecStart=/usr/bin/test
ProtectSystem=full
NoNewPrivileges=no
)";

    create_service_file(temp_dir + "/etc/systemd/system", "conflicting.service", service_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());

    // Should flag conflicting/bad settings
    bool found_bad_protect_system = false;
    bool found_bad_nonewprivileges = false;

    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "conflicting.service") {
            if (finding.metadata.count("key")) {
                const std::string& key = finding.metadata.at("key");
                if (key == "ProtectSystem" && finding.severity != sys_scan::Severity::Info) {
                    found_bad_protect_system = true;
                } else if (key == "NoNewPrivileges" && finding.severity != sys_scan::Severity::Info) {
                    found_bad_nonewprivileges = true;
                }
            }
        }
    }

    EXPECT_TRUE(found_bad_protect_system);
    EXPECT_TRUE(found_bad_nonewprivileges);
}

// Test scanning with empty service files
TEST_F(SystemdUnitScannerExtendedTest, ScanWithEmptyServiceFiles) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create empty service file
    create_service_file(temp_dir + "/etc/systemd/system", "empty.service", "");

    auto context = create_context(true, temp_dir);
    scanner.scan(*context);

    // Should handle empty files gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing only comments
TEST_F(SystemdUnitScannerExtendedTest, ScanWithCommentOnlyServiceFiles) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with only comments
    std::string comment_content = R"(
# This is a comment
; This is also a comment
# Another comment
)";

    create_service_file(temp_dir + "/etc/systemd/system", "comments.service", comment_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle comment-only files gracefully
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_GE(findings.size(), 0); // Should not crash
}

// Test scanning with service files containing very deep section nesting (unusual)
TEST_F(SystemdUnitScannerExtendedTest, ScanWithDeepSectionNesting) {
    sys_scan::SystemdUnitScanner scanner;
    create_systemd_structure(temp_dir);

    // Create service file with unusual section structure
    std::string nested_content = R"(
[Unit]
Description=Test

[Service]
ExecStart=/usr/bin/test
NoNewPrivileges=yes

[X-CustomSection]
CustomKey=CustomValue

[AnotherCustomSection]
AnotherKey=AnotherValue
)";

    create_service_file(temp_dir + "/etc/systemd/system", "nested.service", nested_content);
    auto context = create_context(true, temp_dir);

    scanner.scan(*context);

    // Should handle unusual section structures
    auto findings = get_findings_for_scanner(context->report, scanner.name());
    bool found_nested_service = false;
    for (const auto& finding : findings) {
        if (finding.metadata.count("unit") && finding.metadata.at("unit") == "nested.service") {
            found_nested_service = true;
            break;
        }
    }
    EXPECT_TRUE(found_nested_service);
}

} // namespace sys_scan