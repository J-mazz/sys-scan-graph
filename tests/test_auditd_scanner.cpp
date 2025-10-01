#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <string>
#include "../src/scanners/AuditdScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"

namespace fs = std::filesystem;

class AuditdScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory structure
        test_dir = std::filesystem::temp_directory_path() / "auditd_test";
        std::filesystem::create_directories(test_dir);

        // Create audit rules directory
        audit_rules_dir = test_dir / "etc" / "audit" / "rules.d";
        std::filesystem::create_directories(audit_rules_dir);

        // Create main audit rules file
        audit_rules_file = audit_rules_dir / "audit.rules";
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    fs::path test_dir;
    fs::path audit_rules_dir;
    fs::path audit_rules_file;

    // Helper to create test audit rules file
    void createAuditRules(const std::string& content, const std::string& filename = "audit.rules") {
        std::ofstream file(audit_rules_dir / filename);
        file << content;
    }

    // Helper to create rules.d file
    void createRulesDFile(const std::string& content, const std::string& filename = "test.rules") {
        std::ofstream file(audit_rules_dir / filename);
        file << content;
    }

    // Helper to run scanner and get findings
    std::vector<sys_scan::Finding> runScanner(bool hardening_enabled = true) {
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

// Test scanner disabled when hardening is false
TEST_F(AuditdScannerTest, ScanDisabledWhenHardeningDisabled) {
    createAuditRules("-S execve -k execve");

    auto findings = runScanner(false);

    EXPECT_TRUE(findings.empty());
}

// Test missing audit rules files
TEST_F(AuditdScannerTest, ScanWithMissingAuditFiles) {
    // Don't create any files
    auto findings = runScanner();

    ASSERT_EQ(findings.size(), 1);
    EXPECT_EQ(findings[0].id, "auditd:rules:missing");
    EXPECT_EQ(findings[0].severity, sys_scan::Severity::Medium);
    EXPECT_THAT(findings[0].title, ::testing::HasSubstr("No auditd rules detected"));
}

// Test empty audit rules
TEST_F(AuditdScannerTest, ScanWithEmptyAuditRules) {
    createAuditRules("");

    auto findings = runScanner();

    // Should find all patterns missing
    EXPECT_GE(findings.size(), 7); // At least the basic patterns

    // Check that execve is marked as absent with high severity
    auto execve_absent = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve:absent"; });
    ASSERT_NE(execve_absent, findings.end());
    EXPECT_EQ(execve_absent->severity, sys_scan::Severity::High);
}

// Test complete audit rules with all security patterns
TEST_F(AuditdScannerTest, ScanWithCompleteAuditRules) {
    std::string rules = R"(
# Execve auditing
-S execve -k execve

# Privilege escalation
-S setuid -k setuid
-S setgid -k setgid

# File permission changes
-S chmod -k chmod
-S chown -k chown

# Capability changes
-S capset -k capset

# Module loading
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
)";

    createAuditRules(rules);

    auto findings = runScanner();

    // Should have findings for all patterns present
    EXPECT_GE(findings.size(), 7);

    // Check that execve is present (info level)
    auto execve = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve"; });
    ASSERT_NE(execve, findings.end());
    EXPECT_EQ(execve->severity, sys_scan::Severity::Info);
    EXPECT_THAT(execve->title, ::testing::HasSubstr("present"));
}

// Test rules.d directory scanning
TEST_F(AuditdScannerTest, ScanWithRulesDDirectory) {
    // Create main audit.rules
    createAuditRules("-S execve -k execve");

    // Create rules.d files
    createRulesDFile("-S setuid -k setuid", "privileges.rules");
    createRulesDFile("-S chmod -k chmod", "file_ops.rules");

    auto findings = runScanner();

    // Should find execve, setuid, and chmod present
    auto execve = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve"; });
    auto setuid = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:setuid"; });
    auto chmod = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:chmod"; });

    ASSERT_NE(execve, findings.end());
    ASSERT_NE(setuid, findings.end());
    ASSERT_NE(chmod, findings.end());

    EXPECT_EQ(execve->severity, sys_scan::Severity::Info);
    EXPECT_EQ(setuid->severity, sys_scan::Severity::Info);
    EXPECT_EQ(chmod->severity, sys_scan::Severity::Info);
}

// Test missing critical execve rule
TEST_F(AuditdScannerTest, ScanMissingExecveRule) {
    std::string rules = R"(
-S setuid -k setuid
-S chmod -k chmod
-S chown -k chown
)";

    createAuditRules(rules);

    auto findings = runScanner();

    // Should have execve absent finding with high severity
    auto execve_absent = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve:absent"; });
    ASSERT_NE(execve_absent, findings.end());
    EXPECT_EQ(execve_absent->severity, sys_scan::Severity::High);
    EXPECT_THAT(execve_absent->title, ::testing::HasSubstr("Execve auditing missing"));
}

// Test module loading patterns
TEST_F(AuditdScannerTest, ScanWithModuleLoadingRules) {
    std::string rules = R"(
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
)";

    createAuditRules(rules);

    auto findings = runScanner();

    auto modules = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:insmod"; });
    ASSERT_NE(modules, findings.end());
    EXPECT_EQ(modules->severity, sys_scan::Severity::Info);
    EXPECT_THAT(modules->title, ::testing::HasSubstr("Module load auditing"));
}

// Test case insensitive regex matching
TEST_F(AuditdScannerTest, ScanCaseInsensitiveMatching) {
    std::string rules = R"(
-s execve -k EXECVE
-S SETUID -k setuid
)";

    createAuditRules(rules);

    auto findings = runScanner();

    auto execve = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve"; });
    auto setuid = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:setuid"; });

    ASSERT_NE(execve, findings.end());
    ASSERT_NE(setuid, findings.end());
    EXPECT_EQ(execve->severity, sys_scan::Severity::Info);
    EXPECT_EQ(setuid->severity, sys_scan::Severity::Info);
}

// Test malformed rules don't crash scanner
TEST_F(AuditdScannerTest, ScanWithMalformedRules) {
    std::string rules = R"(
# Valid rule
-S execve -k execve

# Malformed rules that might cause regex issues
[invalid section
-w /path -p invalid
-S
-k
)";

    createAuditRules(rules);

    // Should not crash and should still find valid patterns
    auto findings = runScanner();

    auto execve = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve"; });
    ASSERT_NE(execve, findings.end());
    EXPECT_EQ(execve->severity, sys_scan::Severity::Info);
}

// Test multiple rules files combination
TEST_F(AuditdScannerTest, ScanMultipleRulesFiles) {
    // Main audit.rules
    createAuditRules("-S execve -k execve");

    // Rules.d files
    createRulesDFile("-S setuid -k setuid", "10-privileges.rules");
    createRulesDFile("-S chmod -k chmod", "20-fileops.rules");
    createRulesDFile("# Comment only", "30-comments.rules");

    auto findings = runScanner();

    // Should find execve, setuid, and chmod
    auto execve = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:execve"; });
    auto setuid = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:setuid"; });
    auto chmod = std::find_if(findings.begin(), findings.end(),
        [](const sys_scan::Finding& f) { return f.id == "auditd:chmod"; });

    ASSERT_NE(execve, findings.end());
    ASSERT_NE(setuid, findings.end());
    ASSERT_NE(chmod, findings.end());
}