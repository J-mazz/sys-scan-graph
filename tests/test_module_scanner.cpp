#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/ModuleScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include <filesystem>
#include <fstream>
#include <unistd.h>

// Test fixture for ModuleScanner
class ModuleScannerTest : public ::testing::Test {
protected:
    std::string temp_dir;
    sys_scan::Config config_;
    sys_scan::Report report_;

    void SetUp() override {
        // Create temporary directory for test files
        char template_path[] = "/tmp/module_test_XXXXXX";
        temp_dir = mkdtemp(template_path);
        ASSERT_FALSE(temp_dir.empty()) << "Failed to create temp directory";
        std::cout << "Created temp dir: " << temp_dir << std::endl;

        // Set up default config
        config_.hardening = true;
        config_.test_root = temp_dir;
    }

    void TearDown() override {
        // Clean up temporary directory
        if (!temp_dir.empty()) {
            std::filesystem::remove_all(temp_dir);
        }
    }

    // Helper to create a test context
    std::unique_ptr<sys_scan::ScanContext> create_context() {
        return std::make_unique<sys_scan::ScanContext>(config_, report_);
    }

    // Helper to create test kernel module files
    void create_test_kernel_files(const std::string& kernel_release) {
        std::string lib_modules_dir = temp_dir + "/lib/modules/" + kernel_release;
        std::filesystem::create_directories(lib_modules_dir + "/kernel/drivers");

        // Create modules.dep
        std::ofstream dep_file(lib_modules_dir + "/modules.dep");
        dep_file << "kernel/drivers/test.ko:\n";
        dep_file << "kernel/drivers/test2.ko: kernel/drivers/test.ko\n";
        dep_file.close();

        // Create modules.builtin
        std::ofstream builtin_file(lib_modules_dir + "/modules.builtin");
        builtin_file << "kernel/builtin/test.ko\n";
        builtin_file.close();

        // Create the actual .ko files to avoid missing file anomalies
        std::ofstream test_ko(lib_modules_dir + "/kernel/drivers/test.ko");
        test_ko << "dummy kernel module content";
        test_ko.close();

        std::ofstream test2_ko(lib_modules_dir + "/kernel/drivers/test2.ko");
        test2_ko << "dummy kernel module content";
        test2_ko.close();

        // Create /proc/modules
        std::string proc_dir = temp_dir + "/proc";
        std::filesystem::create_directories(proc_dir);
        std::ofstream proc_file(proc_dir + "/modules");
        proc_file << "test 16384 1 - Live 0x0000000000000000\n";
        proc_file << "test2 8192 0 - Live 0x0000000000000000\n";
        proc_file.close();

        // Create /sys/module
        std::string sys_dir = temp_dir + "/sys/module";
        std::filesystem::create_directories(sys_dir + "/test");
        std::filesystem::create_directories(sys_dir + "/test2");

        // Create /proc/sys/kernel/tainted
        std::string sys_kernel_dir = temp_dir + "/proc/sys/kernel";
        std::filesystem::create_directories(sys_kernel_dir);
        std::ofstream tainted_file(sys_kernel_dir + "/tainted");
        tainted_file << "0\n";
        tainted_file.close();

        // Create /proc/kallsyms
        std::ofstream kallsyms_file(proc_dir + "/kallsyms");
        kallsyms_file << "0000000000000000 t test_function\n";
        kallsyms_file << "0000000000000000 T test_symbol\n";
        kallsyms_file.close();
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
TEST_F(ModuleScannerTest, ScannerProperties) {
    sys_scan::ModuleScanner scanner;
    EXPECT_EQ(scanner.name(), "modules");
    EXPECT_EQ(scanner.description(), "List loaded kernel modules");
}

// Test simple mode (default when no special config is set)
TEST_F(ModuleScannerTest, ScanSimpleMode) {
    config_.modules_summary_only = false;
    config_.modules_anomalies_only = false;

    create_test_kernel_files("5.15.0-test");

    auto context = create_context();
    sys_scan::ModuleScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 2); // Should find test and test2 modules

    const auto* test_finding = find_finding_by_id(findings, "test");
    ASSERT_NE(test_finding, nullptr);
    EXPECT_EQ(test_finding->title, "Module test");
    EXPECT_EQ(test_finding->severity, sys_scan::Severity::Info);

    const auto* test2_finding = find_finding_by_id(findings, "test2");
    ASSERT_NE(test2_finding, nullptr);
    EXPECT_EQ(test2_finding->title, "Module test2");
    EXPECT_EQ(test2_finding->severity, sys_scan::Severity::Info);
}

// Test summary mode
TEST_F(ModuleScannerTest, ScanSummaryMode) {
    config_.modules_summary_only = true;
    config_.modules_anomalies_only = false;

    create_test_kernel_files("5.15.0-test");

    auto context = create_context();
    sys_scan::ModuleScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1); // Should have one summary finding

    const auto* summary_finding = find_finding_by_id(findings, "module_summary");
    ASSERT_NE(summary_finding, nullptr);
    EXPECT_EQ(summary_finding->title, "Kernel Module Summary");
    EXPECT_EQ(summary_finding->metadata.at("total"), "2");
    EXPECT_EQ(summary_finding->metadata.at("sample_count"), "2");
}

// Test anomalies-only mode
TEST_F(ModuleScannerTest, ScanAnomaliesOnlyMode) {
    config_.modules_summary_only = false;
    config_.modules_anomalies_only = true;

    create_test_kernel_files("5.15.0-test");

    auto context = create_context();
    sys_scan::ModuleScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    // Should have findings for anomalies, but our test modules are normal
    // so we expect 0 findings (no anomalies detected)
    EXPECT_TRUE(findings.empty());
}

// Test with missing /proc/modules
TEST_F(ModuleScannerTest, ScanWithMissingProcModules) {
    config_.modules_summary_only = true;

    // Don't create any test files

    auto context = create_context();
    sys_scan::ModuleScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    EXPECT_TRUE(findings.empty()); // Should handle missing files gracefully
}

// Test with empty /proc/modules
TEST_F(ModuleScannerTest, ScanWithEmptyProcModules) {
    config_.modules_summary_only = true;

    std::string proc_dir = temp_dir + "/proc";
    std::filesystem::create_directories(proc_dir);
    std::ofstream proc_file(proc_dir + "/modules");
    proc_file.close(); // Empty file

    auto context = create_context();
    sys_scan::ModuleScanner scanner;

    scanner.scan(*context);

    auto findings = get_findings_for_scanner(context->report, scanner.name());
    ASSERT_EQ(findings.size(), 1); // Should have summary with 0 modules

    const auto* summary_finding = find_finding_by_id(findings, "module_summary");
    ASSERT_NE(summary_finding, nullptr);
    EXPECT_EQ(summary_finding->metadata.at("total"), "0");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}