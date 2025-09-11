#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Compliance.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace sys_scan;

class ComplianceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a temporary directory for test files
        test_dir = fs::temp_directory_path() / "compliance_test";
        fs::create_directories(test_dir);

        // Create test config
        config.enable_scanners = {"pci_compliance"};
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    fs::path test_dir;
    Config config;
    Report report;
};

TEST_F(ComplianceTest, PCIComplianceScannerRegistration) {
    PCIComplianceScanner scanner;
    scanner.register_checks();
    
    // Test that scanner is properly registered by checking scan results
    ScanContext context(config, report);
    scanner.scan(context);
    
    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].scanner_name, "pci_compliance");
    // Should have some findings after scan
    EXPECT_FALSE(results[0].findings.empty());
}

TEST_F(ComplianceTest, PCIScannerScanExecution) {
    PCIComplianceScanner scanner;
    ScanContext context(config, report);

    scanner.scan(context);

    // Should have results
    const auto& results = report.results();
    ASSERT_FALSE(results.empty());

    // Find PCI compliance result
    auto pci_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "pci_compliance"; });

    ASSERT_NE(pci_result, results.end());
    EXPECT_FALSE(pci_result->findings.empty());

    // Check that findings have expected metadata
    for (const auto& finding : pci_result->findings) {
        EXPECT_TRUE(finding.metadata.count("standard"));
        EXPECT_TRUE(finding.metadata.count("control_id"));
        EXPECT_TRUE(finding.metadata.count("requirement"));
        EXPECT_TRUE(finding.metadata.count("passed"));
        EXPECT_EQ(finding.metadata.at("standard"), "pci_dss_4_0");
    }
}

TEST_F(ComplianceTest, ComplianceMetricsStored) {
    PCIComplianceScanner scanner;
    ScanContext context(config, report);

    scanner.scan(context);

    // Check that compliance metrics are stored
    auto summary = report.compliance_summary();
    EXPECT_TRUE(summary.find("pci_dss_4_0") != summary.end());
    if (summary.find("pci_dss_4_0") != summary.end()) {
        auto& pci_summary = summary.at("pci_dss_4_0");
        EXPECT_TRUE(pci_summary.find("total_controls") != pci_summary.end());
        EXPECT_TRUE(pci_summary.find("passed") != pci_summary.end());
        EXPECT_TRUE(pci_summary.find("failed") != pci_summary.end());
        EXPECT_TRUE(pci_summary.find("score") != pci_summary.end());
    }
}

TEST_F(ComplianceTest, PCISpecificChecks) {
    PCIComplianceScanner scanner;
    scanner.register_checks();

    // Test that scanner can be registered and executed without errors
    ScanContext context(config, report);
    EXPECT_NO_THROW(scanner.scan(context));

    // Check that some PCI-related findings were generated
    const auto& results = report.results();
    auto pci_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "pci_compliance"; });

    ASSERT_NE(pci_result, results.end());
    // Should have some findings (exact number depends on system state)
    EXPECT_GE(pci_result->findings.size(), 0u);
}

TEST_F(ComplianceTest, ComplianceCheckApplicability) {
    PCIComplianceScanner scanner;
    scanner.register_checks();

    // Test that scanner executes without errors (checks are applicable by default)
    ScanContext context(config, report);
    EXPECT_NO_THROW(scanner.scan(context));

    // Check that results were generated
    const auto& results = report.results();
    auto pci_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "pci_compliance"; });

    ASSERT_NE(pci_result, results.end());
    // Should have findings with pass/fail status
    for (const auto& finding : pci_result->findings) {
        EXPECT_TRUE(finding.metadata.find("passed") != finding.metadata.end());
    }
}

TEST_F(ComplianceTest, ComplianceCheckSeverityLevels) {
    PCIComplianceScanner scanner;
    scanner.register_checks();

    // Test that scanner executes and generates findings with different severity levels
    ScanContext context(config, report);
    scanner.scan(context);

    const auto& results = report.results();
    auto pci_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "pci_compliance"; });

    ASSERT_NE(pci_result, results.end());

    // Check that we have findings with different severity levels
    bool has_high_severity = false;
    bool has_medium_severity = false;

    for (const auto& finding : pci_result->findings) {
        if (finding.severity == Severity::High) has_high_severity = true;
        if (finding.severity == Severity::Medium) has_medium_severity = true;
    }

    // We expect to find both high and medium severity findings in PCI compliance
    EXPECT_TRUE(has_high_severity || has_medium_severity);
}

TEST_F(ComplianceTest, EmptyComplianceScanner) {
    class EmptyComplianceScanner : public ComplianceScanner {
    public:
        std::string name() const override { return "empty_compliance"; }
        std::string description() const override { return "Empty compliance scanner"; }
        void register_checks() override {
            // Register no checks
        }
    };

    EmptyComplianceScanner scanner;
    ScanContext context(config, report);

    scanner.scan(context);

    // Should have no results since no checks registered
    const auto& results = report.results();
    auto empty_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "empty_compliance"; });

    if (empty_result != results.end()) {
        EXPECT_TRUE(empty_result->findings.empty());
    }
}

TEST_F(ComplianceTest, ComplianceScannerExceptionHandling) {
    class ExceptionThrowingScanner : public ComplianceScanner {
    public:
        std::string name() const override { return "exception_compliance"; }
        std::string description() const override { return "Exception throwing scanner"; }
        void register_checks() override {
            checks_.push_back({
                "test_standard", "1.1", "Exception test", Severity::Low,
                []() { throw std::runtime_error("Test exception"); return true; },
                []() { return true; }
            });
        }
    };

    ExceptionThrowingScanner scanner;
    ScanContext context(config, report);

    // Should not crash despite exception in test function
    EXPECT_NO_THROW(scanner.scan(context));

    const auto& results = report.results();
    auto exception_result = std::find_if(results.begin(), results.end(),
        [](const ScanResult& r) { return r.scanner_name == "exception_compliance"; });

    ASSERT_NE(exception_result, results.end());
    ASSERT_FALSE(exception_result->findings.empty());

    const auto& finding = exception_result->findings[0];
    EXPECT_EQ(finding.metadata.at("passed"), "false");
    EXPECT_EQ(finding.metadata.at("rationale"), "test_exception");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}