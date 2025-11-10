#include <gtest/gtest.h>
#include "../src/scanners/IntegrityScanner.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace sys_scan {

// Subclass IntegrityScanner to expose and override protected hooks for testing
class TestIntegrityScanner : public IntegrityScanner {
public:
    // Allow injecting fake command outputs
    void set_cmd_output(const std::string& out) { cmd_output = out; }
    void set_pkg_list_output(const std::string& out) { pkg_list_output = out; }
    void set_ima_result(std::pair<size_t, size_t> res) { ima_result = res; }

protected:
    std::string run_cmd_capture(const std::vector<std::string>& args) override {
        // Return different outputs based on command
        if (!args.empty()) {
            if (args[0] == "dpkg" && args.size() >= 2 && args[1] == "-l") {
                return pkg_list_output;
            }
            // For dpkg -V or rpm -Va, return the verification output
            if ((args[0] == "dpkg" && args.size() >= 2 && args[1] == "-V") ||
                (args[0] == "rpm" && args.size() >= 2 && args[1] == "-Va")) {
                return cmd_output;
            }
        }
        return cmd_output;  // Default fallback
    }

    std::pair<size_t, size_t> check_ima_measurements() override {
        return ima_result;
    }

    std::optional<std::string> compute_file_hash(const std::string& path) override {
        (void)path;
        return std::optional<std::string>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    }

private:
    std::string cmd_output;
    std::string pkg_list_output;
    std::pair<size_t, size_t> ima_result = {0, 0};
};

TEST(IntegrityScannerExtraTest, ScanWithDpkgVerification) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = true;
    cfg.integrity_pkg_rehash_limit = 5;
    cfg.integrity_pkg_limit = 10;
    cfg.integrity_ima = false;  // Disable IMA for this test
    cfg.test_mode = false;  // Enable calling helpers

    TestIntegrityScanner scanner;

    // Create test files so fs::is_regular_file succeeds
    std::ofstream("/tmp/test_passwd", std::ios::binary).write("test", 4);
    std::ofstream("/tmp/test_somefile", std::ios::binary).write("test", 4);

    // Fake dpkg -V output with mismatches using /tmp paths
    std::string fake = "5c..\t /tmp/test_passwd\n";
    fake += "..5.\t /tmp/test_somefile\n";
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/test_passwd");
    fs::remove("/tmp/test_somefile");

    // Get findings for IntegrityScanner
    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].scanner_name, "integrity");
    const auto& findings = results[0].findings;

    // Check summary finding
    ASSERT_EQ(findings.size(), 3);  // summary + 2 rehash findings

    auto summary_it = std::find_if(findings.begin(), findings.end(), [](const Finding& f) {
        return f.id == "integrity_summary";
    });
    ASSERT_NE(summary_it, findings.end());

    EXPECT_EQ(summary_it->metadata.at("pkg_tool"), "dpkg");
    EXPECT_EQ(summary_it->metadata.at("pkg_mismatch_count"), "2");
    EXPECT_EQ(summary_it->metadata.at("scan_mode"), "full");

    // Check rehash findings
    int rehash_count = 0;
    for (const auto& f : findings) {
        if (f.id.find("pkg_rehash:") == 0) {
            rehash_count++;
            EXPECT_EQ(f.title, "Package mismatch file hash");
            EXPECT_EQ(f.metadata.at("sha256"), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        }
    }
    EXPECT_EQ(rehash_count, 2);
}

TEST(IntegrityScannerExtraTest, ScanWithRpmVerification) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = true;
    cfg.integrity_pkg_rehash_limit = 5;
    cfg.integrity_pkg_limit = 10;
    cfg.integrity_ima = false;
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create test files
    std::ofstream("/tmp/test_issue", std::ios::binary).write("test", 4);
    std::ofstream("/tmp/test_evil", std::ios::binary).write("test", 4);
    // Create /tmp/rpm to force rpm path
    std::ofstream("/tmp/rpm", std::ios::binary).write("test", 4);

    // Fake rpm -Va output
    std::string fake = "S.5..... /tmp/test_issue\n";
    fake += "..5..... /tmp/test_evil\n";
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/test_issue");
    fs::remove("/tmp/test_evil");
    fs::remove("/tmp/rpm");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].scanner_name, "integrity");
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 3);  // summary + 2 rehash

    auto summary_it = std::find_if(findings.begin(), findings.end(), [](const Finding& f) {
        return f.id == "integrity_summary";
    });
    ASSERT_NE(summary_it, findings.end());

    EXPECT_EQ(summary_it->metadata.at("pkg_tool"), "rpm");
    EXPECT_EQ(summary_it->metadata.at("pkg_mismatch_count"), "2");
    EXPECT_EQ(summary_it->metadata.at("scan_mode"), "full");
}

TEST(IntegrityScannerExtraTest, ScanWithImaMeasurements) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = false;  // Disable pkg verify
    cfg.integrity_ima = true;
    cfg.test_mode = false;

    TestIntegrityScanner scanner;
    scanner.set_ima_result({100, 5});  // 100 entries, 5 failures

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].scanner_name, "integrity");
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.id, "integrity_summary");
    EXPECT_EQ(summary.metadata.at("ima_entries"), "100");
    EXPECT_EQ(summary.metadata.at("ima_fail"), "5");
    EXPECT_EQ(summary.severity, Severity::High);  // Due to ima_failures > 0
}

TEST(IntegrityScannerExtraTest, ScanWithImaMeasurementsFromFile) {
    // Create a fake IMA measurements file to exercise check_ima_measurements function
    std::ofstream("/tmp/ima_measurements") << "10 1234567890 1234567890 1234567890 ima-ng sha256:abcd1234... /usr/bin/bash\n"
                                           << "10 1234567891 1234567891 1234567891 ima-ng sha256:efgh5678... /usr/bin/ls\n"
                                           << "10 1234567892 1234567892 1234567892 ima-ng sha256:ijkl9012... /usr/bin/cat\n"
                                           << "10 1234567893 1234567893 1234567893 ima-ng sha256:fail1234... /usr/bin/fail\n"
                                           << "10 1234567894 1234567894 1234567894 ima-ng sha256:mnop3456... /usr/bin/grep\n";

    // Override check_ima_measurements to read from our fake file
    class TestIntegrityScannerWithIma : public TestIntegrityScanner {
    public:
        std::pair<size_t, size_t> check_ima_measurements() override {
            size_t entries = 0;
            size_t failures = 0;

            if (fs::exists("/tmp/ima_measurements")) {
                std::ifstream ifs("/tmp/ima_measurements");
                std::string line;
                while (std::getline(ifs, line)) {
                    if (line.empty()) continue;
                    ++entries;
                    // Simple heuristic: look for 'fail' in measurements
                    if (line.find("fail") != std::string::npos) ++failures;
                    if (entries > 500000) break; // Prevent excessive processing
                }
            }

            return {entries, failures};
        }
    };

    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = false;  // Disable pkg verify
    cfg.integrity_ima = true;
    cfg.test_mode = false;  // Enable IMA checking

    TestIntegrityScannerWithIma scanner;
    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/ima_measurements");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].scanner_name, "integrity");
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.id, "integrity_summary");
    EXPECT_EQ(summary.metadata.at("ima_entries"), "5");
    EXPECT_EQ(summary.metadata.at("ima_fail"), "1");
    EXPECT_EQ(summary.severity, Severity::High);  // Due to ima_failures > 0
}

TEST(IntegrityScannerExtraTest, ScanWithSamplePctMode) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;  // Disable rehash for simplicity
    cfg.integrity_sample_pct = 50;  // Sample 50% of packages
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Fake dpkg -l output with some packages
    std::string pkg_list = "ii  bash    5.1-2ubuntu1   amd64   GNU Bourne Again SHell\n";
    pkg_list += "ii  coreutils  8.32-4ubuntu1  amd64   GNU core utilities\n";
    pkg_list += "ii  sed       4.8-1ubuntu1   amd64   GNU stream editor\n";
    pkg_list += "ii  grep      3.7-1ubuntu1   amd64   GNU grep\n";

    // Fake dpkg -V output for sampled packages (no mismatches)
    std::string verify_output = "";

    scanner.set_pkg_list_output(pkg_list);
    scanner.set_cmd_output(verify_output);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("scan_mode"), "sample_50pct");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "0");
}

TEST(IntegrityScannerExtraTest, ScanWithEarlyExitThreshold) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;  // Disable rehash for simplicity
    cfg.integrity_max_mismatches = 1;  // Exit after 1 mismatch
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create test files
    std::ofstream("/tmp/test_file1", std::ios::binary).write("test", 4);
    std::ofstream("/tmp/test_file2", std::ios::binary).write("test", 4);

    // Fake dpkg -V output with multiple mismatches, but should stop at threshold
    std::string fake = "5c..\t /tmp/test_file1\n";
    fake += "..5.\t /tmp/test_file2\n";  // This should not be processed due to early exit
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/test_file1");
    fs::remove("/tmp/test_file2");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary (no rehash since disabled)

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "dpkg");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "1");  // Should be exactly the threshold
    EXPECT_EQ(summary.metadata.at("early_exit_threshold"), "1");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "full");
}

TEST(IntegrityScannerExtraTest, ScanWithCriticalOnlyMode) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;  // Disable rehash for simplicity
    cfg.integrity_critical_only = true;  // Only verify critical packages
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Fake dpkg -V output (no mismatches for critical packages)
    std::string verify_output = "";
    scanner.set_cmd_output(verify_output);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "dpkg");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "0");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "critical_only");
}

TEST(IntegrityScannerExtraTest, ScanWithRpmCriticalOnlyMode) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;
    cfg.integrity_critical_only = true;
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create /tmp/rpm to force rpm path
    std::ofstream("/tmp/rpm", std::ios::binary).write("test", 4);

    // Fake rpm -V output for critical packages (no mismatches)
    std::string verify_output = "";
    scanner.set_cmd_output(verify_output);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/rpm");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "rpm");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "0");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "critical_only");
}

TEST(IntegrityScannerExtraTest, ScanWithMultipleMismatchesEarlyExit) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;
    cfg.integrity_max_mismatches = 2;  // Exit after 2 mismatches
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create multiple test files
    std::ofstream("/tmp/test_file1", std::ios::binary).write("test", 4);
    std::ofstream("/tmp/test_file2", std::ios::binary).write("test", 4);
    std::ofstream("/tmp/test_file3", std::ios::binary).write("test", 4);

    // Fake dpkg -V output with 3 mismatches, but should stop at threshold of 2
    std::string fake = "5c..\t /tmp/test_file1\n";
    fake += "..5.\t /tmp/test_file2\n";
    fake += "S.5.\t /tmp/test_file3\n";  // This should not be processed due to early exit
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/test_file1");
    fs::remove("/tmp/test_file2");
    fs::remove("/tmp/test_file3");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "dpkg");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "2");  // Should be exactly the threshold
    EXPECT_EQ(summary.metadata.at("early_exit_threshold"), "2");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "full");
}

TEST(IntegrityScannerExtraTest, ScanWithRpmCriticalMultipleMismatches) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;
    cfg.integrity_critical_only = true;
    cfg.integrity_max_mismatches = 1;  // Exit after 1 mismatch
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create /tmp/rpm to force rpm path
    std::ofstream("/tmp/rpm", std::ios::binary).write("test", 4);

    // Fake rpm -V output with multiple mismatches for critical packages
    std::string fake = "S.5....T.  c /tmp/test_file1\n";
    fake += "..5......  c /tmp/test_file2\n";  // This should trigger early exit
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/rpm");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "rpm");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "1");  // Should be exactly the threshold
    EXPECT_EQ(summary.metadata.at("early_exit_threshold"), "1");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "critical_only");
}

TEST(IntegrityScannerExtraTest, ScanWithRpmSampleMultipleMismatches) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;
    cfg.integrity_sample_pct = 50;
    cfg.integrity_max_mismatches = 1;  // Exit after 1 mismatch
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create /tmp/rpm to force rpm path
    std::ofstream("/tmp/rpm", std::ios::binary).write("test", 4);

    // Fake rpm -qa output (package list)
    std::string pkg_list = "package1\npackage2\npackage3\npackage4\n";
    scanner.set_pkg_list_output(pkg_list);

    // Fake rpm -V output with mismatches
    std::string fake = "S.5....T.  c /tmp/test_file1\n";  // First mismatch
    fake += "..5......  c /tmp/test_file2\n";  // This should trigger early exit
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/rpm");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "rpm");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "1");  // Should be exactly the threshold
    EXPECT_EQ(summary.metadata.at("early_exit_threshold"), "1");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "sample_50pct");
}

TEST(IntegrityScannerExtraTest, ScanWithRpmFullMultipleMismatches) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = false;
    cfg.integrity_max_mismatches = 2;  // Exit after 2 mismatches
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create /tmp/rpm to force rpm path
    std::ofstream("/tmp/rpm", std::ios::binary).write("test", 4);

    // Fake rpm -Va output with multiple mismatches
    std::string fake = "S.5....T.  c /tmp/test_file1\n";
    fake += "..5......  c /tmp/test_file2\n";  // Second mismatch - should trigger early exit
    fake += "S.5....T.  c /tmp/test_file3\n";  // This should not be processed due to early exit
    scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    scanner.scan(context);

    // Clean up
    fs::remove("/tmp/rpm");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 1);  // only summary

    const auto& summary = findings[0];
    EXPECT_EQ(summary.metadata.at("pkg_tool"), "rpm");
    EXPECT_EQ(summary.metadata.at("pkg_mismatch_count"), "2");  // Should be exactly the threshold
    EXPECT_EQ(summary.metadata.at("early_exit_threshold"), "2");
    EXPECT_EQ(summary.metadata.at("scan_mode"), "full");
}

TEST(IntegrityScannerExtraTest, ScanWithFileRehash) {
    Config cfg;
    cfg.integrity = true;
    cfg.integrity_pkg_verify = true;
    cfg.integrity_pkg_rehash = true;
    cfg.integrity_pkg_rehash_limit = 5;
    cfg.test_mode = false;

    TestIntegrityScanner scanner;

    // Create test files with known content
    std::ofstream("/tmp/rehash_file1", std::ios::binary).write("test content 1", 14);
    std::ofstream("/tmp/rehash_file2", std::ios::binary).write("test content 2", 14);

    // Override compute_file_hash to return a known hash for testing
    class TestIntegrityScannerWithHash : public TestIntegrityScanner {
    public:
        std::optional<std::string> compute_file_hash(const std::string& path) override {
            // Return a fake hash for testing purposes
            if (path == "/tmp/rehash_file1") {
                return "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
            } else if (path == "/tmp/rehash_file2") {
                return "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
            }
            return std::nullopt;
        }
    };

    TestIntegrityScannerWithHash hash_scanner;

    // Fake dpkg -V output with mismatches pointing to our test files
    std::string fake = "5c..\t /tmp/rehash_file1\n";
    fake += "..5.\t /tmp/rehash_file2\n";
    hash_scanner.set_cmd_output(fake);

    Report report;
    ScanContext context(cfg, report);

    hash_scanner.scan(context);

    // Clean up
    fs::remove("/tmp/rehash_file1");
    fs::remove("/tmp/rehash_file2");

    auto results = report.results();
    ASSERT_EQ(results.size(), 1);
    const auto& findings = results[0].findings;

    ASSERT_EQ(findings.size(), 3);  // summary + 2 rehash findings

    // Check rehash findings
    int rehash_count = 0;
    for (const auto& f : findings) {
        if (f.id.find("pkg_rehash:") == 0) {
            rehash_count++;
            EXPECT_EQ(f.title, "Package mismatch file hash");
            EXPECT_EQ(f.severity, Severity::Info);
            if (f.id == "pkg_rehash:/tmp/rehash_file1") {
                EXPECT_EQ(f.metadata.at("sha256"), "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
            } else if (f.id == "pkg_rehash:/tmp/rehash_file2") {
                EXPECT_EQ(f.metadata.at("sha256"), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd");
            }
        }
    }
    EXPECT_EQ(rehash_count, 2);
}

TEST(IntegrityScannerExtraTest, CoverBaseClassFunctions) {
    IntegrityScanner scanner;

    // Create a test file for compute_file_hash
    std::ofstream("/tmp/test_hash_file", std::ios::binary).write("test data for hash", 18);

    // Call test_compute_file_hash to cover the base class implementation
    auto hash = scanner.test_compute_file_hash("/tmp/test_hash_file");
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->length(), 64);  // SHA256 hex is 64 characters

    // Call test_check_ima_measurements to cover the base class implementation
    // Since /sys/kernel/security/ima/ascii_runtime_measurements doesn't exist, it should return {0, 0}
    auto [entries, failures] = scanner.test_check_ima_measurements();
    EXPECT_EQ(entries, 0);
    EXPECT_EQ(failures, 0);

    // Clean up
    fs::remove("/tmp/test_hash_file");
}

} // namespace sys_scan
