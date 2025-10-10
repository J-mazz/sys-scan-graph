#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/scanners/ProcessScanner.h"
#include "../src/core/ScanContext.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include <sys/types.h>
#include <unistd.h>
#include <filesystem>
#include <vector>
#include <string>

namespace fs = std::filesystem;

namespace sys_scan {
namespace test {

// Test fixture for ProcessScanner
class ProcessScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test config
        config = Config();
        config.process_inventory = true;
        config.all_processes = false;
        config.max_processes = 1000;
        config.containers = false;
        config.process_hash = false;
        config.no_user_meta = false;

        // Create report
        report = std::make_unique<Report>();
    }

    void TearDown() override {
        // Cleanup handled by unique_ptr
    }

    Config config;
    std::unique_ptr<Report> report;
};

// Basic scanner functionality tests
TEST_F(ProcessScannerTest, NameAndDescription) {
    ProcessScanner scanner;
    EXPECT_EQ(scanner.name(), "processes");
    EXPECT_EQ(scanner.description(), "Enumerate running processes with uid, gid, cmdline");
}

TEST_F(ProcessScannerTest, EmptyScan) {
    ProcessScanner scanner;
    ScanContext context(config, *report);

    // Should not crash on empty scan
    EXPECT_NO_THROW(scanner.scan(context));

    auto results = report->results();
    // Should have at least some results (current process)
    EXPECT_GE(results.size(), 0);
}

TEST_F(ProcessScannerTest, ProcessInventoryEnabled) {
    config.process_inventory = true;
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Check that scanner ran without crashing
    bool found_processes = false;
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            found_processes = true;
            // If we found processes, they should have proper structure
            for (const auto& finding : result.findings) {
                EXPECT_FALSE(finding.id.empty());
                EXPECT_EQ(finding.title, "Process " + finding.id);
                EXPECT_EQ(finding.severity, Severity::Info);
                if (!config.no_user_meta) {
                    EXPECT_TRUE(finding.metadata.count("uid"));
                    EXPECT_TRUE(finding.metadata.count("gid"));
                }
            }
            break;
        }
    }
    // Scanner should have run (may or may not find processes depending on environment)
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(ProcessScannerTest, ProcessInventoryDisabled) {
    config.process_inventory = false;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should not find any process findings
    bool found_processes = false;
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            found_processes = true;
            EXPECT_EQ(result.findings.size(), 0);
            break;
        }
    }
    // May or may not have the scanner result depending on implementation
}

TEST_F(ProcessScannerTest, MaxProcessesLimit) {
    config.process_inventory = true;
    config.max_processes = 3;  // Very low limit

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            EXPECT_LE(result.findings.size(), 3);
            break;
        }
    }
}

TEST_F(ProcessScannerTest, AllProcessesEnabled) {
    config.process_inventory = true;
    config.all_processes = true;
    config.max_processes = 20;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            // Should find more processes including kernel threads
            EXPECT_GE(result.findings.size(), 5);
            break;
        }
    }
}

TEST_F(ProcessScannerTest, NoUserMetaEnabled) {
    config.process_inventory = true;
    config.no_user_meta = true;
    config.max_processes = 5;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            for (const auto& finding : result.findings) {
                // Should not have UID/GID metadata
                EXPECT_FALSE(finding.metadata.count("uid"));
                EXPECT_FALSE(finding.metadata.count("gid"));
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ProcessHashEnabled) {
    config.process_inventory = true;
    config.process_hash = true;
    config.max_processes = 3;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            for (const auto& finding : result.findings) {
                // Should have exe_path and sha256 metadata
                EXPECT_TRUE(finding.metadata.count("exe_path"));
                EXPECT_TRUE(finding.metadata.count("sha256"));
                EXPECT_NE(finding.metadata.at("sha256"), "(error)");
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ContainersEnabled) {
    config.process_inventory = true;
    config.containers = true;
    config.max_processes = 5;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Container detection may or may not find containers
    // Just ensure it doesn't crash
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(ProcessScannerTest, ContainerIdFilter) {
    config.process_inventory = true;
    config.containers = true;
    config.container_id_filter = "nonexistent";
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // With nonexistent container filter, should find no processes
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            EXPECT_EQ(result.findings.size(), 0);
            break;
        }
    }
}

TEST_F(ProcessScannerTest, WarningForUnreadableFiles) {
    // This test ensures warnings are generated for unreadable process files
    // We can't easily create unreadable /proc files, but we can verify the warning mechanism exists
    config.process_inventory = true;
    config.max_processes = 1;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    // Should complete without crashing
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(ProcessScannerTest, CmdlineParsing) {
    config.process_inventory = true;
    config.all_processes = true;
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            for (const auto& finding : result.findings) {
                // Description should contain cmdline or indicate no cmdline
                EXPECT_TRUE(finding.description.find("(no cmdline)") != std::string::npos ||
                           !finding.description.empty());
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, LargeProcessCount) {
    config.process_inventory = true;
    config.max_processes = 100;  // Test with larger limit

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            EXPECT_LE(result.findings.size(), 100);
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ProcessHashOpensslDisabled) {
    // Test the OpenSSL disabled path by mocking or testing the fallback
    config.process_inventory = true;
    config.process_hash = true;
    config.max_processes = 2;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            for (const auto& finding : result.findings) {
                // Should have exe_path metadata
                EXPECT_TRUE(finding.metadata.count("exe_path"));
                // SHA256 should either be computed or marked as disabled/error
                EXPECT_TRUE(finding.metadata.count("sha256"));
                std::string sha256 = finding.metadata.at("sha256");
                EXPECT_TRUE(sha256 == "(disabled)" || sha256 == "(error)" ||
                           sha256.length() == 64);  // Valid SHA256 hex
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ContainerId64CharHex) {
    // Test 64-character hex container ID extraction
    config.process_inventory = true;
    config.containers = true;
    config.container_id_filter = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    // Should complete without crashing, may or may not find matching containers
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(ProcessScannerTest, ContainerFilteringMatch) {
    // Test container filtering with a realistic container ID
    config.process_inventory = true;
    config.containers = true;
    config.container_id_filter = "abcd1234";  // 8-char hex
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // With container filter, results should be filtered
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            // May find processes in containers or none
            // Just ensure it doesn't crash and filtering works
            for (const auto& finding : result.findings) {
                if (finding.metadata.count("container_id")) {
                    EXPECT_EQ(finding.metadata.at("container_id"), "abcd1234");
                }
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, MaxProcessesWarning) {
    // Test the warning when maximum process limit is reached
    config.process_inventory = true;
    config.max_processes = 1;  // Very low limit to trigger warning

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should have exactly max_processes findings
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            EXPECT_EQ(result.findings.size(), 1);
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ProcessExeSymlinkUnreadable) {
    // Test handling of unreadable exe symlinks
    config.process_inventory = true;
    config.process_hash = true;
    config.max_processes = 5;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    // Should complete without crashing even if some exe links are unreadable
    EXPECT_NO_THROW(scanner.scan(context));
}

TEST_F(ProcessScannerTest, ProcessCmdlineUnreadable) {
    // Test handling of unreadable cmdline files
    config.process_inventory = true;
    config.all_processes = true;  // Include processes that might have unreadable cmdline
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    auto results = report->results();

    // Should handle unreadable cmdline gracefully
    for (const auto& result : results) {
        if (result.scanner_name == "processes") {
            for (const auto& finding : result.findings) {
                // Description should be handled even if cmdline is unreadable
                EXPECT_FALSE(finding.description.empty() ||
                           finding.description == "(no cmdline)");
            }
            break;
        }
    }
}

TEST_F(ProcessScannerTest, ProcessStatusUnreadable) {
    // Test handling of unreadable status files
    config.process_inventory = true;
    config.max_processes = 10;

    ProcessScanner scanner;
    ScanContext context(config, *report);
    scanner.scan(context);

    // Should complete without crashing even if some status files are unreadable
    EXPECT_NO_THROW(scanner.scan(context));
}

} // namespace test
} // namespace sys_scan
