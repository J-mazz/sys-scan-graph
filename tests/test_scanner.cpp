#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Scanner.h"
#include "../src/core/ScannerRegistry.h"
#include "../src/core/Config.h"
#include "../src/core/Report.h"
#include "../src/core/ScanContext.h"
#include "../src/scanners/NetworkScanner.h"
#include <memory>
#include <string>
#include <vector>

namespace sys_scan {

// Mock scanner for testing
class MockScanner : public Scanner {
public:
    MOCK_METHOD(std::string, name, (), (const, override));
    MOCK_METHOD(std::string, description, (), (const, override));
    MOCK_METHOD(void, scan, (ScanContext& context), (override));
};

// Test fixture for ScannerRegistry tests
class ScannerRegistryTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.enable_scanners = {};
        config.disable_scanners = {};
        config.parallel = false;
        config.parallel_max_threads = 2;
        config.compliance = false;
        config.integrity = false;
        config.rules_enable = false;

        report = std::make_unique<Report>();
        context = std::make_unique<ScanContext>(config, *report);
    }

    Config config;
    std::unique_ptr<Report> report;
    std::unique_ptr<ScanContext> context;
};

TEST_F(ScannerRegistryTest, RegisterScanner) {
    ScannerRegistry registry;

    auto mock_scanner = std::make_unique<MockScanner>();
    EXPECT_CALL(*mock_scanner, name()).WillRepeatedly(testing::Return("mock_scanner"));
    EXPECT_CALL(*mock_scanner, description()).WillRepeatedly(testing::Return("Mock Scanner"));

    registry.register_scanner(std::move(mock_scanner));

    // Verify scanner is registered (indirectly through run_all)
    EXPECT_NO_THROW(registry.run_all(*context));
}

TEST_F(ScannerRegistryTest, RegisterMultipleScanners) {
    ScannerRegistry registry;

    for (int i = 0; i < 3; ++i) {
        auto mock_scanner = std::make_unique<MockScanner>();
        std::string scanner_name = "mock_scanner_" + std::to_string(i);
        EXPECT_CALL(*mock_scanner, name()).WillRepeatedly(testing::Return(scanner_name));
        EXPECT_CALL(*mock_scanner, description()).WillRepeatedly(testing::Return("Mock Scanner " + std::to_string(i)));
        EXPECT_CALL(*mock_scanner, scan(testing::_)).Times(1);

        registry.register_scanner(std::move(mock_scanner));
    }

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, RunAllSequential) {
    ScannerRegistry registry;
    config.parallel = false;

    auto mock_scanner1 = std::make_unique<MockScanner>();
    auto mock_scanner2 = std::make_unique<MockScanner>();

    EXPECT_CALL(*mock_scanner1, name()).WillRepeatedly(testing::Return("scanner1"));
    EXPECT_CALL(*mock_scanner1, description()).WillRepeatedly(testing::Return("Scanner 1"));
    EXPECT_CALL(*mock_scanner1, scan(testing::_)).Times(1);

    EXPECT_CALL(*mock_scanner2, name()).WillRepeatedly(testing::Return("scanner2"));
    EXPECT_CALL(*mock_scanner2, description()).WillRepeatedly(testing::Return("Scanner 2"));
    EXPECT_CALL(*mock_scanner2, scan(testing::_)).Times(1);

    registry.register_scanner(std::move(mock_scanner1));
    registry.register_scanner(std::move(mock_scanner2));

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, RunAllParallel) {
    ScannerRegistry registry;
    config.parallel = true;
    config.parallel_max_threads = 2;

    auto mock_scanner1 = std::make_unique<MockScanner>();
    auto mock_scanner2 = std::make_unique<MockScanner>();

    EXPECT_CALL(*mock_scanner1, name()).WillRepeatedly(testing::Return("scanner1"));
    EXPECT_CALL(*mock_scanner1, description()).WillRepeatedly(testing::Return("Scanner 1"));
    EXPECT_CALL(*mock_scanner1, scan(testing::_)).Times(1);

    EXPECT_CALL(*mock_scanner2, name()).WillRepeatedly(testing::Return("scanner2"));
    EXPECT_CALL(*mock_scanner2, description()).WillRepeatedly(testing::Return("Scanner 2"));
    EXPECT_CALL(*mock_scanner2, scan(testing::_)).Times(1);

    registry.register_scanner(std::move(mock_scanner1));
    registry.register_scanner(std::move(mock_scanner2));

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, EnableScannersFilter) {
    ScannerRegistry registry;
    config.enable_scanners = {"scanner1"};

    auto mock_scanner1 = std::make_unique<MockScanner>();
    auto mock_scanner2 = std::make_unique<MockScanner>();

    EXPECT_CALL(*mock_scanner1, name()).WillRepeatedly(testing::Return("scanner1"));
    EXPECT_CALL(*mock_scanner1, description()).WillRepeatedly(testing::Return("Scanner 1"));
    EXPECT_CALL(*mock_scanner1, scan(testing::_)).Times(1);

    EXPECT_CALL(*mock_scanner2, name()).WillRepeatedly(testing::Return("scanner2"));
    EXPECT_CALL(*mock_scanner2, description()).WillRepeatedly(testing::Return("Scanner 2"));
    EXPECT_CALL(*mock_scanner2, scan(testing::_)).Times(0); // Should not be called

    registry.register_scanner(std::move(mock_scanner1));
    registry.register_scanner(std::move(mock_scanner2));

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, DisableScannersFilter) {
    ScannerRegistry registry;
    config.disable_scanners = {"scanner2"};

    auto mock_scanner1 = std::make_unique<MockScanner>();
    auto mock_scanner2 = std::make_unique<MockScanner>();

    EXPECT_CALL(*mock_scanner1, name()).WillRepeatedly(testing::Return("scanner1"));
    EXPECT_CALL(*mock_scanner1, description()).WillRepeatedly(testing::Return("Scanner 1"));
    EXPECT_CALL(*mock_scanner1, scan(testing::_)).Times(1);

    EXPECT_CALL(*mock_scanner2, name()).WillRepeatedly(testing::Return("scanner2"));
    EXPECT_CALL(*mock_scanner2, description()).WillRepeatedly(testing::Return("Scanner 2"));
    EXPECT_CALL(*mock_scanner2, scan(testing::_)).Times(0); // Should not be called

    registry.register_scanner(std::move(mock_scanner1));
    registry.register_scanner(std::move(mock_scanner2));

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, ScannerExceptionHandling) {
    ScannerRegistry registry;

    auto mock_scanner = std::make_unique<MockScanner>();
    EXPECT_CALL(*mock_scanner, name()).WillRepeatedly(testing::Return("failing_scanner"));
    EXPECT_CALL(*mock_scanner, description()).WillRepeatedly(testing::Return("Failing Scanner"));
    EXPECT_CALL(*mock_scanner, scan(testing::_))
        .WillOnce(testing::Throw(std::runtime_error("Test exception")));

    registry.register_scanner(std::move(mock_scanner));

    // Should not throw, should handle exception gracefully
    EXPECT_NO_THROW(registry.run_all(*context));

    // Should have recorded an error finding
    auto results = report->results();
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].scanner_name, "failing_scanner");
    ASSERT_EQ(results[0].findings.size(), 1);
    EXPECT_EQ(results[0].findings[0].id, "failing_scanner:error");
    EXPECT_EQ(results[0].findings[0].title, "Scanner error");
    EXPECT_EQ(results[0].findings[0].severity, Severity::Error);
    EXPECT_EQ(results[0].findings[0].description, "Test exception");
}

TEST_F(ScannerRegistryTest, EmptyRegistry) {
    ScannerRegistry registry;

    // Should not crash with empty registry
    EXPECT_NO_THROW(registry.run_all(*context));
}

TEST_F(ScannerRegistryTest, RegisterAllDefault) {
    ScannerRegistry registry;

    // This will register all default scanners based on config
    EXPECT_NO_THROW(registry.register_all_default(config));

    // Should be able to run without crashing
    EXPECT_NO_THROW(registry.run_all(*context));
}

TEST_F(ScannerRegistryTest, ParallelMaxThreads) {
    ScannerRegistry registry;
    config.parallel = true;
    config.parallel_max_threads = 1; // Force single thread

    auto mock_scanner1 = std::make_unique<MockScanner>();
    auto mock_scanner2 = std::make_unique<MockScanner>();

    EXPECT_CALL(*mock_scanner1, name()).WillRepeatedly(testing::Return("scanner1"));
    EXPECT_CALL(*mock_scanner1, description()).WillRepeatedly(testing::Return("Scanner 1"));
    EXPECT_CALL(*mock_scanner1, scan(testing::_)).Times(1);

    EXPECT_CALL(*mock_scanner2, name()).WillRepeatedly(testing::Return("scanner2"));
    EXPECT_CALL(*mock_scanner2, description()).WillRepeatedly(testing::Return("Scanner 2"));
    EXPECT_CALL(*mock_scanner2, scan(testing::_)).Times(1);

    registry.register_scanner(std::move(mock_scanner1));
    registry.register_scanner(std::move(mock_scanner2));

    registry.run_all(*context);
}

TEST_F(ScannerRegistryTest, ScannerWithFindings) {
    ScannerRegistry registry;

    auto mock_scanner = std::make_unique<MockScanner>();
    EXPECT_CALL(*mock_scanner, name()).WillRepeatedly(testing::Return("finding_scanner"));
    EXPECT_CALL(*mock_scanner, description()).WillRepeatedly(testing::Return("Finding Scanner"));
    EXPECT_CALL(*mock_scanner, scan(testing::_)).WillOnce([](ScanContext& context) {
        Finding finding;
        finding.id = "TEST-001";
        finding.title = "Test Finding";
        finding.severity = Severity::Medium;
        finding.description = "This is a test finding";
        context.report.add_finding("finding_scanner", std::move(finding));
    });

    registry.register_scanner(std::move(mock_scanner));
    registry.run_all(*context);

    auto results = report->results();
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].scanner_name, "finding_scanner");
    ASSERT_EQ(results[0].findings.size(), 1);
    EXPECT_EQ(results[0].findings[0].id, "TEST-001");
    EXPECT_EQ(results[0].findings[0].title, "Test Finding");
    EXPECT_EQ(results[0].findings[0].severity, Severity::Medium);
}

TEST_F(ScannerRegistryTest, MultipleExceptions) {
    ScannerRegistry registry;

    // Register multiple scanners that throw exceptions
    for (int i = 0; i < 3; ++i) {
        auto mock_scanner = std::make_unique<MockScanner>();
        std::string scanner_name = "failing_scanner_" + std::to_string(i);
        EXPECT_CALL(*mock_scanner, name()).WillRepeatedly(testing::Return(scanner_name));
        EXPECT_CALL(*mock_scanner, description()).WillRepeatedly(testing::Return("Failing Scanner " + std::to_string(i)));
        EXPECT_CALL(*mock_scanner, scan(testing::_))
            .WillOnce(testing::Throw(std::runtime_error("Exception " + std::to_string(i))));

        registry.register_scanner(std::move(mock_scanner));
    }

    EXPECT_NO_THROW(registry.run_all(*context));

    auto results = report->results();
    EXPECT_EQ(results.size(), 3);

    for (int i = 0; i < 3; ++i) {
        std::string expected_name = "failing_scanner_" + std::to_string(i);
        auto it = std::find_if(results.begin(), results.end(),
            [&](const ScanResult& r) { return r.scanner_name == expected_name; });
        ASSERT_NE(it, results.end());
        ASSERT_EQ(it->findings.size(), 1);
        EXPECT_EQ(it->findings[0].id, expected_name + ":error");
        EXPECT_EQ(it->findings[0].description, "Exception " + std::to_string(i));
    }
}

TEST(NetworkScannerTest, NameAndDescription) {
    NetworkScanner scanner;
    EXPECT_EQ(scanner.name(), "network");
    EXPECT_EQ(scanner.description(), "Enumerate listening TCP/UDP sockets");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan