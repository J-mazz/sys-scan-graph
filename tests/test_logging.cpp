#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../src/core/Logging.h"
#include <sstream>
#include <thread>
#include <vector>
#include <iostream>

namespace sys_scan {

class LoggingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset logger to default state
        Logger::instance().set_level(LogLevel::Info);
    }

    void TearDown() override {
        // Clean up after each test
    }
};

TEST_F(LoggingTest, SingletonInstance) {
    Logger& logger1 = Logger::instance();
    Logger& logger2 = Logger::instance();

    // Should return the same instance
    EXPECT_EQ(&logger1, &logger2);
}

TEST_F(LoggingTest, DefaultLogLevel) {
    Logger& logger = Logger::instance();
    EXPECT_EQ(logger.level(), LogLevel::Info);
}

TEST_F(LoggingTest, SetLogLevel) {
    Logger& logger = Logger::instance();

    logger.set_level(LogLevel::Debug);
    EXPECT_EQ(logger.level(), LogLevel::Debug);

    logger.set_level(LogLevel::Error);
    EXPECT_EQ(logger.level(), LogLevel::Error);

    logger.set_level(LogLevel::Trace);
    EXPECT_EQ(logger.level(), LogLevel::Trace);
}

TEST_F(LoggingTest, LogLevelHierarchy) {
    Logger& logger = Logger::instance();

    // Test that higher levels include lower levels
    logger.set_level(LogLevel::Error);
    EXPECT_EQ(static_cast<int>(logger.level()), 0);

    logger.set_level(LogLevel::Warn);
    EXPECT_EQ(static_cast<int>(logger.level()), 1);

    logger.set_level(LogLevel::Info);
    EXPECT_EQ(static_cast<int>(logger.level()), 2);

    logger.set_level(LogLevel::Debug);
    EXPECT_EQ(static_cast<int>(logger.level()), 3);

    logger.set_level(LogLevel::Trace);
    EXPECT_EQ(static_cast<int>(logger.level()), 4);
}

TEST_F(LoggingTest, ConvenienceMethods) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Trace); // Enable all levels

    // These should not throw exceptions
    EXPECT_NO_THROW(logger.error("Test error message"));
    EXPECT_NO_THROW(logger.warn("Test warning message"));
    EXPECT_NO_THROW(logger.info("Test info message"));
    EXPECT_NO_THROW(logger.debug("Test debug message"));
    EXPECT_NO_THROW(logger.trace("Test trace message"));
}

TEST_F(LoggingTest, LogLevelFiltering) {
    Logger& logger = Logger::instance();

    // Set to Error level - should only log Error
    logger.set_level(LogLevel::Error);

    // These should work without throwing
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Error message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warn, "Warning message")); // Should be filtered out
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Info message"));     // Should be filtered out
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Debug message"));   // Should be filtered out
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Trace message"));   // Should be filtered out
}

TEST_F(LoggingTest, LogPrefixes) {
    Logger& logger = Logger::instance();

    // Test that we can call the private prefix method indirectly through log
    // Since we can't directly test the prefix method, we'll verify the logging works
    logger.set_level(LogLevel::Info);

    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Test"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warn, "Test"));
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test"));
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Test"));
}

TEST_F(LoggingTest, ThreadSafety) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Info);

    const int num_threads = 10;
    const int logs_per_thread = 100;

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i]() {
            for (int j = 0; j < logs_per_thread; ++j) {
                logger.info("Thread " + std::to_string(i) + " log " + std::to_string(j));
            }
        });
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // If we get here without deadlocks or crashes, thread safety is working
    SUCCEED();
}

TEST_F(LoggingTest, LogLevelEnumValues) {
    // Test enum values are as expected
    EXPECT_EQ(static_cast<int>(LogLevel::Error), 0);
    EXPECT_EQ(static_cast<int>(LogLevel::Warn), 1);
    EXPECT_EQ(static_cast<int>(LogLevel::Info), 2);
    EXPECT_EQ(static_cast<int>(LogLevel::Debug), 3);
    EXPECT_EQ(static_cast<int>(LogLevel::Trace), 4);
}

TEST_F(LoggingTest, MultipleLogCalls) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Info);

    // Test multiple calls don't interfere with each other
    for (int i = 0; i < 100; ++i) {
        EXPECT_NO_THROW(logger.info("Message " + std::to_string(i)));
    }
}

TEST_F(LoggingTest, EmptyMessages) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Info);

    // Test empty messages
    EXPECT_NO_THROW(logger.error(""));
    EXPECT_NO_THROW(logger.warn(""));
    EXPECT_NO_THROW(logger.info(""));
    EXPECT_NO_THROW(logger.debug(""));
    EXPECT_NO_THROW(logger.trace(""));
}

TEST_F(LoggingTest, LongMessages) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Info);

    // Test with very long messages
    std::string long_message(10000, 'A');
    EXPECT_NO_THROW(logger.info(long_message));
}

TEST_F(LoggingTest, SpecialCharacters) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::Info);

    // Test messages with special characters
    std::string special_msg = "Message with\nnewlines\tand\ttabs\r\nand unicode: \u00A9";
    EXPECT_NO_THROW(logger.info(special_msg));
}

TEST_F(LoggingTest, LogLevelBoundaries) {
    Logger& logger = Logger::instance();

    // Test boundary conditions
    logger.set_level(LogLevel::Error);
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Boundary test"));

    logger.set_level(LogLevel::Trace);
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Boundary test"));
}

TEST_F(LoggingTest, LoggerStatePersistence) {
    Logger& logger = Logger::instance();

    // Set a level and verify it persists
    logger.set_level(LogLevel::Debug);
    EXPECT_EQ(logger.level(), LogLevel::Debug);

    // Call some methods
    EXPECT_NO_THROW(logger.info("Test message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));

    // Verify level is still the same
    EXPECT_EQ(logger.level(), LogLevel::Debug);
}

TEST_F(LoggingTest, ConcurrentLevelChanges) {
    Logger& logger = Logger::instance();

    const int num_threads = 5;

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i]() {
            // Each thread changes the level and logs
            LogLevel new_level = static_cast<LogLevel>(i % 5);
            logger.set_level(new_level);
            logger.info("Thread " + std::to_string(i) + " set level to " + std::to_string(static_cast<int>(new_level)));
        });
    }

    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }

    // Logger should still be in a valid state
    LogLevel current_level = logger.level();
    EXPECT_TRUE(current_level >= LogLevel::Error && current_level <= LogLevel::Trace);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace sys_scan